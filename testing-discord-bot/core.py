import json
import os
import re
import subprocess
import tempfile
import base64
import socket
from datetime import datetime, date, timedelta
from urllib.parse import quote
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional
from uuid import uuid4

CONFIG = Path("/usr/local/etc/xray/config.json")
ROLLING_BACKUP = Path("/usr/local/etc/xray/config.json.backup")

QUOTA_DIR = Path("/opt/quota")
DETAIL_BASE = {
    "vless": Path("/opt/vless"),
    "vmess": Path("/opt/vmess"),
    "trojan": Path("/opt/trojan"),
    "allproto": Path("/opt/allproto"),
}

VALID_PROTO = {"vless","vmess","trojan","allproto"}
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]+$")

def _final_user(proto: str, username: str) -> str:
    return f"{username}@{proto}"

def _atomic_write(path: Path, data: bytes, mode: int, uid: int, gid: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".tmp-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        try:
            os.chown(tmp, uid, gid)
        except PermissionError:
            pass
        os.replace(tmp, path)
    finally:
        try:
            if os.path.exists(tmp):
                os.unlink(tmp)
        except Exception:
            pass

def _load_config() -> Dict[str, Any]:
    if not CONFIG.exists():
        raise FileNotFoundError(str(CONFIG))
    raw = CONFIG.read_text(encoding="utf-8")
    return json.loads(raw)

def _save_config_with_backup(cfg: Dict[str, Any]) -> str:
    # rolling backup (single file)
    try:
        if CONFIG.exists():
            _atomic_write(
                ROLLING_BACKUP,
                CONFIG.read_bytes(),
                mode=0o600,
                uid=0,
                gid=0
            )
    except Exception:
        # best effort backup
        pass

    # ✅ Preserve original permission/owner/group of CONFIG
    if CONFIG.exists():
        st = CONFIG.stat()
        mode = st.st_mode & 0o777
        uid = st.st_uid
        gid = st.st_gid
    else:
        # reasonable default if somehow missing
        mode, uid, gid = 0o644, 0, 0

    data = (json.dumps(cfg, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    _atomic_write(CONFIG, data, mode=mode, uid=uid, gid=gid)
    return str(ROLLING_BACKUP)

def _restart_xray() -> None:
    subprocess.check_call(["systemctl", "restart", "xray"])

def _ensure_client_list(ib: Dict[str, Any]) -> List[Dict[str, Any]]:
    settings = ib.get("settings")
    if not isinstance(settings, dict):
        settings = {}
        ib["settings"] = settings

    clients = settings.get("clients")
    if not isinstance(clients, list):
        clients = []
        settings["clients"] = clients
    return clients

def _email_exists(cfg: Dict[str, Any], email: str) -> bool:
    inbounds = cfg.get("inbounds", [])
    if not isinstance(inbounds, list):
        return False
    for ib in inbounds:
        if not isinstance(ib, dict):
            continue
        proto = ib.get("protocol")
        if proto not in ("vless", "vmess", "trojan"):
            continue
        clients = _ensure_client_list(ib)
        for c in clients:
            if isinstance(c, dict) and c.get("email") == email:
                return True
    return False

def _append(cfg: Dict[str, Any], proto: str, email: str, secret: str) -> int:
    inbounds = cfg.get("inbounds", [])
    if not isinstance(inbounds, list):
        return 0

    n = 0
    for ib in inbounds:
        if not isinstance(ib, dict):
            continue
        if ib.get("protocol") != proto:
            continue

        clients = _ensure_client_list(ib)

        if proto in ("vless", "vmess"):
            clients.append({"id": secret, "email": email})
            n += 1
        elif proto == "trojan":
            clients.append({"password": secret, "email": email})
            n += 1

    return n

def _remove(cfg: Dict[str, Any], proto: str, email: str) -> int:
    inbounds = cfg.get("inbounds", [])
    if not isinstance(inbounds, list):
        return 0

    removed = 0
    for ib in inbounds:
        if not isinstance(ib, dict):
            continue
        if ib.get("protocol") != proto:
            continue

        clients = _ensure_client_list(ib)
        before = len(clients)
        clients[:] = [c for c in clients if not (isinstance(c, dict) and c.get("email") == email)]
        removed += (before - len(clients))

    return removed

def _quota_bytes_from_gb(quota_gb: float) -> int:
    if quota_gb <= 0:
        return 0
    return int(round(quota_gb * 1073741824))

def _write_quota(proto: str, final_u: str, quota_gb: float, days: int) -> str:
    # Note: allproto only writes to /opt/quota/allproto
    d = QUOTA_DIR / proto
    d.mkdir(parents=True, exist_ok=True)

    created = date.today().isoformat()
    expired = (date.today() + timedelta(days=days)).isoformat()

    obj = {
        "username": final_u,
        "protocol": proto,
        "quota_limit": _quota_bytes_from_gb(quota_gb),
        "created_at": created,
        "expired_at": expired,
    }
    p = d / f"{final_u}.json"
    p.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")
    return str(p)

def _read_domain_from_nginx_conf() -> str:
    # parse server_name from /etc/nginx/conf.d/xray.conf
    conf = Path("/etc/nginx/conf.d/xray.conf")
    if not conf.exists():
        return "unknown"
    try:
        txt = conf.read_text(encoding="utf-8", errors="ignore")
        m = re.search(r"^\s*server_name\s+([^;]+);", txt, flags=re.M)
        if m:
            # first token is enough
            return m.group(1).strip().split()[0]
    except Exception:
        pass
    return "unknown"

def _read_public_port_from_nginx_conf(default: int = 443) -> int:
    """
    Ambil port publik dari /etc/nginx/conf.d/xray.conf dengan prioritas:
      1) directive 'listen ... ssl;' (TLS public)
      2) directive 'listen ...;' non-ssl
    Fallback ke default jika tidak ditemukan.

    Contoh yang didukung:
      listen 443 ssl;
      listen [::]:443 ssl;
      listen 0.0.0.0:443 ssl http2;
      listen 80;
      listen [::]:80;
    """
    conf = Path("/etc/nginx/conf.d/xray.conf")
    if not conf.exists():
        return default

    def _extract_port(listen_value: str) -> Optional[int]:
        s = listen_value.strip()

        # Ambil port setelah ":" dulu (ipv4/ipv6 bind)
        m = re.search(r":(\d{2,5})\b", s)
        if m:
            p = int(m.group(1))
            if 1 <= p <= 65535:
                return p

        # Kalau tidak ada ":" ambil angka pertama
        m2 = re.search(r"\b(\d{2,5})\b", s)
        if m2:
            p = int(m2.group(1))
            if 1 <= p <= 65535:
                return p

        return None

    try:
        txt = conf.read_text(encoding="utf-8", errors="ignore")
        listens = re.findall(r"^\s*listen\s+([^;]+);", txt, flags=re.M)

        ssl_ports: List[int] = []
        nonssl_ports: List[int] = []

        for lv in listens:
            port = _extract_port(lv)
            if port is None:
                continue

            # deteksi ssl token pada listen directive
            is_ssl = re.search(r"\bssl\b", lv) is not None
            if is_ssl:
                ssl_ports.append(port)
            else:
                nonssl_ports.append(port)

        # Prioritas: listen ... ssl;
        if ssl_ports:
            return ssl_ports[0]

        # Fallback: listen non-ssl pertama (mis. 80)
        if nonssl_ports:
            return nonssl_ports[0]

    except Exception:
        pass

    return default

def _get_ip() -> str:
    # public IP from ifconfig.me
    try:
        out = subprocess.check_output(
            ["curl", "-s", "--max-time", "5", "ifconfig.me"],
            text=True
        ).strip()
        # validasi sederhana IPv4/IPv6
        if out and len(out) <= 64:
            return out
    except Exception:
        pass

    # fallback (kalau curl gagal)
    try:
        out = subprocess.check_output(["bash", "-lc", "hostname -I | awk '{print $1}'"], text=True).strip()
        if out:
            return out
    except Exception:
        pass

    return "unknown"

def _fmt_quota_gb(quota_gb: float) -> str:
    if quota_gb <= 0:
        return "Unlimited"
    if abs(quota_gb - int(quota_gb)) < 1e-9:
        return f"{int(quota_gb)} GB"
    return f"{quota_gb:g} GB"

def _safe_int(v: Any, default: int) -> int:
    try:
        return int(v)
    except Exception:
        return default

def _quota_scan_protos(proto_filter: str) -> List[str]:
    pf = (proto_filter or "").strip().lower()
    if pf in ("", "all", "*"):
        return ["vless", "vmess", "trojan", "allproto"]
    if pf in VALID_PROTO:
        return [pf]
    return []

def _scan_quota_items(proto_filter: str) -> List[Dict[str, Any]]:
    """Scan /opt/quota/* metadata JSON files and return a de-duplicated list.

    Source of truth for listing = quota metadata (NOT Xray config).
    Dedup key = username; if duplicates exist, keep newest by file mtime.
    """
    protos = _quota_scan_protos(proto_filter)
    if not protos:
        return []

    by_user: Dict[str, Tuple[float, Dict[str, Any]]] = {}

    for proto in protos:
        d = QUOTA_DIR / proto
        if not d.exists() or not d.is_dir():
            continue

        for p in d.glob("*.json"):
            try:
                obj = json.loads(p.read_text(encoding="utf-8"))
                if not isinstance(obj, dict):
                    continue

                username = str(obj.get("username") or "").strip()
                pproto = str(obj.get("protocol") or proto).strip().lower()
                expired_at = str(obj.get("expired_at") or "").strip()
                created_at = str(obj.get("created_at") or "").strip()
                quota_limit = obj.get("quota_limit")

                if pproto not in VALID_PROTO:
                    continue
                if not username or not username.endswith(f"@{pproto}"):
                    continue

                base = DETAIL_BASE["allproto"] if pproto == "allproto" else DETAIL_BASE[pproto]
                detail_path = str(base / f"{username}.txt")

                item = {
                    "username": username,
                    "protocol": pproto,
                    "expired_at": expired_at,
                    "created_at": created_at,
                    "quota_limit": quota_limit,
                    "detail_path": detail_path,
                }

                mtime = p.stat().st_mtime
                prev = by_user.get(username)
                if prev is None or mtime >= prev[0]:
                    by_user[username] = (mtime, item)
            except Exception:
                # skip invalid/corrupt metadata files
                continue

    items = [v[1] for v in by_user.values()]

    def sort_key(it: Dict[str, Any]):
        exp = str(it.get("expired_at") or "").strip() or "9999-12-31"
        return (exp, str(it.get("username") or ""))

    items.sort(key=sort_key)
    return items

def _collect_inbounds(cfg: Dict[str, Any], proto: str):
    """Return list of tuples (port, network, security, streamSettings) for matching protocol inbounds."""
    res = []
    inbounds = cfg.get("inbounds", [])
    if not isinstance(inbounds, list):
        return res
    for ib in inbounds:
        if not isinstance(ib, dict) or ib.get("protocol") != proto:
            continue
        port = ib.get("port")
        stream = ib.get("streamSettings") if isinstance(ib.get("streamSettings"), dict) else {}
        network = stream.get("network", "tcp")
        security = stream.get("security", "tls") or "tls"
        res.append((port, network, security, stream))
    return res

def _build_links_for_vless(domain: str, email: str, uuid: str, items, public_port: int):
    links = []
    def add(label, link):
        links.append(f"{label:10}: {link}")

    # kalau items kosong, fallback minimal
    if not items:
        add("WebSocket", f"vless://{uuid}@{domain}:{public_port}?security=tls&encryption=none&type=ws&path=%2F#" + quote(email))
        return links

    seen = set()
    for _port, network, security, stream in items:
        port = public_port  # ✅ force public port
        ws = stream.get("wsSettings", {}) if isinstance(stream.get("wsSettings"), dict) else {}
        grpc = stream.get("grpcSettings", {}) if isinstance(stream.get("grpcSettings"), dict) else {}
        http = stream.get("httpSettings", {}) if isinstance(stream.get("httpSettings"), dict) else {}

        if network == "ws":
            path_ = ws.get("path", "/")
            key = ("ws", port, path_, security)
            if key in seen:
                continue
            seen.add(key)
            add("WebSocket", f"vless://{uuid}@{domain}:{port}?security={security}&encryption=none&type=ws&path={quote(path_)}#" + quote(email))

        elif network == "grpc":
            sn = grpc.get("serviceName", "grpc")
            key = ("grpc", port, sn, security)
            if key in seen:
                continue
            seen.add(key)
            add("gRPC", f"vless://{uuid}@{domain}:{port}?security={security}&encryption=none&type=grpc&serviceName={quote(sn)}&mode=gun#" + quote(email))

        elif network == "httpupgrade":
            path_ = http.get("path", "/")
            key = ("httpupgrade", port, path_, security)
            if key in seen:
                continue
            seen.add(key)
            add("HTTPUpgrade", f"vless://{uuid}@{domain}:{port}?security={security}&encryption=none&type=httpupgrade&path={quote(path_)}#" + quote(email))

        else:
            key = ("tcp", port, security)
            if key in seen:
                continue
            seen.add(key)
            add("TCP", f"vless://{uuid}@{domain}:{port}?security={security}&encryption=none&type=tcp#" + quote(email))

    return links

def _build_links_for_trojan(domain: str, email: str, pwd: str, items, public_port: int):
    links = []
    def add(label, link):
        links.append(f"{label:10}: {link}")

    add("TLS", f"trojan://{pwd}@{domain}:{public_port}?security=tls&type=tcp#" + quote(email))
    return links

def _build_links_for_vmess(domain: str, email: str, uuid: str, items, public_port: int):
    links = []
    def add(label, link):
        links.append(f"{label:10}: {link}")

    if not items:
        obj = {
            "v": "2",
            "ps": email,
            "add": domain,
            "port": str(public_port),  # ✅ public port
            "id": uuid,
            "aid": "0",
            "net": "ws",
            "type": "none",
            "host": domain,
            "path": "/",
            "tls": "tls",
        }
        b64 = base64.urlsafe_b64encode(json.dumps(obj).encode("utf-8")).decode("ascii").rstrip("=")
        add("WebSocket", f"vmess://{b64}")
        return links

    seen = set()
    for _port, network, security, stream in items:
        port = public_port  # ✅ force public port
        ws = stream.get("wsSettings", {}) if isinstance(stream.get("wsSettings"), dict) else {}
        grpc = stream.get("grpcSettings", {}) if isinstance(stream.get("grpcSettings"), dict) else {}
        http = stream.get("httpSettings", {}) if isinstance(stream.get("httpSettings"), dict) else {}

        if network == "ws":
            path_ = ws.get("path", "/")
            key = ("ws", port, path_, security)
            if key in seen:
                continue
            seen.add(key)
            obj = {
                "v": "2",
                "ps": email,
                "add": domain,
                "port": str(port),
                "id": uuid,
                "aid": "0",
                "net": "ws",
                "type": "none",
                "host": domain,
                "path": path_,
                "tls": security,
            }
            b64 = base64.urlsafe_b64encode(json.dumps(obj).encode("utf-8")).decode("ascii").rstrip("=")
            add("WebSocket", f"vmess://{b64}")

        elif network == "grpc":
            sn = grpc.get("serviceName", "grpc")
            key = ("grpc", port, sn, security)
            if key in seen:
                continue
            seen.add(key)
            obj = {
                "v": "2",
                "ps": email,
                "add": domain,
                "port": str(port),
                "id": uuid,
                "aid": "0",
                "net": "grpc",
                "type": "gun",
                "host": domain,
                "path": sn,
                "tls": security,
            }
            b64 = base64.urlsafe_b64encode(json.dumps(obj).encode("utf-8")).decode("ascii").rstrip("=")
            add("gRPC", f"vmess://{b64}")

        elif network == "httpupgrade":
            path_ = http.get("path", "/")
            key = ("httpupgrade", port, path_, security)
            if key in seen:
                continue
            seen.add(key)
            obj = {
                "v": "2",
                "ps": email,
                "add": domain,
                "port": str(port),
                "id": uuid,
                "aid": "0",
                "net": "httpupgrade",
                "type": "none",
                "host": domain,
                "path": path_,
                "tls": security,
            }
            b64 = base64.urlsafe_b64encode(json.dumps(obj).encode("utf-8")).decode("ascii").rstrip("=")
            add("HTTPUpgrade", f"vmess://{b64}")

        else:
            key = ("tcp", port, security)
            if key in seen:
                continue
            seen.add(key)
            obj = {
                "v": "2",
                "ps": email,
                "add": domain,
                "port": str(port),
                "id": uuid,
                "aid": "0",
                "net": "tcp",
                "type": "none",
                "host": domain,
                "path": "",
                "tls": security,
            }
            b64 = base64.urlsafe_b64encode(json.dumps(obj).encode("utf-8")).decode("ascii").rstrip("=")
            add(network.upper(), f"vmess://{b64}")

    return links

def _write_detail(proto: str, final_u: str, secret: str, days: int, quota_gb: float) -> str:
    base = DETAIL_BASE["allproto"] if proto == "allproto" else DETAIL_BASE[proto]
    base.mkdir(parents=True, exist_ok=True)

    domain = _read_domain_from_nginx_conf()
    ip = _get_ip()

    expired_at = (date.today() + timedelta(days=days)).isoformat()
    created_at = datetime.now().strftime("%a %b %e %H:%M:%S %Z %Y")
    quota = _fmt_quota_gb(quota_gb)

    detail = {
        "domain": domain,
        "ip": ip,
        "username": final_u,
        "protocol": proto,
        "uuid": secret if proto in ("vless", "vmess", "allproto") else None,
        "password": secret if proto == "trojan" else None,
        "quota_limit": quota,
        "expired_days": days,
        "valid_until": expired_at,
        "created": created_at,
    }

    p = base / f"{final_u}.json"
    p.write_text(json.dumps(detail, indent=2) + "\n", encoding="utf-8")
    return str(p)

def _write_detail_txt(cfg: Dict[str, Any], proto: str, final_user: str, secret: str, days: int, quota_gb: float) -> str:
    # ✅ Domain dari nginx xray.conf
    domain = _read_domain_from_nginx_conf()

    # ✅ Public IP dari ifconfig.me (fallback ke _get_ip())
    ipaddr = "unknown"
    try:
        out = subprocess.check_output(
            ["curl", "-s", "--max-time", "5", "ifconfig.me"],
            text=True
        ).strip()
        if out and len(out) <= 64 and (" " not in out) and ("\n" not in out) and ("\r" not in out):
            ipaddr = out
    except Exception:
        pass

    if ipaddr == "unknown":
        try:
            ipaddr = _get_ip()
        except Exception:
            ipaddr = "unknown"

    # ✅ Public port dari nginx xray.conf (default 443)
    public_port = _read_public_port_from_nginx_conf(443)

    valid_until = (date.today() + timedelta(days=days)).isoformat()

    # created (tetap gaya lama)
    try:
        created = datetime.now().strftime("%a %b %d %H:%M:%S %Z %Y").strip()
        if not created:
            created = datetime.now().strftime("%a %b %d %H:%M:%S %Y")
    except Exception:
        created = datetime.now().strftime("%a %b %d %H:%M:%S %Y")

    quota_str = _fmt_quota_gb(quota_gb)

    # Collect inbound streamSettings untuk generate link
    vless_items = _collect_inbounds(cfg, "vless")
    vmess_items = _collect_inbounds(cfg, "vmess")
    trojan_items = _collect_inbounds(cfg, "trojan")

    lines: List[str] = []
    lines.append("=" * 50)
    lines.append(f"{('XRAY ACCOUNT DETAIL (' + proto + ')'):^50}")
    lines.append("=" * 50)
    lines.append(f"Domain     : {domain}")
    lines.append(f"IP         : {ipaddr}")
    lines.append(f"Username   : {final_user}")
    lines.append(f"UUID/Pass  : {secret}")
    lines.append(f"QuotaLimit : {quota_str}")
    lines.append(f"Expired    : {days} Hari")
    lines.append(f"ValidUntil : {valid_until}")
    lines.append(f"Created    : {created}")
    lines.append("=" * 50)

    # ✅ Generate link pakai port publik (public_port) via parameter builder
    if proto == "vless":
        lines.append("[VLESS]")
        lines.extend(_build_links_for_vless(domain, final_user, secret, vless_items, public_port))

    elif proto == "vmess":
        lines.append("[VMESS]")
        lines.extend(_build_links_for_vmess(domain, final_user, secret, vmess_items, public_port))

    elif proto == "trojan":
        lines.append("[TROJAN]")
        lines.extend(_build_links_for_trojan(domain, final_user, secret, trojan_items, public_port))

    else:  # allproto
        lines.append("[VLESS]")
        lines.extend(_build_links_for_vless(domain, final_user, secret, vless_items, public_port))
        lines.append("-" * 50)
        lines.append("[VMESS]")
        lines.extend(_build_links_for_vmess(domain, final_user, secret, vmess_items, public_port))
        lines.append("-" * 50)
        lines.append("[TROJAN]")
        lines.extend(_build_links_for_trojan(domain, final_user, secret, trojan_items, public_port))

    lines.append("-" * 50)
    lines.append("=" * 50)

    content = "\n".join(lines) + "\n"

    base = DETAIL_BASE["allproto"] if proto == "allproto" else DETAIL_BASE[proto]
    base.mkdir(parents=True, exist_ok=True)
    out = base / f"{final_user}.txt"
    out.write_text(content, encoding="utf-8")
    return str(out)

def handle_action(req: Dict[str, Any]) -> Dict[str, Any]:
    action = (req.get("action") or "").strip().lower()

    # Allow read-only + mutating actions
    if action not in ("add", "del", "ping", "status", "list"):
        return {"status": "error", "error": "unsupported action"}

    # -----------------------------
    # Read-only actions (no proto/user required)
    # -----------------------------
    if action == "ping":
        return {"status": "ok"}

    if action == "status":
        def svc(name: str) -> str:
            try:
                p = subprocess.run(
                    ["systemctl", "is-active", name],
                    capture_output=True,
                    text=True
                )
                out = (p.stdout or "").strip()
                err = (p.stderr or "").strip()
                if out:
                    return out
                return err or "unknown"
            except Exception:
                return "unknown"

        return {
            "status": "ok",
            "xray": svc("xray"),
            "nginx": svc("nginx"),
        }

    if action == "list":
        proto_filter = str(req.get("protocol") or "all").strip().lower()
        protos = _quota_scan_protos(proto_filter)
        if not protos:
            return {"status": "error", "error": "invalid protocol"}

        limit = _safe_int(req.get("limit"), 25)
        offset = _safe_int(req.get("offset"), 0)

        # Discord select menu max 25 options; enforce safe bounds.
        if limit < 1:
            limit = 1
        if limit > 25:
            limit = 25
        if offset < 0:
            offset = 0

        items = _scan_quota_items(proto_filter)
        total = len(items)
        page = items[offset: offset + limit]
        has_more = (offset + limit) < total

        return {
            "status": "ok",
            "protocol": proto_filter,
            "offset": offset,
            "limit": limit,
            "total": total,
            "has_more": has_more,
            "items": page,
        }

    # -----------------------------
    # Mutating actions (require proto/user)
    # -----------------------------
    proto = (req.get("protocol") or "").strip().lower()
    username = (req.get("username") or "").strip()

    if proto not in VALID_PROTO:
        return {"status": "error", "error": "invalid protocol"}
    if not USERNAME_RE.match(username):
        return {"status": "error", "error": "invalid username"}

    cfg = _load_config()

    if action == "add":
        # parse args
        try:
            days = int(req.get("days", 0))
        except Exception:
            return {"status": "error", "error": "days must be integer"}

        try:
            quota_gb = float(req.get("quota_gb", 0))
        except Exception:
            return {"status": "error", "error": "quota_gb must be number"}

        if days <= 0 or days > 3650:
            return {"status": "error", "error": "days out of range (1..3650)"}
        if quota_gb < 0:
            return {"status": "error", "error": "quota_gb must be >= 0"}

        final_u = _final_user(proto, username)
        if _email_exists(cfg, final_u):
            return {"status": "error", "error": "duplicate email", "username": final_u}

        secret = str(uuid4())

        # add clients
        if proto == "allproto":
            n1 = _append(cfg, "vless", final_u, secret)
            n2 = _append(cfg, "vmess", final_u, secret)
            n3 = _append(cfg, "trojan", final_u, secret)
            if min(n1, n2, n3) == 0:
                return {"status": "error", "error": "missing inbound for one of vless/vmess/trojan"}
        else:
            n = _append(cfg, proto, final_u, secret)
            if n == 0:
                return {"status": "error", "error": "no matching inbound found"}

        # save config + restart xray
        backup_path = _save_config_with_backup(cfg)
        _restart_xray()

        # quota metadata
        if proto == "allproto":
            _write_quota("allproto", final_u, quota_gb, days)

            # cleanup legacy/duplicate files from older versions
            def _rm_quota(p: Path):
                try:
                    if p.exists():
                        p.unlink()
                except Exception:
                    pass

            _rm_quota(QUOTA_DIR / "vless" / f"{final_u}.json")
            _rm_quota(QUOTA_DIR / "vmess" / f"{final_u}.json")
            _rm_quota(QUOTA_DIR / "trojan" / f"{final_u}.json")
        else:
            _write_quota(proto, final_u, quota_gb, days)

        # detail files: keep JSON + add TXT
        detail_json_path = _write_detail(proto, final_u, secret, days, quota_gb)
        detail_txt_path = _write_detail_txt(cfg, proto, final_u, secret, days, quota_gb)

        expired_at = (date.today() + timedelta(days=days)).isoformat()

        return {
            "status": "ok",
            "username": final_u,
            "uuid": secret if proto != "trojan" else None,
            "password": secret if proto == "trojan" else None,
            "expired_at": expired_at,
            "detail_path": detail_txt_path,           # Discord attaches this (.txt)
            "detail_json_path": detail_json_path,    # still generated (.json)
            "backup_path": backup_path,
        }

    # action == "del"
    final_u = _final_user(proto, username)

    removed = 0
    if proto == "allproto":
        removed += _remove(cfg, "vless", final_u)
        removed += _remove(cfg, "vmess", final_u)
        removed += _remove(cfg, "trojan", final_u)
    else:
        removed = _remove(cfg, proto, final_u)

    if removed == 0:
        return {"status": "error", "error": "user not found", "username": final_u}

    backup_path = _save_config_with_backup(cfg)
    _restart_xray()

    def _rm(p: Path):
        try:
            if p.exists():
                p.unlink()
        except Exception:
            pass

    if proto == "allproto":
        # quota: only allproto
        _rm(QUOTA_DIR / "allproto" / f"{final_u}.json")

        # detail: remove both json+txt for allproto
        _rm(DETAIL_BASE["allproto"] / f"{final_u}.json")
        _rm(DETAIL_BASE["allproto"] / f"{final_u}.txt")

        # best-effort cleanup legacy files from older versions:
        _rm(QUOTA_DIR / "vless" / f"{final_u}.json")
        _rm(QUOTA_DIR / "vmess" / f"{final_u}.json")
        _rm(QUOTA_DIR / "trojan" / f"{final_u}.json")

        _rm(DETAIL_BASE["vless"] / f"{final_u}.json")
        _rm(DETAIL_BASE["vmess"] / f"{final_u}.json")
        _rm(DETAIL_BASE["trojan"] / f"{final_u}.json")

        _rm(DETAIL_BASE["vless"] / f"{final_u}.txt")
        _rm(DETAIL_BASE["vmess"] / f"{final_u}.txt")
        _rm(DETAIL_BASE["trojan"] / f"{final_u}.txt")
    else:
        _rm(QUOTA_DIR / proto / f"{final_u}.json")
        _rm(DETAIL_BASE[proto] / f"{final_u}.json")
        _rm(DETAIL_BASE[proto] / f"{final_u}.txt")

    return {"status": "ok", "username": final_u, "removed": removed, "backup_path": backup_path}


def _cli_usage() -> str:
    return (
        "Usage:\n"
        "  core.py add <proto> <username> <days> <quota_gb>\n"
        "  core.py del <proto> <username>\n"
        "Examples:\n"
        "  core.py add vless andi 30 10\n"
        "  core.py del vless andi\n"
    )

def _cli_main(argv: List[str]) -> int:
    if len(argv) < 2 or argv[1] in ("-h","--help"):
        print(_cli_usage())
        return 0

    action = argv[1].lower()
    if action == "add":
        if len(argv) != 6:
            print(_cli_usage())
            return 2
        proto, user = argv[2], argv[3]
        days = int(argv[4])
        quota = float(argv[5])
        res = handle_action({"action":"add","protocol":proto,"username":user,"days":days,"quota_gb":quota})
        print(json.dumps(res, indent=2))
        return 0 if res.get("status") == "ok" else 1

    if action == "del":
        if len(argv) != 4:
            print(_cli_usage())
            return 2
        proto, user = argv[2], argv[3]
        res = handle_action({"action":"del","protocol":proto,"username":user})
        print(json.dumps(res, indent=2))
        return 0 if res.get("status") == "ok" else 1

    print("Unknown action")
    print(_cli_usage())
    return 2

if __name__ == "__main__":
    import sys
    sys.exit(_cli_main(sys.argv))