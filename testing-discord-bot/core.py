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
from typing import Any, Dict
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
        os.replace(tmp, str(path))
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass

def _restart_xray():
    p = subprocess.run(["systemctl","restart","xray"], capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(p.stderr.strip() or p.stdout.strip() or "restart xray failed")

def _load_config() -> Dict[str, Any]:
    raw = CONFIG.read_bytes()
    return json.loads(raw.decode("utf-8"))

def _save_config_with_backup(cfg: Dict[str, Any]) -> str:
    st = CONFIG.stat()
    original = CONFIG.read_bytes()
    _atomic_write(ROLLING_BACKUP, original, st.st_mode, st.st_uid, st.st_gid)
    data = (json.dumps(cfg, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    _atomic_write(CONFIG, data, st.st_mode, st.st_uid, st.st_gid)
    return str(ROLLING_BACKUP)

def _email_exists(cfg: Dict[str, Any], email: str) -> bool:
    inbounds = cfg.get("inbounds", [])
    if not isinstance(inbounds, list):
        return False
    for ib in inbounds:
        if not isinstance(ib, dict):
            continue
        s = ib.get("settings")
        if not isinstance(s, dict):
            continue
        clients = s.get("clients")
        if not isinstance(clients, list):
            continue
        for c in clients:
            if isinstance(c, dict) and c.get("email") == email:
                return True
    return False

def _append(cfg: Dict[str, Any], proto: str, email: str, secret: str) -> int:
    n = 0
    inbounds = cfg.get("inbounds", [])
    if not isinstance(inbounds, list):
        return 0
    for ib in inbounds:
        if not isinstance(ib, dict) or ib.get("protocol") != proto:
            continue
        s = ib.get("settings")
        if not isinstance(s, dict):
            continue
        clients = s.get("clients")
        if clients is None:
            s["clients"] = []
            clients = s["clients"]
        if not isinstance(clients, list):
            continue
        if proto in ("vless","vmess"):
            clients.append({"id": secret, "email": email}); n += 1
        elif proto == "trojan":
            clients.append({"password": secret, "email": email}); n += 1
    return n

def _remove(cfg: Dict[str, Any], proto: str, email: str) -> int:
    removed = 0
    inbounds = cfg.get("inbounds", [])
    if not isinstance(inbounds, list):
        return 0
    for ib in inbounds:
        if not isinstance(ib, dict) or ib.get("protocol") != proto:
            continue
        s = ib.get("settings")
        if not isinstance(s, dict):
            continue
        clients = s.get("clients")
        if not isinstance(clients, list):
            continue
        before = len(clients)
        clients[:] = [c for c in clients if not (isinstance(c, dict) and c.get("email") == email)]
        removed += (before - len(clients))
    return removed

def _quota_bytes(quota_gb: float) -> int:
    if quota_gb <= 0:
        return 0
    return int(quota_gb * 1073741824)

def _write_quota(proto: str, final_user: str, quota_gb: float, days: int) -> None:
    qbytes = _quota_bytes(quota_gb)
    expired_at = (date.today() + timedelta(days=days)).isoformat()
    obj = {
        "username": final_user,
        "protocol": proto,
        "quota_limit": qbytes,
        "created_at": date.today().isoformat(),
        "expired_at": expired_at,
    }
    p = QUOTA_DIR / proto / f"{final_user}.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

def _write_detail(proto: str, final_user: str, secret: str, days: int, quota_gb: float) -> str:
    expired_at = (date.today() + timedelta(days=days)).isoformat()
    detail = {
        "status": "ok",
        "protocol": proto,
        "username": final_user,
        "uuid_or_password": secret,
        "days": days,
        "quota_gb": quota_gb,
        "quota_bytes": _quota_bytes(quota_gb),
        "expired_at": expired_at,
    }
    # allproto detail MUST go only to /opt/allproto
    base = DETAIL_BASE["allproto"] if proto == "allproto" else DETAIL_BASE[proto]
    base.mkdir(parents=True, exist_ok=True)
    out = base / f"{final_user}.json"
    out.write_text(json.dumps(detail, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return str(out)

def _write_detail_txt(cfg: Dict[str, Any], proto: str, final_user: str, secret: str, days: int, quota_gb: float) -> str:
    domain = _get_domain()
    ipaddr = _get_ip()
    valid_until = (date.today() + timedelta(days=days)).isoformat()
    created = datetime.now().strftime("%a %b %d %H:%M:%S %Z %Y").strip() or datetime.now().strftime("%a %b %d %H:%M:%S %Y")
    quota_str = _fmt_quota_gb(quota_gb)

    # Build links by reading config inbounds
    vless_items = _collect_inbounds(cfg, "vless")
    vmess_items = _collect_inbounds(cfg, "vmess")
    trojan_items = _collect_inbounds(cfg, "trojan")

    lines = []
    lines.append("=" * 50)
    lines.append(f"{('XRAY ACCOUNT DETAIL ('+proto+')'):^50}")
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

    # Link Import section
    if proto == "vless":
        lines.append("[VLESS]")
        lines.extend(_build_links_for_vless(domain, final_user, secret, vless_items))

    elif proto == "vmess":
        lines.append("[VMESS]")
        lines.extend(_build_links_for_vmess(domain, final_user, secret, vmess_items))

    elif proto == "trojan":
        lines.append("[TROJAN]")
        lines.extend(_build_links_for_trojan(domain, final_user, secret, trojan_items))

    else:  # allproto
        lines.append("[VLESS]")
        lines.extend(_build_links_for_vless(domain, final_user, secret, vless_items))
        lines.append("-" * 50)
        lines.append("[VMESS]")
        lines.extend(_build_links_for_vmess(domain, final_user, secret, vmess_items))
        lines.append("-" * 50)
        lines.append("[TROJAN]")
        lines.extend(_build_links_for_trojan(domain, final_user, secret, trojan_items))

    lines.append("-" * 50)
    lines.append("=" * 50)
    content = "\n".join(lines) + "\n"

    base = DETAIL_BASE["allproto"] if proto == "allproto" else DETAIL_BASE[proto]
    base.mkdir(parents=True, exist_ok=True)
    out = base / f"{final_user}.txt"
    out.write_text(content, encoding="utf-8")
    return str(out)

def _get_domain() -> str:
    # Prefer nginx xray.conf server_name
    try:
        p = Path("/etc/nginx/conf.d/xray.conf")
        if p.exists():
            txt = p.read_text(encoding="utf-8", errors="ignore")
            m = re.search(r"server_name\s+([^;]+);", txt)
            if m:
                return m.group(1).strip().split()[0]
    except Exception:
        pass
    # fallback
    try:
        return socket.getfqdn()
    except Exception:
        return "unknown"

def _get_ip() -> str:
    # first IP from hostname -I
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

def _build_links_for_vless(domain: str, email: str, uuid: str, items):
    links = []
    def add(label, link):
        links.append(f"{label:10}: {link}")

    if not items:
        # fallback minimal
        add("WebSocket", f"vless://{uuid}@{domain}:443?security=tls&encryption=none&type=ws&path=%2F#"+quote(email))
        return links

    seen = set()
    for port, network, security, stream in items:
        port = port if isinstance(port, int) else 443
        ws = stream.get("wsSettings", {}) if isinstance(stream.get("wsSettings"), dict) else {}
        grpc = stream.get("grpcSettings", {}) if isinstance(stream.get("grpcSettings"), dict) else {}
        http = stream.get("httpSettings", {}) if isinstance(stream.get("httpSettings"), dict) else {}

        if network == "ws":
            path = ws.get("path", "/")
            key = ("ws", port, path, security)
            if key in seen: 
                continue
            seen.add(key)
            add("WebSocket", f"vless://{uuid}@{domain}:{port}?security={security}&encryption=none&type=ws&path={quote(path)}#"+quote(email))

        elif network == "grpc":
            sn = grpc.get("serviceName", "grpc")
            key = ("grpc", port, sn, security)
            if key in seen: 
                continue
            seen.add(key)
            add("gRPC", f"vless://{uuid}@{domain}:{port}?security={security}&encryption=none&type=grpc&serviceName={quote(sn)}&mode=gun#"+quote(email))

        elif network == "httpupgrade":
            path = http.get("path", "/")
            key = ("httpupgrade", port, path, security)
            if key in seen:
                continue
            seen.add(key)
            add("HTTPUpgrade", f"vless://{uuid}@{domain}:{port}?security={security}&encryption=none&type=httpupgrade&path={quote(path)}#"+quote(email))

        else:
            key = ("tcp", port, security)
            if key in seen:
                continue
            seen.add(key)
            add("TCP", f"vless://{uuid}@{domain}:{port}?security={security}&encryption=none#"+quote(email))

    return links

def _build_links_for_trojan(domain: str, email: str, password: str, items):
    links = []
    def add(label, link):
        links.append(f"{label:10}: {link}")

    if not items:
        add("TROJAN", f"trojan://{password}@{domain}:443?security=tls#"+quote(email))
        return links

    seen = set()
    for port, network, security, stream in items:
        port = port if isinstance(port, int) else 443
        ws = stream.get("wsSettings", {}) if isinstance(stream.get("wsSettings"), dict) else {}
        grpc = stream.get("grpcSettings", {}) if isinstance(stream.get("grpcSettings"), dict) else {}

        if network == "ws":
            path = ws.get("path", "/")
            key = ("ws", port, path, security)
            if key in seen: 
                continue
            seen.add(key)
            add("WebSocket", f"trojan://{password}@{domain}:{port}?security={security}&type=ws&path={quote(path)}#"+quote(email))

        elif network == "grpc":
            sn = grpc.get("serviceName", "grpc")
            key = ("grpc", port, sn, security)
            if key in seen:
                continue
            seen.add(key)
            add("gRPC", f"trojan://{password}@{domain}:{port}?security={security}&type=grpc&serviceName={quote(sn)}#"+quote(email))

        else:
            key = ("tcp", port, security)
            if key in seen:
                continue
            seen.add(key)
            add("TCP", f"trojan://{password}@{domain}:{port}?security={security}#"+quote(email))

    return links

def _build_links_for_vmess(domain: str, email: str, uuid: str, items):
    links = []
    def add(label, link):
        links.append(f"{label:10}: {link}")

    if not items:
        # fallback vmess WS tls 443
        v = {
            "v":"2","ps":email,"add":domain,"port":"443","id":uuid,"aid":"0",
            "net":"ws","type":"none","host":"","path":"/","tls":"tls","sni":domain
        }
        b64 = base64.b64encode(json.dumps(v, separators=(",", ":"), ensure_ascii=False).encode()).decode()
        add("VMESS", f"vmess://{b64}")
        return links

    seen = set()
    for port, network, security, stream in items:
        port = port if isinstance(port, int) else 443
        ws = stream.get("wsSettings", {}) if isinstance(stream.get("wsSettings"), dict) else {}
        grpc = stream.get("grpcSettings", {}) if isinstance(stream.get("grpcSettings"), dict) else {}
        http = stream.get("httpSettings", {}) if isinstance(stream.get("httpSettings"), dict) else {}

        path = "/"
        if network == "ws":
            path = ws.get("path", "/")
        elif network == "grpc":
            path = grpc.get("serviceName", "grpc")
        elif network == "httpupgrade":
            path = http.get("path", "/")

        key = (port, network, security, path)
        if key in seen:
            continue
        seen.add(key)

        v = {
            "v":"2","ps":email,"add":domain,"port":str(port),"id":uuid,"aid":"0",
            "net":network,"type":"none","host":"","path":path,
            "tls":"tls" if security == "tls" else "",
            "sni":domain
        }
        b64 = base64.b64encode(json.dumps(v, separators=(",", ":"), ensure_ascii=False).encode()).decode()
        add(network.upper(), f"vmess://{b64}")

    return links

def handle_action(req: Dict[str, Any]) -> Dict[str, Any]:
    action = (req.get("action") or "").strip().lower()

    # Allow read-only + mutating actions
    if action not in ("add", "del", "ping", "status"):
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