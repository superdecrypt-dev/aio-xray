#!/usr/bin/env bash
set -euo pipefail

# =========================
# install-xray-userctl.sh
# Standalone installer for /usr/local/bin/xray-userctl (latest behavior):
# - NO config.json.bak-* usage
# - ADD output written as .txt file, bot can attach it
# - allproto: save ONLY /opt/allproto/<user@allproto>.txt
# OS: Debian 11/12, Ubuntu 20.04/22.04/24.04
# =========================

SCRIPT_NAME="install-xray-userctl.sh"

TARGET_BIN="/usr/local/bin/xray-userctl"
CONFIG_DIR="/usr/local/etc/xray"
CONFIG_JSON="${CONFIG_DIR}/config.json"

LOG_DIR="/var/log/xray-userctl"
NO_LOGDIR=0

QUOTA_BASE="/opt/quota"
QUOTA_DIRS=(
  "${QUOTA_BASE}/vless"
  "${QUOTA_BASE}/vmess"
  "${QUOTA_BASE}/trojan"
  "${QUOTA_BASE}/allproto"
)

TXT_DIRS=(
  "/opt/vless"
  "/opt/vmess"
  "/opt/trojan"
  "/opt/allproto"
)

FORCE=0
UNINSTALL=0

# ---------- Logging ----------
info()  { echo "[INFO]  $*"; }
ok()    { echo "[OK]    $*"; }
warn()  { echo "[WARN]  $*"; }
error() { echo "[ERROR] $*" >&2; }

die() {
  error "$*"
  exit 1
}

usage() {
  cat <<'EOF'
Usage:
  sudo bash install-xray-userctl.sh [--force] [--uninstall] [--no-logdir]

Options:
  --force       Overwrite /usr/local/bin/xray-userctl if it exists and differs
  --uninstall   Remove /usr/local/bin/xray-userctl and /var/log/xray-userctl only
  --no-logdir   Skip creating /var/log/xray-userctl

Examples:
  sudo bash install-xray-userctl.sh
  sudo bash install-xray-userctl.sh --force
  sudo bash install-xray-userctl.sh --uninstall
EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --force) FORCE=1; shift ;;
      --uninstall) UNINSTALL=1; shift ;;
      --no-logdir) NO_LOGDIR=1; shift ;;
      -h|--help) usage; exit 0 ;;
      *)
        error "Unknown argument: $1"
        usage
        exit 2
        ;;
    esac
  done
}

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    die "Must run as root. Example: sudo bash ${SCRIPT_NAME}"
  fi
}

detect_os() {
  [[ -f /etc/os-release ]] || die "Cannot detect OS: /etc/os-release not found."
  # shellcheck disable=SC1091
  . /etc/os-release

  local id="${ID:-}"
  local ver="${VERSION_ID:-}"

  case "${id}" in
    debian)
      case "${ver}" in
        11|12) ok "Detected OS: Debian ${ver}" ;;
        *) die "Unsupported Debian version: ${ver}. Supported: 11/12" ;;
      esac
      ;;
    ubuntu)
      case "${ver}" in
        20.04|22.04|24.04) ok "Detected OS: Ubuntu ${ver}" ;;
        *) die "Unsupported Ubuntu version: ${ver}. Supported: 20.04/22.04/24.04" ;;
      esac
      ;;
    *)
      die "Unsupported OS ID: ${id}. Supported: Debian 11/12, Ubuntu 20.04/22.04/24.04"
      ;;
  esac
}

apt_install_if_missing() {
  local pkgs=("$@")
  local missing=()

  for p in "${pkgs[@]}"; do
    if ! dpkg -s "$p" >/dev/null 2>&1; then
      missing+=("$p")
    fi
  done

  if [[ ${#missing[@]} -eq 0 ]]; then
    ok "Dependencies already installed: ${pkgs[*]}"
    return 0
  fi

  info "Installing missing packages: ${missing[*]}"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y >/dev/null
  apt-get install -y "${missing[@]}" >/dev/null
  ok "Installed: ${missing[*]}"
}

ensure_deps() {
  # Python needed. ca-certificates is recommended (Python urllib HTTPS needs it for public IP lookup).
  if command -v python3 >/dev/null 2>&1; then
    ok "python3 found: $(python3 --version 2>&1)"
  else
    info "python3 not found. Installing..."
    apt_install_if_missing python3
    ok "python3 installed: $(python3 --version 2>&1)"
  fi

  if dpkg -s ca-certificates >/dev/null 2>&1; then
    ok "ca-certificates present."
  else
    info "Installing ca-certificates (recommended)..."
    apt_install_if_missing ca-certificates
  fi
}

ensure_dirs() {
  info "Ensuring required directories exist (safe permissions)..."

  mkdir -p "${CONFIG_DIR}"
  chown root:root "${CONFIG_DIR}"
  chmod 755 "${CONFIG_DIR}"

  mkdir -p "${QUOTA_BASE}"
  chown root:root "${QUOTA_BASE}"
  chmod 755 "${QUOTA_BASE}"

  for d in "${QUOTA_DIRS[@]}"; do
    mkdir -p "$d"
    chown root:root "$d"
    chmod 755 "$d"
  done

  # TXT dirs for account details
  for d in "${TXT_DIRS[@]}"; do
    mkdir -p "$d"
    chown root:root "$d"
    chmod 755 "$d"
  done

  if [[ "${NO_LOGDIR}" -eq 0 ]]; then
    mkdir -p "${LOG_DIR}"
    chown root:root "${LOG_DIR}"
    chmod 750 "${LOG_DIR}"
  else
    warn "Skipping log directory creation due to --no-logdir"
  fi

  ok "Directories ensured."
}

validate_xray_integration() {
  info "Validating Xray integration..."

  if [[ ! -f "${CONFIG_JSON}" ]]; then
    die "Xray config not found at: ${CONFIG_JSON}
Fix: ensure your Xray installation writes config to ${CONFIG_JSON} (do not create a new config here)."
  fi
  ok "Found Xray config: ${CONFIG_JSON}"

  if ! command -v systemctl >/dev/null 2>&1; then
    die "systemctl not found. This installer requires systemd-based OS."
  fi

  # Confirm unit exists
  if ! systemctl list-unit-files --type=service 2>/dev/null | awk '{print $1}' | grep -qx "xray.service"; then
    # fallback
    if ! systemctl cat xray >/dev/null 2>&1; then
      die "systemd service 'xray' not found.
Fix: ensure your Xray service is installed as 'xray.service'."
    fi
  fi
  ok "systemd service 'xray' exists."
}

delete_legacy_backups() {
  # User requirement: stop using config.json.bak-* and remove legacy ones
  local pattern="${CONFIG_JSON}.bak-"
  local count=0

  if compgen -G "${pattern}*" >/dev/null 2>&1; then
    info "Deleting legacy backups: ${CONFIG_JSON}.bak-*"
    for f in "${pattern}"*; do
      if [[ -f "$f" ]]; then
        rm -f "$f" && count=$((count+1)) || true
      fi
    done
    if [[ $count -gt 0 ]]; then
      ok "Deleted legacy backups: ${count} file(s)"
    fi
  else
    ok "No legacy backups found (config.json.bak-*)."
  fi
}

embedded_python_to_temp() {
  local tmpfile
  tmpfile="$(mktemp /tmp/xray-userctl.XXXXXX)"
  cat >"${tmpfile}" <<'PYEOF'
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import base64
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
from datetime import date, datetime, timedelta
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote
from urllib.request import Request, urlopen
from uuid import uuid4

# ==========================
# PATHS / CONSTANTS
# ==========================
CONFIG_PATH = Path("/usr/local/etc/xray/config.json")
NGINX_XRAY_CONF = Path("/etc/nginx/conf.d/xray.conf")
XRAY_SERVICE = "xray"

QUOTA_BASE = Path("/opt/quota")
QUOTA_DIRS = {
    "vless": QUOTA_BASE / "vless",
    "vmess": QUOTA_BASE / "vmess",
    "trojan": QUOTA_BASE / "trojan",
    "allproto": QUOTA_BASE / "allproto",
}

TXT_BASE_MAP = {
    "vless": Path("/opt/vless"),
    "vmess": Path("/opt/vmess"),
    "trojan": Path("/opt/trojan"),
    "allproto": Path("/opt/allproto"),
}

VALID_MODES = {"vless", "vmess", "trojan", "allproto"}
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]+$")

GB_BYTES = Decimal("1073741824")  # 1024^3

# ==========================
# OUTPUT HELPERS
# ==========================
def eprint(msg: str) -> None:
    print(msg, file=sys.stderr)

def ok(msg: str) -> None:
    print(f"[OK] {msg}")

def warn(msg: str) -> None:
    print(f"[WARN] {msg}")

def err(msg: str) -> None:
    eprint(f"[ERROR] {msg}")

def require_root() -> None:
    if os.geteuid() != 0:
        err("Script ini harus dijalankan sebagai root.")
        sys.exit(2)

# ==========================
# SAFETY IO (ATOMIC WRITE, NO .bak)
# ==========================
def safe_mkdir(p: Path, mode: int = 0o755) -> None:
    p.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(str(p), mode)
    except Exception:
        pass

def atomic_write_bytes(path: Path, data: bytes, *, mode: Optional[int] = None, uid: Optional[int] = None, gid: Optional[int] = None) -> None:
    safe_mkdir(path.parent)
    tmp: Optional[Path] = None
    try:
        fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".tmp-", dir=str(path.parent))
        tmp = Path(tmp_name)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())

        if mode is not None:
            os.chmod(str(tmp), mode)
        if uid is not None and gid is not None:
            try:
                os.chown(str(tmp), uid, gid)
            except PermissionError:
                pass

        os.replace(str(tmp), str(path))
        tmp = None
    finally:
        if tmp and tmp.exists():
            try:
                tmp.unlink()
            except Exception:
                pass

def atomic_write_text(path: Path, content: str, *, mode: int = 0o644) -> None:
    data = (content + ("\n" if not content.endswith("\n") else "")).encode("utf-8")
    atomic_write_bytes(path, data, mode=mode)

def atomic_write_json(path: Path, obj: Any, *, indent: int = 2, mode: int = 0o644) -> None:
    atomic_write_text(path, json.dumps(obj, ensure_ascii=False, indent=indent), mode=mode)

def read_config_bytes() -> bytes:
    if not CONFIG_PATH.exists():
        err(f"Config tidak ditemukan: {CONFIG_PATH}")
        sys.exit(3)
    return CONFIG_PATH.read_bytes()

def load_config_from_bytes(raw: bytes) -> Dict[str, Any]:
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception as ex:
        err(f"Config JSON invalid: {ex}")
        err(f"Fix: python3 -m json.tool {CONFIG_PATH}")
        sys.exit(4)

def save_config_atomically(config_obj: Dict[str, Any], st: os.stat_result) -> None:
    data = (json.dumps(config_obj, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    atomic_write_bytes(CONFIG_PATH, data, mode=st.st_mode, uid=st.st_uid, gid=st.st_gid)

def run_cmd(cmd: List[str]) -> Tuple[int, str, str]:
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()

def restart_xray() -> Tuple[int, str]:
    code, out, er = run_cmd(["systemctl", "restart", XRAY_SERVICE])
    msg = er or out or ""
    return code, msg

# ==========================
# DELETE LEGACY BACKUPS
# ==========================
def delete_legacy_backups() -> None:
    try:
        pattern = CONFIG_PATH.name + ".bak-*"
        backups = list(CONFIG_PATH.parent.glob(pattern))
        if backups:
            n = 0
            for p in backups:
                try:
                    p.unlink()
                    n += 1
                except Exception:
                    pass
            if n > 0:
                warn(f"Deleted legacy backups: {n} file(s) matching {pattern}")
    except Exception:
        pass

# ==========================
# VALIDATION
# ==========================
def normalize_mode(mode: str) -> str:
    m = (mode or "").strip().lower()
    if m not in VALID_MODES:
        err(f"Mode tidak valid: {m}. Pilih: allproto|vless|vmess|trojan")
        sys.exit(2)
    return m

def validate_username(username: str) -> str:
    if not username:
        err("Username kosong.")
        sys.exit(2)
    if not USERNAME_RE.match(username):
        err("Username invalid. Hanya boleh [a-zA-Z0-9_].")
        sys.exit(2)
    return username

def final_user(mode: str, username: str) -> str:
    return f"{username}@{mode}"

def parse_days(days_s: str) -> int:
    try:
        days = int(days_s)
    except ValueError:
        err("days harus integer.")
        sys.exit(2)
    if days <= 0:
        err("days harus > 0.")
        sys.exit(2)
    if days > 3650:
        err("days terlalu besar (maks 3650).")
        sys.exit(2)
    return days

def parse_quota_gb(quota_s: str) -> Tuple[int, str]:
    try:
        q = Decimal(str(quota_s))
    except (InvalidOperation, ValueError):
        err("quota_gb harus angka (contoh: 0, 10, 25.5).")
        sys.exit(2)

    if q < 0:
        err("quota_gb tidak boleh negatif.")
        sys.exit(2)

    if q == 0:
        return 0, "0"

    q_display = format(q.normalize(), "f") if q == q.to_integral() else str(q)
    b = int((q * GB_BYTES).to_integral_value(rounding="ROUND_HALF_UP"))
    return b, q_display

# ==========================
# CONFIG MANIPULATION
# ==========================
def iter_all_clients(config_obj: Dict[str, Any]):
    inbounds = config_obj.get("inbounds", [])
    if not isinstance(inbounds, list):
        return
    for inbound in inbounds:
        if not isinstance(inbound, dict):
            continue
        settings = inbound.get("settings")
        if not isinstance(settings, dict):
            continue
        clients = settings.get("clients")
        if not isinstance(clients, list):
            continue
        for c in clients:
            if isinstance(c, dict):
                yield c

def email_exists_anywhere(config_obj: Dict[str, Any], email: str) -> bool:
    for c in iter_all_clients(config_obj):
        if c.get("email") == email:
            return True
    return False

def append_user_to_protocol(config_obj: Dict[str, Any], protocol: str, email: str, secret: str) -> int:
    appended = 0
    inbounds = config_obj.get("inbounds", [])
    if not isinstance(inbounds, list):
        return 0

    for inbound in inbounds:
        if not isinstance(inbound, dict):
            continue
        if inbound.get("protocol") != protocol:
            continue

        settings = inbound.get("settings")
        if not isinstance(settings, dict):
            continue

        clients = settings.get("clients")
        if clients is None:
            settings["clients"] = []
            clients = settings["clients"]
        if not isinstance(clients, list):
            continue

        if protocol in ("vless", "vmess"):
            clients.append({"id": secret, "email": email})
            appended += 1
        elif protocol == "trojan":
            clients.append({"password": secret, "email": email})
            appended += 1

    return appended

def remove_user_from_protocol(config_obj: Dict[str, Any], protocol: str, email: str) -> int:
    removed = 0
    inbounds = config_obj.get("inbounds", [])
    if not isinstance(inbounds, list):
        return 0

    for inbound in inbounds:
        if not isinstance(inbound, dict):
            continue
        if inbound.get("protocol") != protocol:
            continue

        settings = inbound.get("settings")
        if not isinstance(settings, dict):
            continue
        clients = settings.get("clients")
        if not isinstance(clients, list):
            continue

        before = len(clients)
        clients[:] = [c for c in clients if not (isinstance(c, dict) and c.get("email") == email)]
        removed += (before - len(clients))

    return removed

# ==========================
# DOMAIN / IP / LINKS
# ==========================
def read_domain() -> str:
    if not NGINX_XRAY_CONF.exists():
        return "-"
    try:
        for line in NGINX_XRAY_CONF.read_text(encoding="utf-8", errors="ignore").splitlines():
            m = re.match(r"^\s*server_name\s+([^;]+)\s*;\s*$", line)
            if m:
                tokens = m.group(1).strip().split()
                return tokens[0] if tokens else "-"
    except Exception:
        pass
    return "-"

def public_ip() -> str:
    urls = ["https://api.ipify.org", "https://checkip.amazonaws.com", "https://ifconfig.me/ip"]
    for u in urls:
        try:
            req = Request(u, headers={"User-Agent": "curl/8"})
            with urlopen(req, timeout=5) as r:
                ip = r.read().decode().strip()
                if ip and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                    return ip
        except Exception:
            continue
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "0.0.0.0"

def created_str() -> str:
    return datetime.now().astimezone().strftime("%a %b %d %H:%M:%S %Z %Y")

def quota_display(quota_bytes: int, quota_gb_input: str) -> str:
    if quota_bytes <= 0:
        return "Unlimited"
    return f"{quota_gb_input} GB" if quota_gb_input else f"{quota_bytes} bytes"

def _normalize_path(p: str) -> str:
    if not p:
        return "/"
    return p if p.startswith("/") else ("/" + p)

def discover_transport_params(config_obj: Dict[str, Any], protocol: str) -> Dict[str, str]:
    ws_path: Optional[str] = None
    hu_path: Optional[str] = None
    grpc_service: Optional[str] = None

    inbounds = config_obj.get("inbounds", [])
    if isinstance(inbounds, list):
        for inbound in inbounds:
            if not isinstance(inbound, dict):
                continue
            if inbound.get("protocol") != protocol:
                continue
            ss = inbound.get("streamSettings")
            if not isinstance(ss, dict):
                continue
            net = ss.get("network")

            if net == "ws" and ws_path is None:
                ws = ss.get("wsSettings")
                if isinstance(ws, dict):
                    ws_path = ws.get("path")
            elif net == "httpupgrade" and hu_path is None:
                hu = ss.get("httpupgradeSettings")
                if isinstance(hu, dict):
                    hu_path = hu.get("path")
            elif net == "grpc" and grpc_service is None:
                g = ss.get("grpcSettings")
                if isinstance(g, dict):
                    grpc_service = g.get("serviceName")

            if ws_path and hu_path and grpc_service:
                break

    if not ws_path:
        ws_path = f"/{protocol}-ws"
    if not hu_path:
        hu_path = f"/{protocol}-hu"
    if not grpc_service:
        grpc_service = f"{protocol}-grpc"

    return {
        "ws_path": _normalize_path(str(ws_path)),
        "hu_path": _normalize_path(str(hu_path)),
        "grpc_service": str(grpc_service),
    }

def build_vless_links(domain: str, uuid: str, user: str, params: Dict[str, str]) -> Dict[str, str]:
    ws_path = quote(params["ws_path"], safe="")
    hu_path = quote(params["hu_path"], safe="")
    grpc_service = quote(params["grpc_service"], safe="")

    return {
        "WebSocket": f"vless://{uuid}@{domain}:443?security=tls&encryption=none&type=ws&path={ws_path}#{user}",
        "HTTPUpgrade": f"vless://{uuid}@{domain}:443?security=tls&encryption=none&type=httpupgrade&path={hu_path}#{user}",
        "gRPC": f"vless://{uuid}@{domain}:443?security=tls&encryption=none&type=grpc&serviceName={grpc_service}&mode=gun#{user}",
    }

def build_trojan_links(domain: str, password: str, user: str, params: Dict[str, str]) -> Dict[str, str]:
    ws_path = quote(params["ws_path"], safe="")
    hu_path = quote(params["hu_path"], safe="")
    grpc_service = quote(params["grpc_service"], safe="")

    return {
        "WebSocket": f"trojan://{password}@{domain}:443?security=tls&type=ws&path={ws_path}#{user}",
        "HTTPUpgrade": f"trojan://{password}@{domain}:443?security=tls&type=httpupgrade&path={hu_path}#{user}",
        "gRPC": f"trojan://{password}@{domain}:443?security=tls&type=grpc&serviceName={grpc_service}&mode=gun#{user}",
    }

def build_vmess_link(domain: str, uuid: str, user: str, net: str, path_or_service: str, extra_type: str) -> str:
    obj = {
        "v": "2",
        "ps": user,
        "add": domain,
        "port": "443",
        "id": uuid,
        "aid": "0",
        "scy": "auto",
        "net": net,
        "type": extra_type,
        "host": domain,
        "path": path_or_service,
        "tls": "tls",
        "sni": domain,
    }
    raw = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "vmess://" + base64.b64encode(raw).decode("utf-8")

def build_vmess_links(domain: str, uuid: str, user: str, params: Dict[str, str]) -> Dict[str, str]:
    return {
        "WebSocket": build_vmess_link(domain, uuid, user, "ws", params["ws_path"], "none"),
        "HTTPUpgrade": build_vmess_link(domain, uuid, user, "httpupgrade", params["hu_path"], "none"),
        "gRPC": build_vmess_link(domain, uuid, user, "grpc", params["grpc_service"], "gun"),
    }

def render_detail(mode: str, config_obj: Dict[str, Any], final_username: str, secret: str, days: int, expired_at: str, quota_bytes: int, quota_gb_input: str) -> str:
    domain = read_domain()
    ip = public_ip()
    created = created_str()

    lines: List[str] = []
    lines.append("==================================================")
    lines.append(f"           XRAY ACCOUNT DETAIL ({mode})")
    lines.append("==================================================")
    lines.append(f"Domain     : {domain}")
    lines.append(f"IP         : {ip}")
    lines.append(f"Username   : {final_username}")
    lines.append(f"UUID/Pass  : {secret}")
    lines.append(f"QuotaLimit : {quota_display(quota_bytes, quota_gb_input)}")
    lines.append(f"Expired    : {days} Hari")
    lines.append(f"ValidUntil : {expired_at}")
    lines.append(f"Created    : {created}")
    lines.append("==================================================")

    def section(title: str, kv: Dict[str, str]) -> None:
        lines.append(f"[{title}]")
        lines.append(f"WebSocket  : {kv['WebSocket']}")
        lines.append(f"HTTPUpgrade: {kv['HTTPUpgrade']}")
        lines.append(f"gRPC       : {kv['gRPC']}")
        lines.append("--------------------------------------------------")

    if mode in ("vless", "allproto"):
        params = discover_transport_params(config_obj, "vless")
        section("VLESS", build_vless_links(domain, secret, final_username, params))

    if mode in ("vmess", "allproto"):
        params = discover_transport_params(config_obj, "vmess")
        section("VMESS", build_vmess_links(domain, secret, final_username, params))

    if mode in ("trojan", "allproto"):
        params = discover_transport_params(config_obj, "trojan")
        section("TROJAN", build_trojan_links(domain, secret, final_username, params))

    lines.append("==================================================")
    return "\n".join(lines)

# ==========================
# METADATA / TXT
# ==========================
def build_metadata(final_username: str, protocol: str, quota_bytes: int, expired_at: str) -> Dict[str, Any]:
    return {
        "username": final_username,
        "protocol": protocol,
        "quota_limit": int(quota_bytes),
        "created_at": date.today().strftime("%Y-%m-%d"),
        "expired_at": expired_at,
    }

def write_metadata(mode: str, final_username: str, quota_bytes: int, expired_at: str) -> None:
    def write_one(proto: str) -> None:
        d = QUOTA_DIRS[proto]
        safe_mkdir(d, 0o755)
        p = d / f"{final_username}.json"
        atomic_write_json(p, build_metadata(final_username, proto, quota_bytes, expired_at), mode=0o644)

    if mode == "allproto":
        for proto in ("vless", "vmess", "trojan", "allproto"):
            write_one(proto)
    else:
        write_one(mode)

def write_detail_txt(mode: str, final_username: str, detail: str) -> Path:
    # user request: allproto ONLY saved under /opt/allproto
    base = TXT_BASE_MAP["allproto"] if mode == "allproto" else TXT_BASE_MAP[mode]
    safe_mkdir(base, 0o755)
    p = base / f"{final_username}.txt"
    atomic_write_text(p, detail, mode=0o644)
    return p

def delete_metadata_and_txt(mode: str, final_username: str) -> None:
    def rm_file(p: Path) -> None:
        if p.exists():
            try:
                p.unlink()
            except Exception:
                pass

    if mode == "allproto":
        for proto in ("vless", "vmess", "trojan", "allproto"):
            rm_file(QUOTA_DIRS[proto] / f"{final_username}.json")

        # txt only allproto (also clean possible legacy files)
        rm_file(TXT_BASE_MAP["allproto"] / f"{final_username}.txt")
        rm_file(TXT_BASE_MAP["vless"] / f"{final_username}.txt")
        rm_file(TXT_BASE_MAP["vmess"] / f"{final_username}.txt")
        rm_file(TXT_BASE_MAP["trojan"] / f"{final_username}.txt")
    else:
        rm_file(QUOTA_DIRS[mode] / f"{final_username}.json")
        rm_file(TXT_BASE_MAP[mode] / f"{final_username}.txt")

# ==========================
# COMMANDS
# ==========================
def cmd_add(args: argparse.Namespace) -> int:
    delete_legacy_backups()

    mode = normalize_mode(args.mode)
    username = validate_username(args.username)
    days = parse_days(args.days)
    quota_bytes, quota_gb_input = parse_quota_gb(args.quota_gb)

    fuser = final_user(mode, username)

    raw_before = read_config_bytes()
    config_obj = load_config_from_bytes(raw_before)
    st = os.stat(str(CONFIG_PATH))

    if email_exists_anywhere(config_obj, fuser):
        err(f"Duplikasi: email sudah ada di config.json: {fuser}")
        return 7

    secret = str(uuid4())
    expired_at = (date.today() + timedelta(days=days)).strftime("%Y-%m-%d")

    if mode == "allproto":
        n1 = append_user_to_protocol(config_obj, "vless", fuser, secret)
        n2 = append_user_to_protocol(config_obj, "vmess", fuser, secret)
        n3 = append_user_to_protocol(config_obj, "trojan", fuser, secret)
        if n1 == 0 or n2 == 0 or n3 == 0:
            err("Mode allproto membutuhkan inbound vless + vmess + trojan.")
            err(f"Append result: vless={n1}, vmess={n2}, trojan={n3}")
            return 11
    else:
        n = append_user_to_protocol(config_obj, mode, fuser, secret)
        if n == 0:
            err(f"Tidak menemukan inbound protocol={mode} dengan settings.clients untuk ditambahkan.")
            return 11

    try:
        save_config_atomically(config_obj, st)
    except Exception as ex:
        err(f"Gagal menulis config secara atomic: {ex}")
        try:
            atomic_write_bytes(CONFIG_PATH, raw_before, mode=st.st_mode, uid=st.st_uid, gid=st.st_gid)
        except Exception:
            pass
        return 12

    code, msg = restart_xray()
    if code != 0:
        err(f"Restart xray gagal: {msg or f'exit={code}'}")
        err("Rollback ke config sebelum perubahan...")
        try:
            atomic_write_bytes(CONFIG_PATH, raw_before, mode=st.st_mode, uid=st.st_uid, gid=st.st_gid)
            restart_xray()
        except Exception:
            pass
        return 8

    try:
        detail = render_detail(mode, config_obj, fuser, secret, days, expired_at, quota_bytes, quota_gb_input)
        write_metadata(mode, fuser, quota_bytes, expired_at)
        txt_path = write_detail_txt(mode, fuser, detail)
    except Exception as ex:
        err(f"Gagal membuat metadata/txt: {ex}")
        err("Rollback ke config sebelum perubahan...")
        try:
            atomic_write_bytes(CONFIG_PATH, raw_before, mode=st.st_mode, uid=st.st_uid, gid=st.st_gid)
            restart_xray()
        except Exception:
            pass
        return 13

    ok(f"Add user sukses: {fuser}")
    ok(f"OUTPUT_FILE: {txt_path}")
    return 0

def cmd_del(args: argparse.Namespace) -> int:
    delete_legacy_backups()

    mode = normalize_mode(args.mode)
    username = validate_username(args.username)
    fuser = final_user(mode, username)

    raw_before = read_config_bytes()
    config_obj = load_config_from_bytes(raw_before)
    st = os.stat(str(CONFIG_PATH))

    removed_total = 0
    if mode == "allproto":
        removed_total += remove_user_from_protocol(config_obj, "vless", fuser)
        removed_total += remove_user_from_protocol(config_obj, "vmess", fuser)
        removed_total += remove_user_from_protocol(config_obj, "trojan", fuser)
    else:
        removed_total = remove_user_from_protocol(config_obj, mode, fuser)

    if removed_total == 0:
        err(f"User tidak ditemukan di config.json: {fuser} (mode={mode})")
        return 14

    try:
        save_config_atomically(config_obj, st)
    except Exception as ex:
        err(f"Gagal menulis config secara atomic: {ex}")
        try:
            atomic_write_bytes(CONFIG_PATH, raw_before, mode=st.st_mode, uid=st.st_uid, gid=st.st_gid)
        except Exception:
            pass
        return 12

    code, msg = restart_xray()
    if code != 0:
        err(f"Restart xray gagal: {msg or f'exit={code}'}")
        err("Rollback ke config sebelum perubahan...")
        try:
            atomic_write_bytes(CONFIG_PATH, raw_before, mode=st.st_mode, uid=st.st_uid, gid=st.st_gid)
            restart_xray()
        except Exception:
            pass
        return 8

    try:
        delete_metadata_and_txt(mode, fuser)
    except Exception as ex:
        warn(f"Cleanup metadata/txt gagal (non-fatal): {ex}")

    ok(f"Del user sukses: {fuser} | removed_entries={removed_total}")
    return 0

# ==========================
# CLI
# ==========================
def build_parser() -> argparse.ArgumentParser:
    ep = (
        "Contoh:\n"
        "  xray-userctl add vless testuser 30 10\n"
        "  xray-userctl del vless testuser\n"
        "  xray-userctl add allproto member01 7 0\n"
    )
    p = argparse.ArgumentParser(
        prog="xray-userctl",
        description="Xray user add/del (NO config.json.bak-*, atomic writes, ADD outputs .txt file path).",
        epilog=ep,
        formatter_class=argparse.RawTextHelpFormatter,
    )
    sub = p.add_subparsers(dest="cmd")

    pa = sub.add_parser("add", help="Buat akun user")
    pa.add_argument("mode", help="allproto|vless|vmess|trojan")
    pa.add_argument("username", help="username tanpa suffix (hanya [a-zA-Z0-9_])")
    pa.add_argument("days", help="masa aktif (hari, integer > 0)")
    pa.add_argument("quota_gb", help="quota (GB). 0=unlimited. Boleh desimal, contoh 25.5")
    pa.set_defaults(func=cmd_add)

    pd = sub.add_parser("del", help="Hapus akun user")
    pd.add_argument("mode", help="allproto|vless|vmess|trojan")
    pd.add_argument("username", help="username tanpa suffix (hanya [a-zA-Z0-9_])")
    pd.set_defaults(func=cmd_del)

    return p

def main() -> int:
    require_root()
    parser = build_parser()

    if len(sys.argv) < 2:
        parser.print_help()
        return 2

    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        return 2

    return int(args.func(args))

if __name__ == "__main__":
    sys.exit(main())
PYEOF
  echo "${tmpfile}"
}

sha256_file() {
  local f="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$f" | awk '{print $1}'
  else
    python3 - <<PY
import hashlib, sys
p=sys.argv[1]
h=hashlib.sha256()
with open(p,'rb') as f:
  for chunk in iter(lambda: f.read(1024*1024), b''):
    h.update(chunk)
print(h.hexdigest())
PY
  fi
}

install_python_script() {
  info "Installing xray-userctl to ${TARGET_BIN} (embedded source)..."

  local tmpfile
  tmpfile="$(embedded_python_to_temp)"
  chmod 755 "${tmpfile}"
  chown root:root "${tmpfile}"

  local new_hash
  new_hash="$(sha256_file "${tmpfile}")"

  if [[ -f "${TARGET_BIN}" ]]; then
    local cur_hash
    cur_hash="$(sha256_file "${TARGET_BIN}")"
    if [[ "${cur_hash}" == "${new_hash}" ]]; then
      ok "xray-userctl already up-to-date (sha256 match)."
      rm -f "${tmpfile}"
      return 0
    fi

    if [[ "${FORCE}" -eq 0 ]]; then
      warn "Existing ${TARGET_BIN} differs from embedded version."
      warn "Not overwriting (use --force to overwrite)."
      warn "Current sha256: ${cur_hash}"
      warn "New     sha256: ${new_hash}"
      rm -f "${tmpfile}"
      return 0
    fi

    warn "--force enabled: overwriting existing ${TARGET_BIN}"
  fi

  install -m 0755 -o root -g root "${tmpfile}" "${TARGET_BIN}"
  rm -f "${tmpfile}"
  ok "Installed: ${TARGET_BIN}"
  ok "sha256: ${new_hash}"
}

post_install_checks() {
  info "Running post-install checks..."

  if ! command -v xray-userctl >/dev/null 2>&1; then
    die "xray-userctl not found in PATH after install. Check ${TARGET_BIN}."
  fi

  if xray-userctl --help >/dev/null 2>&1; then
    ok "xray-userctl --help OK"
  else
    die "xray-userctl --help failed. Try: python3 ${TARGET_BIN} --help"
  fi

  if python3 - <<PY >/dev/null 2>&1
import json
p="${CONFIG_JSON}"
with open(p, "r", encoding="utf-8") as f:
  json.load(f)
PY
  then
    ok "Sanity JSON parse OK: ${CONFIG_JSON}"
  else
    die "Sanity JSON parse FAILED: ${CONFIG_JSON}
Fix: python3 -m json.tool ${CONFIG_JSON}"
  fi

  ok "Post-install checks completed."
}

print_summary() {
  echo
  info "===== INSTALL SUMMARY ====="
  echo "Binary   : ${TARGET_BIN}"
  echo "Owner    : root:root"
  echo "Perm     : $(stat -c '%a' "${TARGET_BIN}" 2>/dev/null || echo '-')"
  echo "Python   : $(python3 --version 2>&1 || echo '-')"
  echo "Config   : ${CONFIG_JSON} ($( [[ -f "${CONFIG_JSON}" ]] && echo "found" || echo "missing"))"

  info "Folders:"
  echo "  - ${CONFIG_DIR} ($( [[ -d "${CONFIG_DIR}" ]] && echo "ok" || echo "missing"))"
  for d in "${QUOTA_DIRS[@]}"; do
    echo "  - ${d} ($( [[ -d "$d" ]] && echo "ok" || echo "missing"))"
  done
  for d in "${TXT_DIRS[@]}"; do
    echo "  - ${d} ($( [[ -d "$d" ]] && echo "ok" || echo "missing"))"
  done
  if [[ "${NO_LOGDIR}" -eq 0 ]]; then
    echo "  - ${LOG_DIR} ($( [[ -d "${LOG_DIR}" ]] && echo "ok" || echo "missing"))"
  else
    echo "  - ${LOG_DIR} (skipped)"
  fi

  info "Service:"
  if systemctl is-enabled xray >/dev/null 2>&1; then
    echo "  - xray enabled: yes"
  else
    echo "  - xray enabled: no/unknown"
  fi

  if systemctl is-active xray >/dev/null 2>&1; then
    echo "  - xray active : active"
  else
    echo "  - xray active : inactive"
  fi

  ok "Done."
  echo
}

do_uninstall() {
  require_root
  detect_os

  info "Uninstall mode: removing xray-userctl binary and log directory only..."

  if [[ -f "${TARGET_BIN}" ]]; then
    rm -f "${TARGET_BIN}"
    ok "Removed: ${TARGET_BIN}"
  else
    warn "Not found (already removed): ${TARGET_BIN}"
  fi

  if [[ -d "${LOG_DIR}" ]]; then
    rm -rf "${LOG_DIR}"
    ok "Removed: ${LOG_DIR}"
  else
    warn "Not found (already removed): ${LOG_DIR}"
  fi

  ok "Uninstall completed."
}

main() {
  parse_args "$@"

  if [[ "${UNINSTALL}" -eq 1 ]]; then
    do_uninstall
    exit 0
  fi

  require_root
  detect_os

  ensure_deps
  ensure_dirs
  validate_xray_integration

  # housekeeping requested
  delete_legacy_backups

  install_python_script
  post_install_checks
  print_summary
}

main "$@"