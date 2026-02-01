#!/usr/bin/env bash
set -euo pipefail
trap 'echo "[ERROR] Failed at line $LINENO: $BASH_COMMAND" >&2' ERR

# ============================================================
# install-xray-bot.sh (FINAL + MENU)
# Clean Architecture:
#   - Python Backend (root): logic + system access + UNIX socket IPC + CLI
#   - Node.js Frontend (discordbot): Discord UI only, IPC only (NO sudoers)
#
# Node.js installation via NVM (as discordbot):
#   curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash
#   load ~/.nvm/nvm.sh explicitly (NO reliance on .bashrc)
#   nvm install 25
#
# Menu:
#  1) Install/Update
#  2) Reconfigure Discord creds
#  3) Restart services
#  4) Status + Logs
#  5) Uninstall (remove everything deployed)
# ============================================================

SCRIPT_NAME="install-xray-bot.sh"

# ---- Paths ----
BACKEND_DIR="/opt/xray-backend"
BOT_DIR="/opt/xray-discord-bot"
ENV_DIR="/etc/xray-discord-bot"
ENV_FILE="${ENV_DIR}/env"

SOCK_PATH="/run/xray-backend.sock"

XRAY_CONFIG="/usr/local/etc/xray/config.json"
XRAY_SERVICE="xray"

BACKEND_SERVICE="/etc/systemd/system/xray-backend.service"
BOT_SERVICE="/etc/systemd/system/xray-discord-bot.service"

CLI_BIN="/usr/local/bin/xray-userctl"

BOT_USER="discordbot"

# ---- Helpers ----
info(){ echo "[INFO]  $*"; }
ok(){   echo "[OK]    $*"; }
warn(){ echo "[WARN]  $*"; }
die(){  echo "[ERROR] $*" >&2; exit 1; }

require_root(){
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Run as root: sudo bash ${SCRIPT_NAME}"
}

pause(){
  echo
  read -r -p "Press Enter to continue..." _ || true
}

detect_os(){
  [[ -f /etc/os-release ]] || die "Cannot detect OS: /etc/os-release not found"
  # shellcheck disable=SC1091
  . /etc/os-release
  case "${ID:-}" in
    debian)
      case "${VERSION_ID:-}" in
        11|12) ok "Detected OS: Debian ${VERSION_ID}" ;;
        *) die "Unsupported Debian version: ${VERSION_ID} (supported: 11/12)" ;;
      esac
      ;;
    ubuntu)
      case "${VERSION_ID:-}" in
        20.04|22.04|24.04) ok "Detected OS: Ubuntu ${VERSION_ID}" ;;
        *) die "Unsupported Ubuntu version: ${VERSION_ID} (supported: 20.04/22.04/24.04)" ;;
      esac
      ;;
    *)
      die "Unsupported OS: ${ID:-unknown} (supported: Debian 11/12, Ubuntu 20.04/22.04/24.04)"
      ;;
  esac
}

apt_install_base(){
  export DEBIAN_FRONTEND=noninteractive
  info "Installing base dependencies (python3, curl, ca-certificates)..."
  apt-get update -y >/dev/null
  apt-get install -y python3 curl ca-certificates >/dev/null
  ok "Base dependencies installed"
}

ensure_xray_present(){
  [[ -f "${XRAY_CONFIG}" ]] || die "Missing Xray config: ${XRAY_CONFIG}. Installer will NOT create it."
  command -v systemctl >/dev/null 2>&1 || die "systemctl not found (requires systemd)"
  systemctl cat "${XRAY_SERVICE}" >/dev/null 2>&1 || die "Missing systemd service: ${XRAY_SERVICE}.service"
  ok "Xray OK: config exists + systemd service exists"
}

ensure_bot_user(){
  if ! id "${BOT_USER}" >/dev/null 2>&1; then
    useradd -r -m -d "/home/${BOT_USER}" -s /bin/bash "${BOT_USER}"
    ok "Created user: ${BOT_USER}"
  else
    ok "User exists: ${BOT_USER}"
  fi

  # Ensure group exists & user in it (for socket permission)
  if ! getent group "${BOT_USER}" >/dev/null 2>&1; then
    groupadd "${BOT_USER}"
  fi
  usermod -aG "${BOT_USER}" "${BOT_USER}" || true
  ok "Group ensured: ${BOT_USER}"
}

ensure_dirs(){
  mkdir -p "${BACKEND_DIR}" "${BOT_DIR}" "${ENV_DIR}"
  chmod 755 "${BACKEND_DIR}" "${BOT_DIR}"
  chmod 700 "${ENV_DIR}"

  # Backend output dirs
  mkdir -p /opt/quota/vless /opt/quota/vmess /opt/quota/trojan /opt/quota/allproto
  chmod 755 /opt/quota /opt/quota/vless /opt/quota/vmess /opt/quota/trojan /opt/quota/allproto
  chown -R root:root /opt/quota

  mkdir -p /opt/vless /opt/vmess /opt/trojan /opt/allproto
  chmod 755 /opt/vless /opt/vmess /opt/trojan /opt/allproto
  chown -R root:root /opt/vless /opt/vmess /opt/trojan /opt/allproto

  ok "Directories ensured"
}

# -----------------------------
# Interactive credentials menu
# -----------------------------
prompt_secrets(){
  mkdir -p "${ENV_DIR}"
  chmod 700 "${ENV_DIR}"

  echo
  echo "Input Discord credentials (stored in ${ENV_FILE} with chmod 600)"
  echo -n "DISCORD_BOT_TOKEN: "
  read -rs TOKEN; echo
  [[ -n "${TOKEN}" ]] || die "Token cannot be empty"

  echo -n "DISCORD_GUILD_ID (SERVER ID): "
  read -r GUILD
  [[ "${GUILD}" =~ ^[0-9]+$ ]] || die "DISCORD_GUILD_ID must be numeric"

  echo -n "DISCORD_ADMIN_ROLE_ID: "
  read -r ROLE
  [[ "${ROLE}" =~ ^[0-9]+$ ]] || die "DISCORD_ADMIN_ROLE_ID must be numeric"

  echo -n "DISCORD_CLIENT_ID (Application ID): "
  read -r CID
  [[ "${CID}" =~ ^[0-9]+$ ]] || die "DISCORD_CLIENT_ID must be numeric"

  cat > "${ENV_FILE}" <<EOF
DISCORD_BOT_TOKEN=${TOKEN}
DISCORD_GUILD_ID=${GUILD}
DISCORD_ADMIN_ROLE_ID=${ROLE}
DISCORD_CLIENT_ID=${CID}
EOF

  chmod 600 "${ENV_FILE}"
  chown root:root "${ENV_FILE}"
  ok "Credentials saved: ${ENV_FILE}"
}

reconfigure(){
  require_root
  detect_os
  ensure_bot_user
  prompt_secrets
  restart_services
  ok "Reconfigure done."
}

# -----------------------------------------
# Install NVM + Node 25 as discordbot (FIX)
# -----------------------------------------
install_node_via_nvm(){
  info "Installing NVM + Node.js 25 for user '${BOT_USER}' (idempotent)..."

  local tmp="/tmp/install_nvm_node25_${BOT_USER}.sh"
  cat > "${tmp}" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail

export NVM_DIR="$HOME/.nvm"

if [[ ! -d "$NVM_DIR" ]]; then
  curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash
fi

# Load nvm explicitly (do NOT rely on .bashrc)
# shellcheck disable=SC1091
[[ -s "$NVM_DIR/nvm.sh" ]] && . "$NVM_DIR/nvm.sh"

nvm install 25
nvm alias default 25

node -v
npm -v
EOS

  chmod 755 "${tmp}"
  chown root:root "${tmp}"

  su - "${BOT_USER}" -c "bash '${tmp}'"
  rm -f "${tmp}"

  NODE_BIN="$(su - "${BOT_USER}" -c "bash -lc 'export NVM_DIR=\"\$HOME/.nvm\"; [ -s \"\$NVM_DIR/nvm.sh\" ] && . \"\$NVM_DIR/nvm.sh\"; command -v node'")"
  NPM_BIN="$(su - "${BOT_USER}" -c "bash -lc 'export NVM_DIR=\"\$HOME/.nvm\"; [ -s \"\$NVM_DIR/nvm.sh\" ] && . \"\$NVM_DIR/nvm.sh\"; command -v npm'")"

  [[ -n "${NODE_BIN}" && -x "${NODE_BIN}" ]] || die "Failed to locate node after nvm install"
  [[ -n "${NPM_BIN}" && -x "${NPM_BIN}" ]] || die "Failed to locate npm after nvm install"

  ok "Node installed: ${NODE_BIN}"
  ok "NPM installed : ${NPM_BIN}"
}

# ---------------------------
# Write Python backend source
# ---------------------------
write_backend_sources(){
  info "Writing Python backend sources to ${BACKEND_DIR}..."

  cat > "${BACKEND_DIR}/backend.py" <<'PY'
#!/usr/bin/env python3
import argparse
import json
import os
import socket
import sys
from typing import Dict, Any

from core import handle_action

SOCK_PATH = "/run/xray-backend.sock"
SOCK_GROUP = "discordbot"
SOCK_MODE = 0o660

def die(msg: str, code: int = 1):
    print(msg, file=sys.stderr)
    sys.exit(code)

def ensure_root():
    if os.geteuid() != 0:
        die("Must run as root (backend service).", 2)

def setup_socket():
    if os.path.exists(SOCK_PATH):
        os.remove(SOCK_PATH)

    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(SOCK_PATH)

    import grp
    gid = grp.getgrnam(SOCK_GROUP).gr_gid
    os.chown(SOCK_PATH, 0, gid)
    os.chmod(SOCK_PATH, SOCK_MODE)

    s.listen(50)
    return s

def recv_json_line(conn) -> Dict[str, Any]:
    buf = b""
    while b"\n" not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            break
        buf += chunk
        if len(buf) > 1024 * 1024:
            raise ValueError("Request too large")
    line = buf.split(b"\n", 1)[0].decode("utf-8", errors="strict")
    return json.loads(line)

def send_json(conn, obj: Dict[str, Any]):
    data = (json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8")
    conn.sendall(data)

def serve():
    ensure_root()
    s = setup_socket()
    try:
        while True:
            conn, _ = s.accept()
            try:
                req = recv_json_line(conn)
                resp = handle_action(req)
            except Exception as ex:
                resp = {"status": "error", "error": str(ex)}
            try:
                send_json(conn, resp)
            finally:
                conn.close()
    finally:
        s.close()
        if os.path.exists(SOCK_PATH):
            os.remove(SOCK_PATH)

def cli():
    ensure_root()
    p = argparse.ArgumentParser(prog="xray-userctl", add_help=True)
    sub = p.add_subparsers(dest="cmd", required=True)

    pa = sub.add_parser("add")
    pa.add_argument("protocol", choices=["vless","vmess","trojan","allproto"])
    pa.add_argument("username")
    pa.add_argument("days", type=int)
    pa.add_argument("quota_gb", type=float)

    pd = sub.add_parser("del")
    pd.add_argument("protocol", choices=["vless","vmess","trojan","allproto"])
    pd.add_argument("username")

    args = p.parse_args()
    req = {"action": args.cmd, "protocol": args.protocol, "username": args.username}
    if args.cmd == "add":
        req["days"] = args.days
        req["quota_gb"] = args.quota_gb

    resp = handle_action(req)
    print(json.dumps(resp, ensure_ascii=False, indent=2))
    return 0

if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "--serve":
        serve()
    else:
        sys.exit(cli())
PY

  cat > "${BACKEND_DIR}/core.py" <<'PY'
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
    proto = (req.get("protocol") or "").strip().lower()
    username = (req.get("username") or "").strip()

    if action not in ("add", "del"):
        return {"status": "error", "error": "unsupported action"}
    if proto not in VALID_PROTO:
        return {"status": "error", "error": "invalid protocol"}
    if not USERNAME_RE.match(username):
        return {"status": "error", "error": "invalid username"}

    cfg = _load_config()

    if action == "add":
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

        # allproto: add to vless+vmess+trojan inbounds (single email)
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

            # Cleanup legacy/duplicate quota files from older versions
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

        # detail files:
        # keep JSON (existing behavior) + add TXT (new)
        detail_json_path = _write_detail(proto, final_u, secret, days, quota_gb)
        detail_txt_path = _write_detail_txt(cfg, proto, final_u, secret, days, quota_gb)

        # ✅ FIX: define expired_at (was missing -> NameError)
        expired_at = (date.today() + timedelta(days=days)).isoformat()

        return {
            "status": "ok",
            "username": final_u,
            "uuid": secret if proto != "trojan" else None,
            "password": secret if proto == "trojan" else None,
            "expired_at": expired_at,
            "detail_path": detail_txt_path,           # Discord attaches this (.txt)
            "detail_json_path": detail_json_path,     # still generated (.json)
            "backup_path": backup_path,
        }

    # del
    final_u = _final_user(proto, username)

    removed = 0
    if proto == "allproto":
        # allproto deletes from vless+vmess+trojan inbounds too
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
PY

  chmod 755 "${BACKEND_DIR}/backend.py"
  chmod 644 "${BACKEND_DIR}/core.py"
  chown -R root:root "${BACKEND_DIR}"

  ln -sf "${BACKEND_DIR}/backend.py" "${CLI_BIN}"
  chmod 755 "${CLI_BIN}"
  chown root:root "${CLI_BIN}"

  ok "Backend installed + CLI: ${CLI_BIN}"
}

# -----------------------
# Write Node bot sources
# -----------------------
write_bot_sources(){
  info "Writing Node.js bot sources to ${BOT_DIR}..."

  cat > "${BOT_DIR}/package.json" <<'JSON'
{
  "name": "xray-discord-bot",
  "version": "0.1.0",
  "type": "commonjs",
  "dependencies": {
    "discord.js": "^14.16.0"
  }
}
JSON

  cat > "${BOT_DIR}/bot.js" <<'JS'
const fs = require("fs");
const net = require("net");
const path = require("path");
const {
  Client,
  GatewayIntentBits,
  REST,
  Routes,
  SlashCommandBuilder,
  AttachmentBuilder
} = require("discord.js");

const TOKEN = process.env.DISCORD_BOT_TOKEN;
const GUILD_ID = process.env.DISCORD_GUILD_ID;
const ADMIN_ROLE_ID = process.env.DISCORD_ADMIN_ROLE_ID;
const CLIENT_ID = process.env.DISCORD_CLIENT_ID;

const SOCK_PATH = "/run/xray-backend.sock";
const BACKEND_TIMEOUT_MS = 8000;

if (!TOKEN || !GUILD_ID || !ADMIN_ROLE_ID || !CLIENT_ID) {
  console.error("Missing env vars: DISCORD_BOT_TOKEN / DISCORD_GUILD_ID / DISCORD_ADMIN_ROLE_ID / DISCORD_CLIENT_ID");
  process.exit(1);
}

function isAdmin(member) {
  return member.roles.cache.has(String(ADMIN_ROLE_ID));
}

function mapBackendError(err) {
  const code = err && err.code ? String(err.code) : "";
  if (code === "ENOENT") {
    return "Backend socket not found. Pastikan service xray-backend aktif dan socket ada di /run/xray-backend.sock";
  }
  if (code === "ECONNREFUSED") {
    return "Backend connection refused. Pastikan xray-backend sedang running dan menerima koneksi.";
  }
  if (code === "ETIMEDOUT") {
    return "Backend timeout. Cek beban server atau log xray-backend.";
  }
  return err && err.message ? err.message : "Unknown backend error";
}

function callBackend(req) {
  return new Promise((resolve, reject) => {
    const client = net.createConnection(SOCK_PATH);
    let buf = "";
    let done = false;

    const timer = setTimeout(() => {
      if (done) return;
      done = true;
      const e = new Error("Backend timeout");
      e.code = "ETIMEDOUT";
      try { client.destroy(e); } catch (_) {}
      reject(e);
    }, BACKEND_TIMEOUT_MS);

    const finishReject = (err) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      reject(err);
    };

    const finishResolve = (obj) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve(obj);
    };

    client.on("connect", () => {
      try {
        client.write(JSON.stringify(req) + "\n");
      } catch (e) {
        finishReject(e);
      }
    });

    client.on("data", (data) => {
      buf += data.toString("utf8");
      const idx = buf.indexOf("\n");
      if (idx !== -1) {
        client.end();
        const line = buf.slice(0, idx);
        try {
          finishResolve(JSON.parse(line));
        } catch (e) {
          finishReject(new Error("Invalid JSON response from backend"));
        }
      }
    });

    client.on("error", finishReject);

    client.on("close", () => {
      // jika backend tutup koneksi sebelum kirim newline, jangan hang
      if (!done && buf.length > 0 && !buf.includes("\n")) {
        finishReject(new Error("Backend closed connection before sending a full response"));
      }
    });
  });
}

function lightValidate(protocol, username, days, quota_gb) {
  protocol = String(protocol || "").toLowerCase().trim();
  const okProto = ["vless", "vmess", "trojan", "allproto"].includes(protocol);
  if (!okProto) return { ok: false, msg: "protocol invalid" };
  if (!/^[A-Za-z0-9_]+$/.test(username || "")) return { ok: false, msg: "username invalid" };
  if (days !== undefined) {
    if (!Number.isInteger(days) || days < 1 || days > 3650) return { ok: false, msg: "days out of range (1..3650)" };
  }
  if (quota_gb !== undefined) {
    if (typeof quota_gb !== "number" || quota_gb < 0) return { ok: false, msg: "quota_gb must be >= 0" };
  }
  return { ok: true, protocol };
}

async function registerCommands() {
  const commands = [
    new SlashCommandBuilder()
      .setName("add")
      .setDescription("Create Xray user (via Python backend)")
      .addStringOption(o => o.setName("protocol").setDescription("vless/vmess/trojan/allproto").setRequired(true))
      .addStringOption(o => o.setName("username").setDescription("username tanpa suffix [a-zA-Z0-9_]").setRequired(true))
      .addIntegerOption(o => o.setName("days").setDescription("masa aktif (hari)").setRequired(true))
      .addNumberOption(o => o.setName("quota_gb").setDescription("quota (GB), 0=unlimited").setRequired(true)),
    new SlashCommandBuilder()
      .setName("del")
      .setDescription("Delete Xray user (via Python backend)")
      .addStringOption(o => o.setName("protocol").setDescription("vless/vmess/trojan/allproto").setRequired(true))
      .addStringOption(o => o.setName("username").setDescription("username tanpa suffix [a-zA-Z0-9_]").setRequired(true)),
  ].map(c => c.toJSON());

  const rest = new REST({ version: "10" }).setToken(TOKEN);
  await rest.put(
    Routes.applicationGuildCommands(CLIENT_ID, GUILD_ID),
    { body: commands }
  );
}

const client = new Client({ intents: [GatewayIntentBits.Guilds] });

client.once("ready", () => {
  console.log(`Logged in as ${client.user.tag}`);
});

client.on("interactionCreate", async (interaction) => {
  if (!interaction.isChatInputCommand()) return;

  if (String(interaction.guildId) !== String(GUILD_ID)) {
    return interaction.reply({ content: "❌ Wrong guild", ephemeral: true });
  }
  if (!isAdmin(interaction.member)) {
    return interaction.reply({ content: "❌ Unauthorized", ephemeral: true });
  }

  try {
    if (interaction.commandName === "add") {
      const protocolRaw = interaction.options.getString("protocol", true);
      const username = interaction.options.getString("username", true);
      const days = interaction.options.getInteger("days", true);
      const quota_gb = interaction.options.getNumber("quota_gb", true);

      const v = lightValidate(protocolRaw, username, days, quota_gb);
      if (!v.ok) return interaction.reply({ content: `❌ ${v.msg}`, ephemeral: true });

      await interaction.deferReply({ ephemeral: true });
      const resp = await callBackend({ action: "add", protocol: v.protocol, username, days, quota_gb });

      if (resp.status !== "ok") {
        return interaction.editReply(`❌ Failed: ${resp.error || "unknown error"}`);
      }

      let msg = `✅ OK: ${resp.username}\nValidUntil: ${resp.expired_at}`;
      if (resp.detail_path && fs.existsSync(resp.detail_path)) {
        const bn = path.basename(resp.detail_path);
        if (bn.endsWith(".txt")) {
          const file = new AttachmentBuilder(resp.detail_path, { name: bn });
          return interaction.editReply({ content: msg, files: [file] });
        }
      }
      return interaction.editReply(msg);
    }

    if (interaction.commandName === "del") {
      const protocolRaw = interaction.options.getString("protocol", true);
      const username = interaction.options.getString("username", true);

      const v = lightValidate(protocolRaw, username);
      if (!v.ok) return interaction.reply({ content: `❌ ${v.msg}`, ephemeral: true });

      await interaction.deferReply({ ephemeral: true });
      const resp = await callBackend({ action: "del", protocol: v.protocol, username });

      if (resp.status !== "ok") {
        return interaction.editReply(`❌ Failed: ${resp.error || "unknown error"}`);
      }
      return interaction.editReply(`✅ Deleted: ${resp.username} (removed=${resp.removed || "?"})`);
    }
  } catch (e) {
    console.error(e);
    const msg = mapBackendError(e);
    if (interaction.deferred) return interaction.editReply(`❌ Error: ${msg}`);
    return interaction.reply({ content: `❌ Error: ${msg}`, ephemeral: true });
  }
});

async function main() {
  await registerCommands();
  await client.login(TOKEN);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
JS

  chown -R "${BOT_USER}:${BOT_USER}" "${BOT_DIR}"
  ok "Bot sources written"
}

npm_install_bot(){
  info "Installing npm deps for bot (as ${BOT_USER})..."
  su - "${BOT_USER}" -c "bash -lc 'export NVM_DIR=\"\$HOME/.nvm\"; [ -s \"\$NVM_DIR/nvm.sh\" ] && . \"\$NVM_DIR/nvm.sh\"; cd \"${BOT_DIR}\"; npm install --silent'"
  ok "npm install completed"
}

write_systemd_units(){
  info "Writing systemd units..."

  cat > "${BACKEND_SERVICE}" <<EOF
[Unit]
Description=Xray Backend Service (Python root, UNIX socket IPC)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${BACKEND_DIR}
ExecStart=/usr/bin/python3 ${BACKEND_DIR}/backend.py --serve
Restart=always
RestartSec=2
PrivateTmp=true
NoNewPrivileges=false

[Install]
WantedBy=multi-user.target
EOF

  cat > "${BOT_SERVICE}" <<EOF
[Unit]
Description=Xray Discord Bot (Node.js UI only, non-root)
After=network.target xray-backend.service
Requires=xray-backend.service

[Service]
Type=simple
User=${BOT_USER}
WorkingDirectory=${BOT_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=${NODE_BIN} ${BOT_DIR}/bot.js
Restart=always
RestartSec=2

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadOnlyPaths=${BOT_DIR}
ReadOnlyPaths=/home/${BOT_USER}
ReadWritePaths=/run

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  ok "systemd units installed"
}

enable_start_services(){
  info "Enabling + starting services..."
  systemctl enable --now xray-backend.service
  systemctl enable --now xray-discord-bot.service
  ok "Services enabled + started"
}

install_update(){
  require_root
  detect_os
  apt_install_base
  ensure_xray_present
  ensure_bot_user
  ensure_dirs

  if [[ ! -f "${ENV_FILE}" ]]; then
    warn "Env not found. You must configure Discord credentials."
    prompt_secrets
  else
    ok "Env exists: ${ENV_FILE}"
  fi

  install_node_via_nvm
  write_backend_sources
  write_bot_sources
  npm_install_bot
  write_systemd_units
  enable_start_services

  info "Sanity checks:"
  /usr/bin/python3 -c "import json; json.load(open('${XRAY_CONFIG}','r',encoding='utf-8')); print('JSON OK: ${XRAY_CONFIG}')"
  "${CLI_BIN}" -h >/dev/null && ok "xray-userctl -h OK"

  ok "Install/Update done."
}

restart_services(){
  require_root
  info "Restarting services..."
  systemctl restart xray-backend.service || true
  systemctl restart xray-discord-bot.service || true
  ok "Restart done."
}

status_logs(){
  require_root
  echo
  info "===== STATUS ====="
  systemctl --no-pager --full status xray-backend.service || true
  echo
  systemctl --no-pager --full status xray-discord-bot.service || true

  echo
  info "===== LOGS (last 80 lines) ====="
  echo "--- xray-backend.service ---"
  journalctl -u xray-backend.service -n 80 --no-pager || true
  echo
  echo "--- xray-discord-bot.service ---"
  journalctl -u xray-discord-bot.service -n 80 --no-pager || true

  echo
  info "Socket:"
  if [[ -S "${SOCK_PATH}" ]]; then
    ls -l "${SOCK_PATH}" || true
  else
    warn "Socket not found."
  fi
}

uninstall_all(){
  require_root
  echo
  warn "UNINSTALL will remove EVERYTHING deployed by this installer:"
  echo " - ${BACKEND_DIR}"
  echo " - ${BOT_DIR}"
  echo " - ${ENV_DIR}"
  echo " - ${CLI_BIN}"
  echo " - ${BACKEND_SERVICE} + ${BOT_SERVICE}"
  echo " - systemd services (disable/stop)"
  echo " - user/group: ${BOT_USER}"
  echo " - NVM dir: /home/${BOT_USER}/.nvm (if exists)"
  echo " - output dirs: /opt/quota, /opt/vless, /opt/vmess, /opt/trojan, /opt/allproto"
  echo
  read -r -p "Type UNINSTALL to confirm: " c
  [[ "${c}" == "UNINSTALL" ]] || { warn "Cancelled."; return 0; }

  info "Stopping services..."
  systemctl stop xray-discord-bot.service 2>/dev/null || true
  systemctl stop xray-backend.service 2>/dev/null || true
  systemctl disable xray-discord-bot.service 2>/dev/null || true
  systemctl disable xray-backend.service 2>/dev/null || true

  info "Removing systemd unit files..."
  rm -f "${BOT_SERVICE}" "${BACKEND_SERVICE}"
  systemctl daemon-reload || true

  info "Removing deployed files..."
  rm -f "${CLI_BIN}"
  rm -rf "${BACKEND_DIR}" "${BOT_DIR}" "${ENV_DIR}"
  rm -f "${SOCK_PATH}" 2>/dev/null || true

  info "Removing output dirs..."
  rm -rf /opt/quota /opt/vless /opt/vmess /opt/trojan /opt/allproto

  info "Removing bot user (and home)..."
  if id "${BOT_USER}" >/dev/null 2>&1; then
    userdel -r "${BOT_USER}" 2>/dev/null || true
  fi
  if getent group "${BOT_USER}" >/dev/null 2>&1; then
    groupdel "${BOT_USER}" 2>/dev/null || true
  fi

  ok "Uninstall complete."
}

menu(){
  require_root
  while true; do
    clear || true
    echo "=================================================="
    echo "          XRAY DISCORD BOT INSTALLER"
    echo "=================================================="
    echo "1) Install / Update (deploy + service + run)"
    echo "2) Reconfigure (TOKEN BOT / SERVER ID / ROLE ID / APPLICATION ID)"
    echo "3) Restart service"
    echo "4) Status (service + logs)"
    echo "5) Uninstall (remove everything)"
    echo "0) Exit"
    echo "--------------------------------------------------"
    echo -n "Choose [0-5]: "
    read -r choice || true
    case "${choice:-}" in
      1) install_update; pause ;;
      2) reconfigure; pause ;;
      3) restart_services; pause ;;
      4) status_logs; pause ;;
      5) uninstall_all; pause ;;
      0) exit 0 ;;
      *) warn "Invalid choice."; pause ;;
    esac
  done
}

menu "$@"