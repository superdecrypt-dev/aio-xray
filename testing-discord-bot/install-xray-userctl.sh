#!/usr/bin/env bash
set -euo pipefail

# =========================
# install-xray-userctl.sh
# Standalone installer for /usr/local/bin/xray-userctl
# OS: Debian 11/12, Ubuntu 20.04/22.04/24.04
# =========================

SCRIPT_NAME="install-xray-userctl.sh"
TARGET_BIN="/usr/local/bin/xray-userctl"
CONFIG_DIR="/usr/local/etc/xray"
CONFIG_JSON="${CONFIG_DIR}/config.json"
LOG_DIR="/var/log/xray-userctl"
QUOTA_BASE="/opt/quota"
QUOTA_DIRS=(
  "${QUOTA_BASE}/vless"
  "${QUOTA_BASE}/vmess"
  "${QUOTA_BASE}/trojan"
  "${QUOTA_BASE}/allproto"
)

FORCE=0
UNINSTALL=0

# ---------- Logging helpers ----------
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

NO_LOGDIR=0

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
  if [[ ! -f /etc/os-release ]]; then
    die "Cannot detect OS: /etc/os-release not found."
  fi
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

ensure_python() {
  if command -v python3 >/dev/null 2>&1; then
    ok "python3 found: $(python3 --version 2>&1)"
  else
    info "python3 not found. Installing..."
    apt_install_if_missing python3
    ok "python3 installed: $(python3 --version 2>&1)"
  fi
}

ensure_basic_tools_optional() {
  # Not strictly required for embedded install, but useful baseline tools.
  local need=()
  command -v curl >/dev/null 2>&1 || need+=("curl")
  dpkg -s ca-certificates >/dev/null 2>&1 || need+=("ca-certificates")

  if [[ ${#need[@]} -eq 0 ]]; then
    ok "Basic tools present (curl, ca-certificates)."
  else
    info "Installing basic tools (optional but recommended): ${need[*]}"
    apt_install_if_missing "${need[@]}"
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

  # Verify the unit exists
  if ! systemctl list-unit-files --type=service 2>/dev/null | awk '{print $1}' | grep -qx "xray.service"; then
    # fallback check
    if ! systemctl cat xray >/dev/null 2>&1; then
      die "systemd service 'xray' not found.
Fix: ensure your Xray service is installed as 'xray.service'."
    fi
  fi

  ok "systemd service 'xray' exists."
}

embedded_python_to_temp() {
  local tmpfile
  tmpfile="$(mktemp /tmp/xray-userctl.XXXXXX)"
  cat >"${tmpfile}" <<'PYEOF'
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import date, datetime, timedelta
from decimal import Decimal, InvalidOperation
from pathlib import Path
from uuid import uuid4

CONFIG_PATH = Path("/usr/local/etc/xray/config.json")
NGINX_XRAY_CONF = Path("/etc/nginx/conf.d/xray.conf")
XRAY_SERVICE = "xray"

QUOTA_BASE = Path("/opt/quota")
TXT_BASE_MAP = {
    "vless": Path("/opt/vless"),
    "vmess": Path("/opt/vmess"),
    "trojan": Path("/opt/trojan"),
    "allproto": Path("/opt/allproto"),
}

VALID_MODES = {"vless", "vmess", "trojan", "allproto"}
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]+$")

GB_BYTES = Decimal("1073741824")  # 1024^3

def eprint(msg: str) -> None:
    print(msg, file=sys.stderr)

def ok(msg: str) -> None:
    print(f"[OK] {msg}")

def err(msg: str) -> None:
    eprint(f"[ERROR] {msg}")

def require_root() -> None:
    if os.geteuid() != 0:
        err("Script ini harus dijalankan sebagai root.")
        sys.exit(2)

def ts_compact() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")

def today_str() -> str:
    return date.today().strftime("%Y-%m-%d")

def add_days_str(days: int) -> str:
    return (date.today() + timedelta(days=days)).strftime("%Y-%m-%d")

def parse_domain_from_nginx_conf() -> str:
    if not NGINX_XRAY_CONF.exists():
        return "-"
    try:
        for line in NGINX_XRAY_CONF.read_text(encoding="utf-8", errors="ignore").splitlines():
            m = re.match(r"^\s*server_name\s+([^;]+)\s*;\s*$", line)
            if m:
                tokens = m.group(1).strip().split()
                return tokens[0] if tokens else "-"
    except Exception:
        return "-"
    return "-"

def safe_mkdir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

def atomic_write_text(path: Path, content: str, *, mode: int = None, uid: int = None, gid: int = None) -> None:
    safe_mkdir(path.parent)
    tmp = None
    try:
        fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".tmp-", dir=str(path.parent))
        tmp = Path(tmp_name)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
            if not content.endswith("\n"):
                f.write("\n")
            f.flush()
            os.fsync(f.fileno())

        if mode is not None:
            os.chmod(tmp, mode)
        if uid is not None and gid is not None:
            try:
                os.chown(tmp, uid, gid)
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

def atomic_write_json(path: Path, obj, *, indent: int = 2, mode: int = None, uid: int = None, gid: int = None) -> None:
    content = json.dumps(obj, ensure_ascii=False, indent=indent)
    atomic_write_text(path, content, mode=mode, uid=uid, gid=gid)

def run_cmd(cmd: list[str]) -> tuple[int, str, str]:
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()

def restart_xray_or_rollback(backup_path: Path) -> None:
    code, out, er = run_cmd(["systemctl", "restart", XRAY_SERVICE])
    if code == 0:
        return

    err_detail = er or out or f"systemctl restart {XRAY_SERVICE} gagal (exit={code})."
    err(f"Restart xray gagal. Rollback ke backup: {backup_path.name}")
    try:
        shutil.copy2(str(backup_path), str(CONFIG_PATH))
    except Exception as ex:
        err(f"Rollback copy gagal: {ex}")
        sys.exit(9)

    code2, out2, er2 = run_cmd(["systemctl", "restart", XRAY_SERVICE])
    if code2 != 0:
        err(f"Rollback sukses tapi restart masih gagal. Detail: {(er2 or out2 or '').strip()}")
        sys.exit(10)

    err(f"Detail restart gagal sebelum rollback: {err_detail}")
    sys.exit(8)

def load_config_or_restore_latest_backup() -> dict:
    if not CONFIG_PATH.exists():
        err(f"Config tidak ditemukan: {CONFIG_PATH}")
        sys.exit(3)

    raw = CONFIG_PATH.read_text(encoding="utf-8", errors="strict")
    try:
        return json.loads(raw)
    except Exception as ex:
        err(f"Gagal parse JSON config: {ex}")

        backups = sorted(CONFIG_PATH.parent.glob(CONFIG_PATH.name + ".bak-*"))
        if not backups:
            err("Tidak ada backup ditemukan untuk restore. Perbaiki config.json manual.")
            sys.exit(4)

        latest = backups[-1]
        corrupt_name = CONFIG_PATH.with_name(CONFIG_PATH.name + f".corrupt-{ts_compact()}")
        try:
            shutil.move(str(CONFIG_PATH), str(corrupt_name))
            shutil.copy2(str(latest), str(CONFIG_PATH))
            ok(f"Config corrupt dipindah ke: {corrupt_name.name}")
            ok(f"Restore dari backup terbaru: {latest.name}")
        except Exception as ex2:
            err(f"Restore gagal: {ex2}")
            sys.exit(5)

        try:
            return json.loads(CONFIG_PATH.read_text(encoding="utf-8", errors="strict"))
        except Exception as ex3:
            err(f"Masih gagal parse setelah restore: {ex3}")
            sys.exit(6)

def backup_config() -> Path:
    ts = ts_compact()
    backup = CONFIG_PATH.with_name(CONFIG_PATH.name + f".bak-{ts}")
    shutil.copy2(str(CONFIG_PATH), str(backup))
    return backup

def atomic_save_config(config_obj: dict, st: os.stat_result) -> None:
    tmp = None
    try:
        safe_mkdir(CONFIG_PATH.parent)
        fd, tmp_name = tempfile.mkstemp(prefix="config.json.tmp-", dir=str(CONFIG_PATH.parent))
        tmp = Path(tmp_name)

        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(config_obj, f, ensure_ascii=False, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())

        os.chmod(tmp, st.st_mode)
        try:
            os.chown(tmp, st.st_uid, st.st_gid)
        except PermissionError:
            pass

        os.replace(str(tmp), str(CONFIG_PATH))
        tmp = None
    finally:
        if tmp and tmp.exists():
            try:
                tmp.unlink()
            except Exception:
                pass

def normalize_mode(mode: str) -> str:
    mode = (mode or "").strip().lower()
    if mode not in VALID_MODES:
        err(f"Mode tidak valid: {mode}. Pilih: allproto|vless|vmess|trojan")
        sys.exit(2)
    return mode

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
    return days

def parse_quota_gb(quota_s: str) -> int:
    try:
        q = Decimal(str(quota_s))
    except (InvalidOperation, ValueError):
        err("quota_gb harus angka (contoh: 0, 10, 25.5).")
        sys.exit(2)

    if q < 0:
        err("quota_gb tidak boleh negatif.")
        sys.exit(2)
    if q == 0:
        return 0
    b = int((q * GB_BYTES).to_integral_value(rounding="ROUND_HALF_UP"))
    if b < 0:
        b = 0
    return b

def iter_all_client_entries(config_obj: dict):
    inbounds = config_obj.get("inbounds", [])
    if not isinstance(inbounds, list):
        return
    for i, inbound in enumerate(inbounds):
        if not isinstance(inbound, dict):
            continue
        settings = inbound.get("settings")
        if not isinstance(settings, dict):
            continue
        clients = settings.get("clients")
        if not isinstance(clients, list):
            continue
        for j, c in enumerate(clients):
            if isinstance(c, dict):
                yield i, clients, j, c

def email_exists_anywhere(config_obj: dict, email: str) -> bool:
    for _, _, _, c in iter_all_client_entries(config_obj):
        if c.get("email") == email:
            return True
    return False

def append_user_to_protocol_inbounds(config_obj: dict, protocol: str, email: str, cred: str) -> int:
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
            clients.append({"id": cred, "email": email})
            appended += 1
        elif protocol == "trojan":
            clients.append({"password": cred, "email": email})
            appended += 1

    return appended

def remove_user_from_protocol_inbounds(config_obj: dict, protocol: str, email: str) -> int:
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

def build_metadata(final_username: str, protocol: str, quota_bytes: int, expired_at: str) -> dict:
    return {
        "username": final_username,
        "protocol": protocol,
        "quota_limit": int(quota_bytes),
        "created_at": today_str(),
        "expired_at": expired_at,
    }

def write_metadata_and_txt(mode: str, final_username: str, cred: str, expired_at: str, quota_bytes: int) -> None:
    domain = parse_domain_from_nginx_conf()

    def write_one(proto: str) -> None:
        meta_dir = QUOTA_BASE / proto
        safe_mkdir(meta_dir)
        meta_path = meta_dir / f"{final_username}.json"
        atomic_write_json(meta_path, build_metadata(final_username, proto, quota_bytes, expired_at))

        txt_dir = TXT_BASE_MAP[proto]
        safe_mkdir(txt_dir)
        txt_path = txt_dir / f"{final_username}.txt"
        label = "UUID" if proto in ("vless", "vmess", "allproto") else "Pass"
        txt = (
            f"Domain: {domain}\n"
            f"Username: {final_username}\n"
            f"{label}: {cred}\n"
            f"Expired: {expired_at}\n"
        )
        atomic_write_text(txt_path, txt)

    if mode == "allproto":
        for p in ("vless", "vmess", "trojan", "allproto"):
            write_one(p)
    else:
        write_one(mode)

def delete_metadata_and_txt(mode: str, final_username: str) -> None:
    def rm_one(proto: str) -> None:
        meta_path = QUOTA_BASE / proto / f"{final_username}.json"
        txt_path = TXT_BASE_MAP[proto] / f"{final_username}.txt"
        if meta_path.exists():
            meta_path.unlink()
        if txt_path.exists():
            txt_path.unlink()

    if mode == "allproto":
        for p in ("vless", "vmess", "trojan", "allproto"):
            rm_one(p)
    else:
        rm_one(mode)

def cmd_add(args: argparse.Namespace) -> int:
    mode = normalize_mode(args.mode)
    username = validate_username(args.username)
    days = parse_days(args.days)
    quota_bytes = parse_quota_gb(args.quota_gb)

    fuser = final_user(mode, username)

    config_obj = load_config_or_restore_latest_backup()
    st = os.stat(CONFIG_PATH)

    if email_exists_anywhere(config_obj, fuser):
        err(f"Duplikasi: email sudah ada di config.json: {fuser}")
        return 7

    cred = str(uuid4())
    expired_at = (date.today() + timedelta(days=days)).strftime("%Y-%m-%d")

    backup = backup_config()

    if mode == "allproto":
        n1 = append_user_to_protocol_inbounds(config_obj, "vless", fuser, cred)
        n2 = append_user_to_protocol_inbounds(config_obj, "vmess", fuser, cred)
        n3 = append_user_to_protocol_inbounds(config_obj, "trojan", fuser, cred)
        appended = n1 + n2 + n3
        if appended == 0:
            err("Tidak menemukan inbound vless/vmess/trojan dengan settings.clients untuk ditambahkan.")
            err(f"Backup tersedia: {backup}")
            return 11
    else:
        appended = append_user_to_protocol_inbounds(config_obj, mode, fuser, cred)
        if appended == 0:
            err(f"Tidak menemukan inbound protocol={mode} dengan settings.clients untuk ditambahkan.")
            err(f"Backup tersedia: {backup}")
            return 11

    try:
        atomic_save_config(config_obj, st)
    except Exception as ex:
        err(f"Gagal menulis config secara atomic: {ex}")
        err(f"Restore dari backup: {backup}")
        try:
            shutil.copy2(str(backup), str(CONFIG_PATH))
        except Exception:
            pass
        return 12

    try:
        write_metadata_and_txt(mode, fuser, cred, expired_at, quota_bytes)
    except Exception as ex:
        err(f"Gagal membuat metadata/txt: {ex}")
        err("Rollback config karena metadata gagal.")
        try:
            shutil.copy2(str(backup), str(CONFIG_PATH))
            run_cmd(["systemctl", "restart", XRAY_SERVICE])
        except Exception:
            pass
        return 13

    code, out, er = run_cmd(["systemctl", "restart", XRAY_SERVICE])
    if code != 0:
        err_detail = er or out or f"systemctl restart {XRAY_SERVICE} gagal (exit={code})."
        err(f"Restart xray gagal. Rollback ke backup: {backup.name}")
        try:
            shutil.copy2(str(backup), str(CONFIG_PATH))
            run_cmd(["systemctl", "restart", XRAY_SERVICE])
        except Exception:
            pass
        err(f"Detail: {err_detail}")
        return 8

    cred_label = "UUID" if mode in ("vless", "vmess", "allproto") else "PASS"
    ok(f"Add user sukses: {fuser}")
    ok(f"{cred_label}: {cred}")
    ok(f"Expired: {expired_at}")
    ok(f"Quota bytes: {quota_bytes} (0=unlimited)")
    ok(f"Config backup: {backup.name}")
    ok("Xray restarted.")
    return 0

def cmd_del(args: argparse.Namespace) -> int:
    mode = normalize_mode(args.mode)
    username = validate_username(args.username)
    fuser = final_user(mode, username)

    config_obj = load_config_or_restore_latest_backup()
    st = os.stat(CONFIG_PATH)

    backup = backup_config()

    removed_total = 0
    if mode == "allproto":
        removed_total += remove_user_from_protocol_inbounds(config_obj, "vless", fuser)
        removed_total += remove_user_from_protocol_inbounds(config_obj, "vmess", fuser)
        removed_total += remove_user_from_protocol_inbounds(config_obj, "trojan", fuser)
    else:
        removed_total = remove_user_from_protocol_inbounds(config_obj, mode, fuser)

    if removed_total == 0:
        err(f"User tidak ditemukan di config.json: {fuser} (mode={mode})")
        err(f"Backup dibuat: {backup.name} (tidak ada perubahan yang disimpan)")
        return 14

    try:
        atomic_save_config(config_obj, st)
    except Exception as ex:
        err(f"Gagal menulis config secara atomic: {ex}")
        err(f"Restore dari backup: {backup}")
        try:
            shutil.copy2(str(backup), str(CONFIG_PATH))
        except Exception:
            pass
        return 12

    try:
        delete_metadata_and_txt(mode, fuser)
    except Exception as ex:
        err(f"Gagal hapus metadata/txt: {ex}")
        err("Rollback config karena cleanup metadata gagal.")
        try:
            shutil.copy2(str(backup), str(CONFIG_PATH))
            run_cmd(["systemctl", "restart", XRAY_SERVICE])
        except Exception:
            pass
        return 15

    code, out, er = run_cmd(["systemctl", "restart", XRAY_SERVICE])
    if code != 0:
        err_detail = er or out or f"systemctl restart {XRAY_SERVICE} gagal (exit={code})."
        err(f"Restart xray gagal. Rollback ke backup: {backup.name}")
        try:
            shutil.copy2(str(backup), str(CONFIG_PATH))
            run_cmd(["systemctl", "restart", XRAY_SERVICE])
        except Exception:
            pass
        err(f"Detail: {err_detail}")
        return 8

    ok(f"Del user sukses: {fuser}")
    ok(f"Removed entries: {removed_total}")
    ok(f"Config backup: {backup.name}")
    ok("Xray restarted.")
    return 0

def build_parser() -> argparse.ArgumentParser:
    ep = (
        "Contoh:\n"
        "  xray-userctl add vless testuser 30 10\n"
        "  xray-userctl del vless testuser\n"
        "  xray-userctl add allproto member01 7 0\n"
    )
    p = argparse.ArgumentParser(
        prog="xray-userctl",
        description="Xray user add/del (edit config.json + metadata quota) — standalone script.",
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

  # 1) help
  if xray-userctl --help >/dev/null 2>&1; then
    ok "xray-userctl --help OK"
  else
    die "xray-userctl --help failed. Try: python3 ${TARGET_BIN} --help"
  fi

  # 2) sanity parse config.json (no edit)
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
Fix: validate your JSON. Example: python3 -m json.tool ${CONFIG_JSON}"
  fi

  ok "Post-install checks completed."
}

print_summary() {
  echo
  info "===== INSTALL SUMMARY ====="
  echo "File     : ${TARGET_BIN}"
  echo "Owner    : root:root"
  echo "Perm     : $(stat -c '%a' "${TARGET_BIN}" 2>/dev/null || echo '-')"
  echo "Python   : $(python3 --version 2>&1 || echo '-')"
  echo "Config   : ${CONFIG_JSON} ($( [[ -f "${CONFIG_JSON}" ]] && echo "found" || echo "missing"))"

  info "Folders:"
  echo "  - ${CONFIG_DIR} ($( [[ -d "${CONFIG_DIR}" ]] && echo "ok" || echo "missing"))"
  for d in "${QUOTA_DIRS[@]}"; do
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

  # Dependencies
  ensure_python
  ensure_basic_tools_optional

  # Folders
  ensure_dirs

  # Validate Xray integration
  validate_xray_integration

  # Install embedded python
  install_python_script

  # Post checks
  post_install_checks

  # Summary
  print_summary
}

main "$@"