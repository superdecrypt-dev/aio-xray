#!/usr/bin/env bash
set -euo pipefail
trap 'echo "[ERROR] Failed at line $LINENO: $BASH_COMMAND" >&2' ERR

# ============================================================
# install-xray-bot.sh (DOWNLOAD FROM GITHUB RAW + SHA256 VERIFY)
# Base raw URL (default):
#   https://raw.githubusercontent.com/superdecrypt-dev/aio-xray/main/testing-discord-bot/
# Must contain:
#   backend.py core.py bot.js package.json SHA256SUMS
#
# Clean Architecture:
#   - Python Backend (root): logic + system access + UNIX socket IPC + CLI
#   - Node.js Frontend (discordbot): Discord UI only, IPC only
#
# Menu:
#  1) Install/Update
#  2) Reconfigure (Discord creds / Raw base URL)
#  3) Restart services
#  4) Status + Logs
#  5) Uninstall (remove everything deployed)
# ============================================================

SCRIPT_NAME="install-xray-bot.sh"

# ---- Default RAW base URL (user requested) ----
DEFAULT_RAW_BASE_URL="https://raw.githubusercontent.com/superdecrypt-dev/aio-xray/main/testing-discord-bot"

# ---- Paths ----
BACKEND_DIR="/opt/xray-backend"
BOT_DIR="/opt/xray-discord-bot"
ENV_DIR="/etc/xray-discord-bot"
ENV_FILE="${ENV_DIR}/env"
SOURCE_FILE="${ENV_DIR}/source.conf"

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

  if ! getent group "${BOT_USER}" >/dev/null 2>&1; then
    groupadd "${BOT_USER}"
  fi

  usermod -aG "${BOT_USER}" "${BOT_USER}" >/dev/null 2>&1 || true
  ok "Group ensured: ${BOT_USER}"
}

ensure_dirs(){
  mkdir -p "${BACKEND_DIR}" "${BOT_DIR}" "${ENV_DIR}"
  chmod 755 "${BACKEND_DIR}" "${BOT_DIR}"
  chmod 700 "${ENV_DIR}"

  mkdir -p /opt/quota/vless /opt/quota/vmess /opt/quota/trojan /opt/quota/allproto
  chmod 755 /opt/quota /opt/quota/vless /opt/quota/vmess /opt/quota/trojan /opt/quota/allproto
  chown -R root:root /opt/quota

  mkdir -p /opt/vless /opt/vmess /opt/trojan /opt/allproto
  chmod 755 /opt/vless /opt/vmess /opt/trojan /opt/allproto
  chown -R root:root /opt/vless /opt/vmess /opt/trojan /opt/allproto

  ok "Directories ensured"
}

# -----------------------------
# Discord credentials
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

# -----------------------------
# Source configuration (RAW base URL)
# -----------------------------
save_source(){
  mkdir -p "${ENV_DIR}"
  chmod 700 "${ENV_DIR}"
  cat > "${SOURCE_FILE}" <<EOF
RAW_BASE_URL=${RAW_BASE_URL}
EOF
  chmod 600 "${SOURCE_FILE}"
  chown root:root "${SOURCE_FILE}"
  ok "Source saved: ${SOURCE_FILE}"
}

load_source(){
  RAW_BASE_URL=""
  if [[ -f "${SOURCE_FILE}" ]]; then
    # shellcheck disable=SC1090
    . "${SOURCE_FILE}"
  fi
  if [[ -z "${RAW_BASE_URL}" ]]; then
    RAW_BASE_URL="${DEFAULT_RAW_BASE_URL}"
  fi
  return 0
}

prompt_source(){
  load_source
  echo
  echo "Current RAW base URL:"
  echo "  ${RAW_BASE_URL}"
  echo
  echo "Enter new RAW base URL (press Enter to keep current)."
  echo "Example: https://raw.githubusercontent.com/<owner>/<repo>/<ref>/<path>"
  echo -n "RAW_BASE_URL: "
  read -r NEW_BASE || true
  if [[ -n "${NEW_BASE}" ]]; then
    RAW_BASE_URL="${NEW_BASE%/}"
  fi
  save_source
}

# -----------------------------
# Download + verify SHA256SUMS
# -----------------------------
download_to_tmp(){
  local url="$1" tmp="$2"
  curl -fsSL "$url" -o "$tmp"
}

get_sha_from_manifest(){
  local mf="$1" fn="$2"
  awk -v f="$fn" '$2==f {print $1}' "$mf" | head -n1
}

atomic_install_file(){
  local src="$1" dest="$2" mode="$3" og="$4"
  local d
  d="$(dirname "$dest")"
  mkdir -p "$d"
  chmod 755 "$d" >/dev/null 2>&1 || true
  chmod "$mode" "$src"
  chown "$og" "$src"
  mv -f "$src" "$dest"
}

download_verified(){
  local fn="$1" dest="$2" mode="$3" og="$4" mf="$5"
  local url tmp sha_exp sha_got
  url="${RAW_BASE_URL%/}/${fn}"
  tmp="/tmp/${fn}.$$"

  sha_exp="$(get_sha_from_manifest "$mf" "$fn")"
  [[ -n "${sha_exp}" ]] || die "SHA256 not found for '${fn}' in SHA256SUMS"

  info "Downloading ${fn} ..."
  download_to_tmp "$url" "$tmp"

  sha_got="$(sha256sum "$tmp" | awk '{print $1}')"
  [[ "${sha_got}" == "${sha_exp}" ]] || die "SHA256 mismatch for ${fn} (expected ${sha_exp}, got ${sha_got})"

  atomic_install_file "$tmp" "$dest" "$mode" "$og"
  ok "Installed ${fn} -> ${dest}"
}

download_sources(){
  load_source

  local mf_url mf_tmp
  mf_url="${RAW_BASE_URL%/}/SHA256SUMS"
  mf_tmp="/tmp/SHA256SUMS.$$"

  info "Fetching manifest: ${mf_url}"
  download_to_tmp "$mf_url" "$mf_tmp"
  ok "Manifest downloaded"

  # Backend (root)
  download_verified "backend.py" "${BACKEND_DIR}/backend.py" 755 "root:root" "$mf_tmp"
  download_verified "core.py"    "${BACKEND_DIR}/core.py"    644 "root:root" "$mf_tmp"

  # Bot (discordbot ownership later for npm)
  download_verified "package.json" "${BOT_DIR}/package.json" 644 "root:root" "$mf_tmp"
  download_verified "bot.js"       "${BOT_DIR}/bot.js"       644 "root:root" "$mf_tmp"

  rm -f "$mf_tmp" || true
}

# -----------------------------------------
# Install NVM + Node 25 as discordbot
# -----------------------------------------
install_node_via_nvm(){
  info "Installing NVM + Node.js 25 for user '${BOT_USER}' (idempotent)..."

  local tmp="/tmp/install_nvm_node25_${BOT_USER}.sh"
  cat > "${tmp}" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
export NVM_DIR="${HOME}/.nvm"

if [[ ! -d "${NVM_DIR}" ]]; then
  curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash
fi

# Load nvm explicitly (do NOT rely on .bashrc)
# shellcheck disable=SC1091
[[ -s "${NVM_DIR}/nvm.sh" ]] && . "${NVM_DIR}/nvm.sh"

nvm install 25
nvm alias default 25

node -v
npm -v
EOS

  chmod 755 "${tmp}"
  chown root:root "${tmp}"

  su - "${BOT_USER}" -c "bash '${tmp}'"
  rm -f "${tmp}"

  ok "NVM + Node installed for ${BOT_USER}"
}

node_bin_for_bot(){
  su - "${BOT_USER}" -c "bash -lc 'export NVM_DIR=\"\$HOME/.nvm\"; [ -s \"\$NVM_DIR/nvm.sh\" ] && . \"\$NVM_DIR/nvm.sh\"; command -v node'"
}

npm_bin_for_bot(){
  su - "${BOT_USER}" -c "bash -lc 'export NVM_DIR=\"\$HOME/.nvm\"; [ -s \"\$NVM_DIR/nvm.sh\" ] && . \"\$NVM_DIR/nvm.sh\"; command -v npm'"
}

install_bot_deps(){
  info "Installing Node dependencies in ${BOT_DIR} (as ${BOT_USER})..."
  chown -R "${BOT_USER}:${BOT_USER}" "${BOT_DIR}"
  su - "${BOT_USER}" -c "bash -lc 'cd \"${BOT_DIR}\" && npm install --omit=dev'"
  ok "Node dependencies installed"
}

write_systemd_units(){
  info "Writing systemd units..."

  # Backend service (root)
  cat > "${BACKEND_SERVICE}" <<EOF
[Unit]
Description=Xray Backend (Python, root) - IPC via UNIX socket
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/bin/python3 ${BACKEND_DIR}/backend.py --serve
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

  # Bot service (discordbot)
  local node_bin
  node_bin="$(node_bin_for_bot)"
  [[ -n "${node_bin}" && -x "${node_bin}" ]] || die "Node binary not found for ${BOT_USER}. Install node first."

  cat > "${BOT_SERVICE}" <<EOF
[Unit]
Description=Xray Discord Bot (Node.js, non-root) - UI only
After=network.target xray-backend.service
Requires=xray-backend.service

[Service]
Type=simple
User=${BOT_USER}
Group=${BOT_USER}
EnvironmentFile=${ENV_FILE}
WorkingDirectory=${BOT_DIR}
ExecStart=${node_bin} ${BOT_DIR}/bot.js
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  ok "systemd units installed"
}

restart_services(){
  info "Restarting services..."
  systemctl enable --now xray-backend.service
  systemctl enable --now xray-discord-bot.service
  systemctl restart xray-backend.service || true
  systemctl restart xray-discord-bot.service || true
  ok "Services restarted"
}

post_install_checks(){
  info "Post-install checks..."

  "${CLI_BIN}" --help >/dev/null 2>&1 || die "xray-userctl --help failed"

  python3 - <<PY
import json
p="${XRAY_CONFIG}"
with open(p,"r",encoding="utf-8") as f:
  json.load(f)
print("OK: JSON valid:", p)
PY

  systemctl is-active xray-backend.service >/dev/null || warn "xray-backend not active"
  systemctl is-active xray-discord-bot.service >/dev/null || warn "xray-discord-bot not active"

  ok "Post-install checks done"

  echo
  echo "================ INSTALL SUMMARY ================"
  echo "RAW base    : ${RAW_BASE_URL}"
  echo "Backend dir : ${BACKEND_DIR}"
  echo "Bot dir     : ${BOT_DIR}"
  echo "Env file    : ${ENV_FILE}"
  echo "Source conf : ${SOURCE_FILE}"
  echo "Socket path : ${SOCK_PATH}"
  echo "CLI         : ${CLI_BIN}"
  echo "Python      : $(python3 -V 2>/dev/null || true)"
  echo "Node        : $(node_bin_for_bot 2>/dev/null || true)"
  echo "NPM         : $(npm_bin_for_bot 2>/dev/null || true)"
  echo "Xray svc    : $(systemctl is-active ${XRAY_SERVICE} 2>/dev/null || true)"
  echo "Backend svc : $(systemctl is-active xray-backend.service 2>/dev/null || true)"
  echo "Bot svc     : $(systemctl is-active xray-discord-bot.service 2>/dev/null || true)"
  echo "================================================="
}

install_update(){
  require_root
  detect_os
  apt_install_base
  ensure_xray_present
  ensure_bot_user
  ensure_dirs

  load_source
  ok "Using RAW base URL: ${RAW_BASE_URL}"

  if [[ ! -f "${ENV_FILE}" ]]; then
    warn "Discord env not found. Please configure first."
    prompt_secrets
  fi

  install_node_via_nvm
  download_sources

  # CLI symlink
  ln -sf "${BACKEND_DIR}/backend.py" "${CLI_BIN}"
  chmod 755 "${CLI_BIN}"
  chown root:root "${CLI_BIN}"
  ok "CLI ready: ${CLI_BIN}"

  install_bot_deps
  write_systemd_units
  restart_services
  post_install_checks
  ok "Install/Update done."
}

reconfigure(){
  require_root
  detect_os
  ensure_bot_user
  echo
  echo "Reconfigure menu:"
  echo "  1) Discord credentials (TOKEN/GUILD/ROLE/CLIENT)"
  echo "  2) RAW base URL (GitHub raw)"
  echo "  3) Both"
  echo -n "Choose [1-3]: "
  read -r ch
  case "$ch" in
    1) prompt_secrets ;;
    2) prompt_source ;;
    3) prompt_secrets; prompt_source ;;
    *) die "Invalid choice" ;;
  esac
  restart_services
  ok "Reconfigure done."
}

status_logs(){
  require_root
  echo
  echo "---- systemctl status ----"
  systemctl --no-pager --full status xray-backend.service || true
  echo
  systemctl --no-pager --full status xray-discord-bot.service || true

  echo
  echo "---- last logs (journalctl) ----"
  echo "--- xray-backend.service ---"
  journalctl -u xray-backend.service -n 120 --no-pager || true
  echo
  echo "--- xray-discord-bot.service ---"
  journalctl -u xray-discord-bot.service -n 120 --no-pager || true
}

uninstall_all(){
  require_root
  info "Uninstalling (remove everything deployed)..."

  systemctl stop xray-discord-bot.service 2>/dev/null || true
  systemctl stop xray-backend.service 2>/dev/null || true
  systemctl disable xray-discord-bot.service 2>/dev/null || true
  systemctl disable xray-backend.service 2>/dev/null || true

  rm -f "${BOT_SERVICE}" "${BACKEND_SERVICE}" || true
  systemctl daemon-reload || true

  rm -f "${CLI_BIN}" || true
  rm -rf "${BOT_DIR}" "${BACKEND_DIR}" || true
  rm -rf "${ENV_DIR}" || true

  if id "${BOT_USER}" >/dev/null 2>&1; then
    userdel -r "${BOT_USER}" 2>/dev/null || true
  fi
  if getent group "${BOT_USER}" >/dev/null 2>&1; then
    groupdel "${BOT_USER}" 2>/dev/null || true
  fi

  ok "Uninstall completed."
}

menu(){
  while true; do
    echo
    echo "=============================="
    echo " XRAY DISCORD BOT INSTALLER"
    echo "=============================="
    echo "RAW base: ${DEFAULT_RAW_BASE_URL}"
    echo "------------------------------"
    echo "1) Install / Update (deploy + service + run)"
    echo "2) Reconfigure (Discord creds / RAW base URL)"
    echo "3) Restart service"
    echo "4) Status (service + logs)"
    echo "5) Uninstall (remove everything)"
    echo "0) Exit"
    echo "------------------------------"
    echo -n "Choose: "
    read -r opt

    case "$opt" in
      1) install_update; pause ;;
      2) reconfigure; pause ;;
      3) restart_services; pause ;;
      4) status_logs; pause ;;
      5) uninstall_all; pause ;;
      0) exit 0 ;;
      *) warn "Invalid option"; pause ;;
    esac
  done
}

menu