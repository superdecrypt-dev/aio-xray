#!/usr/bin/env bash
set -euo pipefail

# =========================
# install-discord-xray-bot.sh
# One-file installer for Discord bot (Python) that calls /usr/local/bin/xray-userctl
# OS: Debian 11/12, Ubuntu 20.04/22.04/24.04
# =========================

SCRIPT_NAME="install-discord-xray-bot.sh"

BOT_USER="discordbot"
BOT_GROUP="discordbot"
BOT_DIR="/opt/discord-xray-bot"
BOT_VENV="${BOT_DIR}/.venv"
BOT_PY="${BOT_DIR}/bot.py"

ENV_DIR="/etc/discord-xray-bot"
ENV_FILE="${ENV_DIR}/env"

SERVICE_NAME="discord-xray-bot"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

SUDOERS_FILE="/etc/sudoers.d/${BOT_USER}-xray-userctl"

XRAY_USERCTL="/usr/local/bin/xray-userctl"

NO_COLOR=0

# ---------- logging ----------
info()  { echo "[INFO]  $*"; }
ok()    { echo "[OK]    $*"; }
warn()  { echo "[WARN]  $*"; }
error() { echo "[ERROR] $*" >&2; }

die() {
  error "$*"
  exit 1
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
  info "Ensuring dependencies..."
  apt_install_if_missing ca-certificates curl python3 python3-venv python3-pip
  ok "Deps OK."
}

ensure_systemd() {
  command -v systemctl >/dev/null 2>&1 || die "systemctl not found. This installer requires systemd."
}

ensure_xray_userctl() {
  if [[ ! -x "${XRAY_USERCTL}" ]]; then
    die "Required backend not found: ${XRAY_USERCTL}
Fix: install xray-userctl first (your previous installer), then rerun this script."
  fi
  ok "Found backend: ${XRAY_USERCTL}"
}

ensure_user() {
  if id -u "${BOT_USER}" >/dev/null 2>&1; then
    ok "User exists: ${BOT_USER}"
  else
    info "Creating system user: ${BOT_USER}"
    useradd -r -m -s /usr/sbin/nologin "${BOT_USER}"
    ok "Created: ${BOT_USER}"
  fi
}

ensure_dirs() {
  info "Ensuring bot directories..."
  mkdir -p "${BOT_DIR}"
  chown -R "${BOT_USER}:${BOT_USER}" "${BOT_DIR}"
  chmod 755 "${BOT_DIR}"

  mkdir -p "${ENV_DIR}"
  chown root:root "${ENV_DIR}"
  chmod 700 "${ENV_DIR}"

  ok "Directories OK."
}

write_file_atomic_root() {
  # write_file_atomic_root <path> <content>
  local path="$1"
  local content="$2"
  local tmp
  tmp="$(mktemp "${path}.tmp.XXXXXX")"
  printf "%s\n" "${content}" >"${tmp}"
  install -m 0600 -o root -g root "${tmp}" "${path}"
  rm -f "${tmp}"
}

write_bot_py() {
  info "Deploying bot code: ${BOT_PY}"

  # Bot code is intentionally minimal + safe: no arbitrary command execution.
  # It only calls: sudo -n /usr/local/bin/xray-userctl ...
  local bot_code
  bot_code="$(cat <<'PYEOF'
import os
import re
import subprocess
import discord
from discord import app_commands

TOKEN = os.environ["DISCORD_BOT_TOKEN"]
GUILD_ID = int(os.environ["DISCORD_GUILD_ID"])
ADMIN_ROLE_ID = int(os.environ["DISCORD_ADMIN_ROLE_ID"])

VALID_MODES = {"vless", "vmess", "trojan", "allproto"}
USER_RE = re.compile(r"^[A-Za-z0-9_]+$")

def is_admin(member: discord.Member) -> bool:
    return any(r.id == ADMIN_ROLE_ID for r in getattr(member, "roles", []))

def run_xray_userctl(args: list[str], timeout: int = 45) -> tuple[int, str, str]:
    p = subprocess.run(
        ["sudo", "-n", "/usr/local/bin/xray-userctl", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()

class Client(discord.Client):
    def __init__(self):
        super().__init__(intents=discord.Intents(guilds=True))
        self.tree = app_commands.CommandTree(self)

    async def setup_hook(self):
        # Guild sync for fast testing (commands appear quickly in this guild)
        guild = discord.Object(id=GUILD_ID)
        self.tree.copy_global_to(guild=guild)
        await self.tree.sync(guild=guild)

client = Client()

@client.event
async def on_ready():
    print(f"Logged in as {client.user} | guild={GUILD_ID}")

async def deny(interaction: discord.Interaction):
    await interaction.response.send_message("❌ Unauthorized", ephemeral=True)

@client.tree.command(name="xray_ping", description="Test bot hidup")
async def xray_ping(interaction: discord.Interaction):
    await interaction.response.send_message("✅ pong", ephemeral=True)

@client.tree.command(name="xray_add", description="Buat akun Xray via xray-userctl")
@app_commands.describe(
    mode="vless/vmess/trojan/allproto",
    username="tanpa suffix, hanya [a-zA-Z0-9_]",
    days="masa aktif (hari)",
    quota_gb="quota GB (0=unlimited, boleh desimal)"
)
async def xray_add(interaction: discord.Interaction, mode: str, username: str, days: int, quota_gb: str):
    if interaction.guild_id != GUILD_ID or not is_admin(interaction.user):
        return await deny(interaction)

    mode = (mode or "").lower().strip()
    if mode not in VALID_MODES:
        return await interaction.response.send_message("❌ mode invalid", ephemeral=True)

    if not USER_RE.match(username or ""):
        return await interaction.response.send_message("❌ username invalid (hanya [a-zA-Z0-9_])", ephemeral=True)

    if not (1 <= days <= 3650):
        return await interaction.response.send_message("❌ days out of range (1..3650)", ephemeral=True)

    code, out, er = run_xray_userctl(["add", mode, username, str(days), str(quota_gb)], timeout=60)
    if code != 0:
        msg = er or out or f"exit={code}"
        return await interaction.response.send_message(f"❌ Failed:\n```{msg[:1800]}```", ephemeral=True)

    return await interaction.response.send_message(f"✅ Success:\n```{out[:1800]}```", ephemeral=True)

@client.tree.command(name="xray_del", description="Hapus akun Xray via xray-userctl")
@app_commands.describe(
    mode="vless/vmess/trojan/allproto",
    username="tanpa suffix, hanya [a-zA-Z0-9_]"
)
async def xray_del(interaction: discord.Interaction, mode: str, username: str):
    if interaction.guild_id != GUILD_ID or not is_admin(interaction.user):
        return await deny(interaction)

    mode = (mode or "").lower().strip()
    if mode not in VALID_MODES:
        return await interaction.response.send_message("❌ mode invalid", ephemeral=True)

    if not USER_RE.match(username or ""):
        return await interaction.response.send_message("❌ username invalid (hanya [a-zA-Z0-9_])", ephemeral=True)

    code, out, er = run_xray_userctl(["del", mode, username], timeout=60)
    if code != 0:
        msg = er or out or f"exit={code}"
        return await interaction.response.send_message(f"❌ Failed:\n```{msg[:1800]}```", ephemeral=True)

    return await interaction.response.send_message(f"✅ Success:\n```{out[:1800]}```", ephemeral=True)

client.run(TOKEN)
PYEOF
)"

  # Atomic-ish: write to temp then move; keep ownership for bot user
  local tmp
  tmp="$(mktemp /tmp/bot.py.XXXXXX)"
  printf "%s\n" "${bot_code}" >"${tmp}"
  install -m 0644 -o "${BOT_USER}" -g "${BOT_USER}" "${tmp}" "${BOT_PY}"
  rm -f "${tmp}"
  ok "Bot code deployed."
}

setup_venv() {
  info "Setting up Python venv & installing discord.py..."

  if [[ ! -d "${BOT_VENV}" ]]; then
    info "Creating venv: ${BOT_VENV}"
    sudo -u "${BOT_USER}" -H python3 -m venv "${BOT_VENV}"
    ok "Venv created."
  else
    ok "Venv exists: ${BOT_VENV}"
  fi

  # Upgrade pip and install discord.py inside venv
  sudo -u "${BOT_USER}" -H bash -lc "
set -e
source '${BOT_VENV}/bin/activate'
pip install -U pip >/dev/null
pip install -U discord.py >/dev/null
python -c 'import discord; print(discord.__version__)'
" >/tmp/discord-py-version.txt 2>&1 || {
    error "Failed to install discord.py. Details:"
    cat /tmp/discord-py-version.txt >&2 || true
    exit 1
  }

  ok "discord.py installed: $(tail -n1 /tmp/discord-py-version.txt | tr -d '\r')"
}

ensure_sudoers() {
  info "Configuring sudoers allowlist (bot can run xray-userctl only)..."

  local content
  content="${BOT_USER} ALL=(root) NOPASSWD: ${XRAY_USERCTL} *"

  # Only update if missing or different
  local need_write=1
  if [[ -f "${SUDOERS_FILE}" ]]; then
    if grep -qxF "${content}" "${SUDOERS_FILE}" 2>/dev/null; then
      need_write=0
      ok "Sudoers already configured: ${SUDOERS_FILE}"
    fi
  fi

  if [[ "${need_write}" -eq 1 ]]; then
    echo "${content}" >"${SUDOERS_FILE}"
    chown root:root "${SUDOERS_FILE}"
    chmod 0440 "${SUDOERS_FILE}"

    # Validate sudoers syntax
    if ! visudo -cf "${SUDOERS_FILE}" >/dev/null; then
      rm -f "${SUDOERS_FILE}"
      die "Invalid sudoers file generated. Removed: ${SUDOERS_FILE}"
    fi

    ok "Sudoers installed: ${SUDOERS_FILE}"
  fi

  # Verify sudo works non-interactively for the bot user
  if sudo -u "${BOT_USER}" -H sudo -n "${XRAY_USERCTL}" --help >/dev/null 2>&1; then
    ok "Sudo test OK (non-interactive)."
  else
    die "Sudo test failed for user ${BOT_USER}.
Fix: check ${SUDOERS_FILE} and ensure sudo is installed & working."
  fi
}

prompt_config() {
  info "Interactive configuration (TOKEN, GUILD ID, ADMIN ROLE ID)"

  local reuse="n"
  if [[ -f "${ENV_FILE}" ]]; then
    # Don't print token, only IDs
    local existing_guild existing_role
    existing_guild="$(grep -E '^DISCORD_GUILD_ID=' "${ENV_FILE}" 2>/dev/null | cut -d= -f2- | tr -d '"' || true)"
    existing_role="$(grep -E '^DISCORD_ADMIN_ROLE_ID=' "${ENV_FILE}" 2>/dev/null | cut -d= -f2- | tr -d '"' || true)"
    warn "Existing config found: ${ENV_FILE}"
    warn "  DISCORD_GUILD_ID=${existing_guild:-"(unknown)"}"
    warn "  DISCORD_ADMIN_ROLE_ID=${existing_role:-"(unknown)"}"
    echo -n "Reuse existing config? [Y/n]: "
    read -r reuse
    reuse="${reuse:-Y}"
    if [[ "${reuse}" =~ ^[Yy]$ ]]; then
      ok "Keeping existing config."
      return 0
    fi
  fi

  local token guild_id role_id

  while true; do
    echo -n "Enter DISCORD BOT TOKEN (input hidden): "
    read -r -s token
    echo
    if [[ -n "${token}" ]]; then
      break
    fi
    warn "Token cannot be empty."
  done

  while true; do
    echo -n "Enter DISCORD GUILD ID (Server ID, digits only): "
    read -r guild_id
    if [[ "${guild_id}" =~ ^[0-9]{15,22}$ ]]; then
      break
    fi
    warn "Invalid Guild ID. It should be digits (usually 17-19 digits)."
  done

  while true; do
    echo -n "Enter DISCORD ADMIN ROLE ID (digits only): "
    read -r role_id
    if [[ "${role_id}" =~ ^[0-9]{15,22}$ ]]; then
      break
    fi
    warn "Invalid Role ID. It should be digits (usually 17-19 digits)."
  done

  info "Writing environment file (root-only): ${ENV_FILE}"
  local env_content
  env_content=$(
    cat <<EOF
DISCORD_BOT_TOKEN="${token}"
DISCORD_GUILD_ID="${guild_id}"
DISCORD_ADMIN_ROLE_ID="${role_id}"
EOF
  )

  # Root-only permissions
  write_file_atomic_root "${ENV_FILE}" "${env_content}"
  chown root:root "${ENV_FILE}"
  chmod 0600 "${ENV_FILE}"
  ok "Config saved."
}

write_service() {
  info "Creating/Updating systemd service: ${SERVICE_FILE}"

  local svc
  svc=$(
    cat <<EOF
[Unit]
Description=Discord Xray Bot (calls xray-userctl)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${BOT_USER}
WorkingDirectory=${BOT_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=${BOT_VENV}/bin/python ${BOT_PY}
Restart=on-failure
RestartSec=3
# Hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF
  )

  local tmp
  tmp="$(mktemp /tmp/${SERVICE_NAME}.service.XXXXXX)"
  printf "%s\n" "${svc}" >"${tmp}"
  install -m 0644 -o root -g root "${tmp}" "${SERVICE_FILE}"
  rm -f "${tmp}"

  systemctl daemon-reload
  systemctl enable "${SERVICE_NAME}" >/dev/null 2>&1 || true
  ok "Service file ready."
}

start_service() {
  info "Starting service: ${SERVICE_NAME}"
  systemctl restart "${SERVICE_NAME}"
  systemctl --no-pager --full status "${SERVICE_NAME}" | sed -n '1,12p' || true
  ok "Service started."
}

status_service() {
  systemctl --no-pager --full status "${SERVICE_NAME}" || true
  echo
  info "Recent logs:"
  journalctl -u "${SERVICE_NAME}" -n 80 --no-pager || true
}

uninstall_all() {
  info "Uninstalling Discord bot components..."

  if systemctl list-unit-files | awk '{print $1}' | grep -qx "${SERVICE_NAME}.service"; then
    systemctl stop "${SERVICE_NAME}" >/dev/null 2>&1 || true
    systemctl disable "${SERVICE_NAME}" >/dev/null 2>&1 || true
    ok "Service stopped/disabled."
  else
    warn "Service not found (skip): ${SERVICE_NAME}"
  fi

  if [[ -f "${SERVICE_FILE}" ]]; then
    rm -f "${SERVICE_FILE}"
    ok "Removed: ${SERVICE_FILE}"
  fi

  systemctl daemon-reload >/dev/null 2>&1 || true

  if [[ -d "${BOT_DIR}" ]]; then
    rm -rf "${BOT_DIR}"
    ok "Removed: ${BOT_DIR}"
  fi

  if [[ -d "${ENV_DIR}" ]]; then
    rm -rf "${ENV_DIR}"
    ok "Removed: ${ENV_DIR}"
  fi

  if [[ -f "${SUDOERS_FILE}" ]]; then
    rm -f "${SUDOERS_FILE}"
    ok "Removed: ${SUDOERS_FILE}"
  fi

  warn "User '${BOT_USER}' is NOT removed (safe default). If you want to remove it manually:"
  warn "  sudo userdel -r ${BOT_USER}"

  ok "Uninstall completed."
}

install_flow() {
  require_root
  detect_os
  ensure_systemd
  ensure_deps
  ensure_xray_userctl

  ensure_user
  ensure_dirs

  write_bot_py
  setup_venv

  ensure_sudoers
  prompt_config
  write_service
  start_service

  echo
  ok "Installation complete ✅"
  info "Try in Discord (in your guild): /xray_ping"
  info "Create user: /xray_add mode:vless username:test days:7 quota_gb:10"
  info "Delete user: /xray_del mode:vless username:test"
  echo
  info "Service logs: journalctl -u ${SERVICE_NAME} -n 100 --no-pager"
}

reconfigure_flow() {
  require_root
  ensure_systemd
  [[ -f "${ENV_FILE}" ]] || warn "No existing env file found. Will create new."
  prompt_config
  systemctl restart "${SERVICE_NAME}" >/dev/null 2>&1 || true
  ok "Reconfigured and restarted (if service exists)."
}

menu() {
  while true; do
    echo
    echo "=============================="
    echo " Discord Xray Bot Installer"
    echo "=============================="
    echo "1) Install / Update (deploy + service + run)"
    echo "2) Reconfigure (TOKEN / GUILD ID / ROLE ID)"
    echo "3) Restart service"
    echo "4) Status (service + logs)"
    echo "5) Uninstall"
    echo "0) Exit"
    echo "------------------------------"
    echo -n "Select: "
    read -r choice

    case "${choice}" in
      1) install_flow ;;
      2) reconfigure_flow ;;
      3)
        require_root
        ensure_systemd
        systemctl restart "${SERVICE_NAME}"
        ok "Restarted: ${SERVICE_NAME}"
        ;;
      4)
        require_root
        ensure_systemd
        status_service
        ;;
      5)
        require_root
        ensure_systemd
        uninstall_all
        ;;
      0) ok "Bye."; exit 0 ;;
      *) warn "Invalid option." ;;
    esac
  done
}

menu