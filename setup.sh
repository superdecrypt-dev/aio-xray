#!/bin/bash

# ==============================================================
# Xray-core + Nginx Official Repo Auto Installer (Final Ultimate)
# Protocols: VLESS, VMess, Trojan
# Transports: WebSocket, HTTPUpgrade, gRPC
# Features: Random Ports, Link Gen, BBR, NTP, Swap, Fail2Ban, Anti-Torrent, DoH, Backup Restore (BOT Telegram)
# Add-ons: WGCF v2.2.30 & WireProxy v1.0.9 (SOCKS5 @ 127.0.0.1:40000)
# Security: Fail2Ban Aggressive + Auto XP + Auto Kill IP + Quota + Watchdog
# Domain: Cloudflare API (Auto/Custom) + Smart Validation
# Logging: Output saved to /root/xray_install.log
# Credit: Dibuat oleh Gemini AI
# ==============================================================

# Warna untuk output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Setup Log File
LOG_FILE="/root/xray_install.log"
echo "=== Xray Auto Installer Log Started at $(date) ===" >"$LOG_FILE"

# Cek Root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Script ini harus dijalankan sebagai root!${NC}"
    exit 1
fi

echo "Checking virtualization type..." >>"$LOG_FILE"
VIRT=$(systemd-detect-virt)

if [[ "$VIRT" == "lxc" || "$VIRT" == "openvz" ]]; then
    echo -e "${RED}Error: Script ini hanya mendukung VPS KVM (Full Virtualization)!${NC}"
    echo -e "${YELLOW}Sistem Anda terdeteksi menggunakan: $VIRT${NC}"
    echo -e "${YELLOW}Fitur kernel (BBR, Wireguard, TCP Tuning) tidak didukung di LXC/OpenVZ.${NC}"
    echo "Installation aborted due to unsupported virtualization ($VIRT)." >>"$LOG_FILE"
    exit 1
fi

# Cek Kompatibilitas OS (Ubuntu >= 20 / Debian >= 11)
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_NAME=$ID
    OS_VER=$VERSION_ID
else
    echo -e "${RED}Gagal mendeteksi informasi OS!${NC}"
    exit 1
fi

if [[ "$OS_NAME" == "ubuntu" ]]; then
    # Ambil angka depan (major version) dari misal "20.04" -> "20"
    VER_MAJOR=$(echo "$OS_VER" | cut -d. -f1)
    if [[ $VER_MAJOR -lt 20 ]]; then
        echo -e "${RED}Error: Versi Ubuntu terlalu lama ($OS_VER).${NC}"
        echo -e "${YELLOW}Minimal Ubuntu 20.04 diperlukan.${NC}"
        exit 1
    fi
elif [[ "$OS_NAME" == "debian" ]]; then
    VER_MAJOR=$(echo "$OS_VER" | cut -d. -f1)
    if [[ $VER_MAJOR -lt 11 ]]; then
        echo -e "${RED}Error: Versi Debian terlalu lama ($OS_VER).${NC}"
        echo -e "${YELLOW}Minimal Debian 11 diperlukan.${NC}"
        exit 1
    fi
else
    echo -e "${RED}Error: Distro Linux tidak didukung ($OS_NAME).${NC}"
    echo -e "${YELLOW}Harap gunakan Ubuntu >= 20.04 atau Debian >= 11.${NC}"
    exit 1
fi

# ==========================================
# Helper Functions (Spinner)
# ==========================================
spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while kill -0 $pid 2>/dev/null; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

run_step() {
    local message="$1"
    shift
    printf "${YELLOW}%-50s${NC}" "$message..."

    # Catat marker mulai di log
    echo -e "\n\n[$(date '+%H:%M:%S')] >>> START PROCESS: $message" >>"$LOG_FILE"

    # Jalankan perintah di background & redirect output ke LOG FILE
    ("$@") >>"$LOG_FILE" 2>&1 &
    local pid=$!

    # Tampilkan spinner
    spinner $pid

    wait $pid
    local exit_code=$?

    if [ $exit_code -eq 0 ]; then
        printf "${GREEN}[OK]${NC}\n"
        echo "[$(date '+%H:%M:%S')] >>> STATUS: SUCCESS" >>"$LOG_FILE"
    else
        printf "${RED}[FAIL]${NC}\n"
        echo "[$(date '+%H:%M:%S')] >>> STATUS: FAILED (Exit Code: $exit_code)" >>"$LOG_FILE"
    fi
}

# ==========================================
# Main Installation Logic
# ==========================================

clear
echo -e "${BLUE}=====================================================${NC}"
echo -e "${BLUE}         AUTOSCRIPT XRAY-CORE + NGINX SETUP          ${NC}"
echo -e "${BLUE}               Dibuat oleh Gemini AI                 ${NC}"
echo -e "${BLUE}=====================================================${NC}"
echo -e "${YELLOW}OS Terdeteksi: $PRETTY_NAME${NC}"
echo -e "${YELLOW}Log instalasi tersimpan di: $LOG_FILE${NC}\n"

# Pre-install curl & jq for API calls (Silent but Logged)
echo "Installing dependencies for menu..." >>"$LOG_FILE"
apt update >>"$LOG_FILE" 2>&1
apt install -y curl jq python3 >>"$LOG_FILE" 2>&1

# --- Step 0: Disable IPv6 ---
function disable_ipv6() {
    echo "Disabling IPv6..." >>"$LOG_FILE"

    if ! grep -q "disable_ipv6" /etc/sysctl.conf; then
        cat >>/etc/sysctl.conf <<EOF

# Disable IPv6 (Added by setup.sh)
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
        sysctl -p >>"$LOG_FILE" 2>&1
    fi
}
run_step "0. Menonaktifkan IPv6" disable_ipv6

# --- Step 1: Input Domain (Interactive Menu with Back Feature) ---
echo -e "${YELLOW}Konfigurasi Domain${NC}"

DOMAIN=""
DOMAIN_MODE="" # "custom" or "cf"
IP_VPS=$(curl -s ifconfig.me)

# Decode Cloudflare Token
CF_TOKEN_B64="ejc1SHc3S2RCUVBSN3ctRW5xS2JlY2dWUGFuOFY1MWFoWDg5OGVCNw=="
CF_TOKEN=$(echo "$CF_TOKEN_B64" | base64 -d)

# Main Domain Loop
while true; do
    echo -e "\n   Pilih metode setup domain:"
    echo -e "   1. Input Domain/Subdomain Sendiri (Custom)"
    echo -e "   2. Gunakan Domain Yang Disediakan (Cloudflare Auto)"
    read -p "   Pilih (1/2): " DOMAIN_OPT

    if [[ "$DOMAIN_OPT" == "1" ]]; then
        # --- OPTION 1: CUSTOM DOMAIN ---
        BACK_TO_MAIN=false
        REGEX='^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'

        echo -e "\n   (Ketik '0' untuk kembali ke menu utama)"
        while true; do
            read -p "   Masukkan Domain Anda (contoh: sub.domain.com): " DOMAIN

            # Fitur Kembali
            if [[ "$DOMAIN" == "0" ]]; then
                BACK_TO_MAIN=true
                break
            fi

            if [[ $DOMAIN =~ $REGEX ]]; then
                echo -e "   ${GREEN}Domain valid: $DOMAIN${NC}"
                DOMAIN_MODE="custom"
                break 2 # Keluar dari loop input & loop utama
            else
                echo -e "   ${RED}Format domain tidak valid! Silakan coba lagi.${NC}"
            fi
        done

        if [[ "$BACK_TO_MAIN" == "true" ]]; then continue; fi

    elif [[ "$DOMAIN_OPT" == "2" ]]; then
        # --- OPTION 2: CLOUDFLARE PROVIDED ---
        BACK_TO_MAIN=false
        DOMAIN_MODE="cf"

        # Host Selection Loop
        while true; do
            echo -e "\n   ${YELLOW}Pilih Domain Induk:${NC}"
            echo -e "   1. vyxara1.qzz.io"
            echo -e "   2. vyxara2.qzz.io"
            echo -e "   0. Kembali ke Menu Utama"
            read -p "   Pilih (0-2): " CF_HOST_OPT

            if [[ "$CF_HOST_OPT" == "0" ]]; then
                BACK_TO_MAIN=true
                break
            fi

            BASE_DOMAIN=""
            ROOT_ZONE=""

            case $CF_HOST_OPT in
            1) BASE_DOMAIN="vyxara1.qzz.io" ;;
            2) BASE_DOMAIN="vyxara2.qzz.io" ;;
            *)
                echo -e "   ${RED}Pilihan tidak valid!${NC}"
                continue
                ;;
            esac

            ROOT_ZONE="$BASE_DOMAIN"
            BACK_TO_HOST=false

            # --- PRE-FETCH ZONE ID (Untuk Validasi) ---
            echo -e "   Memverifikasi Zone ID..."
            ZONE_ID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=${ROOT_ZONE}&status=active" \
                -H "Authorization: Bearer ${CF_TOKEN}" \
                -H "Content-Type: application/json" | jq -r .result[0].id)

            if [[ "$ZONE_ID" == "null" || -z "$ZONE_ID" ]]; then
                echo -e "   ${RED}Gagal mendapatkan Zone ID untuk ${ROOT_ZONE}. Cek koneksi/token.${NC}"
                continue
            fi

            # Subdomain Selection Loop
            while true; do
                echo -e "\n   ${YELLOW}Pilih Nama Subdomain:${NC}"
                echo -e "   1. Generate Acak (Random)"
                echo -e "   2. Input Sendiri (Custom)"
                echo -e "   0. Kembali ke Pilihan Domain Induk"
                read -p "   Pilih (0-2): " SUB_OPT

                if [[ "$SUB_OPT" == "0" ]]; then
                    BACK_TO_HOST=true
                    break
                fi

                SUB_PREFIX=""
                if [[ "$SUB_OPT" == "1" ]]; then
                    SUB_PREFIX="vps-$(tr -dc a-z0-9 </dev/urandom | head -c 5)"
                    echo -e "   Subdomain acak: ${GREEN}${SUB_PREFIX}${NC}"
                    
                    # --- Ask for Proxy (Random Mode) ---
                    echo -e "   Apakah subdomain ini ingin di-proxied (CDN) Cloudflare?"
                    read -p "   Pilih (y/n): " PROX_IN
                    if [[ "$PROX_IN" == "y" || "$PROX_IN" == "Y" ]]; then IS_PROXIED="true"; else IS_PROXIED="false"; fi

                elif [[ "$SUB_OPT" == "2" ]]; then
                    echo -e "   (Ketik '0' untuk kembali)"
                    while true; do
                        read -p "   Masukkan nama subdomain (huruf/angka): " SUB_PREFIX

                        if [[ "$SUB_PREFIX" == "0" ]]; then
                            BACK_TO_HOST=true # Flag to go back
                            break             # Break regex loop
                        fi

                        if [[ -z "$SUB_PREFIX" ]]; then
                            echo -e "   ${RED}Tidak boleh kosong!${NC}"
                        elif [[ ! "$SUB_PREFIX" =~ ^[a-zA-Z0-9]+$ ]]; then
                            echo -e "   ${RED}Format salah! Hanya boleh huruf dan angka (tanpa spasi/simbol).${NC}"
                        else
                            # --- LOGIKA VALIDASI CLOUDFLARE ---
                            echo -e "   Memeriksa ketersediaan subdomain..."
                            FULL_DOMAIN="${SUB_PREFIX}.${BASE_DOMAIN}"

                            # Cek DNS Record
                            CHECK_RECORD=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records?name=${FULL_DOMAIN}" \
                                -H "Authorization: Bearer ${CF_TOKEN}" \
                                -H "Content-Type: application/json")

                            RECORD_COUNT=$(echo "$CHECK_RECORD" | jq -r .result_info.count)

                            if [[ "$RECORD_COUNT" -gt 0 ]]; then
                                EXISTING_IP=$(echo "$CHECK_RECORD" | jq -r .result[0].content)

                                if [[ "$EXISTING_IP" == "$IP_VPS" ]]; then
                                    echo -e "   ${BIYellow}Domain ini sudah terdaftar di IP VPS ini.${NC}"
                                    read -p "   Lanjut gunakan domain ini? (y/n): " PROCEED
                                    if [[ "$PROCEED" == "y" || "$PROCEED" == "Y" ]]; then
                                        # --- Ask for Proxy (Custom Mode - Overwrite) ---
                                        echo -e "   Apakah subdomain ini ingin di-proxied (CDN) Cloudflare?"
                                        read -p "   Pilih (y/n): " PROX_IN
                                        if [[ "$PROX_IN" == "y" || "$PROX_IN" == "Y" ]]; then IS_PROXIED="true"; else IS_PROXIED="false"; fi
                                        break # Valid input (overwrite self)
                                    else
                                        continue # Minta input lagi
                                    fi
                                else
                                    echo -e "   ${RED}Maaf, subdomain '${FULL_DOMAIN}' sudah digunakan oleh IP lain (${EXISTING_IP}).${NC}"
                                    echo -e "   Silakan gunakan nama lain."
                                    continue # Minta input lagi
                                fi
                            else
                                # Record belum ada, aman
                                echo -e "   ${GREEN}Subdomain tersedia!${NC}"
                                # --- Ask for Proxy (Custom Mode - New) ---
                                echo -e "   Apakah subdomain ini ingin di-proxied (CDN) Cloudflare?"
                                read -p "   Pilih (y/n): " PROX_IN
                                if [[ "$PROX_IN" == "y" || "$PROX_IN" == "Y" ]]; then IS_PROXIED="true"; else IS_PROXIED="false"; fi
                                break # Valid input
                            fi
                        fi
                    done

                    if [[ "$BACK_TO_HOST" == "true" ]]; then break; fi

                else
                    echo -e "   ${RED}Pilihan tidak valid!${NC}"
                    continue
                fi

                FULL_DOMAIN="${SUB_PREFIX}.${BASE_DOMAIN}"

                echo -e "\n   ${YELLOW}Memproses API Cloudflare...${NC}"
                echo -e "   Target Zone   : ${ROOT_ZONE}"
                echo -e "   Target Domain : ${FULL_DOMAIN}"
                echo -e "   Target IP     : ${IP_VPS}"
                echo -e "   Proxy Status  : ${IS_PROXIED}"

                # 2. Cleanup Existing Records
                echo -e "   Memeriksa DNS record lama di ${ROOT_ZONE}..."
                RECORDS_TO_DELETE=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records?content=${IP_VPS}" \
                    -H "Authorization: Bearer ${CF_TOKEN}" \
                    -H "Content-Type: application/json" | jq -r .result[].id)

                if [[ ! -z "$RECORDS_TO_DELETE" ]]; then
                    for RECORD_ID in $RECORDS_TO_DELETE; do
                        echo -e "   Menghapus record lama (ID: $RECORD_ID)..."
                        curl -s -X DELETE "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records/${RECORD_ID}" \
                            -H "Authorization: Bearer ${CF_TOKEN}" \
                            -H "Content-Type: application/json" >>"$LOG_FILE" 2>&1
                    done
                    echo -e "   ${GREEN}Pembersihan DNS selesai.${NC}"
                fi

                # 3. Create New DNS Record
                RECORD_NAME="${FULL_DOMAIN}"
                RESPONSE=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records" \
                    -H "Authorization: Bearer ${CF_TOKEN}" \
                    -H "Content-Type: application/json" \
                    --data '{"type":"A","name":"'${RECORD_NAME}'","content":"'${IP_VPS}'","ttl":1,"proxied":'$IS_PROXIED'}')

                SUCCESS=$(echo $RESPONSE | jq -r .success)

                if [[ "$SUCCESS" == "true" ]]; then
                    echo -e "   ${GREEN}Berhasil membuat domain Cloudflare!${NC}"
                    DOMAIN=$FULL_DOMAIN
                    sleep 2
                    break 3 # SUCCESS: Break Sub Loop, Host Loop, and Main Loop
                else
                    echo -e "   ${RED}Gagal membuat record DNS via API!${NC}"
                    echo -e "   Pesan Error: $(echo $RESPONSE | jq -r .errors[0].message)"
                    echo "API Response: $RESPONSE" >>"$LOG_FILE"
                    exit 1
                fi
            done

            # Jika user memilih kembali di menu Subdomain
            if [[ "$BACK_TO_HOST" == "true" ]]; then continue; fi
        done

        # Jika user memilih kembali di menu Host
        if [[ "$BACK_TO_MAIN" == "true" ]]; then continue; fi

    else
        echo -e "   ${RED}Pilihan tidak valid!${NC}"
    fi
done

echo -e "\n${BLUE}Melanjutkan Instalasi & Optimasi...${NC}"

# --- Step 2: System Optimization & Security ---
function system_optimization() {
    # 1. Enable TCP BBR
    if ! grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf; then
        echo "net.core.default_qdisc=fq" >>/etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >>/etc/sysctl.conf
        sysctl -p
    fi

    # 2. Tuning Ulimit (File Descriptors)
    if ! grep -q "soft nofile 65535" /etc/security/limits.conf; then
        echo "* soft nofile 65535" >>/etc/security/limits.conf
        echo "* hard nofile 65535" >>/etc/security/limits.conf
    fi
    ulimit -n 65535

    # 3. Auto Swap Memory (2GB) - Mencegah OOM Killer
    if [ ! -f /swapfile ]; then
        fallocate -l 2G /swapfile
        chmod 600 /swapfile
        mkswap /swapfile
        swapon /swapfile
        echo '/swapfile none swap sw 0 0' >>/etc/fstab
    fi

    # 4. Auto Time Sync (NTP)
    apt update
    apt install -y chrony
    systemctl enable chrony
    systemctl restart chrony
    chronyc makestep

    # 5. Fail2Ban (Security Setup - MAX PROTECTION)
    apt install -y fail2ban

    # Membuat konfigurasi custom (jail.local)
    cat >/etc/fail2ban/jail.local <<EOF
[DEFAULT]
# Whitelist IP localhost dan IP Cloudflare (WGCF) jika perlu
ignoreip = 127.0.0.1/8 ::1

# --- ATURAN DASAR ---
# Ban awal: 1 Jam
bantime  = 1h
# Waktu pengawasan: 10 Menit
findtime = 10m
# Kesempatan: 3 kali salah
maxretry = 3

# --- PROTEKSI SSH AGRESIF ---
[sshd]
enabled = true
port    = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
# Mode agresif mendeteksi percobaan login user yang tidak valid & spam auth
mode    = aggressive

# --- PROTEKSI NGINX (WEB SERVER) ---
# Memblokir bot yang mencari celah / brute force HTTP basic auth
[nginx-http-auth]
enabled = true
mode    = aggressive

# Memblokir bot yang melakukan scanning (banyak error 404/403)
[nginx-botsearch]
enabled = true
mode    = aggressive

# --- PENJARA RESIDIVIS (PENTING!) ---
# Jika IP sudah kena ban 3 kali dalam sehari (86400 detik) oleh jail manapun (ssh/nginx),
# Maka IP tersebut akan di-ban selama 1 MINGGU (604800 detik).
[recidive]
enabled  = true
logpath  = /var/log/fail2ban.log
banaction = iptables-allports
bantime  = 1w
findtime = 1d
maxretry = 3
EOF

    systemctl enable fail2ban
    systemctl restart fail2ban
}
run_step "1. Optimasi Sistem (BBR, Swap, NTP, Fail2Ban)" system_optimization


# --- Step 3: Dependencies & Nginx Official ---
function install_dependencies_nginx() {
    apt update
    apt install -y curl dnsutils socat tar unzip zip jq openssl lsb-release gnupg2 ca-certificates ubuntu-keyring

    # Nginx Official Repo Setup
    curl https://nginx.org/keys/nginx_signing.key | gpg --dearmor | tee /usr/share/keyrings/nginx-archive-keyring.gpg
    OS=$(lsb_release -is | tr '[:upper:]' '[:lower:]')
    CODENAME=$(lsb_release -cs)

    echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/${OS} ${CODENAME} nginx" | tee /etc/apt/sources.list.d/nginx.list
    echo -e "Package: *\nPin: origin nginx.org\nPin-Priority: 900\n" | tee /etc/apt/preferences.d/99nginx

    # Install Nginx
    apt update
    apt install -y nginx
    systemctl stop nginx
}
run_step "2. Menginstall Dependencies & Nginx (Official)" install_dependencies_nginx


# --- Step 3b: Install Speedtest (Snapd) ---
function install_speedtest_snap() {
    # Install Snapd
    apt install -y snapd
    systemctl enable --now snapd.socket
    systemctl enable --now snapd.service

    # Give some time for snapd to initialize
    sleep 5

    # Install Speedtest via Snap
    snap install speedtest
}
run_step "3. Menginstall Speedtest via Snap" install_speedtest_snap


# --- Step 3c: Optimize Nginx Config ---
function optimize_nginx_config() {
    cat >/etc/nginx/nginx.conf <<EOF
user nginx;
worker_processes auto;
worker_rlimit_nofile 65535;
pid /var/run/nginx.pid;

events {
    worker_connections 65535;
    multi_accept on;
    use epoll;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    log_format  main  '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                      '\$status \$body_bytes_sent "\$http_referer" '
                      '"\$http_user_agent" "\$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;
    error_log   /var/log/nginx/error.log warn;

    sendfile        on;
    tcp_nopush      on;
    tcp_nodelay     on;
    keepalive_timeout  65;
    client_max_body_size 20m;
    server_tokens   off;

    include /etc/nginx/conf.d/*.conf;
}
EOF
}
run_step "4. Mengoptimalkan Konfigurasi Nginx" optimize_nginx_config


# --- Step 4: Directories & Permissions ---
function setup_dirs() {
    mkdir -p /opt/ssl
    chmod 755 /opt/ssl
    mkdir -p /var/log/xray
    touch /var/log/xray/access.log
    touch /var/log/xray/error.log
    chmod -R 755 /var/log/xray
    chown -R nobody:nogroup /var/log/xray

    # Buat direktori user untuk menu
    mkdir -p /opt/allproto
    mkdir -p /opt/vless
    mkdir -p /opt/vmess
    mkdir -p /opt/trojan
}
run_step "5. Menyiapkan Direktori & Permission Log" setup_dirs


# --- Step 5: SSL Setup (Split Mode: Standalone vs DNS_CF) ---
function setup_ssl() {
    RANDOM_EMAIL="$(tr -dc a-z0-9 </dev/urandom | head -c 10)@gmail.com"
    curl https://get.acme.sh | sh -s email=$RANDOM_EMAIL
    /root/.acme.sh/acme.sh --set-default-ca --server zerossl

    if [[ "$DOMAIN_MODE" == "custom" ]]; then
        # --- MODE 1: CUSTOM DOMAIN (Standalone) ---
        echo -e "   [SSL] Menggunakan Mode Standalone..."
        /root/.acme.sh/acme.sh --issue -d "$DOMAIN" --standalone --force
    else
        # --- MODE 2: PROVIDED DOMAIN (DNS API - Wildcard) ---
        echo -e "   [SSL] Menggunakan Mode DNS Cloudflare (Wildcard)..."
        # Export Token Global Variable untuk acme.sh
        export CF_Token="$CF_TOKEN"
        export CF_Account_ID="" # Optional jika token sudah spesifik zone

        # Issue Wildcard Cert (Domain & *.Domain)
        /root/.acme.sh/acme.sh --issue --dns dns_cf \
            -d "$DOMAIN" -d "*.$DOMAIN" --force
    fi

    # Install Cert dengan Reload Command
    # Note: Acme.sh pintar, dia tahu cert mana yang di-issue terakhir
    /root/.acme.sh/acme.sh --install-cert -d "$DOMAIN" \
        --fullchain-file /opt/ssl/fullchain.pem \
        --key-file /opt/ssl/privkey.pem \
        --reloadcmd "systemctl restart nginx"
}
run_step "6. Setup SSL (Mode: $DOMAIN_MODE) & Auto-Renew" setup_ssl


# --- Step 6: Install Xray ---
function install_xray_core() {
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
}
run_step "7. Menginstall Xray-Core Terbaru" install_xray_core


# --- Step 7: Install WGCF & WireProxy (Updated Specs) ---
function install_wgcf_wireproxy() {
    mkdir -p /etc/wireproxy

    # 1. Download & Install WGCF v2.2.30 (ViRb3)
    curl -L -o /usr/local/bin/wgcf https://github.com/ViRb3/wgcf/releases/download/v2.2.30/wgcf_2.2.30_linux_amd64
    chmod +x /usr/local/bin/wgcf

    # 2. Register WGCF & Generate Profile
    cd /etc/wireproxy
    echo "yes" | wgcf register
    wgcf generate

    # 3. Download & Install WireProxy v1.0.9 (whyvl)
    curl -L -o /tmp/wireproxy.tar.gz https://github.com/whyvl/wireproxy/releases/download/v1.0.9/wireproxy_linux_amd64.tar.gz
    tar -xzf /tmp/wireproxy.tar.gz -C /usr/local/bin/
    chmod +x /usr/local/bin/wireproxy

    # 4. Create WireProxy Config (Copy & Append Method)
    # Copy profile wgcf ke config.conf
    cp wgcf-profile.conf config.conf

    # Tambahkan konfigurasi Socks5 BindAddress
    cat >>config.conf <<EOF

[Socks5]
BindAddress = 127.0.0.1:40000
EOF

    # --- HAPUS FILE ASLI WGCF (CLEANUP) ---
    rm -f wgcf-account.toml wgcf-profile.conf

    # 5. Create Service Systemd for WireProxy
    cat >/etc/systemd/system/wireproxy.service <<EOF
[Unit]
Description=WireProxy Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/wireproxy -c /etc/wireproxy/config.conf
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    # 6. Start WireProxy
    systemctl daemon-reload
    systemctl enable wireproxy
    systemctl start wireproxy
}
run_step "8. Menginstall WGCF & WireProxy" install_wgcf_wireproxy


# --- Step 8: Generate Configs (Routing to Direct) ---
# NOTE: Removed default admin account creation logic
# Use random UUID/Pass for template, but empty clients list

UUID=$(cat /proc/sys/kernel/random/uuid)
TROJAN_PASS=$(tr -dc a-zA-Z0-9 </dev/urandom | head -c 12)

# Ports & Paths Generation Logic
USED_PORTS=()
function get_random_port() {
    local port
    while true; do
        port=$(shuf -i 20000-60000 -n 1)
        if [[ ! " ${USED_PORTS[*]} " =~ " ${port} " ]]; then
            USED_PORTS+=($port)
            echo $port
            break
        fi
    done
}

# Generate 9 Unique Internal Ports
P_VLESS_WS=$(get_random_port)
P_VMESS_WS=$(get_random_port)
P_TROJAN_WS=$(get_random_port)

P_VLESS_HU=$(get_random_port)
P_VMESS_HU=$(get_random_port)
P_TROJAN_HU=$(get_random_port)

P_VLESS_GRPC=$(get_random_port)
P_VMESS_GRPC=$(get_random_port)
P_TROJAN_GRPC=$(get_random_port)

# Generate Random Internal Paths
PATH_VLESS_WS_INT="/$(tr -dc a-z0-9 </dev/urandom | head -c 12)"
PATH_VMESS_WS_INT="/$(tr -dc a-z0-9 </dev/urandom | head -c 12)"
PATH_TROJAN_WS_INT="/$(tr -dc a-z0-9 </dev/urandom | head -c 12)"

PATH_VLESS_HU_INT="/$(tr -dc a-z0-9 </dev/urandom | head -c 12)"
PATH_VMESS_HU_INT="/$(tr -dc a-z0-9 </dev/urandom | head -c 12)"
PATH_TROJAN_HU_INT="/$(tr -dc a-z0-9 </dev/urandom | head -c 12)"

SVC_VLESS_GRPC_INT="$(tr -dc a-z0-9 </dev/urandom | head -c 12)"
SVC_VMESS_GRPC_INT="$(tr -dc a-z0-9 </dev/urandom | head -c 12)"
SVC_TROJAN_GRPC_INT="$(tr -dc a-z0-9 </dev/urandom | head -c 12)"

function generate_configs() {
    cat >/usr/local/etc/xray/config.json <<EOF
{
  "log": {
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "info"
  },
  "api": {
    "tag": "api",
    "services": [
      "HandlerService",
      "LoggerService",
      "StatsService"
    ]
  },
  "dns": {
    "servers": [
      "https://dns.google/dns-query",
      "https://1.1.1.1/dns-query",
      "localhost"
    ]
  },
  "stats": {},
  "policy": {
    "levels": {
      "0": {
        "handshake": 4,
        "connIdle": 300,
        "uplinkOnly": 2,
        "downlinkOnly": 5,
        "statsUserUplink": true,
        "statsUserDownlink": true,
        "bufferSize": 4
      }
    },
    "system": {
      "statsInboundUplink": true,
      "statsInboundDownlink": true
    }
  },
  "inbounds": [
    {
      "port": $P_VLESS_WS,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "tag": "vless-ws",
      "settings": {
        "clients": [
          {
            "id": "$UUID",
            "email": "user@vless-ws"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "$PATH_VLESS_WS_INT"
        }
      },
      "sniffing": {
        "destOverride": [
          "http",
          "tls",
          "quic"
          ]
      }
    },
    {
      "port": $P_VMESS_WS,
      "listen": "127.0.0.1",
      "protocol": "vmess",
      "tag": "vmess-ws",
      "settings": {
        "clients": [
          {
            "id": "$UUID",
            "email": "user@vmess-ws"
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "$PATH_VMESS_WS_INT"
        }
      },
      "sniffing": {
        "destOverride": [
          "http",
          "tls",
          "quic"
          ]
      }
    },
    {
      "port": $P_TROJAN_WS,
      "listen": "127.0.0.1",
      "protocol": "trojan",
      "tag": "trojan-ws",
      "settings": {
        "clients": [
          {
            "password": "$TROJAN_PASS",
            "email": "user@trojan-ws"
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "$PATH_TROJAN_WS_INT"
        }
      },
      "sniffing": {
        "destOverride": [
          "http",
          "tls",
          "quic"
          ]
      }
    },
    {
      "port": $P_VLESS_HU,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "tag": "vless-hu",
      "settings": {
        "clients": [
          {
            "id": "$UUID",
            "email": "user@vless-hu"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "httpupgrade",
        "httpupgradeSettings": {
          "path": "$PATH_VLESS_HU_INT"
        }
      },
      "sniffing": {
        "destOverride": [
          "http",
          "tls",
          "quic"
          ]
      }
    },
    {
      "port": $P_VMESS_HU,
      "listen": "127.0.0.1",
      "protocol": "vmess",
      "tag": "vmess-hu",
      "settings": {
        "clients": [
          {
            "id": "$UUID",
            "email": "user@vmess-hu"
          }
        ]
      },
      "streamSettings": {
        "network": "httpupgrade",
        "httpupgradeSettings": {
          "path": "$PATH_VMESS_HU_INT"
        }
      },
      "sniffing": {
        "destOverride": [
          "http",
          "tls",
          "quic"
          ]
      }
    },
    {
      "port": $P_TROJAN_HU,
      "listen": "127.0.0.1",
      "protocol": "trojan",
      "tag": "trojan-hu",
      "settings": {
        "clients": [
          {
            "password": "$TROJAN_PASS",
            "email": "user@trojan-hu"
          }
        ]
      },
      "streamSettings": {
        "network": "httpupgrade",
        "httpupgradeSettings": {
          "path": "$PATH_TROJAN_HU_INT"
        }
      },
      "sniffing": {
        "destOverride": [
          "http",
          "tls",
          "quic"
          ]
      }
    },
    {
      "port": $P_VLESS_GRPC,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "tag": "vless-grpc",
      "settings": {
        "clients": [
          {
            "id": "$UUID",
            "email": "user@vless-grpc"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "grpc",
        "grpcSettings": {
          "serviceName": "$SVC_VLESS_GRPC_INT"
        }
      },
      "sniffing": {
        "destOverride": [
          "http",
          "tls",
          "quic"
          ]
      }
    },
    {
      "port": $P_VMESS_GRPC,
      "listen": "127.0.0.1",
      "protocol": "vmess",
      "tag": "vmess-grpc",
      "settings": {
        "clients": [
          {
            "id": "$UUID",
            "email": "user@vmess-grpc"
          }
        ]
      },
      "streamSettings": {
        "network": "grpc",
        "grpcSettings": {
          "serviceName": "$SVC_VMESS_GRPC_INT"
        }
      },
      "sniffing": {
        "destOverride": [
          "http",
          "tls",
          "quic"
          ]
      }
    },
    {
      "port": $P_TROJAN_GRPC,
      "listen": "127.0.0.1",
      "protocol": "trojan",
      "tag": "trojan-grpc",
      "settings": {
        "clients": [
          {
            "password": "$TROJAN_PASS",
            "email": "user@trojan-grpc"
          }
        ]
      },
      "streamSettings": {
        "network": "grpc",
        "grpcSettings": {
          "serviceName": "$SVC_TROJAN_GRPC_INT"
        }
      },
      "sniffing": {
        "destOverride": [
          "http",
          "tls",
          "quic"
          ]
      }
    },
    {
      "listen": "127.0.0.1",
      "port": 10080,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1"
      },
      "tag": "api"
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "tag": "blocked"
    },
    {
      "protocol": "socks",
      "settings": {
        "servers": [
          {
            "address": "127.0.0.1",
            "port": 40000,
            "users": []
          }
        ]
      },
      "tag": "warp"
    }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "type": "field",
        "inboundTag": [
          "api"
        ],
        "outboundTag": "api"
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "ip": [
          "geoip:private"
        ]
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "protocol": [
          "bittorrent"
        ]
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "user": [
           "dummy-limit-ip"
        ]
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "user": [
           "dummy-quota-user"
        ]
      },
      {
        "inboundTag": [
          "default-inbounds"
        ],
        "outboundTag": "warp",
        "type": "field"
      },
      {
        "outboundTag": "warp",
        "type": "field",
        "user": [
          "default-user"
        ]
      },
      {
        "domain": [
          "geosite:apple",
          "geosite:meta",
          "geosite:google",
          "geosite:openai",
          "geosite:spotify",
          "geosite:netflix",
          "geosite:reddit"
        ],
        "outboundTag": "direct",
        "type": "field"
      },
      {
        "outboundTag": "direct",
        "port": "1-65535",
        "type": "field"
      }
    ]
  }
}
EOF

    rm -f /etc/nginx/sites-enabled/default
    rm -f /etc/nginx/conf.d/default.conf

    cat >/etc/nginx/conf.d/xray.conf <<EOF
# Map Connection Upgrade
map \$http_upgrade \$connection_upgrade {
    default upgrade;
    ''      close;
}

# 1. Map Public Path ke INTERNAL PORT
map \$uri \$internal_port {
    /vless-ws $P_VLESS_WS;
    /vmess-ws $P_VMESS_WS;
    /trojan-ws $P_TROJAN_WS;
    
    /vless-hu $P_VLESS_HU;
    /vmess-hu $P_VMESS_HU;
    /trojan-hu $P_TROJAN_HU;
    
    /vless-grpc $P_VLESS_GRPC;
    /vmess-grpc $P_VMESS_GRPC;
    /trojan-grpc $P_TROJAN_GRPC;
}

# 2. Map Public Path ke INTERNAL PATH / SERVICE NAME
map \$uri \$internal_path {
    /vless-ws $PATH_VLESS_WS_INT;
    /vmess-ws $PATH_VMESS_WS_INT;
    /trojan-ws $PATH_TROJAN_WS_INT;
    
    /vless-hu $PATH_VLESS_HU_INT;
    /vmess-hu $PATH_VMESS_HU_INT;
    /trojan-hu $PATH_TROJAN_HU_INT;
}

# 3. Map Public Path ke gRPC Service Name
map \$uri \$grpc_service_name {
    /vless-grpc $SVC_VLESS_GRPC_INT;
    /vmess-grpc $SVC_VMESS_GRPC_INT;
    /trojan-grpc $SVC_TROJAN_GRPC_INT;
}

server {
    listen 80;
    listen [::]:80;
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name $DOMAIN;

    ssl_certificate /opt/ssl/fullchain.pem;
    ssl_certificate_key /opt/ssl/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;

    # --- Section 1: Handle WebSocket ---
    location ~ ^/(vless|vmess|trojan)-ws {
        if (\$http_upgrade != "websocket") { return 404; }
        proxy_redirect off;
        proxy_pass http://127.0.0.1:\$internal_port\$internal_path;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }

    # --- Section 2: Handle HTTPUpgrade ---
    location ~ ^/(vless|vmess|trojan)-hu {
        proxy_pass http://127.0.0.1:\$internal_port\$internal_path;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }

    # --- Section 3: Handle gRPC ---
    location ~ ^/(vless|vmess|trojan)-grpc {
        rewrite ^ /$grpc_service_name/Tun break;
        grpc_pass grpc://127.0.0.1:$internal_port;
        grpc_set_header Host $host;
        grpc_set_header X-Real-IP $remote_addr;
        grpc_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
EOF
}
run_step "9. Membuat Konfigurasi" generate_configs

# --- Step 10: Log Cleaner, Auto XP (Python), IP Limiter (Python), Quota Check (Python), Watchdog, Geo Update ---
function setup_maintenance() {
    # 1. Log Cleaner
    (
        crontab -l 2>/dev/null
        echo "0 0 * * * truncate -s 0 /var/log/xray/access.log"
    ) | crontab -
    (
        crontab -l 2>/dev/null
        echo "0 0 * * * truncate -s 0 /var/log/xray/error.log"
    ) | crontab -

    mkdir -p /etc/xray
    # Pastikan direktori quota ada
    mkdir -p /opt/quota/allproto /opt/quota/vless /opt/quota/vmess /opt/quota/trojan
    
    touch /var/log/xray/quota.log
    touch /var/log/xray/xp.log
    touch /var/log/xray/limit.log
    touch /var/log/xray/watchdog.log

    # 2. XP Script (Auto Expired) - JSON SUPPORT
    cat >/usr/local/bin/xray-expiry <<'EOF'
#!/usr/bin/env python3
import os
import json
import subprocess
import glob
from datetime import datetime

CONFIG_FILE = "/usr/local/etc/xray/config.json"
LOG_FILE = "/var/log/xray/xp.log"
QUOTA_BASE = "/opt/quota"
# Mapping folder JSON ke folder TXT
PROTOCOL_MAP = {
    "allproto": "/opt/allproto",
    "vless": "/opt/vless",
    "vmess": "/opt/vmess",
    "trojan": "/opt/trojan"
}
CMD_RESTART = "systemctl restart xray"

def log(msg):
    with open(LOG_FILE, "a") as f:
        f.write(f"[{datetime.now()}] {msg}\n")

def main():
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, 'w').close()
    
    log("--- Auto XP Started (JSON Mode) ---")
    today_dt = datetime.now()
    expired_users = []
    
    # Scan semua file JSON di /opt/quota/*/*.json
    json_files = glob.glob(os.path.join(QUOTA_BASE, "*", "*.json"))
    
    for json_path in json_files:
        try:
            with open(json_path, 'r') as f:
                data = json.load(f)
            
            username = data.get('username')
            protocol = data.get('protocol') # vless, vmess, etc
            expired_at_str = data.get('expired_at')
            
            if username and expired_at_str:
                exp_dt = datetime.strptime(expired_at_str, "%Y-%m-%d")
                
                # Cek apakah expired (Expired Date < Today)
                if exp_dt.date() < today_dt.date():
                    log(f"User {username} ({protocol}) expired on {expired_at_str}. Deleting...")
                    expired_users.append(username)
                    
                    # 1. Hapus File JSON
                    os.remove(json_path)
                    
                    # 2. Hapus File TXT (Config)
                    # Cari di folder protocol yang sesuai
                    txt_folder = PROTOCOL_MAP.get(protocol)
                    if txt_folder:
                        txt_path = os.path.join(txt_folder, f"{username}.txt")
                        if os.path.exists(txt_path):
                            os.remove(txt_path)
                            
        except Exception as e:
            log(f"Error checking {json_path}: {e}")

    if not expired_users:
        return

    # 3. Remove from Xray Config
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
        
        changed = False
        
        if 'inbounds' in config:
            for inbound in config['inbounds']:
                if 'settings' in inbound and 'clients' in inbound['settings']:
                    clients = inbound['settings']['clients']
                    # Filter out expired users
                    new_clients = [c for c in clients if c.get('email') not in expired_users]
                    
                    if len(clients) != len(new_clients):
                        inbound['settings']['clients'] = new_clients
                        changed = True
        
        if changed:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=2)
            
            subprocess.run(CMD_RESTART, shell=True)
            log(f"Removed {len(expired_users)} users from config & restarted.")
            
    except Exception as e:
        log(f"Error updating config: {e}")

if __name__ == "__main__":
    main()
EOF
    chmod +x /usr/local/bin/xray-expiry

    # 3. IP Limiter (Python Version) - LOGIC UPDATE (Unique IP)
    echo "2" >/etc/xray/limit_ip
    cat >/usr/local/bin/xray-limit <<'EOF'
#!/usr/bin/env python3
import os
import json
import subprocess
import re
from datetime import datetime

LOG_FILE = "/var/log/xray/access.log"
CONFIG_FILE = "/usr/local/etc/xray/config.json"
LIMIT_FILE = "/etc/xray/limit_ip"
LOG_OUTPUT = "/var/log/xray/limit.log"
RESTART_CMD = "systemctl restart xray"

def log(msg):
    with open(LOG_OUTPUT, "a") as f:
        f.write(f"[{datetime.now()}] {msg}\n")

def get_limit():
    try:
        with open(LIMIT_FILE, 'r') as f:
            return int(f.read().strip())
    except:
        return 2

def get_access_log(lines=5000):
    cmd = f"tail -n {lines} {LOG_FILE}"
    try:
        output = subprocess.check_output(cmd, shell=True).decode('utf-8', errors='ignore')
        return output.split('\n')
    except:
        return []

def main():
    if not os.path.exists(LOG_OUTPUT):
        open(LOG_OUTPUT, 'w').close()
    
    max_ip = get_limit()
    logs = get_access_log()
    
    # Dictionary: user -> Set of IPs (Set ensures uniqueness)
    user_ips = {} 
    
    # PERBAIKAN REGEX:
    # Menangkap IP yang berada setelah kata "from"
    # Contoh Log: ... accepted tcp:server_ip:443 from 182.2.165.113:12345 email: user
    pattern = re.compile(r"accepted.*from\s+(\d+\.\d+\.\d+\.\d+):\d+.*email:\s+(.+)")

    for line in logs:
        # Filter baris wajib memiliki 'accepted', 'from', dan 'email:'
        if "accepted" in line and "from" in line and "email:" in line:
            match = pattern.search(line)
            if match:
                ip = match.group(1)       # Group 1: IP Source (setelah 'from')
                user = match.group(2).strip() # Group 2: Username
                
                # Abaikan user sistem/dummy
                if user in ['dummy-limit-ip', 'dummy-quota-user', 'api', 'user@vless-ws']: 
                    continue
                    
                if user not in user_ips:
                    user_ips[user] = set()
                
                # Tambahkan IP ke set
                user_ips[user].add(ip)

    violators = []
    for user, ips in user_ips.items():
        unique_count = len(ips)
        if unique_count > max_ip:
            violators.append(user)
            log(f"User {user} uses {unique_count} Unique IPs {ips}. Limit: {max_ip}. Blocked.")

    if not violators:
        return

    # Update Config (Block Violators)
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
        
        updated = False
        
        for rule in config.get('routing', {}).get('rules', []):
            if rule.get('outboundTag') == 'blocked' and 'user' in rule:
                if 'dummy-limit-ip' in rule['user']:
                    current_blocked = rule['user']
                    for bad_user in violators:
                        if bad_user not in current_blocked:
                            current_blocked.append(bad_user)
                            updated = True
                    rule['user'] = current_blocked
                    break
        
        if updated:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=2)
            subprocess.run(RESTART_CMD, shell=True)
            log("Config updated & Xray restarted due to Multi-Login.")

    except Exception as e:
        log(f"Error updating config: {e}")

if __name__ == "__main__":
    main()
EOF
    chmod +x /usr/local/bin/xray-limit

    # 4. Quota Check (Python Daemon) - REALTIME & JSON
    cat >/usr/local/bin/xray-quota <<'EOF'
#!/usr/bin/env python3
import os
import json
import subprocess
import glob
import time
from datetime import datetime

CONFIG_FILE = "/usr/local/etc/xray/config.json"
XRAY_API_CMD = "xray api statsquery --server=127.0.0.1:10080"
QUOTA_BASE = "/opt/quota"
LOG_OUTPUT = "/var/log/xray/quota.log"
RESTART_CMD = "systemctl restart xray"
CHECK_INTERVAL = 10  # Cek setiap 10 detik (Realtime)

def log(msg):
    # Print ke stdout untuk jurnal service
    print(f"[{datetime.now()}] {msg}")
    try:
        with open(LOG_OUTPUT, "a") as f:
            f.write(f"[{datetime.now()}] {msg}\n")
    except: pass

def get_xray_stats():
    try:
        output = subprocess.check_output(XRAY_API_CMD, shell=True).decode('utf-8', errors='ignore')
        data = json.loads(output)
        usage_map = {}
        if 'stat' in data:
            for item in data['stat']:
                parts = item['name'].split('>>>')
                if len(parts) >= 4 and parts[0] == 'user':
                    user = parts[1]
                    value = int(item['value'])
                    if user not in usage_map:
                        usage_map[user] = 0
                    usage_map[user] += value
        return usage_map
    except:
        return {}

def get_user_limits_json():
    user_limits = {}
    # Scan semua JSON di /opt/quota/*/*.json
    files = glob.glob(os.path.join(QUOTA_BASE, "*", "*.json"))
    for file_path in files:
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            username = data.get('username')
            limit = data.get('quota_limit', 0)
            
            # Hanya masukkan jika limit > 0
            if username and limit > 0:
                user_limits[username] = limit
        except:
            continue
    return user_limits

def get_blocked_users_from_config():
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
        for rule in config.get('routing', {}).get('rules', []):
            if rule.get('outboundTag') == 'blocked' and 'user' in rule:
                if 'dummy-quota-user' in rule['user']:
                    return set(rule['user'])
    except: pass
    return set()

def update_xray_config(target_blocked):
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
        
        updated = False
        for rule in config.get('routing', {}).get('rules', []):
            if rule.get('outboundTag') == 'blocked' and 'user' in rule:
                if 'dummy-quota-user' in rule['user']:
                    current_list = rule['user']
                    # Konversi set target ke list
                    new_list = list(target_blocked)
                    # Pastikan dummy tetap ada
                    if 'dummy-quota-user' not in new_list:
                        new_list.append('dummy-quota-user')
                    
                    # Cek apakah beda
                    if set(current_list) != set(new_list):
                        rule['user'] = new_list
                        updated = True
                    break
        
        if updated:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=2)
            subprocess.run(RESTART_CMD, shell=True)
            log("Config updated & Xray restarted (Quota Enforcement).")
            return True
    except Exception as e:
        log(f"Error updating config: {e}")
    return False

def main():
    if not os.path.exists(LOG_OUTPUT):
        open(LOG_OUTPUT, 'w').close()
    
    log("--- Xray Quota Daemon Started (Real-time) ---")
    
    # Loop continuously (Daemon)
    while True:
        try:
            stats = get_xray_stats()
            limits = get_user_limits_json()
            
            # Siapa yang HARUSNYA diblokir saat ini?
            should_be_blocked = set()
            should_be_blocked.add('dummy-quota-user')
            
            for user, limit in limits.items():
                used = stats.get(user, 0)
                if used >= limit:
                    should_be_blocked.add(user)
            
            # Siapa yang SEDANG diblokir?
            currently_blocked = get_blocked_users_from_config()
            
            # Jika beda, update
            if should_be_blocked != currently_blocked:
                # Logging perubahan
                new_blocks = should_be_blocked - currently_blocked
                new_unblocks = currently_blocked - should_be_blocked
                
                for u in new_blocks:
                    if u != 'dummy-quota-user': log(f"Blocking {u} (Over Quota)")
                for u in new_unblocks:
                    if u != 'dummy-quota-user': log(f"Unblocking {u} (Reset/Topup)")
                
                update_xray_config(should_be_blocked)
            
        except Exception as e:
            log(f"Loop error: {e}")
        
        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    main()
EOF
    chmod +x /usr/local/bin/xray-quota

    # 5. Service Watchdog (Xray & Nginx)
    cat >/usr/local/bin/xray-watchdog <<'EOF'
#!/bin/bash
if ! systemctl is-active --quiet xray; then
    systemctl restart xray
    echo "$(date) - Xray restarted by watchdog" >> /var/log/xray/watchdog.log
fi
if ! systemctl is-active --quiet nginx; then
    systemctl restart nginx
    echo "$(date) - Nginx restarted by watchdog" >> /var/log/xray/watchdog.log
fi
EOF
    chmod +x /usr/local/bin/xray-watchdog

    # Systemd for Quota Daemon (Changed to Simple/Daemon)
    cat >/etc/systemd/system/xray-quota.service <<EOF
[Unit]
Description=Xray Quota Daemon (Real-time)
After=network.target xray.service

[Service]
Type=simple
ExecStart=/usr/local/bin/xray-quota
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

    # Disable Old Timer (Jika ada)
    systemctl stop xray-quota.timer 2>/dev/null
    systemctl disable xray-quota.timer 2>/dev/null

    systemctl daemon-reload
    systemctl enable --now xray-quota.service

    cat >/usr/local/bin/xray-update-geodata <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

TMP_FILE="$(mktemp)"
trap 'rm -f "$TMP_FILE"' EXIT

curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh -o "$TMP_FILE"
bash "$TMP_FILE" @ install-geodata
systemctl restart xray
EOF

    chmod +x /usr/local/bin/xray-update-geodata

    # 6. Add Crons (Expiry, Limit, Watchdog, Geo)
    (
        crontab -l 2>/dev/null
        echo "0 0 * * * /usr/local/bin/xray-expiry"
    ) | crontab -
    (
        crontab -l 2>/dev/null
        echo "* * * * * /usr/local/bin/xray-limit"
    ) | crontab -
    (
        crontab -l 2>/dev/null
        echo "*/5 * * * * /usr/local/bin/xray-watchdog"
    ) | crontab -
    ( 
        crontab -l 2>/dev/null
        echo "0 4 * * * /usr/local/bin/xray-update-geodata >/dev/null 2>&1"
    ) | crontab -
    
    # 7. Traffic Monitor (Python Version - Xray API)
    cat >/usr/local/bin/xray-traffic <<'EOF'
#!/usr/bin/env python3
import json
import subprocess
import sys

# ANSI Colors matching menu.sh
BLUE = '\033[1;94m'
WHITE = '\033[1;97m'
GREEN = '\033[1;92m'
YELLOW = '\033[1;93m'
RED = '\033[1;91m'
NC = '\033[0m'

def bytes_to_human(size):
    power = 2**10
    n = 0
    power_labels = {0 : 'B', 1: 'KB', 2: 'MB', 3: 'GB', 4: 'TB'}
    while size > power and n < 4:
        size /= power
        n += 1
    return f"{size:.2f} {power_labels[n]}"

def main():
    cmd = "xray api statsquery --server=127.0.0.1:10080"
    try:
        output = subprocess.check_output(cmd, shell=True).decode('utf-8')
        data = json.loads(output)
    except Exception:
        print(f"   {RED}Gagal mengambil data dari Xray API (Pastikan Xray berjalan).{NC}")
        return

    user_map = {}
    
    if 'stat' not in data:
        print(f"   {YELLOW}Belum ada data trafik yang terekam.{NC}")
        return

    for item in data['stat']:
        # Format API: user>>>email>>>traffic>>>uplink
        parts = item['name'].split('>>>')
        if len(parts) >= 4 and parts[0] == 'user' and parts[2] == 'traffic':
            user = parts[1]
            direction = parts[3]
            value = int(item['value'])
            
            if user not in user_map:
                user_map[user] = {'up': 0, 'down': 0}
            
            if direction == 'uplink':
                user_map[user]['up'] += value
            elif direction == 'downlink':
                user_map[user]['down'] += value

    # Print Table Header
    print(f"{BLUE}+------+-----------------+--------------+--------------+--------------+{NC}")
    print(f"{BLUE}| {WHITE}NO   {BLUE}| {WHITE}USERNAME        {BLUE}| {WHITE}UPLOAD       {BLUE}| {WHITE}DOWNLOAD     {BLUE}| {WHITE}TOTAL        {BLUE}|{NC}")
    print(f"{BLUE}+------+-----------------+--------------+--------------+--------------+{NC}")

    # Sort by Total Usage (Desc)
    sorted_users = sorted(user_map.items(), key=lambda x: x[1]['up'] + x[1]['down'], reverse=True)
    
    if not sorted_users:
         print(f"{BLUE}| {RED}NULL {BLUE}| {WHITE}Tidak ada user  {BLUE}| {WHITE}-            {BLUE}| {WHITE}-            {BLUE}| {WHITE}-            {BLUE}|{NC}")

    for i, (user, stats) in enumerate(sorted_users, 1):
        up_h = bytes_to_human(stats['up'])
        down_h = bytes_to_human(stats['down'])
        total_h = bytes_to_human(stats['up'] + stats['down'])
        
        # Print Row
        print(f"{BLUE}| {GREEN}{i:<4} {BLUE}| {WHITE}{user:<15} {BLUE}| {YELLOW}{up_h:<12} {BLUE}| {YELLOW}{down_h:<12} {BLUE}| {GREEN}{total_h:<12} {BLUE}|{NC}")

    print(f"{BLUE}+------+-----------------+--------------+--------------+--------------+{NC}")

if __name__ == "__main__":
    main()
EOF
    chmod +x /usr/local/bin/xray-traffic
}
run_step "10. Setup Maintenance" setup_maintenance

# --- Step 11: Setup Backup/Restore Data BOT Telegram ---
function setup_telegram_bot() {
    # -------------------------------
    # Dependency Python
    # -------------------------------
    if ! command -v python3 >/dev/null 2>&1; then
        apt-get update -y >/dev/null 2>&1
        apt-get install -y python3 >/dev/null 2>&1
    fi

    if ! command -v pip3 >/dev/null 2>&1; then
        apt-get install -y python3-pip >/dev/null 2>&1
    fi

    # -------------------------------
    # Install pyTelegramBotAPI
    # -------------------------------
    if ! pip3 show pyTelegramBotAPI >/dev/null 2>&1; then
        pip3 install pyTelegramBotAPI --break-system-packages >/dev/null 2>&1
    fi

    # -------------------------------
    # Directory config
    # -------------------------------
    mkdir -p /etc/telegram-backup
    mkdir -p /opt/backup
    chmod 700 /etc/telegram-backup

    # file config default (tidak overwrite)
    touch /etc/telegram-backup/token.conf
    touch /etc/telegram-backup/admin.conf
    touch /etc/telegram-backup/config.json
    touch /etc/telegram-backup/backups.json
    touch /var/log/xray/backup_restore.log

    chmod 600 /etc/telegram-backup/*

    # -------------------------------
    # Deploy bot script
    # -------------------------------
    if [ ! -f /usr/local/bin/xray-telegram-bot.py ]; then
        cat >/usr/local/bin/xray-telegram-bot.py <<'EOF'
#!/usr/bin/env python3

import telebot
import os
import json
import time
import threading
import subprocess
import zipfile
from datetime import datetime

# ==========================================================
# PATH & CONSTANT
# ==========================================================
BASE_DIR = "/etc/telegram-backup"
BACKUP_DIR = "/opt/backup"
LOG_DIR = "/var/log/xray"
LOG_FILE = f"{LOG_DIR}/backup_restore.log"

TOKEN_FILE = f"{BASE_DIR}/token.conf"
ADMIN_FILE = f"{BASE_DIR}/admin.conf"
CONFIG_FILE = f"{BASE_DIR}/config.json"
BACKUP_META = f"{BASE_DIR}/backups.json"

# ==========================================================
# PREPARE DIRECTORY
# ==========================================================
os.makedirs(BASE_DIR, exist_ok=True)
os.makedirs(BACKUP_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

# ==========================================================
# LOGGING (NEW FEATURE)
# ==========================================================
def write_log(level, message):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{level} & {ts}] {message}"
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

print("[INFO] Xray Telegram Bot starting...")
write_log("INFO", "XRAY TELEGRAM BOT STARTING...")

# ==========================================================
# LOAD BOT TOKEN
# ==========================================================
if not os.path.exists(TOKEN_FILE):
    print("[ERROR] Token bot tidak ditemukan")
    write_log("ERROR", "TOKEN BOT TIDAK DITEMUKAN")
    exit(1)

BOT_TOKEN = open(TOKEN_FILE).read().strip()
if not BOT_TOKEN:
    print("[ERROR] Token bot kosong")
    write_log("ERROR", "TOKEN BOT KOSONG")
    exit(1)

bot = telebot.TeleBot(BOT_TOKEN)

# ==========================================================
# JSON HELPERS
# ==========================================================
def load_json(path, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default

def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

# ==========================================================
# ADMIN HELPERS
# ==========================================================
def read_admin_id():
    if not os.path.exists(ADMIN_FILE):
        return None
    try:
        data = open(ADMIN_FILE).read().strip()
    except Exception:
        return None
    if not data.isdigit():
        return None
    return data

def is_admin(chat_id):
    admin_id = read_admin_id()
    if admin_id is None:
        return False
    return str(chat_id) == admin_id

# ==========================================================
# INIT CONFIG
# ==========================================================
config = load_json(CONFIG_FILE, {
    "auto_backup": False,
    "interval_days": 1,
    "last_run": 0
})
save_json(CONFIG_FILE, config)

backups = load_json(BACKUP_META, [])
save_json(BACKUP_META, backups)

# ==========================================================
# /start
# ==========================================================
@bot.message_handler(commands=["start"])
def start_cmd(msg):
    admin_id = read_admin_id()

    if admin_id is None:
        with open(ADMIN_FILE, "w") as f:
            f.write(str(msg.chat.id))
        print(f"[INFO] Admin diset: chat_id={msg.chat.id}")
        write_log("INFO", f"ADMIN DISET: chat_id={msg.chat.id}")
        bot.reply_to(msg, "Admin berhasil diset.\nGunakan /help untuk melihat daftar perintah.")
        return

    if is_admin(msg.chat.id):
        bot.reply_to(msg, "Anda adalah admin bot ini.\nGunakan /help untuk melihat daftar perintah.")
    else:
        bot.reply_to(msg, "Bot ini bersifat privat.")

# ==========================================================
# /help
# ==========================================================
@bot.message_handler(commands=["help"])
def help_cmd(msg):
    if not is_admin(msg.chat.id):
        return

    bot.reply_to(
        msg,
        "📌 XRAY BACKUP & RESTORE BOT\n\n"
        "Perintah yang tersedia:\n\n"
        "/backup\n"
        "Membuat backup konfigurasi Xray, Nginx, dan /opt.\n"
        "File akan dikirim ke Telegram dan tidak disimpan di server.\n\n"
        "/restore latest\n"
        "Mengembalikan sistem dari backup TERAKHIR.\n"
        "⚠️ Perhatian:\n"
        "- File langsung di-unzip ke sistem\n"
        "- Konfigurasi lama akan tertimpa\n"
        "- Xray dan Nginx akan direstart otomatis\n\n"
        "/autobackup on\n"
        "Mengaktifkan auto backup.\n\n"
        "/autobackup off\n"
        "Menonaktifkan auto backup.\n\n"
        "/autobackup interval <hari>\n"
        "Mengatur interval auto backup (contoh: 1 = harian).\n\n"
        "/status\n"
        "Menampilkan status auto backup dan interval.\n\n"
        "ℹ️ Bot ini bersifat privat.\n"
        "Hanya admin yang dapat menggunakan perintah."
    )

# ==========================================================
# BACKUP CORE
# ==========================================================
def run_backup(zip_path):
    subprocess.run(
        [
            "zip", "-r", zip_path,
            "/usr/local/etc/xray",
            "/opt",
            "/etc/nginx/conf.d",
            "/etc/nginx/nginx.conf"
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

# ==========================================================
# /backup
# ==========================================================
@bot.message_handler(commands=["backup"])
def backup_cmd(msg):
    if not is_admin(msg.chat.id):
        return

    date_str = datetime.now().strftime("%d-%m-%Y")
    zip_path = f"{BACKUP_DIR}/{date_str}_backup_xray.zip"

    print(f"[INFO] Backup manual dipicu oleh admin ({msg.chat.id})")
    write_log("INFO", "BACKUP MANUAL START")

    try:
        run_backup(zip_path)
        sent = bot.send_document(msg.chat.id, open(zip_path, "rb"))

        backups = load_json(BACKUP_META, [])
        backups.append({
            "file_id": sent.document.file_id,
            "timestamp": int(time.time())
        })
        save_json(BACKUP_META, backups)

        os.remove(zip_path)
        write_log("INFO", f"BACKUP MANUAL SUCCESS file={os.path.basename(zip_path)}")
        bot.reply_to(msg, "Backup selesai.\n\nKonfigurasi Xray, Nginx, dan /opt\ntelah dibackup dan dikirim ke Telegram.")

    except Exception as e:
        write_log("ERROR", f"BACKUP MANUAL FAILED reason={e}")
        bot.reply_to(msg, "Backup gagal.")

# ==========================================================
# /restore latest
# ==========================================================
@bot.message_handler(commands=["restore"])
def restore_cmd(msg):
    if not is_admin(msg.chat.id):
        return

    args = msg.text.split()
    if len(args) != 2 or args[1] != "latest":
        bot.reply_to(msg, "Gunakan perintah:\n/restore latest")
        return

    backups = load_json(BACKUP_META, [])
    if not backups:
        bot.reply_to(msg, "Tidak ada data backup yang tersedia.")
        return

    bot.reply_to(msg, "Memulai proses restore dari backup terakhir...")
    write_log("WARNING", "RESTORE MANUAL START")

    try:
        file_id = backups[-1]["file_id"]
        file_info = bot.get_file(file_id)
        data = bot.download_file(file_info.file_path)

        date_str = datetime.now().strftime("%d-%m-%Y")
        zip_path = f"{BACKUP_DIR}/{date_str}_restore_xray.zip"

        with open(zip_path, "wb") as f:
            f.write(data)

        with zipfile.ZipFile(zip_path) as z:
            z.extractall("/")

        subprocess.run(["systemctl", "restart", "xray"])
        subprocess.run(["systemctl", "restart", "nginx"])

        if os.path.exists(zip_path):
            os.remove(zip_path)

        bot.reply_to(
            msg,
            "Restore berhasil.\n\n"
            "Sistem telah dipulihkan dari backup terakhir.\n"
            "Xray dan Nginx telah direstart."
        )
        write_log("INFO", "RESTORE MANUAL SUCCESS")

    except Exception as e:
        write_log("ERROR", f"RESTORE MANUAL FAILED reason={e}")
        bot.reply_to(msg, "Restore gagal.")

# ==========================================================
# /autobackup
# ==========================================================
@bot.message_handler(commands=["autobackup"])
def autobackup_cmd(msg):
    if not is_admin(msg.chat.id):
        return

    args = msg.text.split()
    config = load_json(CONFIG_FILE, {})

    if len(args) == 2 and args[1] == "on":
        config["auto_backup"] = True
        save_json(CONFIG_FILE, config)
        bot.reply_to(
            msg,
            "Auto backup berhasil diaktifkan.\n\n"
            "Backup akan berjalan otomatis sesuai interval yang ditentukan."
        )
        return

    if len(args) == 2 and args[1] == "off":
        config["auto_backup"] = False
        save_json(CONFIG_FILE, config)
        bot.reply_to(
            msg,
            "Auto backup berhasil dinonaktifkan.\n\n"
            "Backup manual tetap dapat digunakan."
        )
        return

    if len(args) == 3 and args[1] == "interval":
        try:
            days = int(args[2])
            config["interval_days"] = days
            save_json(CONFIG_FILE, config)
            bot.reply_to(
                msg,
                f"Interval auto backup berhasil diatur.\n\n"
                f"Backup akan dijalankan setiap {days} hari."
            )
        except ValueError:
            bot.reply_to(msg, "Interval harus berupa angka (dalam hari).")
        return

    bot.reply_to(
        msg,
        "Gunakan perintah:\n"
        "/autobackup on\n"
        "/autobackup off\n"
        "/autobackup interval <hari>"
    )

# ==========================================================
# /status
# ==========================================================
@bot.message_handler(commands=["status"])
def status_cmd(msg):
    if not is_admin(msg.chat.id):
        return

    config = load_json(CONFIG_FILE, {})
    status = "ON" if config.get("auto_backup") else "OFF"
    interval = config.get("interval_days", 1)

    bot.reply_to(
        msg,
        "Status Auto Backup:\n"
        f"- Auto Backup : {status}\n"
        f"- Interval    : {interval} hari"
    )

# ==========================================================
# AUTO BACKUP SCHEDULER
# ==========================================================
def scheduler():
    while True:
        time.sleep(60)

        config = load_json(CONFIG_FILE, {})
        if not config.get("auto_backup"):
            continue

        now = int(time.time())
        last = config.get("last_run", 0)
        interval = config.get("interval_days", 1) * 86400

        if now - last >= interval:
            date_str = datetime.now().strftime("%d-%m-%Y")
            zip_path = f"{BACKUP_DIR}/{date_str}_backup_xray.zip"

            run_backup(zip_path)
            os.remove(zip_path)

            config["last_run"] = now
            save_json(CONFIG_FILE, config)

            write_log("INFO", f"BACKUP AUTO SUCCESS file={os.path.basename(zip_path)}")

threading.Thread(target=scheduler, daemon=True).start()

# ==========================================================
# START BOT
# ==========================================================
bot.infinity_polling()
EOF
        chmod +x /usr/local/bin/xray-telegram-bot.py
    fi

    # -------------------------------
    # Systemd service
    # -------------------------------
    if [ ! -f /etc/systemd/system/xray-telegram-bot.service ]; then
        cat >/etc/systemd/system/xray-telegram-bot.service <<EOF
[Unit]
Description=Xray Telegram Backup Bot
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/bin/xray-telegram-bot.py
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF
    fi

    systemctl daemon-reload
}
run_step "11. Setup Backup/Restore BOT Telegram" setup_telegram_bot

# --- Step 12: Restart Services ---
function restart_services() {
    systemctl daemon-reload
    systemctl restart xray
    systemctl restart nginx
}
run_step "12. Merestart Layanan System" restart_services

# --- Step 13: Download Menu---
function download_menu_script() {
    echo "Downloading menu.sh..." >>"$LOG_FILE"

    curl -fsSL \
        https://raw.githubusercontent.com/superdecrypt-dev/aio-xray/master/menu.sh \
        -o /usr/local/bin/menu

    chmod +x /usr/local/bin/menu
}
run_step "13. Mengunduh Menu Management" download_menu_script

# ==========================================
# FINAL OUTPUT
# ==========================================

# Final Output (Without Links, Just Server Info)
echo -e "${BLUE}=========================================================${NC}"
echo -e "${GREEN}       INSTALLATION COMPLETED SUCCESSFULLY               ${NC}"
echo -e "${BLUE}=========================================================${NC}"
echo -e " ${YELLOW}SERVER INFORMATION${NC}"
echo -e "   - IP Address    : $IP_VPS"
echo -e "   - Domain        : $DOMAIN"
echo -e "   - SSL Cert      : /opt/ssl/fullchain.pem"
echo -e "   - SSL Key       : /opt/ssl/privkey.pem"
echo -e ""
echo -e " ${YELLOW}PROTOCOL & TRANSPORT DETAILS${NC}"
echo -e "   - Public Port   : 443 (HTTPS) & 80 (HTTP)"
echo -e "   - Protocols     : VLESS, VMess, Trojan"
echo -e "   - Transports    : WebSocket, HTTPUpgrade, gRPC"
echo -e "   - Websocket Path: /vless-ws, /vmess-ws, /trojan-ws"
echo -e "   - HTTPUpgr Path : /vless-hu, /vmess-hu, /trojan-hu"
echo -e "   - gRPC Service  : vless-grpc, vmess-grpc, trojan-grpc"
echo -e "${BLUE}=========================================================${NC}"
echo -e "${YELLOW}Ketik 'menu' di terminal untuk mengelola server.${NC}"
echo -e "${BLUE}==========================================${NC}"
echo -e "${BLUE}       Dibuat oleh Gemini AI  ✨        ${NC}"
echo -e "${BLUE}==========================================${NC}"