#!/bin/bash

# ==============================================================
# Xray-core CLI Manager (Final Ultimate)
# Credit: Dibuat oleh Gemini AI
# ==============================================================

# --- Warna UI ---
BIBlack='\033[1;90m'      # Black
BIRed='\033[1;91m'        # Red
BIGreen='\033[1;92m'      # Green
BIYellow='\033[1;93m'     # Yellow
BIBlue='\033[1;94m'       # Blue
BIPurple='\033[1;95m'     # Purple
BICyan='\033[1;96m'       # Cyan
BIWhite='\033[1;97m'      # White
NC='\033[0m'              # No Color

# --- Konfigurasi File ---
CONFIG="/usr/local/etc/xray/config.json"
NGINX_CONF="/etc/nginx/conf.d/xray.conf"
DIR_ALL="/opt/allproto"
DIR_VLESS="/opt/vless"
DIR_VMESS="/opt/vmess"
DIR_TROJAN="/opt/trojan"
LOG_ACCESS="/var/log/xray/access.log"
TMP_JSON="/tmp/tmp.json"
TG_BASE="/etc/telegram-backup"
TG_TOKEN_FILE="$TG_BASE/token.conf"
TG_SERVICE="xray-telegram-bot.service"

# Decode Cloudflare Token (Global)
CF_TOKEN_B64="ejc1SHc3S2RCUVBSN3ctRW5xS2JlY2dWUGFuOFY1MWFoWDg5OGVCNw=="
CF_TOKEN=$(echo "$CF_TOKEN_B64" | base64 -d)

# Buat direktori jika belum ada
mkdir -p "$DIR_ALL" "$DIR_VLESS" "$DIR_VMESS" "$DIR_TROJAN"

# --- Cek Root & Dependencies ---
if [[ $EUID -ne 0 ]]; then
    echo -e "${BIRed}Script ini harus dijalankan sebagai root!${NC}"
    exit 1
fi

if ! command -v jq &>/dev/null; then
    echo -e "${BIYellow}Menginstall jq...${NC}"
    apt-get install -y jq >/dev/null 2>&1
fi

if ! command -v curl &>/dev/null; then
    echo -e "${BIYellow}Menginstall curl...${NC}"
    apt-get install -y curl >/dev/null 2>&1
fi

if ! command -v zip &>/dev/null; then
    echo -e "${BIYellow}Menginstall zip...${NC}"
    apt-get install -y zip >/dev/null 2>&1
fi

# --- Info Sistem Dasar ---
IPVPS=$(curl -s ifconfig.me)
OS_NAME=$(grep -w PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')

# Domain
DOMAIN=$(grep "server_name" "$NGINX_CONF" | head -n1 | awk '{print $2}' | tr -d ';')
if [[ -z "$DOMAIN" ]]; then DOMAIN="IP-Address"; fi

# --- Geo IP (ip-api.com) ---
GEO_DATA=$(curl -s http://ip-api.com/json/)
ISP=$(echo "$GEO_DATA" | jq -r .isp)
COUNTRY=$(echo "$GEO_DATA" | jq -r .country)
CITY=$(echo "$GEO_DATA" | jq -r .city)

# --- Hitung Akun ---
COUNT_ALL=$(find "$DIR_ALL" -name "*.txt" 2>/dev/null | wc -l)
COUNT_VLESS=$(find "$DIR_VLESS" -name "*.txt" 2>/dev/null | wc -l)
COUNT_VMESS=$(find "$DIR_VMESS" -name "*.txt" 2>/dev/null | wc -l)
COUNT_TROJAN=$(find "$DIR_TROJAN" -name "*.txt" 2>/dev/null | wc -l)

# ==========================================
# 1. HELPER & UTILITY FUNCTIONS
# ==========================================

function show_header() {
    clear
    echo -e "${BIBlue}==============================================================${NC}"
    echo -e "${BIWhite}                       XRAY MANAGER                           ${NC}"
    echo -e "${BIBlue}==============================================================${NC}"

    echo -e "  ${BICyan}OS       :${NC} $OS_NAME"
    echo -e "  ${BICyan}IP VPS   :${NC} $IPVPS"
    echo -e "  ${BICyan}ISP      :${NC} $ISP"
    echo -e "  ${BICyan}Negara   :${NC} $COUNTRY"
    echo -e "  ${BICyan}Kota     :${NC} $CITY"
    echo -e "  ${BICyan}Domain   :${NC} $DOMAIN"

    echo -e "${BIBlue}--------------------------------------------------------------${NC}"
    echo -e "  ${BIWhite}JUMLAH AKUN TERDAFTAR${NC}"
    echo -e "  ALLPROTO : ${BIGreen}$COUNT_ALL${NC}"
    echo -e "  VLESS    : ${BIGreen}$COUNT_VLESS${NC}"
    echo -e "  VMESS    : ${BIGreen}$COUNT_VMESS${NC}"
    echo -e "  TROJAN   : ${BIGreen}$COUNT_TROJAN${NC}"

    echo -e "${BIBlue}--------------------------------------------------------------${NC}"
    echo -e "  ${BIPurple}Credit: Dibuat oleh Gemini AI ✨${NC}"
    echo -e "${BIBlue}==============================================================${NC}"
}

function show_existing_users() {
    local filter_suffix=$1
    local title_suffix=""

    if [[ -n "$filter_suffix" ]]; then
        title_suffix="(Filter: $filter_suffix)"
    else
        title_suffix="(All Users)"
    fi

    echo -e "\n${BIYellow}--- Daftar User Aktif $title_suffix ---${NC}"
    echo -e "${BIBlue}+------+------------------------------+${NC}"
    echo -e "${BIBlue}| ${BIWhite}NO   ${BIBlue}| ${BIWhite}USERNAME                     ${BIBlue}|${NC}"
    echo -e "${BIBlue}+------+------------------------------+${NC}"

    if [[ -n "$filter_suffix" ]]; then
        users=$(grep -o '"email": "[^"]*' "$CONFIG" | cut -d'"' -f4 | sort | uniq | grep -vE '^user@(vless|vmess|trojan)-(ws|hu|grpc)$' | grep "$filter_suffix")
    else
        users=$(grep -o '"email": "[^"]*' "$CONFIG" | cut -d'"' -f4 | sort | uniq | grep -vE '^user@(vless|vmess|trojan)-(ws|hu|grpc)$')
    fi

    local count=1
    if [[ -z "$users" ]]; then
        echo -e "${BIBlue}| ${BIRed}NULL ${BIBlue}| ${BIWhite}Tidak ada user ditemukan     ${BIBlue}|${NC}"
    else
        while IFS= read -r user; do
            if [[ -n "$user" ]]; then
                printf "${BIBlue}| ${BIGreen}%-4s ${BIBlue}| ${BIWhite}%-28s ${BIBlue}|${NC}\n" "$count" "$user"
                ((count++))
            fi
        done <<<"$users"
    fi
    echo -e "${BIBlue}+------+------------------------------+${NC}"
}

function check_user_exists() {
    local user=$1
    if grep -q "\"email\": \"$user\"" "$CONFIG"; then
        return 0 # Ada
    else
        return 1 # Tidak ada
    fi
}

function restart_system() {
    systemctl restart xray
}

function bytes_to_human() {
    local b=${1:-0}
    local d=''
    local s=0
    local S=(Bytes KB MB GB TB)
    while ((b > 1024)); do
        d=$(printf ".%02d" $((b % 1024 * 100 / 1024)))
        b=$((b / 1024))
        let s++
    done
    echo "$b$d ${S[$s]}"
}

function generate_and_save() {
    local user=$1
    local uuid=$2
    local exp=$3
    local quota=$4 # Input dalam GB
    local type=$5 # all, vless, vmess, trojan
    local path_dir=$6

    # 1. Kalkulasi Data Metadata
    local created_at=$(date +%Y-%m-%d)
    local expired_at=$(date -d "+${exp} days" +%Y-%m-%d)
    
    # Quota input: dalam GB (0 = Unlimited)
    local quota_bytes=0
    local quota_display="Unlimited"
    if [[ -n "$quota" && "$quota" != "0" ]]; then
        quota_bytes=$(($quota * 1073741824))
        quota_display="${quota} GB"
    fi

    # 2. Simpan Metadata ke JSON (/opt/quota/protocol/user.json)
    # Tentukan direktori quota berdasarkan tipe/path
    local protocol_dir=""
    case $type in
        all) protocol_dir="allproto" ;;
        vless) protocol_dir="vless" ;;
        vmess) protocol_dir="vmess" ;;
        trojan) protocol_dir="trojan" ;;
        *) protocol_dir="$type" ;;
    esac

    local quota_dir="/opt/quota/${protocol_dir}"
    mkdir -p "$quota_dir"
    local json_file="${quota_dir}/${user}.json"

    # Tulis JSON
    jq -n \
        --arg u "$user" \
        --arg p "$protocol_dir" \
        --argjson l "$quota_bytes" \
        --arg c "$created_at" \
        --arg e "$expired_at" \
        '{
            username: $u,
            protocol: $p,
            quota_limit: $l,
            created_at: $c,
            expired_at: $e
        }' > "$json_file"

    # 3. Generate Link Config (Sama seperti sebelumnya)
    # Base Links
    local link_vless_ws="vless://${uuid}@${DOMAIN}:443?security=tls&encryption=none&type=ws&path=%2Fvless-ws#${user}"
    local link_trojan_ws="trojan://${uuid}@${DOMAIN}:443?security=tls&type=ws&path=%2Ftrojan-ws#${user}"

    local vmess_json=$(jq -n \
        --arg v "2" --arg ps "$user" --arg add "$DOMAIN" --arg port "443" --arg id "$uuid" \
        --arg aid "0" --arg scy "auto" --arg net "ws" --arg type "none" --arg host "$DOMAIN" \
        --arg path "/vmess-ws" --arg tls "tls" --arg sni "$DOMAIN" '$ARGS.named')
    local link_vmess_ws="vmess://$(echo -n "$vmess_json" | base64 -w 0)"

    local link_vless_grpc="vless://${uuid}@${DOMAIN}:443?security=tls&encryption=none&type=grpc&serviceName=vless-grpc&mode=gun#${user}"
    local link_trojan_grpc="trojan://${uuid}@${DOMAIN}:443?security=tls&type=grpc&serviceName=trojan-grpc&mode=gun#${user}"

    local vmess_grpc_json=$(jq -n \
        --arg v "2" --arg ps "$user" --arg add "$DOMAIN" --arg port "443" --arg id "$uuid" \
        --arg aid "0" --arg scy "auto" --arg net "grpc" --arg type "none" --arg host "$DOMAIN" \
        --arg path "vmess-grpc" --arg tls "tls" --arg sni "$DOMAIN" '$ARGS.named')
    local link_vmess_grpc="vmess://$(echo -n "$vmess_grpc_json" | base64 -w 0)"

    local link_vless_hu="vless://${uuid}@${DOMAIN}:443?security=tls&encryption=none&type=httpupgrade&path=%2Fvless-hu#${user}"

    local vmess_hu_json=$(jq -n \
        --arg v "2" --arg ps "$user" --arg add "$DOMAIN" --arg port "443" --arg id "$uuid" \
        --arg aid "0" --arg scy "auto" --arg net "httpupgrade" --arg type "none" --arg host "$DOMAIN" \
        --arg path "/vmess-hu" --arg tls "tls" --arg sni "$DOMAIN" '$ARGS.named')
    local link_vmess_hu="vmess://$(echo -n "$vmess_hu_json" | base64 -w 0)"

    local link_trojan_hu="trojan://${uuid}@${DOMAIN}:443?security=tls&type=httpupgrade&path=%2Ftrojan-hu#${user}"

    # 4. Build Output TXT (Tampilkan quota dalam GB)
    local output_text=""

    output_text+="==================================================\n"
    output_text+="           XRAY ACCOUNT DETAIL ($type)\n"
    output_text+="==================================================\n"
    output_text+="Domain     : ${DOMAIN}\n"
    output_text+="IP         : ${IPVPS}\n"
    output_text+="Username   : ${user}\n"
    output_text+="UUID/Pass  : ${uuid}\n"
    output_text+="QuotaLimit : ${quota_display}\n"
    output_text+="Expired    : ${exp} Hari\n"
    output_text+="ValidUntil : ${expired_at}\n"
    output_text+="Created    : $(date)\n"
    output_text+="==================================================\n"

    if [[ "$type" == "all" || "$type" == "vless" ]]; then
        output_text+="[VLESS]\n"
        output_text+="WebSocket  : ${link_vless_ws}\n"
        output_text+="HTTPUpgrade: ${link_vless_hu}\n"
        output_text+="gRPC       : ${link_vless_grpc}\n"
        output_text+="--------------------------------------------------\n"
    fi

    if [[ "$type" == "all" || "$type" == "vmess" ]]; then
        output_text+="[VMESS]\n"
        output_text+="WebSocket  : ${link_vmess_ws}\n"
        output_text+="HTTPUpgrade: ${link_vmess_hu}\n"
        output_text+="gRPC       : ${link_vmess_grpc}\n"
        output_text+="--------------------------------------------------\n"
    fi

    if [[ "$type" == "all" || "$type" == "trojan" ]]; then
        output_text+="[TROJAN]\n"
        output_text+="WebSocket  : ${link_trojan_ws}\n"
        output_text+="HTTPUpgrade: ${link_trojan_hu}\n"
        output_text+="gRPC       : ${link_trojan_grpc}\n"
        output_text+="--------------------------------------------------\n"
    fi

    output_text+="=================================================="

    echo -e "$output_text" >"${path_dir}/${user}.txt"
    echo -e "\n${BIGreen}Detail Akun tersimpan di: ${path_dir}/${user}.txt${NC}"
    echo -e "${BIGreen}Metadata Quota tersimpan di: ${json_file}${NC}"
    echo -e "$output_text"
}

# ==========================================
# 2. LOGIC FUNCTIONS (SUB-MENUS FIRST)
# ==========================================

# --- ADGUARD HOME LOGIC (UPDATED) ---
function info_adguard() {
    show_header
    echo -e "${BIYellow}>> INFO ADGUARD HOME${NC}"
    echo -e "${BIBlue}--------------------------------------------------------------${NC}"
    if systemctl is-active --quiet AdGuardHome; then
        echo -e "   Status Service : ${BIGreen}RUNNING (AKTIF)${NC}"
        echo -e "   Akses Web Panel:"
        echo -e "   - URL          : ${BICyan}http://${DOMAIN}/aghome/${NC}"
        echo -e "   - Setup Awal   : Silakan buka URL diatas untuk konfigurasi awal"
        echo -e "   - Port DNS     : 53 (UDP/TCP)"
    else
        echo -e "   Status Service : ${BIRed}NOT RUNNING / NOT INSTALLED${NC}"
    fi
    echo -e "${BIBlue}--------------------------------------------------------------${NC}"
    read -n 1 -s -r -p "   Tekan sembarang tombol untuk kembali..."
    adguard_manager
}

function install_adguard() {
    show_header
    echo -e "${BIYellow}>> INSTALL ADGUARD HOME${NC}"
    echo -e "${BIBlue}--------------------------------------------------------------${NC}"

    if systemctl is-active --quiet AdGuardHome; then
        echo -e "   ${BIGreen}AdGuard Home sudah terinstall!${NC}"
        read -n 1 -s -r -p "   Tekan sembarang tombol..."
        adguard_manager
        return
    fi

    echo -e "   Memulai proses instalasi... Mohon tunggu."

    # 1. Fix Port 53 Conflict (Gold Standard)
    echo -e "   ${BICyan}[1/4] Mengatasi konflik Port 53 (systemd-resolved)...${NC}"
    mkdir -p /etc/systemd/resolved.conf.d
    cat >/etc/systemd/resolved.conf.d/adguardhome.conf <<EOF
[Resolve]
DNS=127.0.0.1
DNSStubListener=no
EOF
    if [ -f "/etc/resolv.conf" ]; then
        mv /etc/resolv.conf /etc/resolv.conf.backup
    fi
    ln -s /run/systemd/resolve/resolv.conf /etc/resolv.conf
    systemctl reload-or-restart systemd-resolved

    # 2. Download & Install AGH (Fixed Path Logic)
    echo -e "   ${BICyan}[2/4] Mengunduh AdGuard Home...${NC}"

    # Hapus sisa instalasi lama jika ada
    rm -rf /opt/AdGuardHome

    # Buat direktori baru
    mkdir -p /opt/AdGuardHome

    # Masuk ke direktori
    cd /opt/AdGuardHome || {
    echo -e "${BIRed}Direktori AdGuardHome tidak ditemukan!${NC}"
    sleep 2
    adguard_manager
    return
    }

    # Unduh & Ekstrak
    if curl -s -L https://static.adguard.com/adguardhome/release/AdGuardHome_linux_amd64.tar.gz -o AdGuardHome.tar.gz; then
        tar -xzf AdGuardHome.tar.gz
        rm AdGuardHome.tar.gz

        # Note: tar.gz akan menghasilkan folder 'AdGuardHome' di dalam /opt/AdGuardHome
        # Jadi path binarynya ada di: /opt/AdGuardHome/AdGuardHome/AdGuardHome
        
        # Validasi keberadaan binary
        if [ -f "/opt/AdGuardHome/AdGuardHome/AdGuardHome" ]; then
            chmod +x /opt/AdGuardHome/AdGuardHome/AdGuardHome
            echo -e "   Download berhasil."
        else
             echo -e "   ${BIRed}Gagal mengekstrak binary AdGuardHome!${NC}"
             read -n 1 -s -r -p "   Tekan sembarang tombol..."
             adguard_manager
             return
        fi
    else
        echo -e "   ${BIRed}Download gagal! Cek koneksi internet.${NC}"
        read -n 1 -s -r -p "   Tekan sembarang tombol..."
        adguard_manager
        return
    fi

    echo -e "   ${BICyan}[3/4] Menginstall Service...${NC}"
    
    # Install service sesuai path yang diminta
    sudo /opt/AdGuardHome/AdGuardHome/AdGuardHome -s install 2>/dev/null

    # 3. Setup Nginx Proxy
    echo -e "   ${BICyan}[4/4] Mengatur Nginx Reverse Proxy (/aghome/)...${NC}"

    if ! grep -q "location /aghome/" "$NGINX_CONF"; then
        # Menghapus kurung kurawal penutup terakhir
        sed -i '$d' "$NGINX_CONF"

        # Menambahkan blok location dan menutup kembali kurung kurawal
        cat >>"$NGINX_CONF" <<EOF

    location /aghome/ {
        proxy_pass http://127.0.0.1:3000/;
        proxy_redirect / /aghome/;
        proxy_cookie_path / /aghome/;
    }
}
EOF
        systemctl reload nginx
    fi
    
    # 4. Update Xray DNS agar menggunakan AdGuard Home (127.0.0.1)
    echo -e "   ${BICyan}[Extra] Mengupdate DNS Xray ke AdGuard Home (127.0.0.1)...${NC}"
    cp "$CONFIG" "${CONFIG}.bak"
    # Mengubah section dns.servers menjadi ["127.0.0.1", "localhost"]
    jq '.dns.servers = ["127.0.0.1", "localhost"]' "$CONFIG" > tmp_dns.json && mv tmp_dns.json "$CONFIG"
    systemctl restart xray

    # FIX: Script Python otomatis pemantau Port AdGuard (Background)
    # Mengganti script bash agh-fixer.sh dengan Python untuk parsing port yang lebih akurat
    cat > /tmp/agh-fixer.py << 'EOF'
#!/usr/bin/env python3
import time
import subprocess
import re
import os

NGINX_CONF_PATH = "/etc/nginx/conf.d/xray.conf"
MAX_LOOPS = 86400  # Monitor selama 1 Jam (86400 detik)

def get_agh_port():
    try:
        # Menjalankan ss -tulpn untuk mencari port AdGuardHome
        result = subprocess.check_output(["ss", "-tulpn"], text=True)
        lines = result.splitlines()
        for line in lines:
            if "AdGuardHome" in line:
                # Mengabaikan port 53 (DNS)
                parts = line.split()
                # Kolom ke-5 biasanya alamat:port
                address_port = parts[4]
                if ":" in address_port:
                    port = address_port.split(":")[-1]
                    if port != "53":
                        return port
    except Exception:
        pass
    return None

def get_nginx_current_port():
    try:
        if os.path.exists(NGINX_CONF_PATH):
            with open(NGINX_CONF_PATH, "r") as f:
                content = f.read()
                # Regex mencari proxy_pass http://127.0.0.1:(PORT)/; di dalam blok /aghome/
                match = re.search(r"location /aghome/ \{.*?proxy_pass http://127\.0\.0\.1:(\d+)/;", content, re.DOTALL)
                if match:
                    return match.group(1)
    except Exception:
        pass
    return None

def update_nginx(old_port, new_port):
    try:
        with open(NGINX_CONF_PATH, "r") as f:
            content = f.read()
        
        # Ganti port lama dengan port baru
        new_content = content.replace(f"127.0.0.1:{old_port}", f"127.0.0.1:{new_port}")
        
        with open(NGINX_CONF_PATH, "w") as f:
            f.write(new_content)
            
        subprocess.run(["systemctl", "reload", "nginx"], check=True)
        return True
    except Exception:
        return False

def main():
    count = 0
    while count < MAX_LOOPS:
        real_port = get_agh_port()
        if real_port:
            current_nginx_port = get_nginx_current_port()
            
            # Jika port Nginx belum diset atau berbeda dengan port asli AGH
            if current_nginx_port and real_port != current_nginx_port:
                if update_nginx(current_nginx_port, real_port):
                    # Hapus script diri sendiri setelah sukses (opsional)
                    try:
                        os.remove("/tmp/agh-fixer.py")
                    except:
                        pass
                    return # Exit sukses
        
        time.sleep(1) # Interval cek 1 detik
        count += 1    # Increment 1 detik

if __name__ == "__main__":
    main()
EOF
    chmod +x /tmp/agh-fixer.py
    nohup python3 /tmp/agh-fixer.py >/dev/null 2>&1 &

    echo -e "\n   ${BIGreen}[SUKSES] AdGuard Home berhasil diinstall!${NC}"
    echo -e "   Akses Panel di: http://${DOMAIN}/aghome/"

    read -n 1 -s -r -p "   Tekan sembarang tombol untuk kembali..."
    adguard_manager
}

function uninstall_adguard() {
    show_header
    echo -e "${BIYellow}>> UNINSTALL ADGUARD HOME${NC}"
    echo -e "${BIBlue}--------------------------------------------------------------${NC}"

    echo -e "   Apakah Anda yakin ingin menghapus AdGuard Home?"
    read -p "   Lanjut? (y/n): " confirm
    if [[ "$confirm" != "y" ]]; then
        adguard_manager
        return
    fi

    echo -e "\n   ${BICyan}[1/4] Menghapus Service...${NC}"
    if [ -f "/opt/AdGuardHome/AdGuardHome/AdGuardHome" ]; then
        sudo /opt/AdGuardHome/AdGuardHome/AdGuardHome -s stop 2>/dev/null
        sudo /opt/AdGuardHome/AdGuardHome/AdGuardHome -s uninstall 2>/dev/null
    fi
    rm -rf /opt/AdGuardHome

    echo -e "   ${BICyan}[2/4] Mengembalikan pengaturan DNS systemd...${NC}"
    rm -f /etc/systemd/resolved.conf.d/adguardhome.conf
    if [ -f "/etc/resolv.conf.backup" ]; then
        rm -f /etc/resolv.conf
        mv /etc/resolv.conf.backup /etc/resolv.conf
    fi
    systemctl reload-or-restart systemd-resolved

    echo -e "   ${BICyan}[3/4] Membersihkan konfigurasi Nginx...${NC}"
    echo -e "   ${BIYellow}Note: Path /aghome/ di Nginx masih ada (tidak berbahaya).${NC}"

    echo -e "   ${BICyan}[4/4] Mengembalikan DNS Xray ke default...${NC}"

    TMP_DNS_FILE="/tmp/tmp_dns.json"
    if jq '.dns.servers = ["https://dns.google/dns-query", "https://1.1.1.1/dns-query", "localhost"]' "$CONFIG" > "$TMP_DNS_FILE"; then
        mv "$TMP_DNS_FILE" "$CONFIG"
    else
        echo -e "   ${BIYellow}[WARNING] Gagal mengembalikan DNS Xray (jq error). Konfigurasi tidak diubah.${NC}"
    fi

    systemctl restart xray

    echo -e "\n   ${BIGreen}[SUKSES] AdGuard Home telah dihapus.${NC}"
    read -n 1 -s -r -p "   Tekan sembarang tombol untuk kembali..."
    adguard_manager
}

# --- WARP LOGIC ---
function check_warp_status() {
    show_header
    echo -e "${BIYellow}>> CEK STATUS WARP (WGCF/WIREPROXY)${NC}"
    echo -e "${BIBlue}--------------------------------------------------------------${NC}"

    local ip_vps=$(curl -s --connect-timeout 5 https://ifconfig.me)
    local warp_response=$(curl -s --connect-timeout 5 --socks5 127.0.0.1:40000 "http://ip-api.com/json/?fields=query,org")

    echo -e "   IP Asli VPS   : $ip_vps"

    if [[ -n "$warp_response" ]]; then
        local ip_warp=$(echo "$warp_response" | jq -r .query)
        local isp_warp=$(echo "$warp_response" | jq -r .org)

        echo -e "   IP via WARP   : ${BIGreen}$ip_warp${NC}"

        if [[ "$ip_vps" != "$ip_warp" ]]; then
            echo -e "\n   ${BIGreen}[STATUS: WORKING]${NC} Koneksi WARP berjalan dan IP berbeda."
            echo -e "   ISP WARP      : $isp_warp"
        else
            echo -e "\n   ${BIYellow}[STATUS: WARNING]${NC} IP sama dengan VPS. Routing mungkin belum efektif."
        fi
    else
        echo -e "   IP via WARP   : ${BIRed}Connection Failed${NC}"
        echo -e "\n   ${BIRed}[STATUS: ERROR]${NC} Tidak bisa terhubung ke WireProxy."
        echo -e "   Coba restart service wireproxy."
    fi

    echo -e "${BIBlue}--------------------------------------------------------------${NC}"
    read -n 1 -s -r -p "   Tekan sembarang tombol untuk kembali..."
    warp_manager
}

function warp_all() {
    show_header
    echo -e "${BIYellow}>> ATUR ROUTING WARP GLOBAL (SEMUA KONEKSI)${NC}"
    echo -e "${BIBlue}--------------------------------------------------------------${NC}"

    CURRENT_MODE=$(jq -r '.routing.rules[] | select(.port == "1-65535") | .outboundTag' "$CONFIG")

    if [[ "$CURRENT_MODE" == "warp" ]]; then
        STATUS="${BIGreen}ON (WARP)${NC}"
    else
        STATUS="${BIYellow}OFF (DIRECT)${NC}"
    fi

    echo -e "   Status Global WARP Saat Ini: $STATUS"
    echo -e "\n   [1] Aktifkan WARP Global (Semua trafik via WARP)"
    echo -e "   [2] Matikan WARP Global (Kembali ke Direct/IP VPS)"
    echo -e "   [0] Kembali"

    read -p "   Pilih: " opt

    TMP_JSON="/tmp/tmp.json"
    case $opt in
    1)
        cp "$CONFIG" "${CONFIG}.bak"
        jq '(.routing.rules[] | select(.port == "1-65535") | .outboundTag) = "warp"' "$CONFIG" >"$TMP_JSON" && mv "$TMP_JSON" "$CONFIG"
        restart_system
        echo -e "   ${BIGreen}[SUKSES] Semua trafik outbound kini melalui WARP!${NC}"
        ;;
    2)
        cp "$CONFIG" "${CONFIG}.bak"
        jq '(.routing.rules[] | select(.port == "1-65535") | .outboundTag) = "direct"' "$CONFIG" >"$TMP_JSON" && mv "$TMP_JSON" "$CONFIG"
        restart_system
        echo -e "   ${BIGreen}[SUKSES] Trafik outbound kembali ke Direct (IP VPS).${NC}"
        ;;
    0) warp_manager; return ;;
    esac

    read -n 1 -s -r -p "   Tekan sembarang tombol..."
    warp_manager
}

function warp_by_tag() {
    show_header
    echo -e "${BIYellow}>> ATUR ROUTING WARP BERDASARKAN TAG INBOUND${NC}"
    echo -e "${BIBlue}--------------------------------------------------------------${NC}"

    TAGS=("vless-ws" "vmess-ws" "trojan-ws" "vless-hu" "vmess-hu" "trojan-hu" "vless-grpc" "vmess-grpc" "trojan-grpc")
    CURRENT_TAGS=$(jq -r '.routing.rules[] | select(.outboundTag == "warp" and .inboundTag != null) | .inboundTag[]' $CONFIG)

    echo -e "   ${BIWhite}TAG             STATUS${NC}"
    echo -e "   -----------------------"

    i=1
    for tag in "${TAGS[@]}"; do
        if echo "$CURRENT_TAGS" | grep -q "$tag"; then
            status="${BIGreen}VIA WARP${NC}"
        else
            status="${BIYellow}DIRECT${NC}"
        fi
        # Menggunakan %b untuk kode warna
        printf "   [%d] %-12s : %b\n" "$i" "$tag" "$status"
        ((i++))
    done

    echo -e "${BIBlue}--------------------------------------------------------------${NC}"
    echo -e "   Ketik nomor tag untuk Toggle (ON/OFF), atau '0' untuk kembali."
    read -p "   Pilih: " opt

    TMP_JSON="/tmp/tmp.json"
    if [[ "$opt" == "0" ]]; then
        warp_manager
        return
    fi

    if [[ "$opt" =~ ^[1-9]$ ]]; then
        idx=$((opt - 1))
        SELECTED_TAG="${TAGS[$idx]}"

        echo -e "\n   ${BICyan}Mengubah status routing untuk $SELECTED_TAG ...${NC}"
        cp $CONFIG ${CONFIG}.bak

        if echo "$CURRENT_TAGS" | grep -q "$SELECTED_TAG"; then
            jq --arg tag "$SELECTED_TAG" '(.routing.rules[] | select(.outboundTag == "warp" and .inboundTag != null) | .inboundTag) -= [$tag]' $CONFIG >$TMP_JSON && mv $TMP_JSON $CONFIG
            jq --arg tag "$SELECTED_TAG" '(.routing.rules[] | select(.outboundTag == "direct" and .inboundTag != null) | .inboundTag) += [$tag]' $CONFIG >$TMP_JSON && mv $TMP_JSON $CONFIG
            echo -e "   ${BIGreen}[SUKSES] $SELECTED_TAG dipindahkan ke DIRECT.${NC}"
        else
            jq --arg tag "$SELECTED_TAG" '(.routing.rules[] | select(.outboundTag == "direct" and .inboundTag != null) | .inboundTag) -= [$tag]' $CONFIG >$TMP_JSON && mv $TMP_JSON $CONFIG
            jq --arg tag "$SELECTED_TAG" '(.routing.rules[] | select(.outboundTag == "warp" and .inboundTag != null) | .inboundTag) += [$tag]' $CONFIG >$TMP_JSON && mv $TMP_JSON $CONFIG
            echo -e "   ${BIGreen}[SUKSES] $SELECTED_TAG dipindahkan ke WARP.${NC}"
        fi
        restart_system
    else
        echo -e "   ${BIRed}Pilihan tidak valid!${NC}"
    fi

    read -n 1 -s -r -p "   Tekan sembarang tombol..."
    warp_by_tag
}

function warp_by_user() {
    show_header
    echo -e "${BIYellow}>> ATUR ROUTING WARP BERDASARKAN USERNAME${NC}"
    echo -e "${BIBlue}--------------------------------------------------------------${NC}"

    WARP_USERS=$(jq -r '.routing.rules[] | select(.outboundTag == "warp" and .user != null) | .user[]' $CONFIG)
    ALL_USERS=$(grep -o '"email": "[^"]*' $CONFIG | cut -d'"' -f4 | sort | uniq | grep -vE '^user@(vless|vmess|trojan)-(ws|hu|grpc)$')

    echo -e "   ${BIWhite}USERNAME                     STATUS${NC}"
    echo -e "   ---------------------------------------"

    if (( ${#USER_ARRAY[@]} == 0 )); then
    echo -e "${BIRed}Tidak ada user tersedia.${NC}"
    sleep 1
    warp_manager
    return
    fi

    i=1
    for user in "${USER_ARRAY[@]}"; do
        if [[ -z "$user" ]]; then continue; fi
        if echo "$WARP_USERS" | grep -q "$user"; then
            status="${BIGreen}VIA WARP${NC}"
        else
            status="${BIYellow}DIRECT${NC}"
        fi
        printf "   [%2d] %-25s : %b\n" "$i" "$user" "$status"
        ((i++))
    done

    echo -e "${BIBlue}--------------------------------------------------------------${NC}"
    echo -e "   Ketik nomor user untuk Toggle (ON/OFF), atau '0' untuk kembali."
    read -p "   Pilih: " opt
    
    # 1️⃣ cek kembali dulu
    if [[ "$opt" == "0" ]]; then
        warp_manager
        return
    fi
    
    # 2️⃣ validasi angka
    if [[ ! "$opt" =~ ^[0-9]+$ ]]; then
        echo -e "${BIRed}Input harus angka!${NC}"
        sleep 1
        warp_manager
        return
    fi
    
    # 3️⃣ validasi range
    idx=$((opt - 1))
    if (( idx < 0 || idx >= ${#USER_ARRAY[@]} )); then
        echo -e "${BIRed}Pilihan di luar daftar!${NC}"
        sleep 1
        warp_manager
        return
    fi
    
    # 4️⃣ baru aman dipakai
    SELECTED_USER="${USER_ARRAY[$idx]}"

    if [[ -n "$SELECTED_USER" ]]; then
        echo -e "\n   ${BICyan}Mengubah status routing untuk user: $SELECTED_USER ...${NC}"
        cp $CONFIG ${CONFIG}.bak

        if echo "$WARP_USERS" | grep -q "$SELECTED_USER"; then
            jq --arg u "$SELECTED_USER" '(.routing.rules[] | select(.outboundTag == "warp" and .user != null) | .user) -= [$u]' $CONFIG >$TMP_JSON && mv $TMP_JSON $CONFIG
            jq --arg u "$SELECTED_USER" '(.routing.rules[] | select(.outboundTag == "direct" and .user != null) | .user) += [$u]' $CONFIG >$TMP_JSON && mv $TMP_JSON $CONFIG
            echo -e "   ${BIGreen}[SUKSES] User $SELECTED_USER dipindahkan ke DIRECT.${NC}"
        else
            jq --arg u "$SELECTED_USER" '(.routing.rules[] | select(.outboundTag == "direct" and .user != null) | .user) -= [$u]' $CONFIG >$TMP_JSON && mv $TMP_JSON $CONFIG
            jq --arg u "$SELECTED_USER" '(.routing.rules[] | select(.outboundTag == "warp" and .user != null) | .user) += [$u]' $CONFIG >$TMP_JSON && mv $TMP_JSON $CONFIG
            echo -e "   ${BIGreen}[SUKSES] User $SELECTED_USER dipindahkan ke WARP.${NC}"
        fi
        restart_system
    else
        echo -e "   ${BIRed}User tidak ditemukan!${NC}"
    fi

    read -n 1 -s -r -p "   Tekan sembarang tombol..."
    warp_by_user
}

function warp_by_geosite() {
    show_header
    echo -e "${BIYellow}>> ATUR ROUTING WARP BERDASARKAN GEOSITE${NC}"
    echo -e "${BIBlue}--------------------------------------------------------------${NC}"

    CURRENT_MODE=$(jq -r '.routing.rules[] | select(.domain != null and (.domain[] | contains("geosite:netflix"))) | .outboundTag' $CONFIG | head -1)

    if [[ "$CURRENT_MODE" == "warp" ]]; then
        STATUS="${BIGreen}ON (WARP)${NC}"
    else
        STATUS="${BIYellow}OFF (DIRECT)${NC}"
    fi

    echo -e "   Daftar Geosite: Netflix, Google, OpenAI, Spotify, Meta, Reddit, Apple"
    echo -e "   Status Routing Saat Ini: $STATUS"
    echo -e ""
    echo -e "   [1] Route Geosite via WARP (Unlock Streaming/AI)"
    echo -e "   [2] Route Geosite via DIRECT"
    echo -e "   [0] Kembali"

    read -p "   Pilih: " opt

    TMP_JSON="/tmp/tmp.json"
    case $opt in
    1)
        echo -e "\n   ${BICyan}Mengaktifkan WARP untuk Geosite...${NC}"
        cp $CONFIG ${CONFIG}.bak
        jq '(.routing.rules[] | select(.domain != null and (.domain[] | contains("geosite:netflix"))) | .outboundTag) = "warp"' $CONFIG >$TMP_JSON && mv $TMP_JSON $CONFIG
        restart_system
        echo -e "   ${BIGreen}[SUKSES] Geosite Streaming/AI kini via WARP!${NC}"
        ;;
    2)
        echo -e "\n   ${BICyan}Mengembalikan Geosite ke Direct...${NC}"
        cp $CONFIG ${CONFIG}.bak
        jq '(.routing.rules[] | select(.domain != null and (.domain[] | contains("geosite:netflix"))) | .outboundTag) = "direct"' $CONFIG >$TMP_JSON && mv $TMP_JSON $CONFIG
        restart_system
        echo -e "   ${BIGreen}[SUKSES] Geosite Streaming/AI kini via DIRECT.${NC}"
        ;;
    0)
        warp_manager
        return
        ;;
    *)
        echo -e "   ${BIRed}Pilihan salah!${NC}"
        ;;
    esac

    read -n 1 -s -r -p "   Tekan sembarang tombol..."
    warp_by_geosite
}

# --- BACKUP RESTORE LOGIC ---
function input_telegram_bot_token() {
    show_header
    echo -e "${BIYellow}>> INPUT TOKEN BOT TELEGRAM${NC}"
    echo -e "${BIBlue}--------------------------------------------------------------${NC}"
    read -p "Masukkan BOT TOKEN Telegram : " BOT_TOKEN

    if [[ -z "$BOT_TOKEN" ]]; then
        echo -e "   ${BIRed}Token tidak boleh kosong.${NC}"
        read -n 1 -s -r -p "Tekan tombol apapun untuk kembali..."
        telegram_backup_manager
        return
    fi

    # Simpan token
    echo "$BOT_TOKEN" > "$TG_TOKEN_FILE"
    chmod 600 "$TG_TOKEN_FILE"

    # Aktifkan dan jalankan service bot otomatis
    systemctl enable "$TG_SERVICE" >/dev/null 2>&1
    systemctl restart "$TG_SERVICE" >/dev/null 2>&1

    echo
    echo -e "   ${BIGreen}Token bot berhasil disimpan.${NC}"
    echo -e "   ${BIGreen}Telegram bot service otomatis dijalankan.${NC}"
    echo -e "   ${BIYellow}Silakan buka bot Telegram dan ketik /start${NC}"
    read -n 1 -s -r -p "Tekan tombol apapun untuk kembali..."
    telegram_backup_manager
}

function delete_telegram_bot_token() {
    clear
    echo -e "${BIBlue}======================================${NC}"
    echo -e "${BIYellow}DELETE TOKEN BOT TELEGRAM${NC}"
    echo -e "${BIBlue}======================================${NC}"

    # Hapus token bot
    > "$TG_TOKEN_FILE"

    # Hapus chat id admin
    > "$TG_BASE/admin.conf"

    # Stop dan disable service bot
    systemctl stop "$TG_SERVICE" >/dev/null 2>&1
    systemctl disable "$TG_SERVICE" >/dev/null 2>&1

    echo
    echo -e "   ${BIGreen}Token bot berhasil dihapus.${NC}"
    echo -e "   ${BIGreen}Chat ID admin berhasil dihapus.${NC}"
    echo -e "   ${BIGreen}Service bot dihentikan dan dinonaktifkan.${NC}"
    echo
    echo -e "   ${BIYellow}Bot kembali ke kondisi awal.${NC}"
    read -n 1 -s -r -p "Tekan tombol apapun untuk kembali..."
    telegram_backup_manager
}

function start_telegram_bot() {
    show_header
    echo -e "   ${BIGreen}START TELEGRAM BOT${NC}"

    if [[ ! -s "$TG_TOKEN_FILE" ]]; then
        echo -e "   ${BIRed}Token bot belum diinput.${NC}"
        read -n 1 -s -r
        telegram_backup_manager
        return
    fi

    systemctl enable --now "$TG_SERVICE"

    echo
    echo -e "   ${BIGreen}Telegram bot service berhasil dijalankan.${NC}"
    read -n 1 -s -r -p "Tekan tombol apapun untuk kembali..."
    telegram_backup_manager
}

function stop_telegram_bot() {
    clear
    echo -e "${BIBlue}======================================${NC}"
    echo -e "${BIYellow}STOP TELEGRAM BOT${NC}"
    echo -e "${BIBlue}======================================${NC}"

    systemctl stop "$TG_SERVICE"

    echo
    echo -e "${BIGreen}Telegram bot service dihentikan.${NC}"
    read -n 1 -s -r -p "Tekan tombol apapun untuk kembali..."
    telegram_backup_manager
}

function status_telegram_bot() {
    clear
    echo -e "${BIBlue}======================================${NC}"
    echo -e " ${BIYellow}STATUS TELEGRAM BOT${NC} "
    echo -e "${BIBlue}======================================${NC}"

    journalctl -u "$TG_SERVICE" --no-pager -l

    echo
    read -n 1 -s -r -p "Tekan tombol apapun untuk kembali..."
    telegram_backup_manager
}

# --- QUOTA SUB-FUNCTIONS ---
function quota_check_usage() {
    echo -e "\n   ${BICyan}Mengambil data statistik dari Xray...${NC}"
    local STATS_DATA=$(xray api statsquery --server=127.0.0.1:10080)

    echo -e "${BIBlue}+----+-----------------+----------+--------------+--------------+--------------+-----------------+${NC}"
    echo -e "${BIBlue}| ${BIWhite}NO ${BIBlue}| ${BIWhite}USERNAME        ${BIBlue}| ${BIWhite}TIPE     ${BIBlue}| ${BIWhite}TERPAKAI     ${BIBlue}| ${BIWhite}LIMIT        ${BIBlue}| ${BIWhite}SISA         ${BIBlue}| ${BIWhite}EXPIRED         ${BIBlue}|${NC}"
    echo -e "${BIBlue}+----+-----------------+----------+--------------+--------------+--------------+-----------------+${NC}"

    num=1
    # Ubah pencarian dari .txt ke .json untuk mendapatkan limit
    found_files=$(find /opt/quota -name "*.json" | sort)

    if [[ -z "$found_files" ]]; then
        echo -e "${BIBlue}| ${BIRed}NULL ${BIBlue}| ${BIWhite}Belum ada user terdaftar.                                                      ${BIBlue}|${NC}"
    else
        while read filepath; do
            user=$(jq -r '.username' "$filepath")
            protocol=$(jq -r '.protocol' "$filepath")
            limit_bytes=$(jq -r '.quota_limit' "$filepath")
            exp_info=$(jq -r '.expired_at' "$filepath")
            
            type=$(echo "$protocol" | tr '[:lower:]' '[:upper:]')

            if [[ -n "$user" ]]; then
                up=$(echo "$STATS_DATA" | jq -r ".stat[] | select(.name == \"user>>>${user}>>>traffic>>>uplink\") | .value" 2>/dev/null)
                down=$(echo "$STATS_DATA" | jq -r ".stat[] | select(.name == \"user>>>${user}>>>traffic>>>downlink\") | .value" 2>/dev/null)
                up=${up:-0}
                down=${down:-0}
                total=$(($up + $down))

                used_human=$(bytes_to_human $total)

                if [[ "$limit_bytes" == "0" || "$limit_bytes" == "null" ]]; then
                    limit_human="Unlimited"
                    sisa_human="∞"
                else
                    limit_human=$(bytes_to_human $limit_bytes)
                    sisa_bytes=$(($limit_bytes - $total))
                    if [[ $sisa_bytes -lt 0 ]]; then sisa_bytes=0; fi
                    sisa_human=$(bytes_to_human $sisa_bytes)
                fi

                printf "${BIBlue}| ${BIGreen}%-2s ${BIBlue}| ${BIWhite}%-15s ${BIBlue}| ${BIYellow}%-8s ${BIBlue}| ${BIWhite}%-12s ${BIBlue}| ${BIGreen}%-12s ${BIBlue}| ${BICyan}%-12s ${BIBlue}| ${BIRed}%-15s ${BIBlue}|${NC}\n" "$num" "${user:0:15}" "${type:0:8}" "$used_human" "$limit_human" "$sisa_human" "$exp_info"
                ((num++))
            fi
        done <<<"$found_files"
    fi
    echo -e "${BIBlue}+----+-----------------+----------+--------------+--------------+--------------+-----------------+${NC}"
    read -n 1 -s -r -p "   Tekan sembarang tombol untuk kembali..."
    quota_manager
}

function quota_resize() {
    show_existing_users
    echo -e "${BIBlue}--------------------------------------------------------------${NC}"
    echo -e "   (Ketik '0' untuk kembali)"
    read -p "   Masukkan Username (lengkap suffix): " user_input
    if [[ "$user_input" == "0" ]]; then
        quota_manager
        return
    fi
    if [[ -z "$user_input" ]]; then
        echo -e "${BIRed}Wajib diisi!${NC}"
        sleep 1
        quota_resize
        return
    fi
    
    # Cari File JSON Target
    target_json=$(find /opt/quota -name "${user_input}.json" | head -n 1)
    
    if [[ ! -f "$target_json" ]]; then
        echo -e "${BIRed}User Data (JSON) tidak ditemukan!${NC}"
        sleep 1
        quota_resize
        return
    fi
    
    echo -e "   (Ketik '0' untuk Unlimited)"
    read -p "   Masukkan Limit Baru (GB): " new_gb
    if [[ ! $new_gb =~ ^[0-9]+$ ]]; then
        echo -e "${BIRed}Input angka!${NC}"
        sleep 1
        quota_resize
        return
    fi
    
    local new_bytes="0"
    if [[ "$new_gb" != "0" ]]; then
        new_bytes=$(($new_gb * 1073741824))
    fi
    
    # Update JSON menggunakan jq
    local tmp_file="/tmp/quota_update.json"
    if jq --argjson lb "$new_bytes" '.quota_limit = $lb' "$target_json" > "$tmp_file"; then
    mv "$tmp_file" "$target_json"
    else
        echo -e "${BIRed}Gagal memproses JSON quota!${NC}"
        back_to_menu
        return
    fi
    
    echo -e "\n   ${BIGreen}[SUKSES] Limit kuota $user_input diubah menjadi $new_gb GB.${NC}"
    read -n 1 -s -r -p "   Tekan sembarang tombol..."
    quota_manager
}

function quota_reset() {
    show_existing_users
    
    echo -e "${BIBlue}--------------------------------------------------------------${NC}"
    echo -e "   (Ketik '0' untuk kembali)"
    read -p "   Masukkan Username (lengkap suffix): " user_input
    TMP_JSON="/tmp/tmp.json"
    if [[ "$user_input" == "0" ]]; then
        quota_manager
        return
    fi
    if [[ -z "$user_input" ]]; then
        echo -e "${BIRed}Wajib diisi!${NC}"
        sleep 1
        quota_reset
        return
    fi
    echo -e "   Mereset statistik..."
    xray api stats -server=127.0.0.1:10080 -name "user>>>${user_input}>>>traffic>>>uplink" -reset >/dev/null 2>&1
    xray api stats -server=127.0.0.1:10080 -name "user>>>${user_input}>>>traffic>>>downlink" -reset >/dev/null 2>&1
    echo -e "   Memastikan user tidak terblokir..."
    cp $CONFIG ${CONFIG}.bak
    if jq --arg u "$user_input" \
    '(.routing.rules[] 
     | select(.outboundTag == "blocked" 
     and .user != null 
     and (.user | contains(["dummy-quota-user"])) ) 
     | .user) -= [$u]' "$CONFIG" > "$TMP_JSON"; then
        mv "$TMP_JSON" "$CONFIG"
    else
        echo -e "${BIRed}Gagal memproses JSON config (quota unblock)!${NC}"
        back_to_menu
        return
    fi
    restart_system
    echo -e "\n   ${BIGreen}[SUKSES] Pemakaian kuota $user_input telah di-reset menjadi 0.${NC}"
    read -n 1 -s -r -p "   Tekan sembarang tombol..."
    quota_manager
}

# --- OTHER LOGIC (LOGS, RENEW, SSL, DOMAIN) ---
function check_system_logs() {
    show_header
    echo -e "${BIYellow}>> CEK LOG AKTIVITAS SISTEM${NC}"
    echo -e "${BIBlue}--------------------------------------------------------------${NC}"
    echo -e "  ${BIGreen}[1]${NC} Log Auto Expired (xray-expiry)"
    echo -e "  ${BIGreen}[2]${NC} Log Limit IP (xray-limit)"
    echo -e "  ${BIGreen}[3]${NC} Log Quota User (xray-quota)"
    echo -e "  ${BIGreen}[4]${NC} Log Akses Xray (General)"
    echo -e "  ${BIRed}[0]${NC} Kembali"
    read -p "  Pilih Menu: " opt
    case $opt in
    1) file="/var/log/xray/xp.log" ;;
    2) file="/var/log/xray/limit.log" ;;
    3) file="/var/log/xray/quota.log" ;;
    4) file="/var/log/xray/access.log" ;;
    0)
        show_menu
        return
        ;;
    *)
        echo -e "\n  ${BIRed}Pilihan tidak valid!${NC}"
        sleep 1
        check_system_logs
        return
        ;;
    esac

    if [[ -f "$file" ]]; then
        echo -e "\n  ${BICyan}Menampilkan 20 baris terakhir dari $file:${NC}"
        echo "------------------------------------------------"
        tail -n 20 "$file"
        echo "------------------------------------------------"
    else
        echo -e "\n  ${BIRed}File log belum tersedia atau kosong.${NC}"
    fi
    read -n 1 -s -r -p "  Tekan sembarang tombol untuk kembali..."
    check_system_logs
}

function check_user_login() {
    show_header
    echo -e "${BIYellow}>> CEK USER LOGIN (REALTIME LOG)${NC}"
    echo -e "${BIBlue}--------------------------------------------------------------${NC}"
    echo -e "   Mengambil data dari $LOG_ACCESS ..."
    if [[ -f "$LOG_ACCESS" ]]; then
        echo -e "${BIWhite}COUNT  | USERNAME${NC}"
        echo -e "-------+---------------------------"
        grep "accepted" "$LOG_ACCESS" | grep "email:" | awk -F'email:' '{print $2}' | awk '{print $1}' | sort | uniq -c | sort -nr | head -n 20
    else
        echo -e "${BIRed}File Log tidak ditemukan ($LOG_ACCESS)!${NC}"
    fi
    echo -e "${BIBlue}--------------------------------------------------------------${NC}"
    read -n 1 -s -r -p "   Tekan sembarang tombol untuk kembali..."
    show_menu
}

function renew_cert_ssl() {
    show_header
    echo -e "${BIYellow}>> PERBARUI SERTIFIKAT SSL${NC}"
    echo -e "${BIBlue}--------------------------------------------------------------${NC}"
    if [[ ! -f "/root/.acme.sh/acme.sh" ]]; then
        echo -e "   ${BIRed}[ERROR] Acme.sh tidak terinstall!${NC}"
        read -n 1 -s -r -p "Back..."
        show_menu
        return
    fi
    echo -e "   Domain Saat Ini: ${BIGreen}$DOMAIN${NC}"
    echo -e "   ${BICyan}Memproses pembaruan sertifikat... (Mohon tunggu)${NC}"
    if [[ "$DOMAIN" == *"vyxara1.qzz.io"* || "$DOMAIN" == *"vyxara2.qzz.io"* ]]; then
        export CF_Token="$CF_TOKEN"
        export CF_Account_ID=""
        "/root/.acme.sh/acme.sh" --issue --dns dns_cf -d "$DOMAIN" -d "*.$DOMAIN" --force >/dev/null 2>&1
    else
        systemctl stop nginx
        "/root/.acme.sh/acme.sh" --issue -d "$DOMAIN" --standalone --force >/dev/null 2>&1
        systemctl start nginx
    fi
    if [[ $? -eq 0 ]]; then
        "/root/.acme.sh/acme.sh" --install-cert -d "$DOMAIN" --fullchain-file /opt/ssl/fullchain.pem --key-file /opt/ssl/privkey.pem --reloadcmd "systemctl restart nginx" >/dev/null 2>&1
        echo -e "\n   ${BIGreen}[SUKSES] Sertifikat berhasil diperbarui!${NC}"
    else
        echo -e "\n   ${BIRed}[GAGAL] Terjadi kesalahan saat renew sertifikat.${NC}"
    fi
    echo -e ""
    read -n 1 -s -r -p "   Tekan sembarang tombol untuk kembali..."
    show_menu
}

function change_domain_setup() {
    show_header
    echo -e "${BIYellow}>> GANTI DOMAIN (RE-SETUP)${NC}"
    echo -e "${BIRed}   [PERINGATAN]${NC} Fitur ini akan mengganti konfigurasi Domain dan SSL."
    echo -e "${BIBlue}--------------------------------------------------------------${NC}"
    local NEW_DOMAIN=""
    local DOMAIN_MODE=""
    local OLD_DOMAIN=$DOMAIN
    local IS_PROXIED="false"

    while true; do
        echo -e "   Pilih metode setup domain baru:"
        echo -e "   1. Input Domain/Subdomain Sendiri (Custom)"
        echo -e "   2. Gunakan Domain Yang Disediakan (Cloudflare Auto)"
        echo -e "   0. Batal / Kembali"
        read -p "   Pilih (0-2): " DOMAIN_OPT

        if [[ "$DOMAIN_OPT" == "0" ]]; then
            show_menu
            return
        fi

        if [[ "$DOMAIN_OPT" == "1" ]]; then
            DOMAIN_MODE="custom"
            echo -e "\n   (Ketik '0' untuk kembali)"
            while true; do
                read -p "   Masukkan Domain Baru: " NEW_DOMAIN
                if [[ "$NEW_DOMAIN" == "0" ]]; then break 2; fi
                if [[ "$NEW_DOMAIN" =~ ^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]; then
                    echo -e "   ${BIGreen}Domain valid.${NC}"
                    echo -e "   Apakah subdomain ini ingin di-proxied (CDN) Cloudflare?"
                    read -p "   Pilih (y/n): " PROX_IN
                    if [[ "$PROX_IN" == "y" || "$PROX_IN" == "Y" ]]; then IS_PROXIED="true"; else IS_PROXIED="false"; fi
                    break 2
                else
                    echo -e "   ${BIRed}Format domain salah!${NC}"
                fi
            done
        elif [[ "$DOMAIN_OPT" == "2" ]]; then
            DOMAIN_MODE="cf"
            while true; do
                echo -e "\n   ${BIYellow}Pilih Domain Induk:${NC}"
                echo -e "   1. vyxara1.qzz.io"
                echo -e "   2. vyxara2.qzz.io"
                echo -e "   0. Kembali"
                read -p "   Pilih (0-2): " CF_HOST_OPT
                if [[ "$CF_HOST_OPT" == "0" ]]; then break; fi
                local BASE_DOMAIN=""
                case $CF_HOST_OPT in
                1) BASE_DOMAIN="vyxara1.qzz.io" ;;
                2) BASE_DOMAIN="vyxara2.qzz.io" ;;
                *)
                    echo -e "   ${BIRed}Pilihan salah.${NC}"
                    continue
                    ;;
                esac

                local ZONE_ID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=${BASE_DOMAIN}&status=active" -H "Authorization: Bearer ${CF_TOKEN}" -H "Content-Type: application/json" | jq -r .result[0].id)
                if [[ "$ZONE_ID" == "null" || -z "$ZONE_ID" ]]; then
                    echo -e "   ${BIRed}Gagal mendapatkan Zone ID.${NC}"
                    break
                fi

                while true; do
                    echo -e "\n   ${BIYellow}Pilih Nama Subdomain:${NC}"
                    echo -e "   1. Generate Acak (Random)"
                    echo -e "   2. Input Sendiri (Custom)"
                    echo -e "   0. Kembali"
                    read -p "   Pilih (0-2): " SUB_OPT
                    if [[ "$SUB_OPT" == "0" ]]; then break; fi
                    local SUB_PREFIX=""
                    if [[ "$SUB_OPT" == "1" ]]; then
                        SUB_PREFIX="vps-$(tr -dc a-z0-9 </dev/urandom | head -c 5)"
                        echo -e "   Subdomain acak: ${BIGreen}${SUB_PREFIX}${NC}"
                        echo -e "   Apakah subdomain ini ingin di-proxied (CDN) Cloudflare?"
                        read -p "   Pilih (y/n): " PROX_IN
                        if [[ "$PROX_IN" == "y" || "$PROX_IN" == "Y" ]]; then IS_PROXIED="true"; else IS_PROXIED="false"; fi
                    elif [[ "$SUB_OPT" == "2" ]]; then
                        echo -e "   (Ketik '0' untuk kembali)"
                        while true; do
                            read -p "   Masukkan nama subdomain (huruf/angka): " SUB_PREFIX
                            if [[ "$SUB_PREFIX" == "0" ]]; then break; fi
                            if [[ -z "$SUB_PREFIX" ]]; then
                                echo -e "   ${BIRed}Tidak boleh kosong!${NC}"
                                continue
                            fi
                            if [[ ! "$SUB_PREFIX" =~ ^[a-zA-Z0-9]+$ ]]; then
                                echo -e "   ${BIRed}Format salah!${NC}"
                                continue
                            fi

                            FULL_DOMAIN="${SUB_PREFIX}.${BASE_DOMAIN}"
                            echo -e "   Memeriksa ketersediaan subdomain..."
                            local CHECK_RECORD=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records?name=${FULL_DOMAIN}" -H "Authorization: Bearer ${CF_TOKEN}" -H "Content-Type: application/json")
                            local RECORD_COUNT=$(echo "$CHECK_RECORD" | jq -r .result_info.count)
                            if [[ "$RECORD_COUNT" -gt 0 ]]; then
                                local EXISTING_IP=$(echo "$CHECK_RECORD" | jq -r .result[0].content)
                                if [[ "$EXISTING_IP" == "$IPVPS" ]]; then
                                    echo -e "   ${BIYellow}Domain ini sudah terdaftar di IP VPS ini.${NC}"
                                    read -p "   Lanjut gunakan domain ini? (y/n): " PROCEED
                                    if [[ "$PROCEED" == "y" || "$PROCEED" == "Y" ]]; then
                                        echo -e "   Apakah subdomain ini ingin di-proxied (CDN) Cloudflare?"
                                        read -p "   Pilih (y/n): " PROX_IN
                                        if [[ "$PROX_IN" == "y" || "$PROX_IN" == "Y" ]]; then IS_PROXIED="true"; else IS_PROXIED="false"; fi
                                        break
                                    else continue; fi
                                else
                                    echo -e "   ${BIRed}Maaf, subdomain digunakan oleh IP lain.${NC}"
                                    continue
                                fi
                            else
                                echo -e "   ${GREEN}Subdomain tersedia!${NC}"
                                echo -e "   Apakah subdomain ini ingin di-proxied (CDN) Cloudflare?"
                                read -p "   Pilih (y/n): " PROX_IN
                                if [[ "$PROX_IN" == "y" || "$PROX_IN" == "Y" ]]; then IS_PROXIED="true"; else IS_PROXIED="false"; fi
                                break
                            fi
                        done
                        if [[ -z "$SUB_PREFIX" ]]; then continue; fi
                    else
                        echo -e "   ${BIRed}Pilihan salah.${NC}"
                        continue
                    fi

                    FULL_DOMAIN="${SUB_PREFIX}.${BASE_DOMAIN}"
                    echo -e "\n   ${BICyan}Memproses API Cloudflare...${NC}"
                    local RECORDS=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records?content=${IPVPS}" -H "Authorization: Bearer ${CF_TOKEN}" -H "Content-Type: application/json" | jq -r .result[].id)
                    for REC_ID in $RECORDS; do curl -s -X DELETE "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records/${REC_ID}" -H "Authorization: Bearer ${CF_TOKEN}" -H "Content-Type: application/json" >/dev/null; done
                    local RESP=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records" -H "Authorization: Bearer ${CF_TOKEN}" -H "Content-Type: application/json" --data '{"type":"A","name":"'${FULL_DOMAIN}'","content":"'${IPVPS}'","ttl":1,"proxied":'$IS_PROXIED'}')
                    local SUCC=$(echo $RESP | jq -r .success)
                    if [[ "$SUCC" == "true" ]]; then
                        echo -e "   ${BIGreen}Domain berhasil dibuat!${NC}"
                        NEW_DOMAIN=$FULL_DOMAIN
                        break 3
                    else
                        echo -e "   ${BIRed}Gagal membuat domain!${NC}"
                        echo -e "   Error: $(echo $RESP | jq -r .errors[0].message)"
                        break
                    fi
                done
            done
        else
            echo -e "   ${BIRed}Pilihan salah.${NC}"
        fi
    done

    echo -e "\n   ${BICyan}Menerapkan perubahan ke: $NEW_DOMAIN${NC}"
    sed -i "s/server_name.*/server_name $NEW_DOMAIN;/g" $NGINX_CONF
    DOMAIN=$NEW_DOMAIN
    echo -e "   Memperbarui Sertifikat SSL... (Mohon tunggu)"
    if [[ "$DOMAIN_MODE" == "custom" ]]; then
        systemctl stop nginx
        "/root/.acme.sh/acme.sh" --issue -d "$NEW_DOMAIN" --standalone --force >/dev/null 2>&1
        systemctl start nginx
    else
        export CF_Token="$CF_TOKEN"
        export CF_Account_ID=""
        "/root/.acme.sh/acme.sh" --issue --dns dns_cf -d "$NEW_DOMAIN" -d "*.$NEW_DOMAIN" --force >/dev/null 2>&1
    fi
    "/root/.acme.sh/acme.sh" --install-cert -d "$NEW_DOMAIN" --fullchain-file /opt/ssl/fullchain.pem --key-file /opt/ssl/privkey.pem --reloadcmd "systemctl restart nginx" >/dev/null 2>&1

    if [[ -n "$OLD_DOMAIN" && "$OLD_DOMAIN" != "IP-Address" ]]; then
        echo -e "   Memperbarui dan regenerate semua file akun yang ada..."
        DIRS="/opt/allproto /opt/vless /opt/vmess /opt/trojan"
        for dir in $DIRS; do
            if [[ -d "$dir" ]]; then
                case $(basename "$dir") in "allproto") type="all" ;; "vless") type="vless" ;; "vmess") type="vmess" ;; "trojan") type="trojan" ;; esac
                for file in "$dir"/*.txt; do
                    if [[ -f "$file" ]]; then
                        user=$(grep "Username" "$file" | cut -d: -f2 | tr -d ' ')
                        uuid=$(grep "UUID/Pass" "$file" | cut -d: -f2 | tr -d ' ')
                        exp=$(grep "Expired" "$file" | cut -d: -f2 | awk '{print $1}')
                        # Quota bisa format baru: "10 GB" atau format lama (bytes)
                        quota_line=$(grep -m1 "^QuotaLimit" "$file" | cut -d: -f2- | xargs)
                        quota_gb="0"
                        if [[ -n "$quota_line" ]]; then
                            if echo "$quota_line" | grep -qiE 'unlimited|tanpa|inf|∞'; then
                                quota_gb="0"
                            elif echo "$quota_line" | grep -qE '^[0-9]+$'; then
                                # Legacy: bytes
                                quota_gb=$(($quota_line / 1073741824))
                            elif echo "$quota_line" | grep -qiE '^[0-9]+[[:space:]]*gb$'; then
                                quota_gb=$(echo "$quota_line" | grep -oE '^[0-9]+')
                            else
                                tmp_num=$(echo "$quota_line" | grep -oE '^[0-9]+')
                                if [[ -n "$tmp_num" ]]; then quota_gb="$tmp_num"; fi
                            fi
                        fi
                        if [[ -n "$user" && -n "$uuid" ]]; then generate_and_save "$user" "$uuid" "$exp" "$quota_gb" "$type" "$dir" >/dev/null 2>&1; fi
                    fi
                done
            fi
        done
    fi
    restart_system
    echo -e "\n   ${BIGreen}[SUKSES] Domain server telah diganti!${NC}\n   Domain baru: $NEW_DOMAIN"
    read -n 1 -s -r -p "   Tekan sembarang tombol untuk kembali..."
    show_menu
}

function renew_user_account() {
    show_header
    echo -e "${BIYellow}>> PERPANJANG MASA AKTIF USER${NC}"
    show_existing_users
    echo -e "${BIBlue}--------------------------------------------------------------${NC}"
    echo -e "   (Ketik '0' untuk kembali)"
    read -p "   Masukkan Username (lengkap dengan suffix, misal: budi@vless): " user_input
    if [[ "$user_input" == "0" ]]; then
        show_menu
        return
    fi
    if [[ -z "$user_input" ]]; then
        echo -e "${BIRed}Username tidak boleh kosong!${NC}"
        sleep 1
        show_menu
        return
    fi
    
    # Target JSON dan TXT
    target_json=$(find /opt/quota -name "${user_input}.json" | head -n 1)
    target_txt=$(find /opt/allproto /opt/vless /opt/vmess /opt/trojan -name "${user_input}.txt" | head -n 1)

    if [[ ! -f "$target_json" ]]; then
        echo -e "\n${BIRed}[ERROR] Data User JSON tidak ditemukan!${NC}"
        read -n 1 -s -r -p "Tekan sembarang tombol..."
        return
    fi

    # Ambil expired saat ini dari JSON
    current_exp_date=$(jq -r '.expired_at' "$target_json")
    
    echo -e "   Expired Saat Ini : ${BIYellow}$current_exp_date${NC}"
    echo -e "   (Ketik '0' untuk kembali)"
    read -p "   Tambah Masa Aktif (hari) : " days_add
    if [[ "$days_add" == "0" ]]; then
        show_menu
        return
    fi
    if [[ ! $days_add =~ ^[0-9]+$ ]]; then
        echo -e "${BIRed}Input harus angka!${NC}"
        sleep 1
        show_menu
        return
    fi
    
    today=$(date +%Y-%m-%d)
    if [[ "$today" > "$current_exp_date" ]]; then base_date="$today"; else base_date="$current_exp_date"; fi
    new_exp_date=$(date -d "$base_date + $days_add days" +%Y-%m-%d)
    
    echo -e "\n   ${BICyan}Memperbarui data...${NC}"
    
    # 1. Update JSON
    tmp_json="/tmp/renew.json"
    jq --arg new_exp "$new_exp_date" '.expired_at = $new_exp' "$target_json" > "$tmp_json" && mv "$tmp_json" "$target_json"
    
    # 2. Update TXT (Visual Only) jika ada
    if [[ -f "$target_txt" ]]; then
        # Coba update baris ValidUntil jika ada, jika format lama
        sed -i "s/ValidUntil :.*/ValidUntil : $new_exp_date/g" "$target_txt"
    fi
    
    sleep 1
    echo -e "   ${BIGreen}[SUKSES] Masa aktif user '$user_input' diperpanjang!${NC}\n   Expired Baru     : ${BIGreen}$new_exp_date${NC}"
    read -n 1 -s -r -p "   Tekan sembarang tombol untuk kembali..."
    show_menu
}

function show_traffic_stats() {
    show_header
    echo -e "${BIYellow}>> MONITORING TRAFIK USER (XRAY API)${NC}"
    echo -e "${BIBlue}--------------------------------------------------------------${NC}"
    
    # Validasi keberadaan script helper
    if [[ ! -f "/usr/local/bin/xray-traffic" ]]; then
         echo -e "   ${BIRed}Error: Helper script 'xray-traffic' tidak ditemukan!${NC}"
         echo -e "   ${BIYellow}Harap jalankan ulang setup.sh atau buat file helper manual.${NC}"
    else
         # Menjalankan script python helper
         python3 /usr/local/bin/xray-traffic
    fi

    echo -e "${BIBlue}--------------------------------------------------------------${NC}"
    read -n 1 -s -r -p "   Tekan sembarang tombol untuk kembali..."
    show_menu
}

function configure_ip_limiter() {
    show_header
    echo -e "${BIYellow}>> LIMITASI IP (AUTO KILL MULTI-LOGIN)${NC}"
    echo -e "${BIBlue}--------------------------------------------------------------${NC}"
    CURRENT=$(cat /etc/xray/limit_ip 2>/dev/null || echo "2")
    if crontab -l 2>/dev/null | grep -q "xray-limit"; then STATUS_CRON="${BIGreen}[AKTIF]${NC}"; else STATUS_CRON="${BIRed}[NON-AKTIF]${NC}"; fi
    echo -e "   Status Auto Kill              : $STATUS_CRON"
    echo -e "   Batas Maksimal Login saat ini : ${BIGreen}${CURRENT} IP${NC}"
    echo -e "${BIBlue}--------------------------------------------------------------${NC}"
    echo -e "   [1] Ubah Batas IP (Max Login)"
    echo -e "   [2] Aktifkan Auto Kill (Pasang Cronjob)"
    echo -e "   [3] Matikan Auto Kill (Hapus Cronjob)"
    echo -e "   [4] Buka Blokir User (Unblock Manual)"
    echo -e "   [0] Kembali"
    read -p "   Pilih Menu : " lim_opt
    TMP_JSON="/tmp/tmp.json"
    case $lim_opt in
    1)
        echo -e "   (Ketik '0' untuk kembali)"
        read -p "   Masukkan Batas Baru (1-100): " new_lim
        if [[ "$new_lim" == "0" ]]; then
            configure_ip_limiter
            return
        fi
        if [[ "$new_lim" =~ ^[0-9]+$ ]] && [ "$new_lim" -gt 0 ]; then
            mkdir -p /etc/xray
            echo "$new_lim" >/etc/xray/limit_ip
            echo -e "   ${BIGreen}Berhasil! Batas diubah menjadi $new_lim IP.${NC}"
        else echo -e "   ${BIRed}Input tidak valid!${NC}"; fi
        ;;
    2)
        if [[ ! -f "/usr/local/bin/xray-limit" ]]; then
            echo -e "   ${BIRed}Error: Script backend 'xray-limit' tidak ditemukan!${NC}"
        else
            chmod +x /usr/local/bin/xray-limit
            (
                crontab -l 2>/dev/null | grep -v "xray-limit"
                echo "* * * * * /usr/local/bin/xray-limit"
            ) | crontab -
            echo -e "   ${BIGreen}Auto Kill Diaktifkan (Check setiap 1 menit)!${NC}"
        fi
        ;;
    3)
        (crontab -l 2>/dev/null | grep -v "xray-limit") | crontab -
        echo -e "   ${BIYellow}Auto Kill Dimatikan.${NC}"
        ;;
    4)
        echo -e "\n   ${BICyan}Daftar User yang Diblokir (Limit IP):${NC}"
        local blocked_users=$(jq -r '.routing.rules[] | select(.outboundTag == "blocked" and .user != null and (.user | contains(["dummy-limit-ip"]))) | .user[] | select(. != "dummy-limit-ip")' $CONFIG 2>/dev/null)
        if [[ -z "$blocked_users" ]]; then
            echo -e "   ${BIGreen}(Tidak ada user yang terkena limit IP)${NC}"
        else
            echo -e "$blocked_users" | nl -w2 -s'. '
            echo -e ""
            echo -e "   (Ketik '0' untuk kembali)"
            read -p "   Masukkan Username untuk di-unblock: " unblock_target
            if [[ "$unblock_target" == "0" ]]; then
                configure_ip_limiter
                return
            fi
            if [[ -n "$unblock_target" ]]; then
                if echo "$blocked_users" | grep -q "$unblock_target"; then
                    cp $CONFIG ${CONFIG}.bak
                    jq --arg u "$unblock_target" '(.routing.rules[] | select(.outboundTag == "blocked" and .user != null and (.user | contains(["dummy-limit-ip"])) ) | .user) -= [$u]' $CONFIG >$TMP_JSON && mv $TMP_JSON $CONFIG
                    restart_system
                    echo -e "   ${BIGreen}User $unblock_target telah dibuka blokirnya!${NC}"
                else echo -e "   ${BIRed}User tidak ditemukan di list blokir limit IP.${NC}"; fi
            fi
        fi
        ;;
    0)
        show_menu
        return
        ;;
    *) echo -e "   ${BIRed}Pilihan salah!${NC}" ;;
    esac
    sleep 1.5
    configure_ip_limiter
}

# ==========================================
# 3. MANAGER FUNCTIONS
# ==========================================

function quota_manager() {
    show_header
    echo -e "${BIYellow}>> MANAJEMEN KUOTA USER${NC}"
    echo -e "${BIBlue}--------------------------------------------------------------${NC}"
    echo -e "  ${BIGreen}[01]${NC} Cek Penggunaan Kuota User"
    echo -e "  ${BIGreen}[02]${NC} Ubah/Tambah Limit Kuota"
    echo -e "  ${BIGreen}[03]${NC} Reset Pemakaian Kuota (Top-up)"
    echo -e "${BIBlue}--------------------------------------------------------------${NC}"
    echo -e "  ${BIRed}[0]${NC}  Kembali ke Menu Utama"
    read -p "  Pilih Menu [0-3]: " q_opt
    case $q_opt in
    1) quota_check_usage ;;
    2) quota_resize ;;
    3) quota_reset ;;
    0)
        show_menu
        ;;
    *)
        echo -e "\n  ${BIRed}Pilihan tidak valid!${NC}" ;
        sleep 1 ;
        quota_manager
        ;;
    esac
}

function warp_manager() {
    show_header
    echo -e "${BIYellow}>> MANAJEMEN ROUTING WARP${NC}"
    echo -e "${BIBlue}--------------------------------------------------------------${NC}"
    echo -e "  ${BIGreen}[01]${NC} Routing: Semua Trafik via WARP (Global)"
    echo -e "  ${BIGreen}[02]${NC} Routing: Berdasarkan Tag Inbound (Proto/Transport)"
    echo -e "  ${BIGreen}[03]${NC} Routing: Berdasarkan Username"
    echo -e "  ${BIGreen}[04]${NC} Routing: Berdasarkan Geosite (Netflix, Google, dll)"
    echo -e "  ${BIGreen}[05]${NC} Cek Status IP & ISP (Via WARP)"
    echo -e "${BIBlue}--------------------------------------------------------------${NC}"
    echo -e "  ${BIRed}[0]${NC}  Kembali ke Menu Utama"
    read -p "  Pilih Menu [0-5]: " w_opt
    case $w_opt in
    1) warp_all ;;
    2) warp_by_tag ;;
    3) warp_by_user ;;
    4) warp_by_geosite ;;
    5) check_warp_status ;;
    0)
        show_menu
        ;;
    *)
        echo -e "\n  ${BIRed}Pilihan tidak valid!${NC}"
        sleep 1
        warp_manager
        ;;
    esac
}

function adguard_manager() {
    show_header
    echo -e "${BIYellow}>> MANAJEMEN ADGUARD HOME${NC}"
    echo -e "${BIBlue}--------------------------------------------------------------${NC}"

    # Header Information
    if systemctl is-active --quiet AdGuardHome; then
        STATUS_AGH="${BIGreen}RUNNING${NC}"
        WEB_URL="http://${DOMAIN}/aghome/"
    else
        STATUS_AGH="${BIRed}NOT RUNNING${NC}"
        WEB_URL="-"
    fi

    echo -e "   Status Service : $STATUS_AGH"
    echo -e "   Web Panel      : ${BICyan}$WEB_URL${NC}"
    echo -e " "
    echo -e "   ${BIRed}PENTING:${NC} Segera lakukan setup di Web Panel dalam 30 menit."
    echo -e "   Jika tidak, auto-fixer port akan berhenti dan akses mungkin error."
    echo -e "${BIBlue}--------------------------------------------------------------${NC}"

    echo -e "  ${BIGreen}[01]${NC} Install AdGuard Home"
    echo -e "  ${BIGreen}[02]${NC} Uninstall AdGuard Home"
    echo -e "${BIBlue}--------------------------------------------------------------${NC}"
    echo -e "  ${BIRed}[0]${NC}  Kembali ke Menu Utama"

    read -p "  Pilih Menu [0-2]: " agh_opt
    case $agh_opt in
        1) install_adguard ;;
        2) uninstall_adguard ;;
        0) show_menu ;;
        *) echo -e "\n  ${BIRed}Pilihan tidak valid!${NC}"; sleep 1; adguard_manager ;;
    esac
}

function telegram_backup_manager() {
    show_header
    echo -e "${BIYellow}>> BACKUP / RESTORE (TELEGRAM BOT)${NC}"
    echo -e "${BIBlue}--------------------------------------------------------------${NC}"
    echo -e "  ${BIGreen}[1]${NC} Input Token Bot Telegram"
    echo -e "  ${BIGreen}[2]${NC} Delete Token Bot Telegram"
    echo -e "  ${BIGreen}[3]${NC} Start Bot Service"
    echo -e "  ${BIGreen}[4]${NC} Stop Bot Service"
    echo -e "  ${BIGreen}[5]${NC} Status Bot Service"
    echo -e "${BIBlue}--------------------------------------------------------------${NC}"
    echo -e "  ${BIRed}[0]${NC} Kembali"
    echo "======================================"
    read -p "   Pilih menu [0 - 5]: " opt

    case "$opt" in
        1) input_telegram_bot_token ;;
        2) delete_telegram_bot_token ;;
        3) start_telegram_bot ;;
        4) stop_telegram_bot ;;
        5) status_telegram_bot ;;
        0) show_menu ;;
        *) telegram_backup_manager ;;
    esac
}

function fail2ban_config() {
    show_header
    echo -e "${BIYellow}>> KONFIGURASI FAIL2BAN${NC}"
    echo -e "${BIBlue}--------------------------------------------------------------${NC}"
    echo -e "  ${BIGreen}[1]${NC} Cek Status Jail (SSH/Nginx)"
    echo -e "  ${BIGreen}[2]${NC} Unban IP Manual"
    echo -e "  ${BIGreen}[3]${NC} Restart Fail2Ban"
    echo -e "  ${BIRed}[0]${NC} Kembali"
    read -p "  Pilih Menu : " f2b_opt
    case $f2b_opt in
    1)
        echo -e "\n   ${BICyan}--- Status Fail2Ban ---${NC}"
        fail2ban-client status
        echo -e "\n   ${BICyan}--- Detail SSH Jail ---${NC}"
        fail2ban-client status sshd
        echo -e "\n   ${BICyan}--- Detail Recidive Jail ---${NC}"
        fail2ban-client status recidive
        ;;
    2)
        echo -e "   (Ketik '0' untuk kembali)"
        read -p "   Masukkan IP yang ingin di-Unban: " unban_ip
        if [[ "$unban_ip" == "0" ]]; then
            fail2ban_config
            return
        fi
        if [[ -n "$unban_ip" ]]; then
            fail2ban-client set sshd unbanip "$unban_ip"
            fail2ban-client set recidive unbanip "$unban_ip"
            echo -e "   ${BIGreen}Perintah Unban dikirim.${NC}"
        fi
        ;;
    3)
        echo -e "   Restarting Fail2Ban..."
        systemctl restart fail2ban
        echo -e "   ${BIGreen}Selesai.${NC}"
        ;;
    0)
        show_menu
        return
        ;;
    *) echo -e "${BIRed}Salah input.${NC}" ;;
    esac
    echo -e ""
    read -n 1 -s -r -p "   Tekan sembarang tombol untuk kembali..."
    fail2ban_config
}

function check_system_logs() {
    show_header
    echo -e "${BIYellow}>> CEK LOG AKTIVITAS SISTEM${NC}"
    echo -e "${BIBlue}--------------------------------------------------------------${NC}"
    echo -e "  ${BIGreen}[1]${NC} Log Auto Expired (xray-expiry)"
    echo -e "  ${BIGreen}[2]${NC} Log Limit IP (xray-limit)"
    echo -e "  ${BIGreen}[3]${NC} Log Quota User (xray-quota)"
    echo -e "  ${BIGreen}[4]${NC} Log Akses Xray (General)"
    echo -e "  ${BIGreen}[5]${NC} Log Backup Restore (BOT Telegram)"
    echo -e "  ${BIRed}[0]${NC} Kembali"
    read -p "  Pilih Menu: " opt
    case $opt in
    1) file="/var/log/xray/xp.log" ;;
    2) file="/var/log/xray/limit.log" ;;
    3) file="/var/log/xray/quota.log" ;;
    4) file="/var/log/xray/access.log" ;;
    5) file="/var/log/xray/backup_restore.log" ;;
    0)
        show_menu
        return
        ;;
    *)
        echo -e "\n  ${BIRed}Pilihan tidak valid!${NC}"
        sleep 1
        check_system_logs
        return
        ;;
    esac
    if [[ -f "$file" ]]; then
        echo -e "\n  ${BICyan}Menampilkan 20 baris terakhir dari $file:${NC}"
        echo "------------------------------------------------"
        tail -n 20 "$file"
        echo "------------------------------------------------"
    else
        echo -e "\n  ${BIRed}File log belum tersedia atau kosong.${NC}"
    fi
    read -n 1 -s -r -p "  Tekan sembarang tombol untuk kembali..."
    check_system_logs
}

# ==========================================
# 4. CORE FUNCTIONS (ADD/DEL/ETC)
# ==========================================

function add_user() {
    local mode=$1
    local title=""
    local target_dir=""
    local user_suffix=""
    case $mode in
    all)
        title="ALL PROTOCOL"
        target_dir=$DIR_ALL
        user_suffix="@allproto"
        ;;
    vless)
        title="VLESS"
        target_dir=$DIR_VLESS
        user_suffix="@vless"
        ;;
    vmess)
        title="VMESS"
        target_dir=$DIR_VMESS
        user_suffix="@vmess"
        ;;
    trojan)
        title="TROJAN"
        target_dir=$DIR_TROJAN
        user_suffix="@trojan"
        ;;
    esac

    show_header
    echo -e "${BIYellow}>> BUAT AKUN BARU ($title)${NC}"
    show_existing_users "$user_suffix"
    echo -e "${BIBlue}--------------------------------------------------------------${NC}"
    echo -e "   (Ketik '0' untuk kembali)"
    read -p "   Masukkan Username (tanpa suffix) : " user_input
    TMP_JSON="/tmp/tmp.json"
    if [[ "$user_input" == "0" ]]; then
        show_menu
        return
    fi
    if [[ -z "$user_input" ]]; then
        echo -e "${BIRed}Username tidak boleh kosong!${NC}"
        sleep 1
        show_menu
        return
    fi
    if [[ "$user_input" =~ [^a-zA-Z0-9_] ]]; then
        echo -e "${BIRed}Username hanya boleh huruf/angka!${NC}"
        sleep 1
        show_menu
        return
    fi
    local final_user="${user_input}${user_suffix}"
    if check_user_exists "$final_user"; then
        echo -e "\n${BIRed}[ERROR] User '$final_user' sudah ada!${NC}"
        read -n 1 -s -r -p "Tekan sembarang tombol..."
        return
    fi
    echo -e "   (Ketik '0' untuk kembali)"
    read -p "   Masa Aktif (hari) : " masaaktif
    if [[ "$masaaktif" == "0" ]]; then
        show_menu
        return
    fi
    if [[ ! $masaaktif =~ ^[0-9]+$ ]]; then
        echo -e "${BIRed}Input harus angka!${NC}"
        sleep 1
        show_menu
        return
    fi

    # Input Quota (GB) -> Logic sama, nanti dikonversi di generate_and_save
    echo -e "   (Ketik '0' untuk Unlimited)"
    read -p "   Batas Kuota (GB) : " quota
    if [[ ! $quota =~ ^[0-9]+$ ]]; then
        echo -e "${BIRed}Input harus angka!${NC}"
        sleep 1
        show_menu
        return
    fi

    echo -e "\n   ${BICyan}Membuat akun '$final_user'... Mohon tunggu.${NC}"
    uuid=$(uuidgen)
    cp $CONFIG ${CONFIG}.bak
    case $mode in
    all)
        jq --arg u "$final_user" --arg id "$uuid" '(.inbounds[] | select(.protocol=="vless" or .protocol=="vmess") .settings.clients) += [{"id":$id,"email":$u}]' $CONFIG >$TMP_JSON && mv $TMP_JSON $CONFIG
        jq --arg u "$final_user" --arg id "$uuid" '(.inbounds[] | select(.protocol=="trojan") .settings.clients) += [{"password":$id,"email":$u}]' $CONFIG >$TMP_JSON && mv $TMP_JSON $CONFIG
        ;;
    vless)
        jq --arg u "$final_user" --arg id "$uuid" '(.inbounds[] | select(.protocol=="vless") .settings.clients) += [{"id":$id,"email":$u}]' $CONFIG >$TMP_JSON && mv $TMP_JSON $CONFIG
        ;;
    vmess)
        jq --arg u "$final_user" --arg id "$uuid" '(.inbounds[] | select(.protocol=="vmess") .settings.clients) += [{"id":$id,"email":$u}]' $CONFIG >$TMP_JSON && mv $TMP_JSON $CONFIG
        ;;
    trojan)
        jq --arg u "$final_user" --arg id "$uuid" '(.inbounds[] | select(.protocol=="trojan") .settings.clients) += [{"password":$id,"email":$u}]' $CONFIG >$TMP_JSON && mv $TMP_JSON $CONFIG
        ;;
    esac
    restart_system
    
    # Panggil fungsi generate_and_save yang sudah diperbarui (JSON + TXT)
    generate_and_save "$final_user" "$uuid" "$masaaktif" "$quota" "$mode" "$target_dir"
    
    echo -e "\n   ${BIGreen}[SUKSES] Akun $final_user berhasil dibuat!${NC}"
    read -n 1 -s -r -p "   Tekan sembarang tombol untuk kembali..."
    show_menu
}

function del_user() {
    local mode=$1
    local title=""
    local user_suffix=""
    local protocol_folder=""
    
    case $mode in
    all)
        title="ALL PROTOCOL"
        user_suffix="@allproto"
        protocol_folder="allproto"
        ;;
    vless)
        title="VLESS"
        user_suffix="@vless"
        protocol_folder="vless"
        ;;
    vmess)
        title="VMESS"
        user_suffix="@vmess"
        protocol_folder="vmess"
        ;;
    trojan)
        title="TROJAN"
        user_suffix="@trojan"
        protocol_folder="trojan"
        ;;
    esac
    show_header
    echo -e "${BIYellow}>> HAPUS AKUN ($title)${NC}"
    show_existing_users "$user_suffix"
    echo -e "   (Ketik '0' untuk kembali)"
    read -p "   Masukkan Username (tanpa suffix) : " user_input
    TMP_JSON="/tmp/tmp.json"
    if [[ "$user_input" == "0" ]]; then
        show_menu
        return
    fi
    if [[ -z "$user_input" ]]; then
        echo -e "${BIRed}Username tidak boleh kosong!${NC}"
        sleep 1
        show_menu
        return
    fi
    local final_user="${user_input}${user_suffix}"
    if ! check_user_exists "$final_user"; then
        echo -e "\n${BIRed}[ERROR] User '$final_user' tidak ditemukan!${NC}"
        read -n 1 -s -r -p "Tekan sembarang tombol..."
        return
    fi
    echo -e "\n   ${BICyan}Menghapus akun $final_user ...${NC}"
    cp $CONFIG ${CONFIG}.bak
    jq --arg u "$final_user" '(.inbounds[] | select(.settings.clients != null) | .settings.clients) |= map(select(.email != $u))' $CONFIG >$TMP_JSON && mv $TMP_JSON $CONFIG
    
    # 1. Hapus File TXT (Config Link)
    case $mode in
    all) rm -f $DIR_ALL/${final_user}.txt ;;
    vless) rm -f $DIR_VLESS/${final_user}.txt ;;
    vmess) rm -f $DIR_VMESS/${final_user}.txt ;;
    trojan) rm -f $DIR_TROJAN/${final_user}.txt ;;
    esac
    
    # 2. Hapus File JSON (Metadata Quota)
    rm -f "/opt/quota/${protocol_folder}/${final_user}.json"

    # Cleanup jika allproto (opsional jika file txt ganda)
    if [[ "$mode" == "all" ]]; then
        rm -f $DIR_ALL/${final_user}.txt $DIR_VLESS/${final_user}.txt $DIR_VMESS/${final_user}.txt $DIR_TROJAN/${final_user}.txt 2>/dev/null
    fi
    
    restart_system
    echo -e "\n   ${BIGreen}[SUKSES] Akun $final_user berhasil dihapus dari sistem!${NC}"
    read -n 1 -s -r -p "   Tekan sembarang tombol untuk kembali..."
    show_menu
}

function list_users_files() {
    show_header
    echo -e "${BIYellow}>> DAFTAR AKUN (METADATA DARI JSON)${NC}"
    echo -e "${BIBlue}+------+----------------+----------+--------------+--------------+--------------+-----------------+${NC}"
    echo -e "${BIBlue}| ${BIWhite}NO   ${BIBlue}| ${BIWhite}USERNAME       ${BIBlue}| ${BIWhite}TIPE     ${BIBlue}| ${BIWhite}TERPAKAI     ${BIBlue}| ${BIWhite}LIMIT        ${BIBlue}| ${BIWhite}SISA         ${BIBlue}| ${BIWhite}EXPIRED         ${BIBlue}|${NC}"
    echo -e "${BIBlue}+------+----------------+----------+--------------+--------------+--------------+-----------------+${NC}"

    local STATS_DATA=$(xray api statsquery --server=127.0.0.1:10080 2>/dev/null)

    num=1
    # Cari file JSON di /opt/quota/
    found_files=$(find /opt/quota -name "*.json" | sort)

    if [[ -z "$found_files" ]]; then
        echo -e "${BIBlue}| ${BIRed}NULL ${BIBlue}| ${BIWhite}Belum ada file record tersimpan.                                                       ${BIBlue}|${NC}"
    else
        while read filepath; do
            # Parse JSON data
            user=$(jq -r '.username' "$filepath")
            protocol=$(jq -r '.protocol' "$filepath")
            limit_bytes=$(jq -r '.quota_limit' "$filepath")
            exp_info=$(jq -r '.expired_at' "$filepath")
            
            # Format Tipe Protocol untuk Display
            type=$(echo "$protocol" | tr '[:lower:]' '[:upper:]')

            # Stats Calculation
            up=$(echo "$STATS_DATA" | jq -r ".stat[] | select(.name == \"user>>>${user}>>>traffic>>>uplink\") | .value" 2>/dev/null)
            down=$(echo "$STATS_DATA" | jq -r ".stat[] | select(.name == \"user>>>${user}>>>traffic>>>downlink\") | .value" 2>/dev/null)

            up=${up:-0}
            down=${down:-0}
            total=$(($up + $down))
            used_human=$(bytes_to_human $total)

            if [[ "$limit_bytes" == "0" || "$limit_bytes" == "null" ]]; then
                limit_human="Unlimited"
                sisa_human="∞"
            else
                limit_human=$(bytes_to_human $limit_bytes)
                sisa_bytes=$(($limit_bytes - $total))
                if [[ $sisa_bytes -lt 0 ]]; then sisa_bytes=0; fi
                sisa_human=$(bytes_to_human $sisa_bytes)
            fi

            printf "${BIBlue}| ${BIGreen}%-4s ${BIBlue}| ${BIWhite}%-14s ${BIBlue}| ${BIYellow}%-8s ${BIBlue}| ${BIWhite}%-12s ${BIBlue}| ${BIGreen}%-12s ${BIBlue}| ${BICyan}%-12s ${BIBlue}| ${BIRed}%-15s ${BIBlue}|${NC}\n" "$num" "${user:0:14}" "$type" "$used_human" "$limit_human" "$sisa_human" "$exp_info"
            ((num++))
        done <<<"$found_files"
    fi
    echo -e "${BIBlue}+------+----------------+----------+--------------+--------------+--------------+-----------------+${NC}"
    echo -e "\n   ${BICyan}[INFO] Ketik nama user untuk melihat detail, atau '0' untuk kembali.${NC}"
    read -p "   Input : " target_user
    if [[ "$target_user" == "0" ]]; then
        show_menu
    else
        # Cari file TXT untuk detail config
        target_file=$(find /opt/allproto /opt/vless /opt/vmess /opt/trojan -name "${target_user}.txt" | head -n 1)
        if [[ -f "$target_file" ]]; then
            clear
            cat "$target_file"
            echo -e ""
            # Tampilkan info tambahan dari JSON jika ada
            json_file=$(find /opt/quota -name "${target_user}.json" | head -n 1)
            if [[ -f "$json_file" ]]; then
                echo -e "${BIYellow}--- Metadata JSON ---${NC}"
                cat "$json_file"
                echo -e ""
            fi
            read -n 1 -s -r -p "   Tekan sembarang tombol untuk kembali ke daftar..."
            list_users_files
        else
            echo -e "\n   ${BIRed}User '$target_user' tidak ditemukan!${NC}"
            sleep 1.5
            list_users_files
        fi
    fi
}

function check_service_status() {
    show_header
    echo -e "${BIYellow}>> STATUS LAYANAN SYSTEM${NC}"
    echo -e "${BIBlue}--------------------------------------------------------------${NC}"
    check() {
        if systemctl is-active "$1" >/dev/null 2>&1; then
            echo -e "   $2 : ${BIGreen}[ON] Running${NC}"
        else
            echo -e "   $2 : ${BIRed}[OFF] Stopped${NC}"
        fi
    }
    check "xray" "Xray-Core Service"
    check "nginx" "Nginx Web Server "
    check "wireproxy" "WireProxy Service"
    check "xray-telegram-bot" "BOT Telegram Backup Restore"
    check "fail2ban" "Fail2Ban Protection"
    check "chrony" "Chrony Time Sync "
    check "snapd" "Snapd Service    "
    echo -e "${BIBlue}--------------------------------------------------------------${NC}"
    read -n 1 -s -r -p "   Tekan sembarang tombol untuk kembali..."
    show_menu
}

function restart_all_services() {
    show_header
    echo -e "${BIYellow}>> RESTART SEMUA SERVICE${NC}"
    echo -e "${BIBlue}--------------------------------------------------------------${NC}"
    echo -e "   ${BICyan}Sedang merestart layanan...${NC}"
    echo -n "   - Restarting Xray Core... "
    systemctl restart xray
    echo -e "${BIGreen}[OK]${NC}"
    echo -n "   - Restarting Nginx...     "
    systemctl restart nginx
    echo -e "${BIGreen}[OK]${NC}"
    echo -n "   - Restarting WireProxy... "
    systemctl restart wireproxy
    echo -e "${BIGreen}[OK]${NC}"
    echo -n "   - Restarting BOT Telegram Backup Restore... "
    systemctl restart xray-telegram-bot
    echo -e "${BIGreen}[OK]${NC}"
    echo -n "   - Restarting Fail2Ban...  "
    systemctl restart fail2ban
    echo -e "${BIGreen}[OK]${NC}"
    echo -n "   - Syncing Time (Chrony).. "
    systemctl restart chrony
    echo -e "${BIGreen}[OK]${NC}"
    echo -e "${BIBlue}--------------------------------------------------------------${NC}"
    echo -e "   ${BIGreen}Semua layanan berhasil direstart!${NC}"
    echo -e ""
    read -n 1 -s -r -p "   Tekan sembarang tombol untuk kembali..."
    show_menu
}

function check_resources() {
    show_header
    echo -e "${BIYellow}>> MONITORING RESOURCE SERVER${NC}"
    echo -e "${BIBlue}--------------------------------------------------------------${NC}"
    echo -e "${BICyan}   [ MEMORY (RAM) ]${NC}"
    free -h | awk 'NR==2{printf "   - Total : %s\n   - Used  : %s\n   - Free  : %s\n   - Cache : %s\n", $2,$3,$4,$6}'
    echo -e ""
    echo -e "${BICyan}   [ CPU SYSTEM ]${NC}"
    load=$(uptime | awk -F'load average:' '{ print $2 }')
    echo -e "   - Load Average :$load"
    model=$(grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2)
    echo -e "   - CPU Model    :$model"
    cores=$(nproc)
    echo -e "   - Total Cores  : $cores Core(s)"
    echo -e ""
    echo -e "${BICyan}   [ DISK SPACE ]${NC}"
    df -h / | awk 'NR==2{printf "   - Total : %s\n   - Used  : %s (%s)\n   - Free  : %s\n", $2,$3,$5,$4}'
    echo -e "${BIBlue}--------------------------------------------------------------${NC}"
    read -n 1 -s -r -p "   Tekan sembarang tombol untuk kembali..."
    show_menu
}

function clear_cache() {
    show_header
    echo -e "${BIYellow}>> BERSIHKAN LOG & CACHE${NC}"
    echo -e "${BIBlue}--------------------------------------------------------------${NC}"
    echo -e "   ${BICyan}Memulai proses pembersihan...${NC}\n"
    echo -n "   - Clearing RAM Cache...        "
    sync
    echo 3 >/proc/sys/vm/drop_caches
    echo -e "${BIGreen}[OK]${NC}"
    echo -n "   - Refreshing Swap Memory...    "
    swapoff -a && swapon -a
    echo -e "${BIGreen}[OK]${NC}"
    echo -n "   - Truncating Xray Logs...      "
    truncate -s 0 /var/log/xray/access.log
    truncate -s 0 /var/log/xray/error.log
    echo -e "${BIGreen}[OK]${NC}"
    echo -n "   - Vacuuming System Journal...  "
    journalctl --vacuum-time=1d >/dev/null 2>&1
    echo -e "${BIGreen}[OK]${NC}"
    echo -e "${BIBlue}--------------------------------------------------------------${NC}"
    echo -e "   ${BIGreen}Sistem berhasil dibersihkan!${NC}"
    echo -e ""
    read -n 1 -s -r -p "   Tekan sembarang tombol untuk kembali..."
    show_menu
}

# --- Menu Utama ---
function show_menu() {
    show_header
    echo -e "${BIYellow}>> QUICK MENU (ALL-IN-ONE)${NC}"
    echo -e "  ${BIGreen}[01]${NC} Buat Akun (All Proto)   ${BIGreen}[02]${NC} Hapus Akun (All Proto)"

    echo -e "\n${BIYellow}>> MANAJEMEN PER-PROTOKOL${NC}"
    echo -e "  ${BIGreen}[03]${NC} Buat Akun VLESS       ${BIGreen}  [06]${NC} Hapus Akun VLESS"
    echo -e "  ${BIGreen}[04]${NC} Buat Akun VMESS       ${BIGreen}  [07]${NC} Hapus Akun VMESS"
    echo -e "  ${BIGreen}[05]${NC} Buat Akun TROJAN      ${BIGreen}  [08]${NC} Hapus Akun TROJAN"
    echo -e "  ${BIGreen}[09]${NC} Daftar Semua Akun     ${BIGreen}  [10]${NC} Cek User Login"

    echo -e "\n${BIYellow}>> MANAJEMEN SISTEM${NC}"
    echo -e "  ${BIGreen}[11]${NC} Cek Status Service    ${BIGreen}  [14]${NC} Speedtest VPS"
    echo -e "  ${BIGreen}[12]${NC} Restart Semua Service ${BIGreen}  [15]${NC} Cek Penggunaan Ram/CPU"
    echo -e "  ${BIGreen}[13]${NC} Perbarui Sertifikat SSL${BIGreen} [16]${NC} Bersihkan Log & Cache"

    echo -e "\n${BIYellow}>> ADD-ONS & LAINNYA${NC}"
    echo -e "  ${BIGreen}[17]${NC} Manajemen Routing WARP  ${BIGreen}[18]${NC} Ganti Domain (Re-Setup)"
    echo -e "  ${BIGreen}[19]${NC} Konfigurasi Fail2Ban  ${BIGreen}  [20]${NC} Manajemen Backup Restore"
    echo -e "  ${BIGreen}[21]${NC} Perpanjang Masa Aktif ${BIGreen}  [22]${NC} Monitoring Trafik"
    echo -e "  ${BIGreen}[23]${NC} Limitasi IP (Auto Kill) ${BIGreen}[24]${NC} Manajemen Kuota User"
    echo -e "  ${BIGreen}[25]${NC} Cek Log System          ${BIGreen}[26]${NC} Manajemen AdGuard Home"

    echo -e "${BIBlue}==============================================================${NC}"
    echo -e "  ${BIRed}[x]${NC}  Keluar (Exit)"
    echo -e "${BIBlue}==============================================================${NC}"

    read -p "  Pilih Menu [1-26]: " menu_opt

    case $menu_opt in
    1) add_user "all" ;;
    2) del_user "all" ;;

    3) add_user "vless" ;;
    4) add_user "vmess" ;;
    5) add_user "trojan" ;;

    6) del_user "vless" ;;
    7) del_user "vmess" ;;
    8) del_user "trojan" ;;

    9) list_users_files ;;
    10) check_user_login ;;

    11) check_service_status ;;
    12) restart_all_services ;;
    13) renew_cert_ssl ;;
    14)
        speedtest
        read -n 1 -s -r -p "Tekan tombol apapun untuk kembali..."
        show_menu
        ;;
    15) check_resources ;;
    16) clear_cache ;;

    17) warp_manager ;;
    18) change_domain_setup ;;
    19) fail2ban_config ;;
    20) telegram_backup_manager ;;

    21) renew_user_account ;;
    22) show_traffic_stats ;;
    23) configure_ip_limiter ;;
    24) quota_manager ;;
    25) check_system_logs ;;
    26) adguard_manager ;;

    x | X)
        clear
        echo -e "${BIGreen}Terima kasih. Keluar dari menu.${NC}"
        exit 0
        ;;
    *)
        echo -e "\n  ${BIRed}Pilihan tidak valid!${NC}"
        sleep 1
        show_menu
        ;;
    esac
}

# Jalankan Menu
show_menu


