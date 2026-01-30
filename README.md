# AIO Xray Core + Nginx Auto Installer
---

## Gambaran Umum

Repository ini menyediakan dua komponen utama:

- **setup.sh**  
  Script installer otomatis untuk membangun environment Xray Core, Nginx, keamanan server, optimasi sistem, serta fitur pendukung lainnya.

- **menu.sh**  
  Menu interaktif berbasis terminal untuk manajemen akun, monitoring trafik, keamanan, dan maintenance server pasca instalasi.

Mendukung **Ubuntu 20.04+** dan **Debian 11+**.

Script ini dikerjakan penuh oleh **Gemini AI** ✨

---

## Fitur Utama

### Core & Network
- Xray Core (versi terbaru)
- Nginx (Official Repository)
- Protokol:
  - VLESS
  - VMess
  - Trojan
- Transport:
  - WebSocket
  - HTTPUpgrade
  - gRPC
- Reverse proxy penuh melalui Nginx
- Internal port dan path di-generate secara acak (meningkatkan stealth & keamanan)

### Domain & SSL
- Domain custom (manual)
- Domain otomatis melalui Cloudflare API
- Sertifikat SSL otomatis (acme.sh + ZeroSSL)
- Mendukung wildcard domain (mode DNS)

### Optimasi Sistem
- TCP BBR congestion control
- Auto swap memory
- Tuning ulimit (file descriptor)
- Sinkronisasi waktu server (Chrony / NTP)

### Keamanan
- Fail2Ban dengan mode agresif (SSH & Nginx)
- Pemblokiran trafik BitTorrent
- Limitasi multi-login IP (auto block)
- Sistem quota user (real-time enforcement)
- Watchdog untuk Xray & Nginx

### Add-ons
- Cloudflare WARP
  - WGCF + WireProxy
  - SOCKS5 proxy: `127.0.0.1:40000`
- Routing fleksibel:
  - Global
  - Per user
  - Per protokol / inbound
  - Per geosite (Netflix, Google, OpenAI, dll)

### Monitoring & Maintenance
- Monitoring trafik user secara realtime (Xray API)
- Auto expired user
- Auto pembersihan log
- Auto update geo data
- Restart service terpusat

### Backup & Restore
- Backup & restore melalui Telegram Bot (private)
- Data yang dibackup:
  - Konfigurasi Xray
  - Konfigurasi Nginx
  - Data akun & quota
- Restore dapat dilakukan langsung dari Telegram

---

## Port & Akses

- **Public Port**: `80` dan `443`
- Semua inbound Xray berjalan pada `127.0.0.1`
- Akses client melalui path berikut:
  - WebSocket:  
    `/vless-ws`, `/vmess-ws`, `/trojan-ws`
  - HTTPUpgrade:  
    `/vless-hu`, `/vmess-hu`, `/trojan-hu`
  - gRPC:  
    `/vless-grpc`, `/vmess-grpc`, `/trojan-grpc`

---

## Instalasi

Jalankan perintah berikut sebagai **root**:

```bash
rm -rf setup.sh && wget -O setup.sh https://s.id/aio-xray && bash setup.sh
```

Ikuti menu interaktif hingga proses instalasi selesai.

---

## Menu Manajemen

Setelah instalasi berhasil, jalankan menu manajemen dengan perintah:

```bash
menu
```

### Fitur Menu
- Manajemen akun (tambah, hapus, perpanjang)
- Pengaturan quota dan masa aktif
- Monitoring trafik per user
- Limitasi IP (auto kill multi-login)
- Manajemen routing WARP
- Backup & restore
- Restart service & maintenance sistem
- Monitoring resource dan log server
- AdGuard Home

---

## Catatan Penting
- Wajib dijalankan sebagai **root**
- Direkomendasikan menggunakan VPS fresh
- Pastikan port `80` dan `443` terbuka
- Hindari mengedit konfigurasi secara manual tanpa pemahaman yang memadai

---

## Lisensi
Project ini disediakan untuk keperluan pembelajaran dan pengembangan.  
Gunakan secara bertanggung jawab sesuai dengan kebijakan server dan hukum yang berlaku.
