import json
import re
import time
import threading
import subprocess
import requests
from collections import deque, Counter
from datetime import datetime
from logging.handlers import RotatingFileHandler
from telegram.ext import Application, CommandHandler, ContextTypes, CallbackQueryHandler
from telegram import Update, InlineKeyboardMarkup, InlineKeyboardButton
import logging
import configparser
import os
import asyncio


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, 'config.ini')
LOG_FILE = '/var/log/caddy/access.log'  # Default log file
LOG_FILE_ID = '/var/log/caddy/museum_acces.log'
BLACKLIST_FILE = os.path.join(BASE_DIR, 'blacklist.txt')
CHECK_INTERVAL = 60  # Seconds
REQUEST_THRESHOLD = 100  # Requests per CHECK_INTERVAL
SUSPICIOUS_IPS = set()
STRIKE_COUNTER = {}  # Menyimpan jumlah pelanggaran/serangan per IP
AUTO_BLOCK_STRIKE_LIMIT = 3  # Batas Strike untuk Pola KRITIS atau IP Luar Negeri
STRIKE_LIMIT_CRITICAL = 3    # Level 1 (KRITIS): 3x langsung Auto-Block (Semua IP)
STRIKE_LIMIT_FOREIGN = 3     # IP Luar Negeri (Non-ID): 3x langsung Auto-Block (Semua Level)
STRIKE_LIMIT_ID_MEDIUM = 10  # IP Indonesia + Level 2 (SQLi/XSS Teks): Toleransi 10x (Cegah False Positive Pegawai)
OWNER_ID = 0  # Diisi otomatis dari config.ini
AUTO_BLOCK_ENABLED = True
AUTO_BLOCK_ENABLED_ID = True

# Level 1: Pola Ancaman KRITIS (Eksploitasi Sistem, File Rahasia, RCE, LFI, Backdoor -> Limit 3x langsung Blokir)
CRITICAL_PATTERNS = [
    r"(?i)(\.\.[/\\]|%2e%2e[/\\%])",  # Path Traversal
    r"(?i)(cmd=|exec=|[\s;|&]{2,}|\|\s*(?:sh|bash|nc|wget|curl|php|python|perl|ls|cat|id|whoami)\b|;\s*(?:ls|cat|id|whoami|wget|curl)\b|\bsystem\s*\(|\bshell_exec\b|\bpassthru\s*\(|\bphpinfo\s*\(|\bbase64_decode\s*\()",  # Command Injection & RCE
    r"(?i)(/etc/passwd|/etc/shadow|/proc/self|\.\./.*config|boot\.ini|win\.ini|php://filter|php://input)",  # LFI
    r"(?i)https?://[^ ]+\.(php|sh|txt|pl|asp|jsp)",  # RFI
    r"(?i)(?:^|/)(\.env|\.git|\.svn|\.htaccess|\.aws|\.ssh|wp-config\.php|wp-admin|wp-login\.php|xmlrpc\.php|phpmyadmin|adminer|vendor/phpunit|storage/|bootstrap/cache|node_modules/|\.sql$|\.bak$|\.tar\.gz$|\.cmd$|\.py$|\.sh$|\.exe$|\.bat$)",  # Sensitive File / Directory Probe (Caddy 403)
    r"(?i)^/(?!index\.php\b).*\.php(?:\?|$)",  # Unauthorized PHP / Webshell Backdoor Probe (Caddy @blockphp 403)
    r"(?i)(169\.254\.169\.254|metadata\.google\.internal|\$\{jndi:|\{\{.*\*.*\}\})",  # SSRF, Log4Shell & SSTI
]

# Level 2: Pola Ancaman MEDIUM/HIGH (Teks SQLi / XSS Kontekstual -> IP Luar Limit 3x, IP Indonesia Toleransi 10x)
MEDIUM_HIGH_PATTERNS = [
    r"(?i)(union\s+(?:all\s+)?select\b|\bselect\b.{1,100}?\bfrom\b|\binsert\s+into\b|\bupdate\b.{1,100}?\bset\b|\bdelete\s+from\b|\bdrop\s+(?:table|database|user)\b|\balter\s+table\b|\bexec\s*\(|\bcast\s*\(|sleep\s*\(|benchmark\s*\(|information_schema|waitfor\s+delay|'\s*(?:or|and)\s*['\d]|1\s*=\s*1|(?:['\";]|%27|%22)\s*--)",  # SQLi Kontekstual
    r"(?i)(<script.*?>|</script>|%3cscript|javascript:|onerror\s*=|onload\s*=|onmouseover\s*=|onfocus\s*=|<iframe|<svg|<img|alert\s*\(|document\.cookie|eval\s*\()",  # XSS
]

SUSPICIOUS_PATTERNS = CRITICAL_PATTERNS + MEDIUM_HIGH_PATTERNS

BAD_USER_AGENT_PATTERN = re.compile(
    r"(?i)(sqlmap|nikto|nuclei|nmap|masscan|gobuster|dirbuster|ffuf|wpscan|acunetix|burpsuite|zgrab|hydra|metasploit|curl/|wget/|python-requests|scrapy)"
)

# Static asset whitelist untuk mencegah false positive (seperti multiple-select.js)
STATIC_EXTENSIONS = (
    '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg',
    '.woff', '.woff2', '.ttf', '.eot', '.webp', '.map'
)
STATIC_PREFIXES = ('/assets/', '/build/', '/pendukung/', '/public/', '/plugins/')

def is_static_asset_path(path_str):
    """Cek apakah path merupakan file asset statis murni untuk mencegah false positive."""
    clean_path = path_str.split('?')[0].lower()
    return clean_path.endswith(STATIC_EXTENSIONS) or any(clean_path.startswith(prefix) for prefix in STATIC_PREFIXES)


# Setup logging with RotatingFileHandler (max 10MB per file, max 3 backups)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler(os.path.join(BASE_DIR, 'monitor.log'), maxBytes=10 * 1024 * 1024, backupCount=3, encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Load configuration
config = configparser.ConfigParser()
if os.path.exists(CONFIG_FILE):
    config.read(CONFIG_FILE)
    TELEGRAM_TOKEN = config.get('Telegram', 'Token', fallback=None)
    CHAT_ID = config.get('Telegram', 'ChatID', fallback=None)
    try:
        if CHAT_ID:
            OWNER_ID = int(CHAT_ID)
    except ValueError:
        pass

    AI_ENABLED = config.getboolean('AI', 'Enabled', fallback=True)
    GEMINI_KEY = config.get('AI', 'GeminiKey', fallback='YOUR_GEMINI_API_KEY_HERE')
    AI_MODEL = config.get('AI', 'Model', fallback='gemini-3.8-flash')
    logger.info(f"Konfigurasi AI dimuat: Enabled={AI_ENABLED}, Model={AI_MODEL}")
else:
    logger.error(f"Configuration file {CONFIG_FILE} not found")
    exit(1)

# === Functions ===
def send_telegram(message):
    """Send alert message to Telegram."""
    url = f'https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage'
    payload = {
        'chat_id': CHAT_ID,
        'text': message,
        'parse_mode': 'Markdown'
    }
    try:
        response = requests.post(url, data=payload, timeout=5)
        response.raise_for_status()
    except requests.RequestException as e:
        logger.error(f"Failed to send to Telegram: {e}")

def add_to_blacklist(ip):
    """Add IP to blacklist file and in-memory set."""
    ip = ip.strip()
    if ip not in SUSPICIOUS_IPS:
        try:
            with open(BLACKLIST_FILE, 'a') as f:
                f.write(ip + '\n')
            SUSPICIOUS_IPS.add(ip)
            logger.info(f"IP added to blacklist: {ip}")
        except IOError as e:
            logger.error(f"Failed to write to blacklist file: {e}")

def remove_from_blacklist(ip):
    """Hapus IP dari in-memory set dan file blacklist.txt saat di-unblock."""
    ip = ip.strip()
    SUSPICIOUS_IPS.discard(ip)
    if os.path.exists(BLACKLIST_FILE):
        try:
            with open(BLACKLIST_FILE, 'r') as f:
                lines = [line.strip() for line in f if line.strip() and line.strip() != ip]
            with open(BLACKLIST_FILE, 'w') as f:
                for line in lines:
                    f.write(line + '\n')
        except IOError as e:
            logger.error(f"Failed to update blacklist file on unblock: {e}")
GEOIP_CACHE = {}

def is_foreign_ip(ip):
    """
    Cek asal negara IP menggunakan In-Memory Cache + Public Geo-IP API (Tanpa server 192.168.22.2:5000).
    Hanya memanggil API maksimal 1x per IP unik sehingga 0ms latency untuk request berikutnya.
    """
    ip = (ip or '').strip()
    if not ip or ip in ('127.0.0.1', '::1', '-') or ip.startswith(('192.168.', '10.', '127.', '172.16.', '172.17.', '172.18.', '172.19.', '172.2', '172.3')):
        return False, "ID (Local)"

    if ip in GEOIP_CACHE:
        return GEOIP_CACHE[ip]

    try:
        res = requests.get(f"http://ip-api.com/json/{ip}?fields=status,countryCode,isp", timeout=1.5)
        if res.status_code == 200:
            data = res.json()
            if data.get('status') == 'success':
                cc = data.get('countryCode', 'ID')
                isp = data.get('isp', '')
                label = f"{cc} ({isp})" if isp else cc
                result = (cc != "ID", label)
                GEOIP_CACHE[ip] = result
                return result
    except Exception:
        pass

    GEOIP_CACHE[ip] = (False, "ID")
    return False, "ID"

def _run_iptables_raw(args_list):
    """Jalankan binary iptables (langsung atau via sudo) dengan dukungan PATH lengkap."""
    for bin_path in ('/usr/sbin/iptables', '/sbin/iptables', 'iptables'):
        try:
            res = subprocess.run([bin_path] + args_list, capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                return True, res.stdout.strip()
            res_sudo = subprocess.run(['sudo', bin_path] + args_list, capture_output=True, text=True, timeout=5)
            if res_sudo.returncode == 0:
                return True, res_sudo.stdout.strip()
        except FileNotFoundError:
            continue
        except Exception as e:
            return False, str(e)
    return False, "Perintah iptables gagal atau aturan belum ada"

def execute_iptables_cmd(action, ip):
    """
    Eksekusi iptables dengan aman (action: '-I' untuk block, '-D' untuk unblock).
    Menggunakan Dual-Layer Kernel Drop:
    1. Layer-3 Source IP Drop (-s <ip> -j DROP) untuk serangan langsung ke IP server.
    2. Layer-7 Kernel DPI String Match (-p tcp -m string --string <ip> --algo bm -j DROP)
       agar serangan yang datang lewat Cloudflare Proxy / Tunnel / VPN (Cf-Connecting-Ip /
       X-Forwarded-For) tetap langsung di-DROP oleh kernel di Chain INPUT!
    """
    ip = ip.strip()
    if not ip or ip in ('127.0.0.1', '::1', '-'):
        return False, "IP tidak valid atau localhost (tidak boleh diblokir)"

    if ':' in ip and not ip.startswith('['):
        ip = ip.split(':')[0].strip()

    if action == '-I':
        # 1. Pasang aturan Layer-3 Source IP (-s <ip>) di baris #1 Chain INPUT
        #    agar tampilan `iptables -L INPUT -n -v --line-numbers` di PuTTY selalu rapi & bersih!
        already_in_kernel, _ = _run_iptables_raw(['-C', 'INPUT', '-s', ip, '-j', 'DROP'])
        if not already_in_kernel:
            ok, err = _run_iptables_raw(['-I', 'INPUT', '1', '-s', ip, '-j', 'DROP'])
            if not ok:
                return False, err

        # 2. Pasang Layer-7 Kernel DPI (-m string) di Chain OUTPUT (menuju WAF 127.0.0.1 & Backend 192.168.14.2)
        #    agar serangan yang masuk lewat VPN / Cloudflare Proxy (membawa X-Forwarded-For / Cf-Connecting-Ip)
        #    langsung MATI TOTAL (muter-muter) tanpa mengotori tampilan tabel Chain INPUT!
        dpi_out = ['OUTPUT', '-p', 'tcp', '-m', 'multiport', '--dports', '80,8000,8080,8086,8089,8090,8092,8094', '-m', 'string', '--string', ip, '--algo', 'bm', '-j', 'DROP']
        already_out, _ = _run_iptables_raw(['-C'] + dpi_out)
        if not already_out:
            ok_out, _ = _run_iptables_raw(['-I', 'OUTPUT', '1', '-p', 'tcp', '-m', 'multiport', '--dports', '80,8000,8080,8086,8089,8090,8092,8094', '-m', 'string', '--string', ip, '--algo', 'bm', '-j', 'DROP'])
            if not ok_out:
                already_out2, _ = _run_iptables_raw(['-C', 'OUTPUT', '-d', '192.168.14.2', '-p', 'tcp', '-m', 'string', '--string', ip, '--algo', 'bm', '-j', 'DROP'])
                if not already_out2:
                    _run_iptables_raw(['-I', 'OUTPUT', '1', '-d', '192.168.14.2', '-p', 'tcp', '-m', 'string', '--string', ip, '--algo', 'bm', '-j', 'DROP'])

        # 3. Putuskan juga koneksi TCP Keep-Alive yang masih menggantung dari IP penyerang
        try:
            subprocess.run(['ss', '-K', 'dst', ip], capture_output=True, timeout=2)
        except Exception:
            pass
        return True, f"Berhasil memblokir IP {ip} di iptables"

    elif action == '-D':
        # Hapus seluruh aturan DROP (baik di INPUT maupun OUTPUT) untuk IP ini
        removed_count = 0
        for _ in range(10):
            ok1, _ = _run_iptables_raw(['-D', 'INPUT', '-s', ip, '-j', 'DROP'])
            ok2, _ = _run_iptables_raw(['-D', 'INPUT', '-p', 'tcp', '-m', 'multiport', '--dports', '80,443,8080', '-m', 'string', '--string', ip, '--algo', 'bm', '-j', 'DROP'])
            ok3, _ = _run_iptables_raw(['-D', 'INPUT', '-p', 'tcp', '-m', 'string', '--string', ip, '--algo', 'bm', '-j', 'DROP'])
            ok4, _ = _run_iptables_raw(['-D', 'OUTPUT', '-p', 'tcp', '-m', 'multiport', '--dports', '80,8000,8080,8086,8089,8090,8092,8094', '-m', 'string', '--string', ip, '--algo', 'bm', '-j', 'DROP'])
            ok5, _ = _run_iptables_raw(['-D', 'OUTPUT', '-d', '192.168.14.2', '-p', 'tcp', '-m', 'string', '--string', ip, '--algo', 'bm', '-j', 'DROP'])
            if ok1 or ok2 or ok3 or ok4 or ok5:
                removed_count += 1
            else:
                break
        if removed_count > 0:
            return True, f"Berhasil membuka blokir IP {ip} ({removed_count} aturan dihapus)"
        return False, f"IP {ip} sudah tidak ada di daftar blokir iptables"

    return False, f"Action tidak dikenal: {action}"

def block_ip(ip):
    success, msg = execute_iptables_cmd('-I', ip)
    if success:
        logger.info(msg)
    else:
        logger.error(f"Gagal blokir IP {ip}: {msg}")
    return success, msg

def extract_real_ip(req_dict):
    """Ambil IP publik asli klien dari Caddy log (client_ip, Cf-Connecting-Ip, XFF, remote_ip)."""
    client_ip = req_dict.get('client_ip')
    if client_ip and client_ip not in ('127.0.0.1', '::1', '-'):
        return client_ip.strip()

    headers = req_dict.get('headers', {})
    if 'Cf-Connecting-Ip' in headers and headers['Cf-Connecting-Ip']:
        cf_ip = headers['Cf-Connecting-Ip'][0].strip()
        if cf_ip and cf_ip not in ('127.0.0.1', '::1'):
            return cf_ip

    if 'X-Forwarded-For' in headers and headers['X-Forwarded-For']:
        xff = headers['X-Forwarded-For'][0].split(',')[0].strip()
        if xff and xff not in ('127.0.0.1', '::1'):
            return xff

    remote_ip = req_dict.get('remote_ip', '-')
    if remote_ip and ':' in remote_ip and not remote_ip.startswith('['):
        remote_ip = remote_ip.split(':')[0].strip()
    return remote_ip

def local_tactical_ai_analysis(ip, domain, uri, pattern, body=""):
    """
    Mesin Analisis Taktis Lokal (Edge Heuristic AI Engine) sebagai fallback otomatis
    ketika Cloud Gemini API sedang mengalami lonjakan trafik (503) atau kehabisan kuota.
    """
    combined = f"{uri} {body}".lower()
    endpoint = uri.split('?')[0] if uri else '/'

    if any(k in combined for k in ('union', 'select', 'insert', 'drop', 'update', 'delete', '--', 'cast', 'exec')) or 'select' in pattern.lower():
        sub_tech = "UNION-Based Data Exfiltration" if "union" in combined else "Authentication Bypass / Query Manipulation"
        return (
            f"• Tipe: SQL Injection ({sub_tech} - CWE-89)\n"
            f"• Tingkat Bahaya: 🔴 KRITIS\n"
            f"• Taktik: Penyerang ({ip}) menyisipkan klausa SQL berbahaya pada endpoint `{endpoint}` untuk memanipulasi kueri dan mengekstrak struktur database `{domain}`.\n"
            f"• Saran Taktis AI: Isolasi IP `{ip}` segera via tombol Blokir (iptables DROP) dan pastikan kueri menggunakan Prepared Statements."
        )
    elif any(k in combined for k in ('<script', 'javascript:', 'onerror', 'onload', '<iframe', 'document.cookie')) or 'script' in pattern.lower():
        return (
            f"• Tipe: Cross-Site Scripting / XSS (CWE-79)\n"
            f"• Tingkat Bahaya: 🟠 TINGGI\n"
            f"• Taktik: Penyerang ({ip}) mencoba menyuntikkan skrip berbahaya pada `{endpoint}` untuk membajak sesi pengguna atau mencuri token autentikasi.\n"
            f"• Saran Taktis AI: Blokir IP `{ip}` pada firewall kernel dan terapkan sanitasi HTML serta Content-Security-Policy (CSP)."
        )
    elif any(k in combined for k in ('/etc/passwd', '/etc/shadow', 'boot.ini', 'config')) or 'passwd' in pattern.lower():
        return (
            f"• Tipe: Local File Inclusion / LFI (CWE-98)\n"
            f"• Tingkat Bahaya: 🔴 KRITIS\n"
            f"• Taktik: Penyerang ({ip}) berupaya membaca berkas konfigurasi/kredensial sistem operasi secara langsung melalui parameter pada `{endpoint}`.\n"
            f"• Saran Taktis AI: Lakukan penangkalan instan (iptables DROP) terhadap IP `{ip}` dan batasi akses direktori sistem."
        )
    elif '..' in combined or '..' in pattern:
        return (
            f"• Tipe: Path / Directory Traversal (CWE-22)\n"
            f"• Tingkat Bahaya: 🟠 TINGGI\n"
            f"• Taktik: Penyerang ({ip}) mencoba keluar dari direktori web root pada `{endpoint}` untuk mengakses berkas internal server `{domain}`.\n"
            f"• Saran Taktis AI: Blokir IP `{ip}` segera dan validasi path input menggunakan whitelist."
        )
    elif any(k in combined for k in ('cmd=', ';', '|', '&&')) or 'cmd=' in pattern.lower():
        return (
            f"• Tipe: OS Command Injection / RCE (CWE-78)\n"
            f"• Tingkat Bahaya: 🔴 KRITIS\n"
            f"• Taktik: Penyerang ({ip}) berupaya mengeksekusi perintah shell sistem operasi dari jarak jauh melalui `{endpoint}`.\n"
            f"• Saran Taktis AI: Putuskan koneksi IP `{ip}` pada level kernel (iptables DROP) dan audit hak akses service web."
        )
    elif any(k in combined for k in ('.env', '.git', '.svn', '.htaccess', '.aws', '.ssh', 'wp-config', '.sql', '.bak', 'phpmyadmin', 'adminer', 'storage/', 'vendor/phpunit')):
        return (
            f"• Tipe: Sensitive File & Credential Exposure Probe (CWE-538 / CWE-200)\n"
            f"• Tingkat Bahaya: 🔴 KRITIS\n"
            f"• Taktik: Penyerang ({ip}) mencoba mengunduh berkas konfigurasi rahasia (`{endpoint}`) untuk mencuri kredensial database, API key, atau kode sumber `{domain}`.\n"
            f"• Saran Taktis AI: Blokir IP `{ip}` secara permanen di level kernel (iptables DROP) karena ini adalah indikasi kuat pemindaian pencurian data."
        )
    elif endpoint.lower().endswith('.php') and 'index.php' not in endpoint.lower():
        return (
            f"• Tipe: Webshell / Backdoor PHP Recon Probe (CWE-434 / CWE-284)\n"
            f"• Tingkat Bahaya: 🟠 TINGGI\n"
            f"• Taktik: Penyerang ({ip}) memindai keberadaan berkas backdoor atau skrip PHP terlarang (`{endpoint}`) pada server `{domain}`.\n"
            f"• Saran Taktis AI: Blokir IP `{ip}` melalui tombol Blokir (iptables DROP) untuk menghentikan pemindaian direktori."
        )
    elif 'user-agent' in pattern.lower() or any(k in combined for k in ('sqlmap', 'nikto', 'nuclei', 'nmap', 'gobuster', 'dirbuster', 'ffuf', 'wpscan', 'curl/', 'wget/', 'python-requests')):
        return (
            f"• Tipe: Automated Vulnerability Scanner / Recon Bot (MITRE T1595)\n"
            f"• Tingkat Bahaya: 🟠 TINGGI\n"
            f"• Taktik: Penyerang ({ip}) menggunakan perangkat pemindai otomatis (`{pattern}`) terhadap `{endpoint}` untuk mencari celah keamanan pada `{domain}`.\n"
            f"• Saran Taktis AI: Isolasi IP `{ip}` segera di level firewall kernel (iptables DROP) sebelum pemindaian berlanjut ke tahap eksploitasi."
        )
    elif any(k in combined for k in ('169.254.169.254', 'metadata.google', '${jndi:', '{{')):
        return (
            f"• Tipe: SSRF / Remote Template & JNDI Injection (CWE-918 / CWE-94)\n"
            f"• Tingkat Bahaya: 🔴 KRITIS\n"
            f"• Taktik: Penyerang ({ip}) berupaya memaksa server `{domain}` mengakses metadata internal atau mengeksekusi kode jarak jauh pada `{endpoint}`.\n"
            f"• Saran Taktis AI: Blokir IP `{ip}` secara permanen via iptables DROP dan perketat filter keluar (egress) server."
        )
    elif 'ddos' in pattern.lower() or 'traffic' in pattern.lower():
        return (
            f"• Tipe: Volumetric HTTP Flood / Indikasi DDoS (CWE-400 / MITRE T1499)\n"
            f"• Tingkat Bahaya: 🟠 TINGGI\n"
            f"• Taktik: IP `{ip}` mendominasi lonjakan trafik dinamis ke `{endpoint}` pada `{domain}` yang berpotensi menguras sumber daya server.\n"
            f"• Saran Taktis AI: Verifikasi apakah `{ip}` adalah jaringan kantor/ISP pegawai; jika murni bot/flood, konfirmasi blokir via iptables DROP."
        )
    else:
        return (
            f"• Tipe: Anomali Eksploitasi Web / Remote Probe (CWE-20)\n"
            f"• Tingkat Bahaya: 🟠 TINGGI\n"
            f"• Taktik: Penyerang ({ip}) mengirimkan muatan mencurigakan ke `{endpoint}` yang memicu sensor deteksi pola pada `{domain}`.\n"
            f"• Saran Taktis AI: Pantau atau blokir IP `{ip}` melalui iptables untuk mencegah eskalasi serangan."
        )

def analyze_threat_with_ai(ip, domain, uri, pattern, body=""):
    """
    Analisis ancaman menggunakan Hybrid AI (Cloud Google Gemini + Local Edge Tactical Fallback).
    Menjamin ketersediaan analisis 100% meskipun API Cloud mengalami lonjakan 503 atau kuota habis.
    """
    if not AI_ENABLED:
        return None

    # Bersihkan body dari kata sandi jika ada
    clean_body = re.sub(r'(?i)(password|pass|pwd|secret)=([^&]*)', r'\1=******', body or '')
    if len(clean_body) > 300:
        clean_body = clean_body[:300] + "..."

    prompt = (
        "Kamu adalah Cyber Threat Intelligence AI untuk Pusat Pertahanan Siber (Pussiberad TNI AD / CSIRT Nasional).\n"
        "Analisis temuan serangan berikut secara ringkas, padat, taktis, dan profesional dalam Bahasa Indonesia:\n"
        f"- Target Domain: {domain}\n"
        f"- IP Penyerang: {ip}\n"
        f"- URI: {uri}\n"
        f"- Pola Regex Terdeteksi: {pattern}\n"
        f"- Payload Body: {clean_body or '(tidak ada)'}\n\n"
        "Format balasan WAJIB persis seperti berikut (maksimal 4 baris, tanpa salam/basa-basi):\n"
        "• Tipe: [Nama Serangan & CWE jika relevan]\n"
        "• Tingkat Bahaya: [🔴 KRITIS / 🟠 TINGGI / 🟡 SEDANG]\n"
        "• Taktik: [1 kalimat motif dan dampak penyerang]\n"
        "• Saran Taktis AI: [1 kalimat aksi mitigasi spesifik]"
    )

    models_to_try = [
        "gemini-flash-latest",
        "gemini-flash-lite-latest",
        "gemma-4-31b-it",
        "gemini-3.5-flash",
        "gemini-3.5-flash-lite",
        AI_MODEL,
        "gemini-3.6-flash",
        "gemini-3.8-flash"
    ]
    seen = set()
    models = [m for m in models_to_try if m and not (m in seen or seen.add(m))]

    payload = {
        "contents": [{"parts": [{"text": prompt}]}]
    }

    if GEMINI_KEY:
        for model_name in models:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={GEMINI_KEY}"
            try:
                logger.info(f"Mengirim analisis ancaman ke Gemini AI model {model_name}...")
                res = requests.post(
                    url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=6.0
                )
                if res.status_code == 200:
                    data = res.json()
                    candidates = data.get("candidates", [])
                    if candidates:
                        parts = candidates[0].get("content", {}).get("parts", [])
                        if parts:
                            ai_text = parts[0].get("text", "").strip()
                            if ai_text:
                                logger.info(f"Analisis AI sukses didapatkan dari Cloud ({model_name})!")
                                return ai_text
                else:
                    logger.warning(f"Gemini API ({model_name}) status {res.status_code}: mencoba model berikutnya...")
                    continue
            except Exception as e:
                logger.warning(f"Gemini AI ({model_name}) error: {e}")
                continue

    logger.info("Mengaktifkan Local Edge Tactical AI Engine (Fallback Anti-503)...")
    return local_tactical_ai_analysis(ip, domain, uri, pattern, body)

THREAT_CACHE = {}

def send_alert_with_button(ip, alert, show_ai=False, already_blocked=False):
    url = f'https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage'
    if already_blocked:
        buttons = [{'text': '✅ IP Diblokir Otomatis', 'callback_data': f'blocked_done:{ip}'}]
    else:
        buttons = [{'text': '🔒 Blokir IP Ini', 'callback_data': f'blockip:{ip}'}]
    if show_ai and AI_ENABLED:
        buttons.append({'text': '🧠 Minta Analisis AI', 'callback_data': f'askai:{ip}'})

    keyboard = {
        'inline_keyboard': [buttons]
    }
    payload = {
        'chat_id': CHAT_ID,
        'text': alert,
        'parse_mode': 'Markdown',
        'reply_markup': json.dumps(keyboard)
    }

    try:
        response = requests.post(url, data=payload, timeout=5)
        response.raise_for_status()
        logger.info(f"Alert Telegram sukses terkirim untuk IP {ip}")
    except requests.RequestException as e:
        logger.warning(f"Pengiriman Markdown gagal ({e}), mencoba fallback plain text...")
        payload.pop('parse_mode', None)
        try:
            res_plain = requests.post(url, data=payload, timeout=5)
            res_plain.raise_for_status()
            logger.info(f"Alert Telegram (Plain Text) sukses terkirim untuk IP {ip}")
        except Exception as e2:
            logger.error(f"Gagal mengirim alert ke Telegram: {e2}")

def format_pattern_label(pattern, matched_str=""):
    """Ubah regex panjang menjadi label ancaman ringkas & rapi agar Markdown Telegram tidak pernah rusak."""
    snippet = re.sub(r'[`*_~\[\]\n\r]', '', (matched_str or '').strip())[:35]
    p_low = pattern.lower()
    if 'union' in p_low or 'select' in p_low:
        base = "SQL Injection (CWE-89)"
    elif '<script' in p_low or 'onerror' in p_low:
        base = "XSS Payload (CWE-79)"
    elif '\\.\\.[' in p_low or '%2e%2e' in p_low:
        base = "Path Traversal (CWE-22)"
    elif 'cmd=' in p_low or 'shell_exec' in p_low:
        base = "Command Injection / RCE (CWE-78)"
    elif '/etc/passwd' in p_low or 'boot\\.ini' in p_low:
        base = "Local File Inclusion / LFI (CWE-98)"
    elif 'https?://' in p_low:
        base = "Remote File Inclusion / RFI"
    elif '\\.env' in p_low or 'wp-config' in p_low:
        base = "Sensitive File Probe (CWE-538)"
    elif 'index\\.php' in p_low:
        base = "Unauthorized PHP / Backdoor Probe"
    elif '169\\.254' in p_low or 'jndi:' in p_low:
        base = "SSRF / Log4Shell Exploit"
    else:
        base = "Suspicious Exploit Pattern"
    return f"{base} [{snippet}]" if snippet else base       
def monitor_caddy_log(log_path, domain_label, is_auto_block_fn):
    """Monitor Caddy JSON logs for suspicious activity."""
    logger.info(f"Starting log monitoring for {domain_label} ({log_path})...")
    request_times = deque()
    last_alert_time = 0

    try:
        process = subprocess.Popen(['tail', '-F', log_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        logger.error(f"Log file {log_path} not found or 'tail' command unavailable")
        return

    for line in iter(process.stdout.readline, b''):
        try:
            log_entry = json.loads(line.decode())
            if log_entry.get('request'):
                now = time.time()
                req_obj = log_entry['request']
                ip = extract_real_ip(req_obj)
                raw_uri = req_obj.get('uri', '')
                raw_body = req_obj.get('body', '')
                uri = re.sub(r'(?i)(password|pass|pwd|passwd|secret)=([^&]*)', r'\1=******', raw_uri)
                body = re.sub(r'(?i)(password|pass|pwd|passwd|secret)=([^&]*)', r'\1=******', raw_body)
                headers = req_obj.get('headers', {})
                ua_list = headers.get('User-Agent', [])
                user_agent = ua_list[0] if ua_list else ''

                uri_parts = uri.split('?', 1)
                req_path = uri_parts[0]
                req_query = uri_parts[1] if len(uri_parts) > 1 else ''
                is_static = is_static_asset_path(req_path) or 'multiple-select' in uri.lower()

                # Hanya hitung request halaman dinamis (bukan file statis .css/.js/.png/.jpg)
                # agar pegawai yang memuat banyak gambar/script saat buka web tidak memicu alarm DDoS palsu
                if not is_static:
                    request_times.append((now, ip, req_path or '/'))

                # Clean up deque (hapus entri yang lebih tua dari CHECK_INTERVAL)
                while request_times and now - request_times[0][0] > CHECK_INTERVAL:
                    request_times.popleft()

                count = len(request_times)

                # Detect high traffic / DDoS berdasarkan Top IP Dominan (Opsi 3)
                if not is_static and count >= REQUEST_THRESHOLD and now - last_alert_time > CHECK_INTERVAL:
                    ip_counts = Counter(item[1] for item in request_times)
                    top_ip, top_ip_count = ip_counts.most_common(1)[0]
                    uri_counts = Counter(item[2] for item in request_times if item[1] == top_ip)
                    top_uri = uri_counts.most_common(1)[0][0] if uri_counts else (req_path or '/')
                    pct = int((top_ip_count / count) * 100) if count else 0

                    _, geo_label = is_foreign_ip(top_ip)
                    THREAT_CACHE[top_ip] = {
                        'domain': domain_label,
                        'uri': top_uri,
                        'pattern': f'DDoS / High Traffic ({top_ip_count}/{count} req/{CHECK_INTERVAL}s)',
                        'body': f"Top Offender IP: {top_ip} ({top_ip_count} dari {count} req dalam {CHECK_INTERVAL} detik)"
                    }
                    msg = (
                        f"🚨 *Traffic Tinggi / Indikasi DDoS Terdeteksi*\n"
                        f"🌐 Domain: `{domain_label}`\n"
                        f"🕒 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                        f"📍 Top IP Dominan: `{top_ip}` ({geo_label})\n"
                        f"📊 Kontribusi IP: `{top_ip_count} dari {count} req/{CHECK_INTERVAL} detik ({pct}%)`\n"
                        f"🔗 Target URI Dominan: `{top_uri}`"
                    )
                    logger.info(msg)
                    send_alert_with_button(top_ip, msg, show_ai=True)
                    last_alert_time = now

                # Pengecualian mutlak untuk file statis / plugin (seperti multiple-select.js)
                if is_static:
                    # Jika asset statis membawa query string (?v=123), periksa HANYA query string-nya
                    if req_query:
                        target_to_check = req_query
                    else:
                        target_to_check = ''
                else:
                    target_to_check = uri

                matched_pattern = None
                is_critical_hit = False
                if target_to_check or body:
                    from urllib.parse import unquote_plus
                    decoded_target = unquote_plus(target_to_check) if target_to_check else ''
                    decoded_body = unquote_plus(body) if body else ''
                    # Cek Level 1 (CRITICAL_PATTERNS) terlebih dahulu
                    for pattern in CRITICAL_PATTERNS:
                        m = (re.search(pattern, decoded_target, re.IGNORECASE) if decoded_target else None) or (re.search(pattern, decoded_body, re.IGNORECASE) if decoded_body else None)
                        if m:
                            matched_pattern = format_pattern_label(pattern, m.group(0))
                            is_critical_hit = True
                            break
                    # Jika belum kena Level 1, cek Level 2 (MEDIUM_HIGH_PATTERNS: SQLi/XSS Kontekstual)
                    if not matched_pattern:
                        for pattern in MEDIUM_HIGH_PATTERNS:
                            m = (re.search(pattern, decoded_target, re.IGNORECASE) if decoded_target else None) or (re.search(pattern, decoded_body, re.IGNORECASE) if decoded_body else None)
                            if m:
                                matched_pattern = format_pattern_label(pattern, m.group(0))
                                is_critical_hit = False
                                break

                # Deteksi Scanner / Bot Berbahaya dari User-Agent (sqlmap, nikto, nuclei, curl, wget, dll) -> Level 1 KRITIS
                if not matched_pattern and user_agent:
                    m_ua = BAD_USER_AGENT_PATTERN.search(user_agent)
                    if m_ua:
                        matched_pattern = f"Scanner User-Agent ({m_ua.group(1)})"
                        is_critical_hit = True

                if matched_pattern:
                    is_foreign, geo_label = is_foreign_ip(ip)
                    # Tambah hitungan pelanggaran (Strike Counter) untuk IP ini
                    STRIKE_COUNTER[ip] = STRIKE_COUNTER.get(ip, 0) + 1
                    strikes = STRIKE_COUNTER[ip]

                    # Adaptive Risk-Based Threshold:
                    # - Pola KRITIS (Level 1) -> Limit 3x (Semua IP)
                    # - IP Luar Negeri (Non-ID) -> Limit 3x (Semua Level)
                    # - IP Indonesia + Pola Medium/High (SQLi/XSS Teks) -> Toleransi 10x
                    if is_critical_hit:
                        effective_limit = STRIKE_LIMIT_CRITICAL
                        severity_badge = "🔴 KRITIS (Limit 3x)"
                    elif is_foreign:
                        effective_limit = STRIKE_LIMIT_FOREIGN
                        severity_badge = "🌍 IP LUAR NEGERI (Limit 3x)"
                    else:
                        effective_limit = STRIKE_LIMIT_ID_MEDIUM
                        severity_badge = "🟠 MEDIUM/HIGH - IP Indonesia (Toleransi 10x)"

                    # Simpan konteks ancaman untuk On-Demand AI Copilot
                    THREAT_CACHE[ip] = {
                        'domain': domain_label,
                        'uri': uri,
                        'pattern': matched_pattern,
                        'body': body or (f"User-Agent: {user_agent[:120]}" if user_agent else "")
                    }

                    # Jika Auto-Block aktif DAN jumlah serangan sudah mencapai effective_limit (3x atau 10x):
                    # SELALU panggil block_ip(ip) tanpa terhalang cache SUSPICIOUS_IPS agar aturan iptables
                    # di kernel dipastikan benar-benar terpasang pada baris #1!
                    auto_blocked_now = False
                    if is_auto_block_fn() and strikes >= effective_limit:
                        ok_blk, msg_blk = block_ip(ip)
                        add_to_blacklist(ip)
                        if ok_blk:
                            auto_blocked_now = True
                            status_line = f"🚨 *Status Auto-Block:* `AKTIF — Strike {strikes}/{effective_limit} (IP LANGSUNG DIBLOKIR IPTABLES!)`"
                        else:
                            status_line = f"⚠️ *Status Auto-Block:* `Strike {strikes}/{effective_limit} (Gagal Auto-Block: {msg_blk} — Silakan Klik Tombol Blokir)`"
                    else:
                        mode_str = "ON" if is_auto_block_fn() else "OFF"
                        status_line = f"⚡ *Hitungan Serangan:* `Strike {strikes}/{effective_limit}` (Auto-Block: {mode_str})"

                    alert = (
                        f"⚠️ *Pola Mencurigakan Terdeteksi*\n"
                        f"🌐 Domain: `{domain_label}`\n"
                        f"🕒 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                        f"📍 IP: `{ip}` ({geo_label})\n"
                        f"🛡️ Level Risiko: `{severity_badge}`\n"
                        f"🔗 URI: `{uri}`\n"
                        f"📝 Body/Info: `{(body or user_agent or '-')[:250]}`\n"
                        f"🔍 Pattern: `{matched_pattern}`\n"
                        f"{status_line}"
                    )
                    logger.info(alert)
                    send_alert_with_button(ip, alert, show_ai=True, already_blocked=auto_blocked_now)

        except json.JSONDecodeError:
            continue
        except Exception as e:
            logger.error(f"Error processing log [{domain_label}]: {e}")

def monitor_requests():
    monitor_caddy_log(LOG_FILE, "sangiran.xyz", lambda: AUTO_BLOCK_ENABLED)

def monitor_requests_id():
    monitor_caddy_log(LOG_FILE_ID, "sangiran.id", lambda: AUTO_BLOCK_ENABLED_ID)

async def handle_block_button(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    user_id = update.effective_user.id if update.effective_user else None
    chat_id = update.effective_chat.id if update.effective_chat else None

    # Izinkan jika user_id sesuai ATAU pesan berada di chat_id yang terdaftar
    is_admin = (not OWNER_ID) or (user_id == OWNER_ID) or (chat_id == OWNER_ID)
    if not is_admin:
        await query.answer(f"❌ Akses ditolak! ID Anda ({user_id}) bukan admin ({OWNER_ID}).", show_alert=True)
        return

    if not query.data:
        await query.answer()
        return

    if query.data.startswith("blocked_done"):
        parts = query.data.split(":", 1)
        if len(parts) == 2 and parts[1].strip():
            chk_ip = parts[1].strip()
            ok, _ = execute_iptables_cmd('-I', chk_ip)
            if ok:
                add_to_blacklist(chk_ip)
                await query.answer(f"✅ Terverifikasi: IP {chk_ip} aktif diblokir di baris #1 iptables!", show_alert=True)
                return
        await query.answer("ℹ️ IP ini sudah diblokir di iptables.", show_alert=False)
        return

    old_text = query.message.text or ""
    has_ai_done = "ANALISIS INTELIJEN AI" in old_text

    # LANGKAH 1: Konfirmasi 2-Langkah saat tombol "🔒 Blokir IP Ini" diklik (Mencegah Salah Pencet!)
    if query.data.startswith("blockip:"):
        ip = query.data.split(":", 1)[1].strip()
        await query.answer(f"⚠️ Konfirmasi diperlukan sebelum memblokir IP {ip}", show_alert=False)
        rows = [[
            InlineKeyboardButton(f"⚠️ Yakin Blokir {ip}?", callback_data=f"confirmblock:{ip}"),
            InlineKeyboardButton("❌ Batal", callback_data=f"cancelblock:{ip}")
        ]]
        if AI_ENABLED:
            if has_ai_done:
                rows.append([InlineKeyboardButton("✅ Analisis Selesai", callback_data="ai_done")])
            else:
                rows.append([InlineKeyboardButton("🧠 Minta Analisis AI", callback_data=f"askai:{ip}")])
        try:
            await query.edit_message_reply_markup(reply_markup=InlineKeyboardMarkup(rows))
        except Exception:
            pass
        return

    # BATAL BLOKIR: Kembalikan ke tampilan tombol semula jika admin menekan "❌ Batal"
    if query.data.startswith("cancelblock:"):
        ip = query.data.split(":", 1)[1].strip()
        await query.answer(f"✅ Dibatalkan! IP {ip} tidak jadi diblokir.", show_alert=False)
        buttons = [InlineKeyboardButton("🔒 Blokir IP Ini", callback_data=f"blockip:{ip}")]
        if AI_ENABLED:
            if has_ai_done:
                buttons.append(InlineKeyboardButton("✅ Analisis Selesai", callback_data="ai_done"))
            else:
                buttons.append(InlineKeyboardButton("🧠 Minta Analisis AI", callback_data=f"askai:{ip}"))
        try:
            await query.edit_message_reply_markup(reply_markup=InlineKeyboardMarkup([buttons]))
        except Exception:
            pass
        return

    if not query.data.startswith("confirmblock:"):
        await query.answer()
        return

    # LANGKAH 2: Eksekusi iptables DROP setelah admin mengonfirmasi "⚠️ Yakin Blokir"
    ip = query.data.split(":", 1)[1].strip()

    try:
        # Beri respon instan agar tombol tidak berputar/loading di layar Telegram
        await query.answer(f"⏳ Memproses blokir IP {ip} di iptables...", show_alert=False)

        success, msg = execute_iptables_cmd('-I', ip)

        if success:
            add_to_blacklist(ip)
            updated_text = old_text + f"\n\n🔒 Status: IP {ip} BERHASIL DIBLOKIR oleh admin."
            buttons = [InlineKeyboardButton("✅ IP Telah Diblokir", callback_data=f"blocked_done:{ip}")]
            if not has_ai_done and AI_ENABLED:
                buttons.append(InlineKeyboardButton("🧠 Minta Analisis AI", callback_data=f"askai:{ip}"))
            new_keyboard = InlineKeyboardMarkup([buttons])
            try:
                await query.edit_message_text(updated_text, reply_markup=new_keyboard)
            except Exception:
                pass
        else:
            await query.answer(f"⚠️ Gagal blokir: {msg}", show_alert=True)
            logger.error(f"Gagal blokir IP {ip}: {msg}")
    except Exception as e:
        logger.error(f"Exception di handle_block_button: {e}")
        try:
            await query.answer(f"⚠️ Terjadi error: {e}", show_alert=True)
        except Exception:
            pass

async def handle_ai_button(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    user_id = update.effective_user.id if update.effective_user else None
    chat_id = update.effective_chat.id if update.effective_chat else None

    is_admin = (not OWNER_ID) or (user_id == OWNER_ID) or (chat_id == OWNER_ID)
    if not is_admin:
        await query.answer(f"❌ Akses ditolak! ID Anda ({user_id}) bukan admin.", show_alert=True)
        return

    if query.data in ("ai_loading", "ai_done"):
        await query.answer()
        return

    if not query.data or not query.data.startswith("askai:"):
        await query.answer()
        return

    ip = query.data.split(":", 1)[1].strip()
    old_text = query.message.text or ""

    threat = THREAT_CACHE.get(ip, {})
    domain = threat.get('domain', '')
    uri = threat.get('uri', '')
    pattern = threat.get('pattern', '')
    body = threat.get('body', '')

    # Ekstrak langsung dari teks pesan Telegram jika alert berasal dari WAF Go atau cache belum terisi
    if not uri or "WAF Go" in old_text:
        m_host = re.search(r'(?:Domain|Host):\s*([^\n]+)', old_text)
        m_uri = re.search(r'URI:\s*([^\n]+)', old_text)
        m_body = re.search(r'Body:\s*([^\n]+)', old_text)
        m_pat = re.search(r'Pattern:\s*([^\n]+)', old_text)
        if m_host:
            domain = m_host.group(1).strip(' `')
        if m_uri:
            uri = m_uri.group(1).strip(' `')
        if m_body:
            body = m_body.group(1).strip(' `')
        if m_pat:
            pattern = m_pat.group(1).strip(' `')

    domain = domain or 'sangiran.xyz'
    uri = uri or '/'
    pattern = pattern or 'Pola Mencurigakan'

    await query.answer("🧠 Mengontak Gemini AI SOC Threat Copilot...", show_alert=False)

    is_blocked = ("BERHASIL DIBLOKIR" in old_text) or ("DIBLOKIR IPTABLES" in old_text) or (ip in SUSPICIOUS_IPS)

    # Update tampilan tombol menjadi loading
    block_btn = InlineKeyboardButton("✅ IP Telah Diblokir", callback_data=f"blocked_done:{ip}") if is_blocked else InlineKeyboardButton("🔒 Blokir IP Ini", callback_data=f"blockip:{ip}")
    loading_kb = InlineKeyboardMarkup([[
        block_btn,
        InlineKeyboardButton("⏳ AI Sedang Menganalisis...", callback_data="ai_loading")
    ]])
    try:
        await query.edit_message_reply_markup(reply_markup=loading_kb)
    except Exception:
        pass

    # Panggil Gemini AI secara asinkron di worker thread (non-blocking)
    loop = asyncio.get_running_loop()
    ai_text = await loop.run_in_executor(None, analyze_threat_with_ai, ip, domain, uri, pattern, body)

    if ai_text:
        updated_text = (
            f"{old_text}\n\n"
            f"🧠 --- ANALISIS INTELIJEN AI (GEMINI SOC) ---\n"
            f"{ai_text}"
        )
        done_kb = InlineKeyboardMarkup([[
            block_btn,
            InlineKeyboardButton("✅ Analisis Selesai", callback_data="ai_done")
        ]])
        try:
            await query.edit_message_text(updated_text, parse_mode="Markdown", reply_markup=done_kb)
        except Exception:
            await query.edit_message_text(updated_text, reply_markup=done_kb)
    else:
        await query.answer("⚠️ Google Gemini API sedang sibuk (503). Silakan klik ulang dalam beberapa detik.", show_alert=True)
        retry_kb = InlineKeyboardMarkup([[
            block_btn,
            InlineKeyboardButton("🧠 Coba Analisis AI Lagi", callback_data=f"askai:{ip}")
        ]])
        try:
            await query.edit_message_reply_markup(reply_markup=retry_kb)
        except Exception:
            pass

async def unblock_ip_iptables(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if OWNER_ID and update.effective_user.id != OWNER_ID:
        await update.message.reply_text("❌ Akses ditolak.")
        return

    if len(context.args) != 1:
        await update.message.reply_text("Usage: /unblock <ip>")
        return

    ip = context.args[0].strip()
    STRIKE_COUNTER.pop(ip, None)
    remove_from_blacklist(ip)
    success, msg = execute_iptables_cmd('-D', ip)
    if success:
        await update.message.reply_text(f"✅ IP `{ip}` berhasil di-unblock, dihapus dari blacklist, dan hitungan Strike di-reset ke 0.", parse_mode="Markdown")
    else:
        await update.message.reply_text(f"⚠️ Info unblock IP `{ip}`: {msg} (Hitungan Strike & Blacklist sudah di-reset ke 0)")

async def block_ip_iptables(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if OWNER_ID and update.effective_user.id != OWNER_ID:
        await update.message.reply_text("❌ Akses ditolak.")
        return

    if len(context.args) != 1:
        await update.message.reply_text("Usage: /block <ip>")
        return

    ip = context.args[0].strip()
    success, msg = execute_iptables_cmd('-I', ip)
    if success:
        add_to_blacklist(ip)
        await update.message.reply_text(f"✅ IP `{ip}` berhasil diblokir.", parse_mode="Markdown")
    else:
        await update.message.reply_text(f"⚠️ Gagal blokir IP `{ip}`: {msg}")

async def autoblock_on(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global AUTO_BLOCK_ENABLED
    if update.effective_user.id != OWNER_ID:
        await update.message.reply_text("❌")
        return
    AUTO_BLOCK_ENABLED = True
    await update.message.reply_text(
        f"✅ Adaptive Smart Auto-Block DIHIDUPKAN:\n"
        f"• Pola KRITIS / Scanner: {STRIKE_LIMIT_CRITICAL}x Strike langsung blokir\n"
        f"• IP Luar Negeri: {STRIKE_LIMIT_FOREIGN}x Strike langsung blokir\n"
        f"• IP Indonesia (SQLi/XSS Teks): Toleransi {STRIKE_LIMIT_ID_MEDIUM}x Strike"
    )

async def autoblock_off(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global AUTO_BLOCK_ENABLED
    if update.effective_user.id != OWNER_ID:
        await update.message.reply_text("❌")
        return
    AUTO_BLOCK_ENABLED = False
    await update.message.reply_text("🛑 Smart Auto-Block DIMATIKAN (Hanya mengirim peringatan & tombol blokir manual).")
async def autoblock_on_id(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global AUTO_BLOCK_ENABLED_ID
    if update.effective_user.id != OWNER_ID:
        await update.message.reply_text("❌")
        return
    AUTO_BLOCK_ENABLED_ID = True
    await update.message.reply_text(
        f"✅ Adaptive Smart Auto-Block sangiran.id DIHIDUPKAN "
        f"(Kritis/Luar Negeri: {STRIKE_LIMIT_CRITICAL}x | IP Indonesia Medium: {STRIKE_LIMIT_ID_MEDIUM}x)."
    )

async def autoblock_off_id(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global AUTO_BLOCK_ENABLED_ID
    if update.effective_user.id != OWNER_ID:
        await update.message.reply_text("❌")
        return
    AUTO_BLOCK_ENABLED_ID = False
    await update.message.reply_text("🛑 Smart Auto-Block sangiran.id DIMATIKAN.")    
def start_telegram_bot():
    try:
        app = Application.builder().token(TELEGRAM_TOKEN).build()
        app.add_handler(CommandHandler("unblock", unblock_ip_iptables))
        app.add_handler(CommandHandler("block", block_ip_iptables))
        app.add_handler(CommandHandler("block_on", autoblock_on))
        app.add_handler(CommandHandler("block_off", autoblock_off))
        app.add_handler(CommandHandler("block_id_off", autoblock_off_id))
        app.add_handler(CommandHandler("block_id_on", autoblock_on_id))
        app.add_handler(CallbackQueryHandler(handle_block_button, pattern=r"^(blockip:|confirmblock:|cancelblock:|blocked_done)"))
        app.add_handler(CallbackQueryHandler(handle_ai_button, pattern=r"^(askai:|ai_loading|ai_done)"))
        logger.info("Telegram bot started")
        app.run_polling()
    except Exception as e:
        logger.error(f"Failed to start Telegram bot: {e}")
        exit(1)

# === Main ===
if __name__ == "__main__":
    # Load existing blacklist
    if os.path.exists(BLACKLIST_FILE):
        try:
            with open(BLACKLIST_FILE, 'r') as f:
                SUSPICIOUS_IPS.update(line.strip() for line in f if line.strip())
        except IOError as e:
            logger.error(f"Failed to read blacklist file: {e}")

    # Start monitoring in background
    threading.Thread(target=monitor_requests, daemon=True).start()
    
    threading.Thread(target=monitor_requests_id, daemon=True).start()

    # Start bot (sync style)
    start_telegram_bot()

