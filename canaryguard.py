import json
import time
from collections import defaultdict
import requests
import os
from datetime import datetime

# Configuration
RATE_LIMIT = 100  # Number of attempts allowed within the time window
TIME_WINDOW = 60  # Time window in seconds
BAN_DURATION = 3 * 24 * 60 * 60  # Ban duration in seconds (3 days)
LOG_FILE = '/path/to/your/opencanary.log'  # Replace with your own path
PIHOLE_API_URL = 'http://your-pihole-ip/admin/api.php'  # Replace with your Pi-hole IP
PIHOLE_API_KEY = 'your_pihole_api_key'  # Replace with your Pi-hole API key
ABUSE_IPDB_API_KEY = 'your_abuse_ipdb_api_key'  # Replace with your Abuse IPDB API key
BAN_FILE = 'banned_ips.json'
METRICS_FILE = 'metrics.json'
CANARYGUARD_LOG = 'canaryguard.log'
ARCHIVE_FOLDER = 'log_archive'
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10MB

# Data structures
attempts = defaultdict(list)
banned_ips = {}
username_frequency = defaultdict(int)
password_frequency = defaultdict(int)
repeat_offenders = defaultdict(int)
total_login_attempts = 0
unique_ips = set()
banned_ips_count = 0
ban_ip_recurrence = defaultdict(int)

def load_banned_ips():
    if os.path.exists(BAN_FILE):
        with open(BAN_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_banned_ips():
    with open(BAN_FILE, 'w') as f:
        json.dump(banned_ips, f)

def load_metrics():
    if os.path.exists(METRICS_FILE):
        with open(METRICS_FILE, 'r') as f:
            metrics = json.load(f)
            return (defaultdict(int, metrics.get('username_frequency', {})),
                    defaultdict(int, metrics.get('password_frequency', {})),
                    metrics.get('total_login_attempts', 0),
                    set(metrics.get('unique_ips', [])),
                    metrics.get('repeat_offenders', {}),
                    metrics.get('banned_ips_count', 0),
                    defaultdict(int, metrics.get('ban_ip_recurrence', {})))
    return defaultdict(int), defaultdict(int), 0, set(), defaultdict(int), 0, defaultdict(int)

def save_metrics():
    metrics = {
        'username_frequency': dict(username_frequency),
        'password_frequency': dict(password_frequency),
        'total_login_attempts': total_login_attempts,
        'unique_ips': list(unique_ips),
        'repeat_offenders': dict(repeat_offenders),
        'banned_ips_count': banned_ips_count,
        'ban_ip_recurrence': dict(ban_ip_recurrence),
        'last_update': time.time()
    }
    with open(METRICS_FILE, 'w') as f:
        json.dump(metrics, f)

def log_to_canaryguard(message):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(CANARYGUARD_LOG, 'a') as log_file:
        log_file.write(f"{timestamp} - {message}\n")
    check_log_size()

def check_log_size():
    if os.path.getsize(CANARYGUARD_LOG) > MAX_LOG_SIZE:
        archive_log()

def archive_log():
    if not os.path.exists(ARCHIVE_FOLDER):
        os.makedirs(ARCHIVE_FOLDER)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    archive_name = f"{ARCHIVE_FOLDER}/canaryguard_{timestamp}.log"
    os.rename(CANARYGUARD_LOG, archive_name)
    open(CANARYGUARD_LOG, 'w').close()  # Create a new empty log file
    log_to_canaryguard(f"Archived log to {archive_name}")

def ban_ip(ip):
    try:
        url = f"{PIHOLE_API_URL}?list=black&add={ip}&comment=CanaryGuard&auth={PIHOLE_API_KEY}"
        response = requests.get(url)
        if response.status_code == 200:
            banned_ips[ip] = time.time() + BAN_DURATION
            ban_ip_recurrence[ip] += 1
            save_banned_ips()
            log_to_canaryguard(f"Banned IP: {ip} for {BAN_DURATION / 86400} days")
        else:
            log_to_canaryguard(f"Failed to ban IP: {ip}")
    except Exception as e:
        log_to_canaryguard(f"Error banning IP: {ip}, {e}")

def unban_ip(ip):
    try:
        url = f"{PIHOLE_API_URL}?list=black&sub={ip}&auth={PIHOLE_API_KEY}"
        response = requests.get(url)
        if response.status_code == 200:
            del banned_ips[ip]
            save_banned_ips()
            log_to_canaryguard(f"Unbanned IP: {ip}")
        else:
            log_to_canaryguard(f"Failed to unban IP: {ip}")
    except Exception as e:
        log_to_canaryguard(f"Error unbanning IP: {ip}, {e}")

def report_to_abuse_ipdb(ip, details):
    try:
        url = f"https://api.abuseipdb.com/api/v2/report"
        headers = {
            'Accept': 'application/json',
            'Key': ABUSE_IPDB_API_KEY
        }
        data = {
            'ip': ip,
            'categories': '18',  # SSH
            'comment': f"Brute force attack detected: {details}"
        }
        response = requests.post(url, headers=headers, data=data)
        return response.json()
    except Exception as e:
        log_to_canaryguard(f"Error reporting to Abuse IPDB: {ip}, {e}")
        return None

def parse_log_line(line):
    try:
        log_entry = json.loads(line)
        src_ip = log_entry['src_host']
        username = log_entry['logdata'].get('USERNAME')
        password = log_entry['logdata'].get('PASSWORD')
        return src_ip, username, password
    except json.JSONDecodeError as e:
        log_to_canaryguard(f"Error parsing log line: {line}, {e}")
        return None, None, None

def process_log(last_position):
    global total_login_attempts, banned_ips_count
    with open(LOG_FILE, 'r') as f:
        f.seek(last_position)
        lines = f.readlines()
        new_position = f.tell()
        for line in lines:
            src_ip, username, password = parse_log_line(line)
            if not src_ip or (username is None and password is None):
                continue
            current_time = time.time()
            attempts[src_ip].append(current_time)
            attempts[src_ip] = [t for t in attempts[src_ip] if current_time - t < TIME_WINDOW]

            total_login_attempts += 1
            unique_ips.add(src_ip)

            if username:
                username_frequency[username] += 1
            if password:
                password_frequency[password] += 1

            log_to_canaryguard(f"SSH - IPADDRESS: {src_ip} USERNAME: {username} PASSWORD: {password}")

            if len(attempts[src_ip]) > RATE_LIMIT:
                if src_ip not in banned_ips:
                    details = f"Username: {username}, Password: {password}"
                    ban_ip(src_ip)
                    report_to_abuse_ipdb(src_ip, details)
                    repeat_offenders[src_ip] += 1
                    banned_ips_count += 1
    save_metrics()
    return new_position

def unban_expired_ips():
    current_time = time.time()
    for ip, ban_time in list(banned_ips.items()):
        if current_time > ban_time:
            unban_ip(ip)

# Load banned IPs and metrics from file on startup
banned_ips = load_banned_ips()
(username_frequency, password_frequency, total_login_attempts, unique_ips, repeat_offenders, banned_ips_count, ban_ip_recurrence) = load_metrics()
last_position = 0

while True:
    last_position = process_log(last_position)
    unban_expired_ips()
    time.sleep(10)
