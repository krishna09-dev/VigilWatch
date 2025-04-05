#!/home/krishna/VigilWatch/vigilwatch/bin/python
import os
import json
import logging
import subprocess
import time
from datetime import datetime, timedelta
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

import ldap3
import requests
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "your_secret_key")

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# Additional logger for authentication failures (Fail2Ban)
import os
import logging

# Create a local logs directory
LOG_DIR = os.path.join(os.getcwd(), "logs")
os.makedirs(LOG_DIR, exist_ok=True)
auth_log_path = os.path.join(LOG_DIR, "flask_auth.log")

# Set up the auth logger
auth_logger = logging.getLogger('flask_auth')
fh = logging.FileHandler(auth_log_path)
fh.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
auth_logger.addHandler(fh)
auth_logger.setLevel(logging.WARNING)

# Configuration
config = {
    "rate_limit_requests": 20,        # max requests per IP per minute
    "failed_login_threshold": 10,
    "download_threshold": 5,
    "alert_dedup_interval": 60,       # deduplicate alerts (seconds)
    "working_hours": (8, 18)          # normal working hours
}

# VirusTotal API key
VT_API_KEY = os.environ.get("VT_API_KEY", "<YOUR_API_KEY>")

# Quarantine directory (inside project folder)
QUARANTINE_DIR = os.path.join(os.getcwd(), "quarantine")
try:
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    logger.info(f"Using local quarantine dir: {QUARANTINE_DIR}")
except Exception as e:
    logger.error(f"Could not create quarantine dir {QUARANTINE_DIR}: {e}")

# In-memory storage
failed_logins = defaultdict(list)
alerts = []  # list of dict: {message, timestamp, severity}
ip_login_users = defaultdict(list)
user_downloads = defaultdict(list)
blocked_users = {}
ip_request_log = defaultdict(list)
last_alerts = {}
system_activity_logs = []

# Known IP addresses for each user
known_user_ips = {
    "john_doe": ["192.168.1.100"],
    "jane_doe": ["192.168.1.101"]
}

# Spam keywords
spam_keywords = ["free money", "win prize", "urgent", "click here", "lottery"]

# Thread pool for background tasks (e.g., virus scanning)
executor = ThreadPoolExecutor(max_workers=4)

# --- Rate Limiting: Token Bucket ---

class TokenBucket:
    def __init__(self, capacity, refill_rate):
        self.capacity = capacity
        self.tokens = capacity
        self.refill_rate = refill_rate
        self.last_refill = time.time()

    def consume(self, tokens=1):
        now = time.time()
        delta = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + delta * self.refill_rate)
        self.last_refill = now
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False

token_buckets = {}

def get_token_bucket(ip):
    if ip not in token_buckets:
        token_buckets[ip] = TokenBucket(config["rate_limit_requests"], config["rate_limit_requests"]/60.0)
    return token_buckets[ip]

# --- Defense Actions ---

def block_ip(ip):
    """Block traffic from the given IP using iptables."""
    try:
        subprocess.run(["sudo", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        logger.info(f"Blocked IP {ip}")
    except Exception as e:
        logger.error(f"Failed to block IP {ip}: {e}")

def lock_user_account(username):
    """Lock the user’s account in LDAP/AD. In testing mode, if the server address is invalid, log a warning instead."""
    try:
        server = ldap3.Server("ldaps://ldap.bank.local")
        conn = ldap3.Connection(server, user="cn=admin,dc=bank,dc=local", password="secret")
        if not conn.bind():
            raise Exception("LDAP bind failed")
        user_dn = f"cn={username},ou=Users,dc=bank,dc=local"
        if not conn.modify(user_dn, {'userAccountControl': [(ldap3.MODIFY_REPLACE, [514])] }):
            raise Exception("LDAP modify failed")
        conn.unbind()
        logger.info(f"Locked account for user {username}")
    except Exception as e:
        logger.warning(f"Test mode: Could not lock account for {username} (simulated lockout): {e}")

# --- Prepopulate Logs from JSON ---

def load_prepopulated_logs():
    try:
        with open("prepopulated_logs.json", "r") as f:
            data = json.load(f)
            alerts.extend(data.get("alerts", []))
            for ip, times in data.get("ip_request_log", {}).items():
                ip_request_log[ip] = [datetime.fromisoformat(ts) for ts in times]
            for ip, times in data.get("failed_logins", {}).items():
                failed_logins[ip] = [datetime.fromisoformat(ts) for ts in times]
            for ip, attempts in data.get("ip_login_users", {}).items():
                ip_login_users[ip] = [(datetime.fromisoformat(item[0]), item[1]) for item in attempts]
            for user, times in data.get("user_downloads", {}).items():
                user_downloads[user] = [datetime.fromisoformat(ts) for ts in times]
            logger.info("Prepopulated logs loaded.")
    except Exception as e:
        logger.error(f"Error loading prepopulated logs: {e}")

load_prepopulated_logs()

# --- Flask Routes ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/log', methods=['POST'])
def log_event():
    ip = request.remote_addr
    bucket = get_token_bucket(ip)
    if not bucket.consume():
        send_alert("Rate limit exceeded", "Medium", {"ip": ip})
        return jsonify({"status":"error","message":"Rate limit exceeded"}), 429
    process_event(request.json)
    return jsonify({"status":"ok"}), 200

@app.route('/system_activity', methods=['POST'])
def system_activity():
    process_system_activity(request.json)
    return jsonify({"status":"ok"}), 200

@app.route('/log_analysis', methods=['GET'])
def log_analysis():
    counts = {}
    for e in system_activity_logs:
        t = e.get("type","unknown")
        counts[t] = counts.get(t,0) + 1
    return jsonify(counts), 200

@app.route('/upload', methods=['POST'])
def upload_file():
    user = request.form.get("user")
    if not user:
        return jsonify({"status":"error","message":"User required"}), 400
    if "upload_file" not in request.files:
        return jsonify({"status":"error","message":"No file part"}), 400
    file = request.files["upload_file"]
    if not file or file.filename=="":
        return jsonify({"status":"error","message":"No file selected"}), 400

    content = file.read()
    virus = executor.submit(real_virus_scan, content).result()
    if virus:
        quarantine_file(file.filename, content)
        send_alert(f"Virus in {file.filename}", "Critical", {"user":user})
        return jsonify({"status":"alert","message":"File quarantined"}), 200
    return jsonify({"status":"success","message":"File clean"}), 200

@app.route('/alerts', methods=['GET'])
def get_alerts():
    return jsonify(alerts)

@app.route('/config', methods=['GET'])
def get_config():
    return jsonify(config)

@app.route('/config', methods=['POST'])
def update_config():
    cfg = request.json
    config.update(cfg)
    return jsonify({"status":"ok","config":config})

@app.route('/admin')
def admin_dashboard():
    def toiso(d): return {k:[ts.isoformat() for ts in v] for k,v in d.items()}
    def tologin(d): return {k:[(t.isoformat(),u) for t,u in v] for k,v in d.items()}
    return render_template('admin.html',
                           alerts=alerts,
                           ip_requests=toiso(ip_request_log),
                           failed_logins=toiso(failed_logins),
                           ip_login_users=tologin(ip_login_users),
                           user_downloads=toiso(user_downloads),
                           config=config)

# --- Event Processing & Defense Triggers ---

def process_event(e):
    t = e.get("type")
    if t=="login_attempt": process_login_attempt(e)
    elif t=="permission_change": process_permission_change(e)
    elif t=="file_access": process_file_access(e)
    elif t=="email": process_email_event(e)
    elif t=="file_upload": process_file_upload(e)

def process_login_attempt(e):
    user, ip = e["user"], e["ip"]
    ts = datetime.fromisoformat(e["timestamp"])
    if e["success"] and ip not in known_user_ips.get(user,[]):
        send_alert("Unknown-location login","Medium",{"ip":ip,"user":user})
    if not e["success"]:
        auth_logger.warning(f"LOGIN_FAILED ip={ip} user={user}")
        failed_logins[ip].append(ts)
        cutoff = ts - timedelta(minutes=1)
        failed_logins[ip] = [t for t in failed_logins[ip] if t>cutoff]
        if len(failed_logins[ip])>config["failed_login_threshold"]:
            send_alert("Brute-force attack","Critical",{"ip":ip})
    ip_login_users[ip].append((ts,user))
    cutoff = ts - timedelta(minutes=1)
    ip_login_users[ip] = [(t,u) for t,u in ip_login_users[ip] if t>cutoff]
    if len({u for _,u in ip_login_users[ip]})>1:
        send_alert("Multiple-user login","Medium",{"ip":ip})
    start,end=config["working_hours"]
    if e["success"] and not(start<=ts.hour<end):
        send_alert("Off-hours login","Low",{"user":user})

def process_permission_change(e):
    if e["new_role"]=="admin":
        send_alert("Permission escalation","Critical",{"user":e["user"]})

def process_file_access(e):
    user, ts = e["user"], datetime.fromisoformat(e["timestamp"])
    if e["access_type"]=="download":
        if user in blocked_users and ts<blocked_users[user]:
            send_alert("Download blocked","Medium",{"user":user})
            return
        user_downloads[user].append(ts)
        cutoff = ts - timedelta(minutes=1)
        user_downloads[user] = [t for t in user_downloads[user] if t>cutoff]
        if len(user_downloads[user])>config["download_threshold"]:
            blocked_users[user]=ts+timedelta(minutes=1)
            send_alert("High download rate","Critical",{"user":user})

def process_email_event(e):
    txt=(e.get("subject","")+" "+e.get("body","")).lower()
    if any(k in txt for k in spam_keywords):
        send_alert("Suspicious email","Low",{"user":e["user"]})

def process_file_upload(e):
    virus = real_virus_scan(e["content"].encode())
    if virus:
        quarantine_file(e["file"],e["content"].encode())
        send_alert("Malicious upload","Critical",{"user":e["user"]})

def process_system_activity(e):
    system_activity_logs.append(e)
    if e["type"]=="transaction":
        a=e.get("amount",0)
        send_alert("Large transaction","Critical" if a>1e6 else "Low")
    elif e["type"]=="network":
        ip=e.get("ip","")
        lvl="Medium" if not ip.startswith("10.") else "Low"
        send_alert("Network anomaly","Medium",{"ip":ip}) if lvl=="Medium" else send_alert("Network OK","Low")
    elif e["type"]=="auth":
        f=e.get("failures",0)
        send_alert("Auth failures","Critical" if f>5 else "Low")

# At the top of the file, define the EICAR signature for local testing
EICAR_SIGNATURE = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'



def real_virus_scan(file_content):
    """
    Scan binary file content using local EICAR signature check first,
    then fall back to the VirusTotal API.
    """
    # 1. Local EICAR test signature detection
    if EICAR_SIGNATURE in file_content:
        logger.info("Local EICAR test signature detected.")
        return True

    # 2. VirusTotal API scan
    headers = {"x-apikey": VT_API_KEY}
    upload_url = "https://www.virustotal.com/api/v3/files"
    files = {"file": ("uploaded_file", file_content)}
    try:
        response = requests.post(upload_url, headers=headers, files=files)
        response.raise_for_status()
    except Exception as e:
        logger.error("Error uploading file to VirusTotal: %s", e)
        return False

    analysis_id = response.json().get("data", {}).get("id")
    if not analysis_id:
        logger.error("No analysis ID returned from VirusTotal.")
        return False

    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    for _ in range(15):
        time.sleep(5)
        try:
            analysis_response = requests.get(analysis_url, headers=headers)
            analysis_response.raise_for_status()
        except Exception as e:
            logger.error("Error polling VirusTotal analysis: %s", e)
            continue

        data = analysis_response.json().get("data", {}).get("attributes", {})
        if data.get("status") == "completed":
            stats = data.get("stats", {})
            malicious_count = stats.get("malicious", 0)
            logger.info("VirusTotal detected %d malicious engines.", malicious_count)
            return malicious_count > 0

    logger.warning("VirusTotal analysis did not complete in time.")
    return False


def quarantine_file(name,content):
    path=os.path.join(QUARANTINE_DIR,name)
    with open(path,"wb") as f: f.write(content)

def save_alerts_to_file():
    try:
        with open("prepopulated_logs.json","w") as f:
            json.dump({"alerts":alerts},f,indent=2)
    except: pass

def send_alert(msg,severity="Low",meta=None):
    now=datetime.now()
    last=last_alerts.get(msg)
    if last and (now-last).seconds<config["alert_dedup_interval"]:
        return
    last_alerts[msg]=now
    alert={"message":msg,"timestamp":now.isoformat(),"severity":severity}
    logger.info("ALERT: %s",alert)
    alerts.append(alert)
    save_alerts_to_file()
    if severity=="Critical":
        if meta and meta.get("ip"):
            block_ip(meta["ip"])
        if meta and meta.get("user"):
            lock_user_account(meta["user"])

if __name__=='__main__':
    app.run(debug=True)
