import os
import json
import logging
import time
from datetime import datetime, timedelta
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

import requests
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "your_secret_key")

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# Configuration
config = {
    "rate_limit_requests": 20,        # max requests per IP per minute
    "failed_login_threshold": 10,
    "download_threshold": 5,
    "alert_dedup_interval": 60,       # deduplicate alerts (seconds)
    "working_hours": (8, 18)          # normal working hours (8 AM to 6 PM)
}

# VirusTotal API key (use environment variable or hardcode for testing)
VT_API_KEY = os.environ.get("VT_API_KEY", "e3605f634b36188236c5896d08f49b890d9e28e4918bc635140f704755423a35")

# In-memory storage
failed_logins = defaultdict(list)
alerts = []  # list of dict: {message, timestamp, severity}
ip_login_users = defaultdict(list)
user_downloads = defaultdict(list)
blocked_users = {}
ip_request_log = defaultdict(list)
last_alerts = {}
system_activity_logs = []

# Known IP addresses per user
known_user_ips = {
    "john_doe": ["192.168.1.100"],
    "jane_doe": ["192.168.1.101"]
}

# Spam keywords
spam_keywords = ["free money", "win prize", "urgent", "click here", "lottery"]

# --- Rate Limiting: Token & Leaky Bucket ---

class TokenBucket:
    def __init__(self, capacity, refill_rate):
        self.capacity = capacity
        self.tokens = capacity
        self.refill_rate = refill_rate  # tokens per second
        self.last_refill_timestamp = time.time()

    def consume(self, tokens=1):
        now = time.time()
        delta = now - self.last_refill_timestamp
        self.tokens = min(self.capacity, self.tokens + delta * self.refill_rate)
        self.last_refill_timestamp = now
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False

class LeakyBucket:
    def __init__(self, capacity, leak_rate):
        self.capacity = capacity
        self.water = 0
        self.leak_rate = leak_rate
        self.last_check = time.time()

    def allow_request(self):
        now = time.time()
        elapsed = now - self.last_check
        leaked = elapsed * self.leak_rate
        self.water = max(0, self.water - leaked)
        self.last_check = now
        if self.water < self.capacity:
            self.water += 1
            return True
        return False

token_buckets = {}
leaky_buckets = {}

def get_token_bucket(ip):
    if ip not in token_buckets:
        token_buckets[ip] = TokenBucket(config["rate_limit_requests"], config["rate_limit_requests"] / 60.0)
    return token_buckets[ip]

def get_leaky_bucket(ip):
    if ip not in leaky_buckets:
        leaky_buckets[ip] = LeakyBucket(config["rate_limit_requests"], config["rate_limit_requests"] / 60.0)
    return leaky_buckets[ip]

# Thread pool for background tasks (e.g., virus scanning)
executor = ThreadPoolExecutor(max_workers=4)

def get_geolocation(ip):
    # Dummy geolocation
    return "Unknown Country"

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
            logger.info("Prepopulated logs loaded successfully.")
    except Exception as e:
        logger.error("Error loading prepopulated logs: %s", e)

load_prepopulated_logs()

# --- Routes ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/log', methods=['POST'])
def log_event():
    remote_ip = request.remote_addr
    bucket = get_token_bucket(remote_ip)
    if not bucket.consume():
        send_alert(f"IP {remote_ip} exceeded rate limit (Token Bucket).", severity="Medium")
        return jsonify({"status": "error", "message": "Rate limit exceeded (Token Bucket)."}), 429

    event = request.json
    process_event(event)
    return jsonify({"status": "event processed"}), 200

@app.route('/system_activity', methods=['POST'])
def system_activity():
    event = request.json
    process_system_activity(event)
    return jsonify({"status": "system activity processed"}), 200

@app.route('/log_analysis', methods=['GET'])
def log_analysis():
    analysis = {}
    for event in system_activity_logs:
        etype = event.get("type", "unknown")
        analysis[etype] = analysis.get(etype, 0) + 1
    return jsonify(analysis), 200

@app.route('/upload', methods=['POST'])
def upload_file():
    user = request.form.get("user")
    if not user:
        return jsonify({"status": "error", "message": "User is required for file upload."}), 400
    if "upload_file" not in request.files:
        return jsonify({"status": "error", "message": "No file part in the request."}), 400
    file = request.files["upload_file"]
    if file.filename == "":
        return jsonify({"status": "error", "message": "No file selected."}), 400
    file_content = file.read()
    future = executor.submit(real_virus_scan, file_content)
    virus_found = future.result()  # For testing, we block until scanning is done.
    if virus_found:
        send_alert(f"Virus detected in uploaded file {file.filename} by user {user}", severity="Critical")
        return jsonify({"status": "alert", "message": f"Virus detected in file {file.filename}."})
    else:
        return jsonify({"status": "success", "message": f"File {file.filename} uploaded and scanned successfully."})

@app.route('/alerts', methods=['GET'])
def get_alerts():
    return jsonify(alerts)

@app.route('/config', methods=['GET'])
def get_config():
    return jsonify(config)

@app.route('/config', methods=['POST'])
def update_config():
    new_config = request.json
    config.update(new_config)
    logger.info("Configuration updated: %s", config)
    return jsonify({"status": "config updated", "config": config})

@app.route('/admin')
def admin_dashboard():
    def convert_times(log_dict):
        return { key: [ts.isoformat() for ts in times] for key, times in log_dict.items() }
    def convert_login_users(log_dict):
        return { key: [(t.isoformat(), u) for t, u in times] for key, times in log_dict.items() }
    return render_template('admin.html',
                           alerts=alerts,
                           ip_requests=convert_times(ip_request_log),
                           failed_logins=convert_times(failed_logins),
                           ip_login_users=convert_login_users(ip_login_users),
                           user_downloads=convert_times(user_downloads),
                           config=config)

# --- Event Processing Functions ---

def process_event(event):
    etype = event.get("type")
    if etype == "login_attempt":
        process_login_attempt(event)
    elif etype == "permission_change":
        process_permission_change(event)
    elif etype == "file_access":
        process_file_access(event)
    elif etype == "email":
        process_email_event(event)
    elif etype == "file_upload":
        process_file_upload(event)
    else:
        logger.warning("Unknown event type: %s", etype)

def process_login_attempt(event):
    user = event.get("user")
    ip = event.get("ip")
    success = event.get("success")
    timestamp = datetime.fromisoformat(event.get("timestamp"))
    location = get_geolocation(ip)
    if success and ip not in known_user_ips.get(user, []):
        send_alert(f"Login from unknown location: user {user} from IP {ip} ({location})", severity="Medium")
    if not success:
        failed_logins[ip].append(timestamp)
        cutoff = timestamp - timedelta(minutes=1)
        failed_logins[ip] = [t for t in failed_logins[ip] if t > cutoff]
        if len(failed_logins[ip]) > config["failed_login_threshold"]:
            send_alert(f"Brute-force attack detected from IP {ip}", severity="Critical")
    ip_login_users[ip].append((timestamp, user))
    cutoff = timestamp - timedelta(minutes=1)
    ip_login_users[ip] = [(t, u) for t, u in ip_login_users[ip] if t > cutoff]
    unique_users = set(u for t, u in ip_login_users[ip])
    if len(unique_users) > 1:
        send_alert(f"Multiple users logged in from IP {ip}: {', '.join(unique_users)}", severity="Medium")
    start, end = config["working_hours"]
    if success and not (start <= timestamp.hour < end):
        send_alert(f"Unusual login time for user {user} at {timestamp.isoformat()}", severity="Low")

def process_permission_change(event):
    user = event.get("user")
    new_role = event.get("new_role")
    if new_role == "admin":
        send_alert(f"Unusual permission change: User {user} escalated to admin", severity="Critical")

def process_file_access(event):
    user = event.get("user")
    access_type = event.get("access_type")
    timestamp = datetime.fromisoformat(event.get("timestamp"))
    now = datetime.now()
    if access_type == "download":
        if user in blocked_users:
            if now < blocked_users[user]:
                send_alert(f"Download attempt blocked for user {user} due to high file access.", severity="Medium")
                return
            else:
                del blocked_users[user]
        user_downloads[user].append(timestamp)
        cutoff = timestamp - timedelta(minutes=1)
        user_downloads[user] = [t for t in user_downloads[user] if t > cutoff]
        if len(user_downloads[user]) > config["download_threshold"]:
            send_alert(f"High file download rate detected for user {user}. Blocking downloads for 1 minute.", severity="Critical")
            blocked_users[user] = now + timedelta(minutes=1)

def process_email_event(event):
    user = event.get("user")
    subject = event.get("subject", "")
    body = event.get("body", "")
    content = f"{subject} {body}".lower()
    if any(keyword in content for keyword in spam_keywords):
        send_alert(f"Suspicious email detected for user {user}: {subject}", severity="Low")

def process_file_upload(event):
    user = event.get("user")
    file_name = event.get("file")
    file_content = event.get("content", "")
    virus_found = real_virus_scan(file_content.encode())
    if virus_found:
        send_alert(f"Virus detected in uploaded file {file_name} by user {user}", severity="Critical")

def process_system_activity(event):
    system_activity_logs.append(event)
    etype = event.get("type")
    timestamp = datetime.fromisoformat(event.get("timestamp"))
    message = event.get("message", "")
    if etype == "transaction":
        amount = event.get("amount", 0)
        if amount > 1000000:
            send_alert(f"Suspicious large transaction of ${amount} detected", severity="Critical")
        else:
            send_alert(f"Transaction of ${amount} processed", severity="Low")
    elif etype == "network":
        ip = event.get("ip", "unknown")
        if not ip.startswith("10."):
            send_alert(f"Suspicious network activity from IP {ip}", severity="Medium")
        else:
            send_alert(f"Normal network activity from IP {ip}", severity="Low")
    elif etype == "auth":
        failures = event.get("failures", 0)
        if failures > 5:
            send_alert(f"High number of authentication failures ({failures}) detected", severity="Critical")
        else:
            send_alert(f"Authentication event logged", severity="Low")
    else:
        send_alert(f"System activity event: {message}", severity="Low")

def real_virus_scan(file_content):
    headers = {"x-apikey": VT_API_KEY}
    upload_url = "https://www.virustotal.com/api/v3/files"
    files = {"file": ("uploaded_file", file_content)}
    response = requests.post(upload_url, headers=headers, files=files)
    if response.status_code == 200:
        json_response = response.json()
        analysis_id = json_response.get("data", {}).get("id", None)
        if not analysis_id:
            logger.error("No analysis ID returned from VirusTotal.")
            return False
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        for i in range(15):
            time.sleep(5)
            analysis_response = requests.get(analysis_url, headers=headers)
            if analysis_response.status_code == 200:
                analysis_data = analysis_response.json()
                status = analysis_data.get("data", {}).get("attributes", {}).get("status", "")
                if status == "completed":
                    stats = analysis_data.get("data", {}).get("attributes", {}).get("stats", {})
                    if stats.get("malicious", 0) > 0:
                        return True
                    else:
                        return False
            else:
                logger.error("Error polling VirusTotal analysis: %s", analysis_response.status_code)
        logger.warning("VirusTotal analysis did not complete in time.")
        return False
    else:
        logger.error("Error uploading file to VirusTotal: %s", response.status_code)
        return False

def save_alerts_to_file():
    try:
        with open("prepopulated_logs.json", "w") as f:
            json.dump({"alerts": alerts}, f, indent=2)
        logger.info("Alerts saved to JSON file.")
    except Exception as e:
        logger.error("Error saving alerts: %s", e)

def send_alert(message, severity="Low"):
    now = datetime.now()
    last_time = last_alerts.get(message)
    if last_time and (now - last_time).total_seconds() < config["alert_dedup_interval"]:
        return
    last_alerts[message] = now
    alert = {"message": message, "timestamp": now.isoformat(), "severity": severity}
    logger.info("ALERT: %s", alert)
    alerts.append(alert)
    save_alerts_to_file()

if __name__ == '__main__':
    app.run(debug=True)
