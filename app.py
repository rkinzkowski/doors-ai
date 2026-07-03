from flask import Flask, render_template, request, redirect, url_for
import pandas as pd
import requests
from sklearn.ensemble import IsolationForest
from iso3166 import countries
from functools import lru_cache
import ipaddress
import subprocess
import platform
import csv
import os
import random
import threading
import time
from datetime import datetime
import psutil
import json
import shutil
from scanner.scanner_engine import (
    load_scan_config,
    normalize_folder,
    save_scan_config,
    scan_folder,
)

app = Flask(__name__)

PROCESS_LOG = "process_logs.csv"
SCAN_LOG = "scanner_logs.csv"
LOGIN_LOG = "logs.csv"
THREAT_LOG = "threat_list.csv"
WHITELIST_FILE = "whitelist.json"
ARCHIVE_DIR = "archives"
AUTO_BLOCK_IPS = os.environ.get("DOORS_AUTO_BLOCK_IPS") == "1"

SUSPICIOUS_KEYWORDS = [
    "mimikatz",
    "netcat",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "wmic.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "at.exe",
    "schtasks.exe",
    "taskkill",
    "invoke-obfuscation",
]

SUSPICIOUS_COMMAND_PATTERNS = [
    "executionpolicy bypass",
    "-executionpolicy bypass",
    "encodedcommand",
    "-enc ",
    "invoke-obfuscation",
    "downloadstring(",
    "frombase64string(",
    " iwr ",
    " invoke-webrequest ",
]

PROCESS_LOG_HEADERS = ["timestamp", "pid", "name", "path", "reason"]
SCAN_LOG_HEADERS = ["filename", "sha256", "result", "reason", "timestamp"]
LOGIN_LOG_HEADERS = ["timestamp", "ip", "location", "user_agent", "login_attempts"]
PROCESS_LOG_ROTATE_ROWS = 500
SCAN_LOG_ROTATE_ROWS = 1000
LOGIN_LOG_ROTATE_ROWS = 1000

RECENT_PROCESS_ALERTS = set()

DEMO_IP_POOL = [
    "198.51.100.23",
    "198.51.100.84",
    "203.0.113.11",
    "203.0.113.91",
    "192.0.2.44",
]

DEMO_USER_AGENTS = ["Chrome", "Firefox", "Edge", "Safari", "Mobile App", "Unknown"]

INFO_TEXT = {
    "login_records": "Number of login events currently loaded from logs.csv.",
    "flagged_ips": "IP rows that triggered anomaly, VPN/proxy, or local threat-list checks.",
    "file_alerts": "Files that were malicious or errored. Clean files are not shown here.",
    "suspicious_processes": "Unique process alerts after deduping repeated child processes.",
    "ip": "The network address that attempted to sign in.",
    "login_attempts": "How many sign-in attempts this IP made in the sampled time window.",
    "location": "Country estimated from the IP address. Private or demo IPs may show Unknown.",
    "user_agent": "Browser, client, or tool reported by the login request.",
    "anomaly": "Machine-learning decision: -1 means unusual compared with the current login set; 1 means normal.",
    "anomaly_score": "Isolation Forest confidence score. Lower or negative scores are more unusual.",
    "abuse_score": "Local threat-intel confidence from threat_list.csv, from 0 to 100. Higher means more suspicious.",
    "category": "Human-readable reason from the local threat-intel list or the detector.",
}


def load_whitelist():
    if os.path.exists(WHITELIST_FILE):
        try:
            with open(WHITELIST_FILE, "r") as f:
                return set(json.load(f))
        except Exception as e:
            print(f"[WHITELIST] Failed to load whitelist: {e}")
            return set()
    return set()


def save_whitelist(whitelist):
    with open(WHITELIST_FILE, "w") as f:
        json.dump(sorted(list(whitelist)), f, indent=2)


WHITELIST = load_whitelist()


@lru_cache(maxsize=1000)
def get_country_name_from_code(code):
    try:
        return countries.get(code).name
    except:
        return "Unknown"


def is_non_public_ip(ip):
    try:
        address = ipaddress.ip_address(ip)
        return (
            address.is_private
            or address.is_loopback
            or address.is_reserved
            or address.is_multicast
        )
    except ValueError:
        return True


@lru_cache(maxsize=1000)
def get_country_from_ip(ip):
    if is_non_public_ip(ip):
        return "Private or Demo Network"

    try:
        response = requests.get(f"https://ipinfo.io/{ip}/country", timeout=3)
        if response.status_code == 200:
            code = response.text.strip()
            return get_country_name_from_code(code)
    except Exception as e:
        print(f"[GEO] Error for {ip}: {e}")
    return "Unknown"


@lru_cache(maxsize=1000)
def is_vpn_local(ip):
    try:
        with open("vpn_list.txt") as f:
            vpn_ips = set(line.strip() for line in f if line.strip())
            return ip in vpn_ips
    except Exception as e:
        print(f"[VPN-LOCAL] Error reading vpn_list.txt: {e}")
        return False


@lru_cache(maxsize=1000)
def is_vpn_api(ip):
    if is_non_public_ip(ip):
        return False

    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip}?fields=proxy,hosting",
            timeout=2
        )
        data = response.json()
        return data.get("proxy", False) or data.get("hosting", False)
    except Exception as e:
        print(f"[VPN-API] Error checking {ip}: {e}")
        return False


@lru_cache(maxsize=1000)
def check_local_threat_db(ip):
    best_match = {"abuse_score": 0, "categories": "Clean"}

    try:
        with open(THREAT_LOG, newline="") as file:
            reader = csv.DictReader(file)
            for row in reader:
                if row.get("ip") != ip:
                    continue

                try:
                    score = int(float(row.get("confidence", 0)))
                except (TypeError, ValueError):
                    score = 0

                score = max(0, min(score, 100))

                if score >= best_match["abuse_score"]:
                    best_match = {
                        "abuse_score": score,
                        "categories": row.get("reason") or "Threat list match"
                    }
    except FileNotFoundError:
        print("[THREAT DB] File not found. Skipping check.")
    except Exception as e:
        print(f"[THREAT DB] Error: {e}")

    return best_match


def log_threat(ip, reason, score=60):
    path = THREAT_LOG
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    exists = os.path.isfile(path)

    if exists:
        with open(path, newline="") as file:
            reader = csv.DictReader(file)
            for row in reader:
                if row.get("ip") == ip:
                    print(f"[THREAT DB] IP {ip} already logged. Skipping.")
                    return

    with open(path, "a", newline="") as file:
        writer = csv.writer(file)
        if not exists:
            writer.writerow(["ip", "reason", "confidence", "timestamp"])
        writer.writerow([ip, reason, score, timestamp])
        print(f"[THREAT DB] Logged: {ip} - {reason} at {timestamp}")


def block_ip(ip):
    print(f"[FIREWALL] Blocking IP: {ip}")
    try:
        if platform.system() == "Windows":
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name=Block_{ip}", "dir=in", "action=block", f"remoteip={ip}"
            ], check=True)
        elif platform.system() == "Linux":
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        else:
            print("[FIREWALL] Unsupported OS — skipping firewall")
    except Exception as e:
        print(f"[FIREWALL] Error blocking {ip}: {e}")


def ensure_csv_headers(path, headers):
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(headers)


def log_suspicious_process(pid, name, path, reason):
    ensure_csv_headers(PROCESS_LOG, PROCESS_LOG_HEADERS)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(PROCESS_LOG, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, pid, name, path, reason])

    print(f"[ALERT] Suspicious process: {name} (PID: {pid}) — {reason}")


def match_suspicious_process(name, exe_path, cmdline):
    full_text = f"{name} {exe_path} {cmdline}".lower()

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in full_text:
            return f"Matched keyword: {keyword}"

    for pattern in SUSPICIOUS_COMMAND_PATTERNS:
        if pattern in full_text:
            return f"Matched command pattern: {pattern}"

    return None


def scan_processes():
    global RECENT_PROCESS_ALERTS

    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
        try:
            pid = proc.info["pid"]
            raw_name = proc.info["name"] or ""
            name = raw_name.lower()
            exe_path = proc.info["exe"] or ""
            cmdline = " ".join(proc.info["cmdline"]) if proc.info["cmdline"] else ""

            if name in WHITELIST:
                continue

            reason = match_suspicious_process(name, exe_path, cmdline)

            if not reason:
                continue

            alert_key = f"{name}:{exe_path.lower()}:{reason}"

            if alert_key in RECENT_PROCESS_ALERTS:
                continue

            RECENT_PROCESS_ALERTS.add(alert_key)
            log_suspicious_process(pid, raw_name, exe_path, reason)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue


def start_process_monitor_thread():
    def loop():
        while True:
            scan_processes()
            time.sleep(30)

    threading.Thread(target=loop, daemon=True).start()


def archive_log_file(path, headers):
    if not os.path.exists(path):
        ensure_csv_headers(path, headers)
        return

    os.makedirs(ARCHIVE_DIR, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = os.path.splitext(os.path.basename(path))[0]
    archive_path = os.path.join(ARCHIVE_DIR, f"{base_name}_{timestamp}.csv")

    shutil.move(path, archive_path)
    ensure_csv_headers(path, headers)

    print(f"[LOGS] Archived {path} to {archive_path}")


def clear_log_file(path, headers):
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(headers)

    print(f"[LOGS] Cleared {path}")


def count_csv_data_rows(path):
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return 0

    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        return max(sum(1 for _ in f) - 1, 0)


def rotate_log_if_needed(path, headers, max_rows):
    try:
        if count_csv_data_rows(path) > max_rows:
            archive_log_file(path, headers)
    except Exception as e:
        print(f"[LOGS] Failed to rotate {path}: {e}")


def normalize_process_log_columns(df_proc):
    df_proc.columns = df_proc.columns.str.strip()

    if "path" not in df_proc.columns and "cmdline" in df_proc.columns:
        df_proc["path"] = df_proc["cmdline"]

    if "cmdline" not in df_proc.columns and "path" in df_proc.columns:
        df_proc["cmdline"] = df_proc["path"]

    for column in PROCESS_LOG_HEADERS:
        if column not in df_proc.columns:
            df_proc[column] = ""

    if "cmdline" not in df_proc.columns:
        df_proc["cmdline"] = ""

    return df_proc


def filter_actionable_process_logs(df_proc):
    if df_proc.empty:
        return df_proc

    df_proc["reason"] = df_proc["reason"].fillna("")
    df_proc["name"] = df_proc["name"].fillna("")
    df_proc["path"] = df_proc["path"].fillna("")

    # Hide legacy false positives from the old broad "bypass" keyword rule.
    legacy_bypass = df_proc["reason"].str.lower().str.strip().eq("matched keyword: bypass")
    df_proc = df_proc[~legacy_bypass]

    if WHITELIST:
        df_proc = df_proc[~df_proc["name"].str.lower().isin(WHITELIST)]

    return df_proc.drop_duplicates(
        subset=["name", "path", "reason"],
        keep="first",
    )


def append_login_event(ip, location, user_agent, login_attempts):
    ensure_csv_headers(LOGIN_LOG, LOGIN_LOG_HEADERS)
    timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

    with open(LOGIN_LOG, "a", newline="") as f:
        csv.writer(f).writerow([timestamp, ip, location, user_agent, login_attempts])


def generate_demo_login_event():
    append_login_event(
        random.choice(DEMO_IP_POOL),
        "Demo",
        random.choice(DEMO_USER_AGENTS),
        random.randint(1, 8),
    )


@app.route("/")
def home():
    ip_logs, scan_logs, proc_logs = [], [], []
    df = None
    scan_config = load_scan_config()

    rotate_log_if_needed(PROCESS_LOG, PROCESS_LOG_HEADERS, PROCESS_LOG_ROTATE_ROWS)
    rotate_log_if_needed(SCAN_LOG, SCAN_LOG_HEADERS, SCAN_LOG_ROTATE_ROWS)
    rotate_log_if_needed(LOGIN_LOG, LOGIN_LOG_HEADERS, LOGIN_LOG_ROTATE_ROWS)

    try:
        ensure_csv_headers(LOGIN_LOG, LOGIN_LOG_HEADERS)
        df = pd.read_csv(LOGIN_LOG)
        df = df.dropna(subset=["ip", "user_agent", "login_attempts"])
        df["login_attempts"] = pd.to_numeric(df["login_attempts"], errors="coerce").fillna(0)
        df["location_code"] = df["location"].fillna("Unknown").astype("category").cat.codes
        df["agent_code"] = df["user_agent"].fillna("Unknown").astype("category").cat.codes
        X = df[["login_attempts", "location_code", "agent_code"]]

        if not df.empty:
            model = IsolationForest(contamination=0.3)
            model.fit(X)

            df["anomaly"] = model.predict(X)
            df["anomaly_score"] = model.decision_function(X).round(4)
        else:
            df["anomaly"] = []
            df["anomaly_score"] = []

        df["location"] = df["ip"].apply(get_country_from_ip)
        df["abuse_score"] = df["ip"].apply(lambda ip: check_local_threat_db(ip)["abuse_score"])
        df["abuse_category"] = df["ip"].apply(lambda ip: check_local_threat_db(ip)["categories"])

        df["is_vpn_local"] = df["ip"].apply(is_vpn_local)
        df["is_vpn_api"] = df["ip"].apply(is_vpn_api)
        df["vpn_flagged"] = df["is_vpn_local"] | df["is_vpn_api"]
        df["flagged"] = (
            (df["anomaly"] == -1)
            | df["vpn_flagged"]
            | (pd.to_numeric(df["abuse_score"], errors="coerce").fillna(0) > 50)
        )

        if AUTO_BLOCK_IPS:
            for _, row in df[df["flagged"]].iterrows():
                block_ip(row["ip"])
                log_threat(row["ip"], "Auto-blocked by Doors AI", row["abuse_score"] or 60)

        ip_logs = df.sort_values(by="anomaly_score", ascending=True).to_dict(orient="records")

    except Exception as e:
        print(f"[ERROR] Loading {LOGIN_LOG}: {e}")

    if os.path.exists(SCAN_LOG):
        try:
            df_scan = pd.read_csv(SCAN_LOG)
            df_scan = df_scan[df_scan["result"].fillna("").str.lower() != "safe"]
            scan_logs = df_scan.sort_values(by="timestamp", ascending=False).head(200).to_dict(orient="records")
        except Exception as e:
            print(f"[ERROR] Failed to load scanner logs: {e}")

    if os.path.exists(PROCESS_LOG):
        try:
            df_proc = pd.read_csv(PROCESS_LOG)
            df_proc = normalize_process_log_columns(df_proc)
            df_proc = df_proc.sort_values(by="timestamp", ascending=False)
            df_proc = filter_actionable_process_logs(df_proc)
            proc_logs = df_proc.head(200).to_dict(orient="records")
        except Exception as e:
            print(f"[ERROR] Failed to load process logs: {e}")

    alerts = df[df["flagged"]].to_dict(orient="records") if df is not None and "flagged" in df.columns else []

    return render_template(
        "dashboard.html",
        data=ip_logs,
        scan_logs=scan_logs,
        proc_logs=proc_logs,
        alerts=alerts,
        whitelist=sorted(list(WHITELIST)),
        scan_config=scan_config,
        info=INFO_TEXT,
        auto_block_ips=AUTO_BLOCK_IPS
    )


@app.route("/whitelist/add", methods=["POST"])
def add_whitelist():
    global WHITELIST

    process_name = request.form.get("process_name", "").strip().lower()

    if process_name:
        WHITELIST.add(process_name)
        save_whitelist(WHITELIST)
        print(f"[WHITELIST] Added {process_name}")

    return redirect(url_for("home"))


@app.route("/whitelist/remove", methods=["POST"])
def remove_whitelist():
    global WHITELIST

    process_name = request.form.get("process_name", "").strip().lower()

    if process_name in WHITELIST:
        WHITELIST.remove(process_name)
        save_whitelist(WHITELIST)
        print(f"[WHITELIST] Removed {process_name}")

    return redirect(url_for("home"))


@app.route("/process/terminate", methods=["POST"])
def terminate_process():
    pid_raw = request.form.get("pid", "").strip()

    try:
        pid = int(pid_raw)
        proc = psutil.Process(pid)
        proc_name = proc.name()
        proc.terminate()

        print(f"[PROCESS] Manually terminated {proc_name} with PID {pid}")

    except Exception as e:
        print(f"[PROCESS] Failed to terminate PID {pid_raw}: {e}")

    return redirect(url_for("home"))


@app.route("/logs/archive", methods=["POST"])
def archive_logs():
    log_type = request.form.get("log_type", "").strip().lower()

    if log_type == "scanner":
        archive_log_file(SCAN_LOG, SCAN_LOG_HEADERS)
    elif log_type == "process":
        archive_log_file(PROCESS_LOG, PROCESS_LOG_HEADERS)
    elif log_type == "login":
        archive_log_file(LOGIN_LOG, LOGIN_LOG_HEADERS)

    return redirect(url_for("home"))


@app.route("/logs/clear", methods=["POST"])
def clear_logs():
    log_type = request.form.get("log_type", "").strip().lower()

    if log_type == "scanner":
        clear_log_file(SCAN_LOG, SCAN_LOG_HEADERS)
    elif log_type == "process":
        clear_log_file(PROCESS_LOG, PROCESS_LOG_HEADERS)
    elif log_type == "login":
        clear_log_file(LOGIN_LOG, LOGIN_LOG_HEADERS)

    return redirect(url_for("home"))


@app.route("/login/add", methods=["POST"])
def add_login_event():
    ip = request.form.get("ip", "").strip()
    user_agent = request.form.get("user_agent", "").strip() or "Unknown"
    location = request.form.get("location", "").strip() or "Manual"

    try:
        login_attempts = max(1, int(request.form.get("login_attempts", "1")))
    except ValueError:
        login_attempts = 1

    if ip:
        append_login_event(ip, location, user_agent, login_attempts)

    return redirect(url_for("home"))


@app.route("/login/simulate", methods=["POST"])
def simulate_login_event():
    generate_demo_login_event()
    return redirect(url_for("home"))


@app.route("/scanner/folders/add", methods=["POST"])
def add_scan_folder():
    folder = request.form.get("folder", "").strip()
    recursive_watch = bool(request.form.get("recursive_watch"))

    if folder:
        config = load_scan_config()
        normalized = normalize_folder(folder)

        if os.path.isdir(normalized):
            config["watch_folders"] = sorted(set(config["watch_folders"] + [normalized]))
            config["recursive_watch"] = recursive_watch
            save_scan_config(config)
            print(f"[SCANNER] Added watch folder: {normalized}")
        else:
            print(f"[SCANNER] Cannot add missing folder: {normalized}")

    return redirect(url_for("home"))


@app.route("/scanner/folders/remove", methods=["POST"])
def remove_scan_folder():
    folder = request.form.get("folder", "").strip()

    if folder:
        config = load_scan_config()
        normalized = normalize_folder(folder)
        config["watch_folders"] = [
            item for item in config["watch_folders"]
            if normalize_folder(item) != normalized
        ]
        save_scan_config(config)
        print(f"[SCANNER] Removed watch folder: {normalized}")

    return redirect(url_for("home"))


@app.route("/scanner/scan-now", methods=["POST"])
def scan_now():
    folder = request.form.get("folder", "").strip()
    recursive = bool(request.form.get("recursive"))

    if folder:
        normalized = normalize_folder(folder)

        if os.path.isdir(normalized):
            summary = scan_folder(normalized, recursive=recursive)
            print(f"[SCANNER] Manual scan summary for {normalized}: {summary}")
        else:
            print(f"[SCANNER] Cannot scan missing folder: {normalized}")

    return redirect(url_for("home"))


# Backward-compatible old route
@app.route("/whitelist", methods=["GET", "POST"])
def manage_whitelist():
    if request.method == "POST":
        return add_whitelist()

    return redirect(url_for("home"))


if __name__ == "__main__":
    ensure_csv_headers(PROCESS_LOG, PROCESS_LOG_HEADERS)
    ensure_csv_headers(SCAN_LOG, SCAN_LOG_HEADERS)
    ensure_csv_headers(LOGIN_LOG, LOGIN_LOG_HEADERS)
    rotate_log_if_needed(PROCESS_LOG, PROCESS_LOG_HEADERS, PROCESS_LOG_ROTATE_ROWS)
    rotate_log_if_needed(SCAN_LOG, SCAN_LOG_HEADERS, SCAN_LOG_ROTATE_ROWS)
    rotate_log_if_needed(LOGIN_LOG, LOGIN_LOG_HEADERS, LOGIN_LOG_ROTATE_ROWS)
    start_process_monitor_thread()
    app.run(debug=True, use_reloader=False)
