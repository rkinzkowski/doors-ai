from flask import Flask, render_template
import pandas as pd
import requests
from sklearn.ensemble import IsolationForest
from iso3166 import countries
from functools import lru_cache
import subprocess
import platform
import csv
import os
import threading
import time
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import hashlib
import joblib
import numpy as np
import psutil
import json
from scanner_engine import load_scan_config, scan_file

app = Flask(__name__)

# === Settings ===
WATCH_FOLDER = os.path.expanduser("~/Downloads")
HASH_DB = "malware_hashes.csv"
QUARANTINE_FOLDER = "quarantine"
MODEL_PATH = "scanner/models/rf_model.pkl"
SCAN_LOG = "scanner_logs.csv"
PROCESS_LOG = "process_logs.csv"

model = joblib.load(MODEL_PATH)

@lru_cache(maxsize=1000)
def get_country_name_from_code(code):
    try:
        return countries.get(code).name
    except:
        return "Unknown"

@lru_cache(maxsize=1000)
def get_country_from_ip(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/country")
        if response.status_code == 200:
            code = response.text.strip()
            return get_country_name_from_code(code)
    except Exception as e:
        print(f"[GEO] Error for {ip}: {e}")
    return "Unknown"

def load_hash_db():
    try:
        df = pd.read_csv(HASH_DB)
        return set(df["sha256"])
    except Exception as e:
        print(f"[ERROR] Could not load hash DB: {e}")
        return set()

def add_to_hash_db(sha256):
    try:
        with open(HASH_DB, "a") as f:
            f.write(f"{sha256}\n")
        print(f"[LEARNED] Added to hash DB: {sha256}")
    except Exception as e:
        print(f"[ERROR] Could not update hash DB: {e}")

def log_scan(filename, sha256, result, reason):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{filename},{sha256},{result},{reason},{timestamp}\n"
    try:
        if not os.path.exists(SCAN_LOG):
            with open(SCAN_LOG, "w") as f:
                f.write("filename,sha256,result,reason,timestamp\n")
        with open(SCAN_LOG, "a") as f:
            f.write(log_entry)
    except Exception as e:
        print(f"[ERROR] Failed to log scan: {e}")

def log_process(pid, name, cmdline, reason):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        exists = os.path.exists(PROCESS_LOG)
        with open(PROCESS_LOG, "a", newline="") as f:
            writer = csv.writer(f)
            if not exists:
                writer.writerow(["timestamp", "pid", "name", "cmdline", "reason"])
            writer.writerow([timestamp, pid, name, cmdline, reason])
        print(f"[PROCESS] Logged suspicious process: {name} ({pid})")
    except Exception as e:
        print(f"[ERROR] Failed to log process: {e}")

def monitor_processes():
    flagged_keywords = ["powershell", "cmd", "wmic", "regsvr32", "bitsadmin"]
    seen = set()
    while True:
        for proc in psutil.process_iter(attrs=["pid", "name", "cmdline"]):
            try:
                pid = proc.info["pid"]
                name = proc.info["name"]
                cmdline = " ".join(proc.info["cmdline"])
                if pid not in seen:
                    for keyword in flagged_keywords:
                        if keyword in name.lower() or keyword in cmdline.lower():
                            log_process(pid, name, cmdline, f"Matched keyword: {keyword}")
                            seen.add(pid)
                            break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        time.sleep(5)

def compute_sha256(filepath):
    try:
        with open(filepath, "rb") as f:
            bytes = f.read()
            return hashlib.sha256(bytes).hexdigest()
    except:
        return None

def extract_features(filepath):
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        file_size = len(data)
        entropy = -sum(p * np.log2(p) for p in np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256) / len(data) if p > 0)
        unique_bytes = len(set(data))
        ascii_chars = sum(32 <= b <= 126 for b in data)
        ascii_ratio = ascii_chars / len(data) if len(data) > 0 else 0
        return [file_size, entropy, unique_bytes, ascii_ratio]
    except Exception as e:
        print(f"[ERROR] Feature extraction failed: {e}")
        return None

def quarantine_file(path):
    os.makedirs(QUARANTINE_FOLDER, exist_ok=True)
    filename = os.path.basename(path)
    quarantine_path = os.path.join(QUARANTINE_FOLDER, filename)
    try:
        os.rename(path, quarantine_path)
        print(f"[QUARANTINE] {filename} moved to quarantine.")
    except Exception as e:
        print(f"[ERROR] Failed to quarantine: {e}")

class FileHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            time.sleep(1)
            print(f"[SCANNER] New file detected: {event.src_path}")
            scan_file(event.src_path)
            return
            filepath = event.src_path
            print(f"[NEW FILE] {filepath}")
            filename = os.path.basename(filepath)

            sha256 = compute_sha256(filepath)
            if not sha256:
                print("[ERROR] Could not hash file.")
                log_scan(filename, "unknown", "error", "failed_hash")
                return

            print(f"[HASH] {sha256}")

            if sha256 in malicious_hashes:
                print(f"[ALERT] ⚠️ Known malicious hash detected.")
                quarantine_file(filepath)
                log_scan(filename, sha256, "malicious", "hash")
                return

            features = extract_features(filepath)
            if features:
                prediction = model.predict([features])[0]
                if prediction == 1:
                    print(f"[ALERT] 🛑 AI flagged file as malware.")
                    quarantine_file(filepath)
                    log_scan(filename, sha256, "malicious", "AI")
                    if sha256 not in malicious_hashes:
                        add_to_hash_db(sha256)
                        malicious_hashes.add(sha256)
                else:
                    print("[OK] ✅ AI marked file as safe.")
                    log_scan(filename, sha256, "safe", "AI")
            else:
                print("[ERROR] Could not analyze file.")
                log_scan(filename, sha256, "error", "failed_extract")

def start_background_threads():
    config = load_scan_config()
    observer = Observer()
    watched = 0

    for folder in config["watch_folders"]:
        if os.path.isdir(folder):
            observer.schedule(
                FileHandler(),
                folder,
                recursive=bool(config.get("recursive_watch", False)),
            )
            watched += 1
            print(f"[SCANNER] Watching: {folder}")
        else:
            print(f"[SCANNER] Skipping missing folder: {folder}")

    observer.start()
    print(f"[SCANNER] Active watched folders: {watched}")
    return observer

@app.route('/')
def home():
    ip_logs, scan_logs, proc_logs = [], [], []

    try:
        df = pd.read_csv("logs.csv")
    except Exception as e:
        return f"Error loading logs.csv: {e}"

    df["location_code"] = df["location"].astype('category').cat.codes
    df["agent_code"] = df["user_agent"].astype('category').cat.codes
    X = df[["login_attempts", "location_code", "agent_code"]]

    model = IsolationForest(contamination=0.3)
    model.fit(X)
    df["anomaly"] = model.predict(X)
    df["anomaly_score"] = model.decision_function(X).round(4)

    df["location"] = df["ip"].apply(get_country_from_ip)
    df["abuse_score"] = 60
    df["abuse_category"] = "Auto-blocked by Doors AI"

    ip_logs = df.sort_values(by="anomaly_score", ascending=True).to_dict(orient="records")

    if os.path.exists(SCAN_LOG):
        try:
            df_scan = pd.read_csv(SCAN_LOG)
            scan_logs = df_scan.sort_values(by="timestamp", ascending=False).to_dict(orient="records")
        except Exception as e:
            print(f"[ERROR] Failed to load scanner logs: {e}")

    if os.path.exists(PROCESS_LOG):
        try:
            df_proc = pd.read_csv(PROCESS_LOG)
            proc_logs = df_proc.sort_values(by="timestamp", ascending=False).to_dict(orient="records")
        except Exception as e:
            print(f"[ERROR] Failed to load process logs: {e}")

    return render_template(
        'dashboard.html',
        data=ip_logs,
        scan_logs=scan_logs,
        proc_logs=proc_logs,
        alerts=df[df["anomaly"] == -1].to_dict(orient="records")
    )

if __name__ == '__main__':
    malicious_hashes = load_hash_db()
    observer = None
    active_signature = None

    try:
        while True:
            config = load_scan_config()
            signature = (
                tuple(config["watch_folders"]),
                bool(config.get("recursive_watch", False)),
            )

            if signature != active_signature:
                if observer:
                    observer.stop()
                    observer.join()

                observer = start_background_threads()
                active_signature = signature

            time.sleep(5)
    except KeyboardInterrupt:
        if observer:
            observer.stop()
            observer.join()
