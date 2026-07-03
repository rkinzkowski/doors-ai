import psutil
import csv
import os
import time
from datetime import datetime

LOG_FILE = "process_logs.csv"
CHECK_INTERVAL = 5  # seconds

# Define suspicious process keywords or names
SUSPICIOUS_KEYWORDS = [
    "keylogger", "metasploit", "mimikatz", "rat", "backdoor", "malware",
    "powershell.exe", "cmd.exe", "nc.exe", "netcat", "svchost_fake", "python malware"
]

# Create CSV header if it doesn't exist
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "pid", "name", "cmdline", "reason"])

def is_suspicious(proc):
    try:
        name = proc.name().lower()
        cmdline = " ".join(proc.cmdline()).lower()

        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in name or keyword in cmdline:
                return f"Matched keyword: {keyword}"

        return None
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        return None

def monitor_processes():
    print("👀 Monitoring processes...")
    while True:
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            reason = is_suspicious(proc)
            if reason:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                with open(LOG_FILE, "a", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow([timestamp, proc.pid, proc.name(), " ".join(proc.cmdline()), reason])
                print(f"[ALERT] Suspicious process: {proc.name()} (PID: {proc.pid}) — {reason}")
        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    monitor_processes()