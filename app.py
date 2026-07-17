from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, Response
import secrets
import hashlib
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
    add_to_hash_db,
    add_trusted_hash,
    delete_quarantined_file,
    find_file_in_watch_folders,
    get_scan_status,
    list_quarantined_files,
    load_hash_db,
    load_publisher_lists,
    load_scan_config,
    load_trusted_hashes,
    normalize_folder,
    set_publisher_strict,
    update_publisher_list,
    normalize_sha256,
    quarantine_file,
    restore_quarantined_file,
    save_scan_config,
    scan_folder,
    ensure_model,
)
from scanner.file_watcher import get_file_watcher_status, start_file_watcher_thread
from monitor.endpoint_monitor import (
    ENDPOINT_LOG_HEADERS,
    get_endpoint_monitor_status,
    reset_baseline,
    start_endpoint_monitor_thread,
)
from monitor.login_events import (
    get_login_import_status,
    import_login_events,
    start_login_import_thread,
)
from monitor.network_monitor import get_network_snapshot
from monitor.mitre import tag_technique
from monitor.defender import get_defender_status
from monitor.notify import set_enabled as set_notify_enabled, is_enabled as notify_enabled
from monitor.scheduler import (
    load_scheduler_config,
    set_scheduler_option,
    start_scheduler_thread,
)
from monitor.events_db import get_daily_counts, get_summary
from monitor.correlation import get_incidents
from monitor.net_intel import (
    assess_vulnerabilities,
    check_new_devices,
    get_active_connections,
    get_dns_cache,
    get_firewall_status,
    reset_device_baseline,
    start_connection_monitor_thread,
)
from monitor.threat_feeds import (
    load_feeds_config,
    save_feeds_config,
    save_virustotal_key,
    update_feodo,
    update_ipsum,
    update_malware_hashes,
    vt_lookup,
)

app = Flask(__name__)

SECURITY_CONFIG = "security_config.json"


def load_security_config():
    if os.path.exists(SECURITY_CONFIG):
        try:
            with open(SECURITY_CONFIG, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def save_security_config(cfg):
    with open(SECURITY_CONFIG, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)


def _get_or_create_secret():
    cfg = load_security_config()
    if not cfg.get("secret_key"):
        cfg["secret_key"] = secrets.token_hex(32)
        save_security_config(cfg)
    return cfg["secret_key"]


def _hash_passphrase(passphrase, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt.encode("utf-8"), 100_000)
    return salt, digest.hex()


def _passphrase_matches(passphrase, stored):
    if not stored or "salt" not in stored or "hash" not in stored:
        return False
    _, computed = _hash_passphrase(passphrase, stored["salt"])
    return secrets.compare_digest(computed, stored["hash"])


# A persistent random secret makes sessions and CSRF tokens unforgeable.
app.secret_key = _get_or_create_secret()


@app.before_request
def _security_gate():
    # 1. Ensure every session has a CSRF token.
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)

    endpoint = request.endpoint or ""

    # 2. First-run wizard: only for a fresh install with nothing configured.
    cfg_setup = load_security_config()
    if not cfg_setup.get("setup_complete") and endpoint not in ("setup", "setup_complete", "login", "static"):
        try:
            configured = bool(load_scan_config().get("watch_folders"))
        except Exception:
            configured = True
        if not configured and request.method == "GET":
            return redirect(url_for("setup"))

    # 2b. Passphrase lock (only when the user has set one).
    cfg = load_security_config()
    if cfg.get("passphrase") and not session.get("authed"):
        if endpoint not in ("login", "static"):
            if request.method == "GET":
                return redirect(url_for("login"))
            abort(403)

    # 3. CSRF check on every state-changing POST (login exempt: it carries
    #    its own secret, the passphrase).
    if request.method == "POST" and endpoint != "login":
        if request.form.get("csrf_token", "") != session.get("csrf"):
            abort(400, "Invalid or missing security token. Reload the page and try again.")


@app.context_processor
def _inject_csrf():
    return {"csrf_token": session.get("csrf", "")}


@app.route("/login", methods=["GET", "POST"])
def login():
    cfg = load_security_config()
    stored = cfg.get("passphrase")

    if not stored:
        # No lock configured; nothing to log into.
        session["authed"] = True
        return redirect(url_for("home"))

    if request.method == "POST":
        if _passphrase_matches(request.form.get("passphrase", ""), stored):
            session["authed"] = True
            return redirect(url_for("home"))
        return render_template("login.html", error="Incorrect passphrase.")

    return render_template("login.html", error=None)


@app.route("/logout", methods=["POST"])
def logout():
    session.pop("authed", None)
    return redirect(url_for("login"))


@app.route("/report/weekly")
def weekly_report():
    scan_config = load_scan_config()
    summary = {
        "login_records": 0, "flagged_ips": 0, "file_alerts": 0,
        "suspicious_processes": 0, "endpoint_alerts": 0, "active_alerts": 0,
    }
    runtime_status = build_runtime_status(0)
    try:
        network = get_network_snapshot()
    except Exception:
        network = {"devices": [], "ports": [], "error": None}
    try:
        defender = get_defender_status()
    except Exception:
        defender = {"available": False}

    posture = compute_posture(summary, runtime_status, network, scan_config, defender)
    trend = get_daily_counts(14)
    trend_max = max((d["count"] for d in trend), default=0)

    html = render_template(
        "report.html",
        generated=datetime.now().strftime("%Y-%m-%d %H:%M"),
        posture=posture,
        week=get_summary(7),
        trend=trend,
        trend_max=trend_max,
        incidents=get_incidents(days=7),
    )
    filename = f"doors-ai-report-{datetime.now().strftime('%Y%m%d')}.html"
    return Response(
        html, mimetype="text/html",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.route("/setup")
def setup():
    default_downloads = str(os.path.join(os.path.expanduser("~"), "Downloads"))
    return render_template("setup.html", default_folder=default_downloads)


@app.route("/setup/complete", methods=["POST"])
def setup_complete():
    folders_raw = request.form.get("folders", "")
    config = load_scan_config()
    added = list(config.get("watch_folders", []))

    for line in folders_raw.splitlines():
        folder = line.strip()
        if not folder:
            continue
        normalized = normalize_folder(folder)
        if os.path.isdir(normalized) and normalized not in added:
            added.append(normalized)

    config["watch_folders"] = sorted(set(added))
    save_scan_config(config)

    set_notify_enabled(request.form.get("notifications") == "1")

    cfg = load_security_config()
    cfg["setup_complete"] = True
    cfg["notifications"] = request.form.get("notifications") == "1"
    save_security_config(cfg)

    flash("Setup complete - Doors AI is now protecting your PC.", "success")
    return redirect(url_for("home"))


@app.route("/schedule/update", methods=["POST"])
def schedule_update():
    for key in ("auto_scan", "auto_feeds"):
        if request.form.get(key) is not None:
            set_scheduler_option(key, request.form.get(key) == "1")
    for key in ("scan_interval_hours", "feed_interval_hours"):
        if request.form.get(key):
            set_scheduler_option(key, request.form.get(key))
    flash("Automation settings saved.", "success")
    return redirect(url_for("home"))


@app.route("/security/notifications", methods=["POST"])
def toggle_notifications():
    cfg = load_security_config()
    new_value = request.form.get("enabled") == "1"
    cfg["notifications"] = new_value
    save_security_config(cfg)
    set_notify_enabled(new_value)
    flash(f"Desktop notifications turned {'on' if new_value else 'off'}.", "success")
    return redirect(url_for("home"))


@app.route("/security/set-passphrase", methods=["POST"])
def set_passphrase():
    new = request.form.get("passphrase", "").strip()
    cfg = load_security_config()

    if new:
        salt, digest = _hash_passphrase(new)
        cfg["passphrase"] = {"salt": salt, "hash": digest}
        save_security_config(cfg)
        session["authed"] = True
        flash("Dashboard lock enabled. You'll need this passphrase next time.", "success")
    else:
        cfg.pop("passphrase", None)
        save_security_config(cfg)
        flash("Dashboard lock removed.", "info")

    return redirect(url_for("home"))

PROCESS_LOG = "process_logs.csv"
SCAN_LOG = "scanner_logs.csv"
ENDPOINT_LOG = "endpoint_logs.csv"
LOGIN_LOG = "logs.csv"
THREAT_LOG = "threat_list.csv"
WHITELIST_FILE = "whitelist.json"
ARCHIVE_DIR = "archives"
AUTO_BLOCK_IPS = os.environ.get("DOORS_AUTO_BLOCK_IPS") == "1"
ENABLE_EXTERNAL_IP_LOOKUPS = os.environ.get("DOORS_ENABLE_EXTERNAL_IP_LOOKUPS") == "1"

# Names that are suspicious on sight: real attack tools, never part of a
# normal Windows workflow. Matching any of these always raises an alert.
MALWARE_PROCESS_NAMES = [
    "mimikatz",
    "lazagne",
    "meterpreter",
    "cobaltstrike",
    "netcat",
    "nc.exe",
    "nc64.exe",
    "invoke-obfuscation",
]

# Living-off-the-land binaries: legitimate Windows tools that attackers
# abuse. Flagging them by name alone floods the log with false positives
# (rundll32/cscript run constantly on a healthy system), so they only
# alert when their command line or location also looks hostile.
LOLBIN_NAMES = {
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "wmic.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "at.exe",
    "schtasks.exe",
    "bitsadmin.exe",
    "certutil.exe",
}

SUSPICIOUS_COMMAND_PATTERNS = [
    "executionpolicy bypass",
    "-executionpolicy bypass",
    "encodedcommand",
    "-enc ",
    "invoke-obfuscation",
    "downloadstring(",
    "downloadfile(",
    "frombase64string(",
    " iwr ",
    " invoke-webrequest ",
    "certutil -urlcache",
    "certutil.exe -urlcache",
    "bitsadmin /transfer",
    "vssadmin delete shadows",
    "scrobj.dll",
]

# Command lines that point a LOLBin at user-writable staging directories.
USER_WRITABLE_PATH_HINTS = [
    "\\appdata\\local\\temp\\",
    "\\downloads\\",
    "\\public\\",
    "\\programdata\\",
    "%temp%",
]

SYSTEM_BINARY_DIRS = ("c:\\windows\\system32", "c:\\windows\\syswow64")

# Behavioral rule: document readers, office apps, and browsers have no
# business launching shells or script hosts. That parent-child pair is the
# signature of macro payloads and drive-by downloads.
DOCUMENT_APP_NAMES = {
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "msaccess.exe",
    "onenote.exe",
    "acrord32.exe",
    "acrobat.exe",
    "foxitreader.exe",
    "sumatrapdf.exe",
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "brave.exe",
    "opera.exe",
}

SCRIPT_HOST_NAMES = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "bitsadmin.exe",
    "certutil.exe",
}

PROCESS_LOG_HEADERS = ["timestamp", "pid", "name", "path", "reason"]
SCAN_LOG_HEADERS = ["filename", "sha256", "result", "reason", "timestamp"]
LOGIN_LOG_HEADERS = ["timestamp", "ip", "location", "user_agent", "login_attempts"]
PROCESS_LOG_ROTATE_ROWS = 500
SCAN_LOG_ROTATE_ROWS = 1000
ENDPOINT_LOG_ROTATE_ROWS = 1000
LOGIN_LOG_ROTATE_ROWS = 1000
PROCESS_LOG_ROTATE_BYTES = 2 * 1024 * 1024
SCAN_LOG_ROTATE_BYTES = 2 * 1024 * 1024
ENDPOINT_LOG_ROTATE_BYTES = 2 * 1024 * 1024
LOGIN_LOG_ROTATE_BYTES = 1 * 1024 * 1024
PAGE_SIZE = 25

RECENT_PROCESS_ALERTS = set()
PROCESS_ALERT_CACHE_MAX = 2000
PROCESS_MONITOR_INTERVAL = 30
PROCESS_MONITOR_STATUS = {
    "running": False,
    "last_scan_time": None,
    "last_process_count": 0,
    "last_alert_count": 0,
    "last_error": None,
}
PROCESS_MONITOR_LOCK = threading.Lock()
SEVERITY_OPTIONS = ["low", "medium", "high", "critical"]

DEMO_IP_POOL = [
    "198.51.100.23",
    "198.51.100.84",
    "203.0.113.11",
    "203.0.113.91",
    "192.0.2.44",
]

DEMO_USER_AGENTS = ["Chrome", "Firefox", "Edge", "Safari", "Mobile App", "Unknown"]

INFO_TEXT = {
    "login_records": "How many sign-in events Doors AI currently knows about.",
    "flagged_ips": "Addresses that looked unusual, used a VPN/proxy, or matched your threat list.",
    "file_alerts": "Files that need a look: known malware, suspicious traits, or scan errors. Clean files are not listed.",
    "suspicious_processes": "Running programs that matched a hacking tool, dangerous command, or odd behavior.",
    "ip": "The network address the sign-in came from.",
    "login_attempts": "How many times this address tried to sign in.",
    "location": "Where the sign-in came from, when known.",
    "user_agent": "What kind of sign-in it was (browser, remote desktop, this PC, and so on).",
    "anomaly": "The AI's verdict: Unusual means this sign-in stands out from the others.",
    "anomaly_score": "How confident the AI is. More negative = more unusual.",
    "abuse_score": "Threat score from your local threat list, 0 to 100. Higher = more dangerous.",
    "category": "Why this address was flagged, in plain words.",
    "endpoint_alerts": "Changes to what runs automatically on this PC (startup programs, scheduled tasks, services) plus ransomware warning signs.",
    "security_score": "One number summarizing your protection right now. It drops when alerts pile up, protective guards stop, or risky doors are open to your network.",
}


def load_whitelist():
    if os.path.exists(WHITELIST_FILE):
        try:
            with open(WHITELIST_FILE, "r", encoding="utf-8") as f:
                return set(json.load(f))
        except Exception as e:
            print(f"[WHITELIST] Failed to load whitelist: {e}")
            return set()
    return set()


def save_whitelist(whitelist):
    with open(WHITELIST_FILE, "w", encoding="utf-8") as f:
        json.dump(sorted(list(whitelist)), f, indent=2)


WHITELIST = load_whitelist()


@lru_cache(maxsize=1000)
def get_country_name_from_code(code):
    try:
        return countries.get(code).name
    except (KeyError, AttributeError):
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
    if not ENABLE_EXTERNAL_IP_LOOKUPS:
        return "External lookup disabled"

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
    if not ENABLE_EXTERNAL_IP_LOOKUPS:
        return False

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
        with open(THREAT_LOG, newline="", encoding="utf-8") as file:
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
        with open(path, newline="", encoding="utf-8") as file:
            reader = csv.DictReader(file)
            for row in reader:
                if row.get("ip") == ip:
                    print(f"[THREAT DB] IP {ip} already logged. Skipping.")
                    return

    with open(path, "a", newline="", encoding="utf-8") as file:
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
            print("[FIREWALL] Unsupported OS - skipping firewall")
    except Exception as e:
        print(f"[FIREWALL] Error blocking {ip}: {e}")


def ensure_csv_headers(path, headers):
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)


def read_csv_or_empty(path, headers):
    ensure_csv_headers(path, headers)

    try:
        df = pd.read_csv(path)
    except pd.errors.EmptyDataError:
        return pd.DataFrame(columns=headers)

    df.columns = df.columns.str.strip()
    for column in headers:
        if column not in df.columns:
            df[column] = ""

    return df


def parse_positive_int(value, default=1):
    try:
        return max(1, int(value))
    except (TypeError, ValueError):
        return default


def safe_int(value, default=0):
    try:
        if pd.isna(value):
            return default
        return int(float(value))
    except (TypeError, ValueError):
        return default


def paginate_records(records, page, page_size=PAGE_SIZE):
    total = len(records)
    pages = max((total + page_size - 1) // page_size, 1)
    page = min(max(1, page), pages)
    start = (page - 1) * page_size
    end = start + page_size

    return records[start:end], {
        "page": page,
        "pages": pages,
        "page_size": page_size,
        "total": total,
        "start": start + 1 if total else 0,
        "end": min(end, total),
        "has_prev": page > 1,
        "has_next": page < pages,
        "prev_page": max(page - 1, 1),
        "next_page": min(page + 1, pages),
    }


def get_dashboard_filters():
    return {
        "ip": request.args.get("ip", "").strip(),
        "filename": request.args.get("filename", "").strip(),
        "process": request.args.get("process", "").strip(),
        "timestamp": request.args.get("timestamp", "").strip(),
        "severity": request.args.get("severity", "").strip().lower(),
    }


def contains_text(series, value):
    if not value:
        return pd.Series(True, index=series.index)
    return series.fillna("").astype(str).str.contains(value, case=False, na=False, regex=False)


def classify_ip_severity(row):
    attempts = safe_int(row.get("login_attempts", 0))
    abuse_score = safe_int(row.get("abuse_score", 0))

    if abuse_score >= 90 or attempts >= 20:
        return "critical"
    if abuse_score > 50 or bool(row.get("vpn_flagged")) or row.get("anomaly") == -1:
        return "high"
    if attempts >= 5:
        return "medium"
    return "low"


def classify_scan_severity(row):
    result = str(row.get("result", "")).lower()

    if result == "malicious":
        return "critical"
    if result == "suspicious":
        return "high"
    if result == "error":
        return "medium"
    return "low"


def classify_process_severity(row):
    text = " ".join(
        str(row.get(field, "")).lower()
        for field in ("name", "path", "cmdline", "reason")
    )

    if any(term in text for term in ("mimikatz", "netcat", "frombase64string", "encodedcommand")):
        return "critical"
    if any(term in text for term in ("executionpolicy bypass", "downloadstring(", "regsvr32.exe", "rundll32.exe", "behavioral:", "non-standard location")):
        return "high"
    if any(term in text for term in ("mshta.exe", "wscript.exe", "cscript.exe", "wmic.exe", "schtasks.exe")):
        return "medium"
    return "low"


def apply_severity_filter(df, severity):
    if severity in SEVERITY_OPTIONS and "severity" in df.columns:
        return df[df["severity"] == severity]
    return df


def get_process_monitor_status():
    with PROCESS_MONITOR_LOCK:
        return PROCESS_MONITOR_STATUS.copy()


def update_process_monitor_status(**updates):
    with PROCESS_MONITOR_LOCK:
        PROCESS_MONITOR_STATUS.update(updates)


def build_runtime_status(active_alerts):
    watcher_status = get_file_watcher_status()
    scan_status = get_scan_status()
    process_status = get_process_monitor_status()
    endpoint_status = get_endpoint_monitor_status()
    login_status = get_login_import_status()

    return {
        "scanner_running": bool(
            watcher_status.get("thread_running")
            and watcher_status.get("observer_running")
        ),
        "scanner_thread_running": bool(watcher_status.get("thread_running")),
        "scanner_watch_count": watcher_status.get("active_watches", 0),
        "scanner_last_error": watcher_status.get("last_error"),
        "last_scan_time": scan_status.get("last_scan_time"),
        "last_scan_result": scan_status.get("last_scan_result"),
        "process_monitor_running": bool(process_status.get("running")),
        "process_last_scan_time": process_status.get("last_scan_time"),
        "process_last_error": process_status.get("last_error"),
        "endpoint_monitor_running": bool(endpoint_status.get("running")),
        "endpoint_baseline_established": bool(endpoint_status.get("baseline_established")),
        "endpoint_tracked_entries": endpoint_status.get("tracked_entries", 0),
        "endpoint_last_scan_time": endpoint_status.get("last_scan_time"),
        "endpoint_last_error": endpoint_status.get("last_error"),
        "login_import_available": login_status.get("available"),
        "login_import_requires_admin": bool(login_status.get("requires_admin")),
        "login_import_last_time": login_status.get("last_import_time"),
        "login_import_total": login_status.get("total_imported", 0),
        "active_alerts": active_alerts,
    }


def compute_posture(summary, runtime_status, network, scan_config, defender=None,
                    firewall=None, flagged_connections=0):
    """Security health score (0-100) with plain-language recommendations."""
    score = 100
    recommendations = []

    if flagged_connections:
        score -= min(flagged_connections * 12, 30)
        recommendations.append(
            f"{flagged_connections} program(s) are talking to a flagged address right now - check Active Connections."
        )

    if firewall:
        off = [p["name"] for p in firewall.get("profiles", []) if not p["on"]]
        if off:
            score -= min(len(off) * 8, 16)
            recommendations.append(
                f"Windows Firewall is off for: {', '.join(off)}. Turn it back on in Windows Security."
            )

    if defender and defender.get("available"):
        if not defender.get("antivirus_enabled"):
            score -= 15
            recommendations.append("Windows Defender antivirus is turned off - turn it back on in Windows Security.")
        elif not defender.get("realtime_enabled"):
            score -= 8
            recommendations.append("Windows Defender real-time protection is off - turn it on in Windows Security.")
        active_threats = [t for t in defender.get("threats", []) if t.get("active")]
        if active_threats:
            score -= min(len(active_threats) * 8, 20)
            recommendations.append(
                f"Windows Defender has {len(active_threats)} active threat(s) - open Windows Security to remove them."
            )

    if summary["file_alerts"]:
        score -= min(summary["file_alerts"] * 5, 20)
        recommendations.append(
            f"Review {summary['file_alerts']} flagged file(s) in File Protection - mark them safe or malicious."
        )
    if summary["suspicious_processes"]:
        score -= min(summary["suspicious_processes"] * 5, 20)
        recommendations.append(
            f"Check {summary['suspicious_processes']} suspicious program(s) in Program Activity."
        )
    if summary["endpoint_alerts"]:
        score -= min(summary["endpoint_alerts"] * 3, 15)
        recommendations.append(
            f"Look over {summary['endpoint_alerts']} recent system change(s) in Startup & System Changes."
        )
    if summary["flagged_ips"]:
        score -= min(summary["flagged_ips"] * 2, 10)
        recommendations.append(
            f"Review {summary['flagged_ips']} flagged sign-in address(es)."
        )

    if not runtime_status["scanner_running"]:
        score -= 10
        recommendations.append("File Guard is not watching any folders - add a folder in File Protection.")
    if not runtime_status["process_monitor_running"]:
        score -= 10
        recommendations.append("Program Guard stopped - restart Doors AI.")
    if not runtime_status["endpoint_monitor_running"]:
        score -= 10
        recommendations.append("System Guard stopped - restart Doors AI.")

    if runtime_status.get("login_import_requires_admin"):
        score -= 5
        recommendations.append(
            "Run Doors AI as administrator so it can watch Windows sign-ins."
        )

    if not scan_config.get("ransomware_canaries", True):
        score -= 5
        recommendations.append("Ransomware tripwire files are turned off in the scanner settings.")

    risky_open = [
        p for p in network.get("ports", [])
        if p["severity"] == "high" and p["binding"] != "localhost only"
    ]
    seen_ports = set()
    for port in risky_open:
        if port["port"] in seen_ports:
            continue
        seen_ports.add(port["port"])
        score -= 8
        service = port["service"] or f"port {port['port']}"
        recommendations.append(
            f"{service} (port {port['port']}) is reachable from your network - turn it off if you do not use it."
        )
    score = max(0, min(100, score))

    if score >= 90:
        grade, label = "A", "Well protected"
    elif score >= 80:
        grade, label = "B", "Good"
    elif score >= 70:
        grade, label = "C", "Needs a little attention"
    elif score >= 60:
        grade, label = "D", "Needs attention"
    else:
        grade, label = "F", "At risk"

    if not recommendations:
        recommendations.append("You're all set - no action needed right now.")

    return {
        "score": score,
        "grade": grade,
        "label": label,
        "recommendations": recommendations[:6],
    }


def load_recent_process_alerts():
    global RECENT_PROCESS_ALERTS

    if not os.path.exists(PROCESS_LOG):
        return

    try:
        df = read_csv_or_empty(PROCESS_LOG, PROCESS_LOG_HEADERS)
        df = normalize_process_log_columns(df)
        for _, row in df.iterrows():
            name = str(row.get("name", "")).lower()
            path = str(row.get("path", "")).lower()
            reason = str(row.get("reason", ""))
            if name and reason:
                RECENT_PROCESS_ALERTS.add(f"{name}:{path}:{reason}")
    except Exception as e:
        print(f"[PROCESS] Failed to preload alert cache: {e}")


def process_alert_key(name, path, reason):
    return f"{name.lower()}:{path.lower()}:{reason}"


def log_suspicious_process(pid, name, path, reason):
    ensure_csv_headers(PROCESS_LOG, PROCESS_LOG_HEADERS)

    alert_key = process_alert_key(name, path, reason)
    if alert_key in RECENT_PROCESS_ALERTS:
        return False

    RECENT_PROCESS_ALERTS.add(alert_key)
    if len(RECENT_PROCESS_ALERTS) > PROCESS_ALERT_CACHE_MAX:
        RECENT_PROCESS_ALERTS.clear()
        load_recent_process_alerts()

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(PROCESS_LOG, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, pid, name, path, reason])

    print(f"[ALERT] Suspicious process: {name} (PID: {pid}) - {reason}")

    severity = classify_process_severity({"name": name, "path": path, "reason": reason})
    try:
        from monitor.notify import notify
        if severity in ("high", "critical"):
            notify("Doors AI: Suspicious program", f"{name} - {reason}", key=alert_key)
    except Exception:
        pass

    try:
        from monitor.events_db import record_event
        record_event("process", severity, name, reason)
    except Exception:
        pass

    return True


def match_suspicious_process(name, exe_path, cmdline):
    name = name.lower()
    exe_lower = exe_path.lower()
    cmd_lower = cmdline.lower()
    full_text = f"{name} {exe_lower} {cmd_lower}"

    for keyword in MALWARE_PROCESS_NAMES:
        if keyword in full_text:
            return f"Matched keyword: {keyword}"

    for pattern in SUSPICIOUS_COMMAND_PATTERNS:
        if pattern in full_text:
            return f"Matched command pattern: {pattern}"

    if name in LOLBIN_NAMES:
        # A system tool binary running from outside the Windows system
        # directories is a classic masquerading technique.
        if exe_lower and not exe_lower.startswith(SYSTEM_BINARY_DIRS):
            return f"System binary running from non-standard location: {exe_path}"

        for hint in USER_WRITABLE_PATH_HINTS:
            if hint in cmd_lower:
                return f"{name} referencing user-writable path: {hint.strip(chr(92))}"

    return None


def scan_processes():
    global WHITELIST

    WHITELIST = load_whitelist()
    scanned = 0
    alerts = 0

    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
        try:
            scanned += 1
            pid = proc.info["pid"]
            raw_name = proc.info["name"] or ""
            name = raw_name.lower()
            exe_path = proc.info["exe"] or ""
            cmdline = " ".join(proc.info["cmdline"]) if proc.info["cmdline"] else ""

            # Behavioral parent-child check runs before the whitelist:
            # whitelisting powershell.exe means "powershell is fine", not
            # "Word launching powershell is fine".
            reason = None
            if name in SCRIPT_HOST_NAMES:
                try:
                    parent = proc.parent()
                    parent_name = parent.name().lower() if parent else ""
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    parent_name = ""
                if parent_name in DOCUMENT_APP_NAMES:
                    reason = f"Behavioral: {parent_name} spawned {name}"

            if reason is None:
                if name in WHITELIST:
                    continue
                reason = match_suspicious_process(name, exe_path, cmdline)

            if not reason:
                continue

            if log_suspicious_process(pid, raw_name, exe_path, reason):
                alerts += 1

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return {"scanned": scanned, "alerts": alerts}


def start_process_monitor_thread():
    def loop():
        while True:
            try:
                summary = scan_processes()
                update_process_monitor_status(
                    running=True,
                    last_scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    last_process_count=summary["scanned"],
                    last_alert_count=summary["alerts"],
                    last_error=None,
                )
            except Exception as e:
                update_process_monitor_status(
                    running=False,
                    last_error=str(e),
                )
                print(f"[PROCESS] Monitor error: {e}")
            time.sleep(PROCESS_MONITOR_INTERVAL)

    update_process_monitor_status(running=True)
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
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)

    print(f"[LOGS] Cleared {path}")


def count_csv_data_rows(path):
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return 0

    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        return max(sum(1 for _ in f) - 1, 0)


def rotate_log_if_needed(path, headers, max_rows, max_bytes):
    try:
        if not os.path.exists(path):
            ensure_csv_headers(path, headers)
            return

        row_count = count_csv_data_rows(path)
        file_size = os.path.getsize(path)

        if row_count > max_rows or file_size > max_bytes:
            archive_log_file(path, headers)
    except Exception as e:
        print(f"[LOGS] Failed to rotate {path}: {e}")


def initialize_runtime_files():
    log_specs = [
        (PROCESS_LOG, PROCESS_LOG_HEADERS, PROCESS_LOG_ROTATE_ROWS, PROCESS_LOG_ROTATE_BYTES),
        (SCAN_LOG, SCAN_LOG_HEADERS, SCAN_LOG_ROTATE_ROWS, SCAN_LOG_ROTATE_BYTES),
        (ENDPOINT_LOG, ENDPOINT_LOG_HEADERS, ENDPOINT_LOG_ROTATE_ROWS, ENDPOINT_LOG_ROTATE_BYTES),
        (LOGIN_LOG, LOGIN_LOG_HEADERS, LOGIN_LOG_ROTATE_ROWS, LOGIN_LOG_ROTATE_BYTES),
    ]

    for path, headers, max_rows, max_bytes in log_specs:
        ensure_csv_headers(path, headers)
        rotate_log_if_needed(path, headers, max_rows, max_bytes)


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

    # Hide legacy false positives from retired detection rules: the old broad
    # "bypass" keyword and name-only matches on LOLBins (rundll32, cscript,
    # etc.), which now require suspicious command-line context to alert.
    reasons = df_proc["reason"].str.lower().str.strip()
    legacy_keywords = {"bypass", "taskkill"} | LOLBIN_NAMES
    legacy_rows = reasons.isin({f"matched keyword: {kw}" for kw in legacy_keywords})
    df_proc = df_proc[~legacy_rows]

    if WHITELIST:
        df_proc = df_proc[~df_proc["name"].str.lower().isin(WHITELIST)]

    return df_proc.drop_duplicates(
        subset=["name", "path", "reason"],
        keep="first",
    )


def append_login_event(ip, location, user_agent, login_attempts):
    ensure_csv_headers(LOGIN_LOG, LOGIN_LOG_HEADERS)
    timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

    with open(LOGIN_LOG, "a", newline="", encoding="utf-8") as f:
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
    ip_records, scan_records, proc_records = [], [], []
    alert_records = []
    df = None
    scan_config = load_scan_config()
    filters = get_dashboard_filters()
    pages = {}
    summary = {
        "login_records": 0,
        "flagged_ips": 0,
        "file_alerts": 0,
        "suspicious_processes": 0,
        "endpoint_alerts": 0,
        "active_alerts": 0,
    }

    initialize_runtime_files()

    try:
        df = read_csv_or_empty(LOGIN_LOG, LOGIN_LOG_HEADERS)
        df = df.dropna(subset=["ip", "user_agent", "login_attempts"])
        df["login_attempts"] = pd.to_numeric(df["login_attempts"], errors="coerce").fillna(0)
        df["location_code"] = df["location"].fillna("Unknown").astype("category").cat.codes
        df["agent_code"] = df["user_agent"].fillna("Unknown").astype("category").cat.codes
        X = df[["login_attempts", "location_code", "agent_code"]]

        if not df.empty:
            model = IsolationForest(contamination=0.3, random_state=42)
            model.fit(X)

            df["anomaly"] = model.predict(X)
            df["anomaly_score"] = model.decision_function(X).round(4)
        else:
            df["anomaly"] = []
            df["anomaly_score"] = []

        if ENABLE_EXTERNAL_IP_LOOKUPS:
            df["location"] = df["ip"].apply(get_country_from_ip)
        else:
            df["location"] = df["location"].fillna("Unknown")

        threat_info = df["ip"].apply(check_local_threat_db)
        df["abuse_score"] = threat_info.apply(lambda item: item["abuse_score"])
        df["abuse_category"] = threat_info.apply(lambda item: item["categories"])

        df["is_vpn_local"] = df["ip"].apply(is_vpn_local)
        df["is_vpn_api"] = df["ip"].apply(is_vpn_api)
        df["vpn_flagged"] = df["is_vpn_local"] | df["is_vpn_api"]
        df["flagged"] = (
            (df["anomaly"] == -1)
            | df["vpn_flagged"]
            | (pd.to_numeric(df["abuse_score"], errors="coerce").fillna(0) > 50)
        )
        df["severity"] = df.apply(classify_ip_severity, axis=1)

        if AUTO_BLOCK_IPS:
            for _, row in df[df["flagged"]].iterrows():
                block_ip(row["ip"])
                log_threat(row["ip"], "Auto-blocked by Doors AI", row["abuse_score"] or 60)

        alerts = df[df["flagged"]].to_dict(orient="records")
        summary["login_records"] = len(df)
        summary["flagged_ips"] = len(alerts)

        df_display = df.copy()
        df_display = df_display[contains_text(df_display["ip"], filters["ip"])]
        df_display = df_display[contains_text(df_display["timestamp"], filters["timestamp"])]
        df_display = apply_severity_filter(df_display, filters["severity"])
        alert_records = df_display[df_display["flagged"]].to_dict(orient="records")
        ip_records = df_display.sort_values(by="anomaly_score", ascending=True).to_dict(orient="records")

    except Exception as e:
        print(f"[ERROR] Loading {LOGIN_LOG}: {e}")
        alerts = []

    try:
        df_scan = read_csv_or_empty(SCAN_LOG, SCAN_LOG_HEADERS)
        df_scan["result"] = df_scan["result"].fillna("")
        df_scan["severity"] = df_scan.apply(classify_scan_severity, axis=1)
        df_scan = df_scan[df_scan["result"].str.lower() != "safe"]

        # Rows the user has marked safe no longer count as alerts.
        trusted_hashes = load_trusted_hashes()
        if trusted_hashes:
            df_scan = df_scan[
                ~df_scan["sha256"].fillna("").astype(str).str.lower().isin(trusted_hashes)
            ]

        summary["file_alerts"] = len(df_scan)

        df_scan = df_scan[contains_text(df_scan["filename"], filters["filename"])]
        df_scan = df_scan[contains_text(df_scan["timestamp"], filters["timestamp"])]
        df_scan = apply_severity_filter(df_scan, filters["severity"])
        scan_records = df_scan.sort_values(by="timestamp", ascending=False).to_dict(orient="records")
        for entry in scan_records:
            entry["mitre"] = tag_technique(entry.get("reason"), entry.get("result"))
    except Exception as e:
        print(f"[ERROR] Failed to load scanner logs: {e}")

    try:
        df_proc = read_csv_or_empty(PROCESS_LOG, PROCESS_LOG_HEADERS)
        df_proc = normalize_process_log_columns(df_proc)
        df_proc = df_proc.sort_values(by="timestamp", ascending=False)
        df_proc = filter_actionable_process_logs(df_proc)
        df_proc["severity"] = df_proc.apply(classify_process_severity, axis=1)
        summary["suspicious_processes"] = len(df_proc)

        df_proc = df_proc[contains_text(df_proc["name"], filters["process"])]
        df_proc = df_proc[contains_text(df_proc["timestamp"], filters["timestamp"])]
        df_proc = apply_severity_filter(df_proc, filters["severity"])
        proc_records = df_proc.to_dict(orient="records")
        for entry in proc_records:
            entry["cmdline"] = entry.get("path") or entry.get("cmdline") or ""
            entry["mitre"] = tag_technique(entry.get("reason"), entry.get("name"), entry.get("path"))
    except Exception as e:
        print(f"[ERROR] Failed to load process logs: {e}")

    endpoint_records = []
    try:
        df_endpoint = read_csv_or_empty(ENDPOINT_LOG, ENDPOINT_LOG_HEADERS)
        df_endpoint["severity"] = (
            df_endpoint["severity"].fillna("medium").astype(str).str.lower()
        )
        df_endpoint = df_endpoint.sort_values(by="timestamp", ascending=False)
        summary["endpoint_alerts"] = len(df_endpoint)

        df_endpoint = df_endpoint[contains_text(df_endpoint["name"], filters["process"])]
        df_endpoint = df_endpoint[contains_text(df_endpoint["timestamp"], filters["timestamp"])]
        df_endpoint = apply_severity_filter(df_endpoint, filters["severity"])
        endpoint_records = df_endpoint.to_dict(orient="records")
        for entry in endpoint_records:
            entry["mitre"] = tag_technique(entry.get("reason"), entry.get("category"), entry.get("detail"))
    except Exception as e:
        print(f"[ERROR] Failed to load endpoint logs: {e}")

    summary["active_alerts"] = (
        summary["flagged_ips"]
        + summary["file_alerts"]
        + summary["suspicious_processes"]
        + summary.get("endpoint_alerts", 0)
    )

    ip_logs, pages["login"] = paginate_records(
        ip_records,
        parse_positive_int(request.args.get("login_page")),
    )
    scan_logs, pages["scan"] = paginate_records(
        scan_records,
        parse_positive_int(request.args.get("scan_page")),
    )
    proc_logs, pages["process"] = paginate_records(
        proc_records,
        parse_positive_int(request.args.get("process_page")),
    )
    endpoint_logs, pages["endpoint"] = paginate_records(
        endpoint_records,
        parse_positive_int(request.args.get("endpoint_page")),
    )

    runtime_status = build_runtime_status(summary["active_alerts"])

    try:
        quarantine_entries = list_quarantined_files()
    except Exception as e:
        print(f"[ERROR] Failed to list quarantine: {e}")
        quarantine_entries = []

    try:
        hash_db_count = len(load_hash_db())
    except Exception:
        hash_db_count = 0

    try:
        publisher_lists = load_publisher_lists()
    except Exception:
        publisher_lists = {"allow": [], "deny": [], "strict": False}

    try:
        trend_days = get_daily_counts(14)
        trend_max = max((d["count"] for d in trend_days), default=0)
        week_summary = get_summary(7)
    except Exception as e:
        print(f"[ERROR] Trend history failed: {e}")
        trend_days, trend_max, week_summary = [], 0, {"days": 7, "total": 0, "by_kind": {}, "by_severity": {}}

    try:
        incidents = get_incidents(days=7)
    except Exception as e:
        print(f"[ERROR] Incident correlation failed: {e}")
        incidents = []

    try:
        network = get_network_snapshot()
    except Exception as e:
        print(f"[ERROR] Network snapshot failed: {e}")
        network = {"devices": [], "ports": [], "error": str(e)}

    try:
        defender = get_defender_status()
    except Exception as e:
        print(f"[ERROR] Defender status failed: {e}")
        defender = {"available": False, "error": str(e)}

    try:
        connections = get_active_connections()
    except Exception as e:
        print(f"[ERROR] Connections failed: {e}")
        connections = {"connections": [], "flagged": [], "error": str(e)}
    try:
        dns = get_dns_cache()
    except Exception as e:
        print(f"[ERROR] DNS cache failed: {e}")
        dns = {"records": [], "error": str(e)}
    try:
        firewall = get_firewall_status()
        vulnerabilities = assess_vulnerabilities(network, defender)
    except Exception as e:
        print(f"[ERROR] Vulnerability assessment failed: {e}")
        firewall, vulnerabilities = {"profiles": []}, []
    try:
        new_devices = check_new_devices(network.get("devices", []))
    except Exception as e:
        print(f"[ERROR] New-device check failed: {e}")
        new_devices = []

    posture = compute_posture(summary, runtime_status, network, scan_config, defender,
                              firewall=firewall, flagged_connections=len(connections.get("flagged", [])))

    feeds_config = load_feeds_config()
    feeds = {
        "ipsum_min_lists": feeds_config.get("ipsum_min_lists", 3),
        "ipsum_last_sync": feeds_config.get("ipsum_last_sync"),
        "ipsum_last_count": feeds_config.get("ipsum_last_count", 0),
        "bazaar_has_key": bool(feeds_config.get("malwarebazaar_auth_key")),
        "bazaar_last_sync": feeds_config.get("bazaar_last_sync"),
        "bazaar_last_count": feeds_config.get("bazaar_last_count", 0),
        "feodo_last_sync": feeds_config.get("feodo_last_sync"),
        "feodo_last_count": feeds_config.get("feodo_last_count", 0),
        "vt_has_key": bool(feeds_config.get("virustotal_api_key")),
    }

    return render_template(
        "dashboard.html",
        data=ip_logs,
        scan_logs=scan_logs,
        proc_logs=proc_logs,
        endpoint_logs=endpoint_logs,
        alerts=alert_records,
        whitelist=sorted(list(WHITELIST)),
        scan_config=scan_config,
        filters=filters,
        info=INFO_TEXT,
        pages=pages,
        severity_options=SEVERITY_OPTIONS,
        summary=summary,
        runtime_status=runtime_status,
        auto_block_ips=AUTO_BLOCK_IPS,
        quarantine_entries=quarantine_entries,
        hash_db_count=hash_db_count,
        network=network,
        posture=posture,
        feeds=feeds,
        defender=defender,
        publisher_lists=publisher_lists,
        security_locked=bool(load_security_config().get("passphrase")),
        notifications_enabled=notify_enabled(),
        schedule=load_scheduler_config(),
        trend_days=trend_days,
        trend_max=trend_max,
        week_summary=week_summary,
        incidents=incidents,
        connections=connections,
        dns=dns,
        vulnerabilities=vulnerabilities,
        new_devices=new_devices,
    )


@app.route("/whitelist/add", methods=["POST"])
def add_whitelist():
    global WHITELIST

    process_name = request.form.get("process_name", "").strip().lower()

    if process_name:
        WHITELIST.add(process_name)
        save_whitelist(WHITELIST)
        print(f"[WHITELIST] Added {process_name}")
        flash(f"{process_name} added to trusted programs.", "success")

    return redirect(url_for("home"))


@app.route("/whitelist/remove", methods=["POST"])
def remove_whitelist():
    global WHITELIST

    process_name = request.form.get("process_name", "").strip().lower()

    if process_name in WHITELIST:
        WHITELIST.remove(process_name)
        save_whitelist(WHITELIST)
        print(f"[WHITELIST] Removed {process_name}")
        flash(f"{process_name} removed from trusted programs.", "success")

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
        flash(f"Stopped {proc_name} (PID {pid}).", "success")

    except Exception as e:
        print(f"[PROCESS] Failed to terminate PID {pid_raw}: {e}")
        flash(f"Could not stop that program: {e}", "error")

    return redirect(url_for("home"))


@app.route("/logs/archive", methods=["POST"])
def archive_logs():
    log_type = request.form.get("log_type", "").strip().lower()

    if log_type == "scanner":
        archive_log_file(SCAN_LOG, SCAN_LOG_HEADERS)
    elif log_type == "process":
        archive_log_file(PROCESS_LOG, PROCESS_LOG_HEADERS)
        RECENT_PROCESS_ALERTS.clear()
    elif log_type == "endpoint":
        archive_log_file(ENDPOINT_LOG, ENDPOINT_LOG_HEADERS)
    elif log_type == "login":
        archive_log_file(LOGIN_LOG, LOGIN_LOG_HEADERS)

    if log_type:
        flash("Log saved to the archives folder and cleared from view.", "success")

    return redirect(url_for("home"))


@app.route("/logs/clear", methods=["POST"])
def clear_logs():
    log_type = request.form.get("log_type", "").strip().lower()

    if log_type == "scanner":
        clear_log_file(SCAN_LOG, SCAN_LOG_HEADERS)
    elif log_type == "process":
        clear_log_file(PROCESS_LOG, PROCESS_LOG_HEADERS)
        RECENT_PROCESS_ALERTS.clear()
    elif log_type == "endpoint":
        clear_log_file(ENDPOINT_LOG, ENDPOINT_LOG_HEADERS)
    elif log_type == "login":
        clear_log_file(LOGIN_LOG, LOGIN_LOG_HEADERS)

    if log_type:
        flash("Log cleared.", "success")

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


@app.route("/login/import-windows", methods=["POST"])
def import_windows_logins():
    summary = import_login_events()
    print(f"[LOGIN-IMPORT] Manual import: {summary}")

    if summary["error"] == "requires_admin":
        flash("Windows only lets administrators read sign-in history. Restart Doors AI as administrator to use this.", "error")
    elif summary["error"]:
        flash(f"Import failed: {summary['error']}", "error")
    elif summary["imported"]:
        flash(f"Imported {summary['imported']} sign-in event group(s) from Windows.", "success")
    else:
        flash("No new sign-in events since the last import.", "info")

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
            flash(f"Now watching {normalized} for new files.", "success")
        else:
            print(f"[SCANNER] Cannot add missing folder: {normalized}")
            flash(f"That folder doesn't exist: {normalized}", "error")

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
        flash(f"Stopped watching {normalized}.", "success")

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
            flash(
                f"Scan finished: {summary['scanned']} file(s) checked, "
                f"{summary['alerts']} flagged, {summary['errors']} error(s).",
                "success" if not summary["alerts"] else "info",
            )
        else:
            print(f"[SCANNER] Cannot scan missing folder: {normalized}")
            flash(f"That folder doesn't exist: {normalized}", "error")

    return redirect(url_for("home"))


@app.route("/file/trust", methods=["POST"])
def trust_file():
    sha256 = normalize_sha256(request.form.get("sha256", ""))
    filename = request.form.get("filename", "").strip()

    if sha256:
        add_trusted_hash(sha256, filename)
        print(f"[SCANNER] User marked {filename or sha256} as safe")
        flash(f"{filename or 'File'} marked as safe - it won't be flagged again.", "success")

    return redirect(url_for("home"))


@app.route("/file/confirm-malicious", methods=["POST"])
def confirm_malicious_file():
    sha256 = normalize_sha256(request.form.get("sha256", ""))
    filename = request.form.get("filename", "").strip()

    if not sha256:
        return redirect(url_for("home"))

    add_to_hash_db(sha256, f"User confirmed malicious: {filename or 'unknown'}")

    located = find_file_in_watch_folders(filename, sha256=sha256)
    if located is not None:
        try:
            quarantine_file(located, sha256=sha256, reason="User confirmed malicious")
            flash(f"{filename} learned as malware and moved to quarantine.", "success")
        except Exception as e:
            print(f"[SCANNER] Failed to quarantine {located}: {e}")
            flash(f"Fingerprint learned, but the file could not be quarantined: {e}", "error")
    else:
        print(f"[SCANNER] {filename} not found in watch folders; hash learned only")
        flash(
            f"Fingerprint learned. {filename} was not found in the watched folders, "
            "but it will be caught instantly if it ever appears.",
            "info",
        )

    return redirect(url_for("home"))


@app.route("/quarantine/restore", methods=["POST"])
def quarantine_restore():
    filename = request.form.get("filename", "").strip()

    if filename:
        ok, detail = restore_quarantined_file(filename)
        if ok:
            flash(f"{filename} restored to {detail}.", "success")
        else:
            print(f"[QUARANTINE] Restore failed for {filename}: {detail}")
            flash(f"Could not restore {filename}: {detail}", "error")

    return redirect(url_for("home"))


@app.route("/quarantine/delete", methods=["POST"])
def quarantine_delete():
    filename = request.form.get("filename", "").strip()

    if filename:
        ok, detail = delete_quarantined_file(filename)
        if ok:
            flash(f"{filename} permanently deleted from quarantine.", "success")
        else:
            print(f"[QUARANTINE] Delete failed for {filename}: {detail}")
            flash(f"Could not delete {filename}: {detail}", "error")

    return redirect(url_for("home"))


@app.route("/publishers/update", methods=["POST"])
def publishers_update():
    action = request.form.get("action", "").strip()
    publisher = request.form.get("publisher", "").strip()

    if action == "strict":
        set_publisher_strict(request.form.get("strict") == "1")
        flash("Publisher strict mode updated.", "success")
    elif action in ("allow", "deny", "remove-allow", "remove-deny") and publisher:
        update_publisher_list(action, publisher)
        verb = {"allow": "trusted", "deny": "blocked",
                "remove-allow": "removed from trusted", "remove-deny": "removed from blocked"}[action]
        flash(f"Publisher \"{publisher}\" {verb}.", "success")

    return redirect(url_for("home"))


@app.route("/network/reset-devices", methods=["POST"])
def network_reset_devices():
    if reset_device_baseline():
        flash("Network device list reset. Current devices are now the trusted baseline.", "success")
    else:
        flash("Could not reset the device baseline.", "error")
    return redirect(url_for("home"))


@app.route("/system/open-location", methods=["POST"])
def open_location():
    path = request.form.get("path", "").strip()

    if not path or not os.path.exists(path):
        flash("That file is no longer on disk - the program may have closed or been removed already.", "error")
        return redirect(url_for("home"))

    if platform.system() != "Windows":
        flash("Opening a file location is only supported on Windows.", "error")
        return redirect(url_for("home"))

    try:
        norm = os.path.normpath(path)
        if os.path.isfile(norm):
            # explorer /select, highlights the file inside its folder.
            subprocess.Popen(["explorer", "/select,", norm])
        else:
            os.startfile(norm)
        flash(f"Opened File Explorer to {os.path.basename(norm)}.", "info")
    except Exception as e:
        print(f"[SYSTEM] Failed to open location {path}: {e}")
        flash(f"Could not open that location: {e}", "error")

    return redirect(url_for("home"))


@app.route("/endpoint/rebaseline", methods=["POST"])
def endpoint_rebaseline():
    if reset_baseline():
        flash("Current setup marked as trusted. Only new changes will alert from now on.", "success")
    else:
        flash("Could not reset the baseline - check the console for details.", "error")
    return redirect(url_for("home"))


@app.route("/ip/log-threat", methods=["POST"])
def ip_log_threat():
    ip = request.form.get("ip", "").strip()
    reason = request.form.get("reason", "").strip() or "Manually flagged from dashboard"

    if ip:
        log_threat(ip, reason, score=80)
        flash(f"{ip} added to your threat list.", "success")

    return redirect(url_for("home"))


@app.route("/ip/block", methods=["POST"])
def ip_block():
    ip = request.form.get("ip", "").strip()

    if ip:
        block_ip(ip)
        log_threat(ip, "Manually blocked from dashboard", score=90)
        flash(
            f"Firewall block requested for {ip}. If Doors AI is not running as administrator, the rule may not have been created.",
            "info",
        )

    return redirect(url_for("home"))


@app.route("/feeds/update-ipsum", methods=["POST"])
def feeds_update_ipsum():
    min_lists = request.form.get("min_lists", "").strip()
    result = update_ipsum(min_lists=min_lists or None)

    if result["ok"]:
        # New threat-list entries invalidate the per-IP lookup cache.
        check_local_threat_db.cache_clear()
        flash(
            f"Threat list updated from IPsum: {result['count']} address(es) "
            f"on {result['min_lists']}+ blocklists.",
            "success",
        )
    else:
        flash(f"IPsum update failed: {result['error']}", "error")

    return redirect(url_for("home"))


@app.route("/feeds/update-feodo", methods=["POST"])
def feeds_update_feodo():
    result = update_feodo()
    if result["ok"]:
        check_local_threat_db.cache_clear()
        flash(f"Threat list updated from Feodo Tracker: {result['count']} botnet C2 address(es).", "success")
    else:
        flash(f"Feodo Tracker update failed: {result['error']}", "error")
    return redirect(url_for("home"))


@app.route("/feeds/update-hashes", methods=["POST"])
def feeds_update_hashes():
    auth_key = request.form.get("auth_key", "").strip()
    result = update_malware_hashes(auth_key=auth_key or None)

    if result["ok"]:
        flash(
            f"Malware fingerprints updated from MalwareBazaar: "
            f"{result['count']} new (of {result['seen']} in the latest export).",
            "success",
        )
    elif result["error"] == "auth_required":
        flash(
            "MalwareBazaar needs a free Auth-Key. Get one at auth.abuse.ch, "
            "then paste it in the field and try again.",
            "info",
        )
    elif result["error"] == "auth_rejected":
        flash("MalwareBazaar rejected that Auth-Key. Double-check it at auth.abuse.ch.", "error")
    else:
        flash(f"MalwareBazaar update failed: {result['error']}", "error")

    return redirect(url_for("home"))


@app.route("/vt/save-key", methods=["POST"])
def vt_save_key():
    save_virustotal_key(request.form.get("api_key", ""))
    flash("VirusTotal key saved.", "success")
    return redirect(url_for("home"))


@app.route("/vt/check", methods=["POST"])
def vt_check():
    sha256 = request.form.get("sha256", "").strip()
    filename = request.form.get("filename", "").strip() or "That file"
    result = vt_lookup(sha256)

    if not result["ok"]:
        if result["error"] == "auth_required":
            flash("Add a free VirusTotal API key (in Threat Intelligence Feeds) to use this.", "info")
        elif result["error"] == "auth_rejected":
            flash("VirusTotal rejected that API key - check it at virustotal.com.", "error")
        else:
            flash(f"VirusTotal lookup failed: {result['error']}", "error")
    elif not result.get("found"):
        flash(f"{filename} is not known to VirusTotal (no engines have seen this fingerprint).", "info")
    else:
        verdict = "success" if result["malicious"] == 0 else "error"
        flash(
            f"{filename}: {result['malicious']} of {result['total']} VirusTotal engines flag it as malicious"
            f"{' (' + str(result['suspicious']) + ' suspicious)' if result['suspicious'] else ''}.",
            verdict,
        )

    return redirect(url_for("home"))


@app.route("/hashdb/add", methods=["POST"])
def hashdb_add():
    sha256 = normalize_sha256(request.form.get("sha256", ""))
    description = request.form.get("description", "").strip() or "Manual malware hash"

    if sha256:
        add_to_hash_db(sha256, description)
        flash("Malware fingerprint added. Matching files will be quarantined on sight.", "success")
    else:
        flash("That doesn't look like a valid SHA256 fingerprint (need 64 hex characters).", "error")

    return redirect(url_for("home"))


if __name__ == "__main__":
    set_notify_enabled(load_security_config().get("notifications", True))
    initialize_runtime_files()
    ensure_model()
    load_recent_process_alerts()
    start_file_watcher_thread()
    start_process_monitor_thread()
    start_endpoint_monitor_thread()
    start_login_import_thread()
    start_scheduler_thread()
    start_connection_monitor_thread()
    # Bind to localhost only: the dashboard can terminate programs and delete
    # files, so it must never be reachable from the network.
    app.run(host="127.0.0.1", debug=True, use_reloader=False)
