"""Endpoint persistence monitoring.

Watches the classic Windows persistence locations — registry autorun keys,
startup folders, scheduled tasks, and services — and raises an alert when
something NEW appears compared to the stored baseline. The first scan
establishes the baseline silently; later scans only flag changes, so a
stable machine produces zero alerts.
"""

import csv
import json
import os
import platform
import subprocess
import threading
import time
from collections import OrderedDict
from datetime import datetime
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
ENDPOINT_LOG = ROOT_DIR / "endpoint_logs.csv"
BASELINE_FILE = ROOT_DIR / "persistence_baseline.json"
ENDPOINT_LOG_HEADERS = ["timestamp", "category", "severity", "name", "detail", "reason"]
POLL_INTERVAL_SEC = 120
DETAIL_MAX_CHARS = 300

USER_WRITABLE_HINTS = [
    "\\appdata\\",
    "\\temp\\",
    "\\downloads\\",
    "\\public\\",
    "\\programdata\\",
]

HOSTILE_COMMAND_HINTS = [
    "-enc ",
    "encodedcommand",
    "frombase64string(",
    "downloadstring(",
    "downloadfile(",
    "mshta",
    "certutil -urlcache",
    "bitsadmin /transfer",
    "vssadmin delete shadows",
]

REGISTRY_AUTORUN_KEYS = [
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
]

_status_lock = threading.Lock()
_log_lock = threading.Lock()
_recent_alerts = {}
ALERT_COOLDOWN_SEC = 300
_monitor_status = {
    "running": False,
    "last_scan_time": None,
    "last_error": None,
    "baseline_established": False,
    "tracked_entries": 0,
    "new_last_scan": 0,
}


def get_endpoint_monitor_status():
    with _status_lock:
        return _monitor_status.copy()


def _set_status(**updates):
    with _status_lock:
        _monitor_status.update(updates)


def ensure_endpoint_log():
    if not ENDPOINT_LOG.exists() or ENDPOINT_LOG.stat().st_size == 0:
        with open(ENDPOINT_LOG, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(ENDPOINT_LOG_HEADERS)


def log_endpoint_alert(category, severity, name, detail, reason):
    """Append one endpoint alert row; suppress exact repeats for a cooldown."""
    key = f"{category}:{name}:{reason}"
    now = time.time()

    with _log_lock:
        last = _recent_alerts.get(key, 0)
        if now - last < ALERT_COOLDOWN_SEC:
            return False
        _recent_alerts[key] = now

        ensure_endpoint_log()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        detail = str(detail or "")[:DETAIL_MAX_CHARS]

        with open(ENDPOINT_LOG, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([timestamp, category, severity, name, detail, reason])

    print(f"[ENDPOINT] {severity.upper()} {category}: {name} - {reason}")

    try:
        from monitor.notify import notify_if_serious
        label = "Ransomware warning" if category == "ransomware" else "System change detected"
        notify_if_serious(severity, f"Doors AI: {label}", f"{name} - {reason}", key=key)
    except Exception:
        pass

    try:
        from monitor.events_db import record_event
        record_event(f"endpoint:{category}", severity, name, reason)
    except Exception:
        pass

    return True


def _classify_new_entry(detail):
    text = str(detail or "").lower()

    for hint in HOSTILE_COMMAND_HINTS:
        if hint in text:
            return "critical", f"Hostile command pattern in autorun entry: {hint.strip()}"

    for hint in USER_WRITABLE_HINTS:
        if hint in text:
            return "high", f"Runs from user-writable location: {hint.strip(chr(92))}"

    return "medium", "New persistence entry since baseline"


def snapshot_registry_autoruns():
    entries = {}
    if platform.system() != "Windows":
        return entries

    import winreg

    roots = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}

    for root_name, subkey in REGISTRY_AUTORUN_KEYS:
        try:
            with winreg.OpenKey(roots[root_name], subkey) as key:
                index = 0
                while True:
                    try:
                        value_name, value_data, _ = winreg.EnumValue(key, index)
                    except OSError:
                        break
                    entry_key = f"{root_name}\\{subkey}::{value_name}"
                    entries[entry_key] = str(value_data)
                    index += 1
        except FileNotFoundError:
            continue
        except Exception as e:
            print(f"[ENDPOINT] Registry read error {root_name}\\{subkey}: {e}")

    return entries


def snapshot_startup_folders():
    entries = {}

    folders = [
        Path(os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup")),
        Path(os.path.expandvars(r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp")),
    ]

    for folder in folders:
        if not folder.is_dir():
            continue
        try:
            for item in folder.iterdir():
                if item.name.lower() == "desktop.ini":
                    continue
                entries[f"startup::{item.name}"] = str(item)
        except OSError as e:
            print(f"[ENDPOINT] Startup folder read error {folder}: {e}")

    return entries


def snapshot_scheduled_tasks():
    entries = {}
    if platform.system() != "Windows":
        return entries

    try:
        completed = subprocess.run(
            ["schtasks", "/query", "/fo", "csv", "/nh"],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=60,
        )
    except Exception as e:
        print(f"[ENDPOINT] schtasks query failed: {e}")
        return entries

    for row in csv.reader(completed.stdout.splitlines()):
        if not row or len(row) < 1:
            continue
        task_name = row[0].strip()
        if not task_name.startswith("\\") or task_name.lower().startswith("\\microsoft"):
            continue
        entries[f"task::{task_name}"] = task_name

    return entries


def snapshot_services():
    entries = {}

    try:
        import psutil

        for service in psutil.win_service_iter():
            try:
                info = service.as_dict()
            except Exception:
                continue
            name = info.get("name") or ""
            binpath = info.get("binpath") or ""
            if name:
                entries[f"service::{name}"] = binpath
    except Exception as e:
        print(f"[ENDPOINT] Service enumeration failed: {e}")

    return entries


def take_snapshot():
    snapshot = OrderedDict()
    snapshot["registry"] = snapshot_registry_autoruns()
    snapshot["startup"] = snapshot_startup_folders()
    snapshot["task"] = snapshot_scheduled_tasks()
    snapshot["service"] = snapshot_services()
    return snapshot


def load_baseline():
    if not BASELINE_FILE.exists():
        return None
    try:
        with open(BASELINE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[ENDPOINT] Failed to load baseline: {e}")
        return None


def save_baseline(snapshot):
    try:
        with open(BASELINE_FILE, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=2)
    except Exception as e:
        print(f"[ENDPOINT] Failed to save baseline: {e}")


def reset_baseline():
    """Delete the stored baseline; the next poll re-baselines silently."""
    try:
        if BASELINE_FILE.exists():
            BASELINE_FILE.unlink()
        _set_status(baseline_established=False)
        print("[ENDPOINT] Baseline reset; next scan will re-baseline")
        return True
    except Exception as e:
        print(f"[ENDPOINT] Failed to reset baseline: {e}")
        return False


def _count_entries(snapshot):
    return sum(len(section) for section in snapshot.values())


def scan_for_changes():
    """Diff current state against baseline; alert on new entries."""
    snapshot = take_snapshot()
    baseline = load_baseline()

    if baseline is None:
        save_baseline(snapshot)
        _set_status(
            baseline_established=True,
            tracked_entries=_count_entries(snapshot),
            new_last_scan=0,
        )
        print(f"[ENDPOINT] Baseline established: {_count_entries(snapshot)} entries")
        return 0

    new_alerts = 0
    for category, current in snapshot.items():
        known = baseline.get(category, {})
        for entry_key, detail in current.items():
            display_name = entry_key.split("::", 1)[-1]

            if entry_key not in known:
                severity, reason = _classify_new_entry(detail)
                if log_endpoint_alert(category, severity, display_name, detail, reason):
                    new_alerts += 1
                continue

            # Existing entry whose target changed: a classic persistence
            # hijack (an autorun repointed at a new payload). Escalate if
            # the new value looks hostile, otherwise flag it as high since
            # a silently-changed autorun is inherently suspicious.
            if known[entry_key] != detail:
                severity, hint = _classify_new_entry(detail)
                if severity == "medium":
                    severity = "high"
                reason = f"Existing {category} entry changed target ({hint})"
                changed_detail = f"was: {known[entry_key]} | now: {detail}"
                if log_endpoint_alert(category, severity, display_name, changed_detail, reason):
                    new_alerts += 1

    # Persist the fresh snapshot so each change alerts exactly once and
    # removed entries stop being tracked.
    save_baseline(snapshot)
    _set_status(
        baseline_established=True,
        tracked_entries=_count_entries(snapshot),
        new_last_scan=new_alerts,
    )
    return new_alerts


def start_endpoint_monitor_thread():
    def loop():
        _set_status(running=True)
        while True:
            try:
                scan_for_changes()
                _set_status(
                    last_scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    last_error=None,
                )
            except Exception as e:
                _set_status(last_error=str(e))
                print(f"[ENDPOINT] Monitor error: {e}")
            time.sleep(POLL_INTERVAL_SEC)

    threading.Thread(target=loop, daemon=True).start()
