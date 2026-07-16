"""Windows Security log ingestion — real logon events instead of demo data.

Pulls logon events (4624 success, 4625 failure) from the Security event
log via wevtutil, deduplicates by record ID, filters out machine-account
noise, and appends them to logs.csv in the dashboard's schema.

Reading the Security log requires administrator rights; when the app runs
unelevated the importer reports that instead of failing silently.
"""

import csv
import json
import platform
import subprocess
import threading
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
LOGIN_LOG = ROOT_DIR / "logs.csv"
STATE_FILE = ROOT_DIR / "login_import_state.json"
LOGIN_LOG_HEADERS = ["timestamp", "ip", "location", "user_agent", "login_attempts"]
POLL_INTERVAL_SEC = 300
MAX_EVENTS_PER_QUERY = 300
EVENT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

LOGON_TYPE_LABELS = {
    "2": "Interactive",
    "3": "Network",
    "4": "Batch",
    "5": "Service",
    "7": "Unlock",
    "8": "NetworkCleartext",
    "9": "NewCredentials",
    "10": "RDP",
    "11": "CachedInteractive",
}

# Successful logons of these types are always worth recording; other types
# only matter when they arrive from a real remote address.
ALWAYS_RECORD_SUCCESS_TYPES = {"2", "7", "10", "11"}

SKIP_ACCOUNTS = {"system", "local service", "network service", "anonymous logon", "-"}
LOCAL_IP_MARKERS = {"-", "", "127.0.0.1", "::1"}

_lock = threading.Lock()
_import_status = {
    "available": None,
    "requires_admin": False,
    "running": False,
    "last_import_time": None,
    "last_imported_count": 0,
    "total_imported": 0,
    "last_error": None,
}


def get_login_import_status():
    with _lock:
        return _import_status.copy()


def _set_status(**updates):
    with _lock:
        _import_status.update(updates)


def _load_state():
    if not STATE_FILE.exists():
        return {"last_record_id": 0}
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"last_record_id": 0}


def _save_state(state):
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
    except Exception as e:
        print(f"[LOGIN-IMPORT] Could not save state: {e}")


def _query_security_events():
    """Return (xml_text, error). Access denied is reported, not raised."""
    if platform.system() != "Windows":
        return None, "Only supported on Windows"

    try:
        completed = subprocess.run(
            [
                "wevtutil", "qe", "Security",
                "/q:*[System[(EventID=4624 or EventID=4625)]]",
                f"/c:{MAX_EVENTS_PER_QUERY}",
                "/rd:true",
                "/f:xml",
            ],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=60,
        )
    except Exception as e:
        return None, str(e)

    if completed.returncode != 0:
        stderr = (completed.stderr or "").strip()
        if "denied" in stderr.lower():
            return None, "access_denied"
        return None, stderr or f"wevtutil exited {completed.returncode}"

    return completed.stdout, None


def _event_data(event):
    """Extract the EventData Name->value mapping from one event element."""
    data = {}
    for item in event.iter(f"{EVENT_NS}Data"):
        name = item.get("Name")
        if name:
            data[name] = item.text or ""
    return data


def _parse_events(xml_text):
    """Yield dicts for each event, newest first (wevtutil /rd:true order)."""
    try:
        root = ET.fromstring(f"<Events>{xml_text}</Events>")
    except ET.ParseError as e:
        print(f"[LOGIN-IMPORT] XML parse error: {e}")
        return

    for event in root.iter(f"{EVENT_NS}Event"):
        system = event.find(f"{EVENT_NS}System")
        if system is None:
            continue

        event_id = (system.findtext(f"{EVENT_NS}EventID") or "").strip()
        record_id = (system.findtext(f"{EVENT_NS}EventRecordID") or "0").strip()
        time_node = system.find(f"{EVENT_NS}TimeCreated")
        raw_time = time_node.get("SystemTime") if time_node is not None else ""

        data = _event_data(event)

        yield {
            "event_id": event_id,
            "record_id": int(record_id) if record_id.isdigit() else 0,
            "time": raw_time,
            "user": data.get("TargetUserName", ""),
            "ip": data.get("IpAddress", "-").strip(),
            "logon_type": data.get("LogonType", "").strip(),
            "workstation": data.get("WorkstationName", "").strip(),
        }


def _should_record(event):
    user = event["user"].lower()

    if user in SKIP_ACCOUNTS or user.endswith("$"):
        return False
    if user.startswith(("dwm-", "umfd-")):
        return False

    is_failure = event["event_id"] == "4625"
    if is_failure:
        return True

    logon_type = event["logon_type"]
    if logon_type in ALWAYS_RECORD_SUCCESS_TYPES:
        return True

    # Network-style logons only matter when they come from somewhere real.
    return event["ip"] not in LOCAL_IP_MARKERS


def _format_timestamp(raw_time):
    if raw_time:
        try:
            return datetime.fromisoformat(raw_time.split(".")[0]).strftime(
                "%Y-%m-%dT%H:%M:%S"
            )
        except ValueError:
            pass
    return datetime.now().strftime("%Y-%m-%dT%H:%M:%S")


def _ensure_login_log():
    if not LOGIN_LOG.exists() or LOGIN_LOG.stat().st_size == 0:
        with open(LOGIN_LOG, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(LOGIN_LOG_HEADERS)


def import_login_events():
    """One import pass. Returns a summary dict."""
    xml_text, error = _query_security_events()

    if error == "access_denied":
        _set_status(
            available=False,
            requires_admin=True,
            last_error="Reading the Security log requires administrator rights",
        )
        return {"imported": 0, "error": "requires_admin"}

    if error:
        _set_status(available=False, last_error=error)
        return {"imported": 0, "error": error}

    state = _load_state()
    last_record_id = int(state.get("last_record_id", 0))
    max_record_id = last_record_id

    # Aggregate per (ip, outcome+type, user) so bursts of failures collapse
    # into one row with a real attempt count for the anomaly model.
    groups = {}

    for event in _parse_events(xml_text):
        if event["record_id"] <= last_record_id:
            continue
        max_record_id = max(max_record_id, event["record_id"])

        if not _should_record(event):
            continue

        label = LOGON_TYPE_LABELS.get(event["logon_type"], f"Type {event['logon_type']}")
        outcome = "Failed " if event["event_id"] == "4625" else ""
        agent = f"{outcome}{label} logon"

        ip = event["ip"]
        if ip in LOCAL_IP_MARKERS:
            ip = "local"
            location = "This machine"
        else:
            location = event["workstation"] or "Remote"

        key = (ip, agent, event["user"].lower())
        entry = groups.setdefault(
            key,
            {"count": 0, "timestamp": "", "ip": ip, "agent": agent, "location": location},
        )
        entry["count"] += 1
        timestamp = _format_timestamp(event["time"])
        entry["timestamp"] = max(entry["timestamp"], timestamp)

    imported = 0
    if groups:
        _ensure_login_log()
        with open(LOGIN_LOG, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            for entry in sorted(groups.values(), key=lambda item: item["timestamp"]):
                writer.writerow([
                    entry["timestamp"],
                    entry["ip"],
                    entry["location"],
                    entry["agent"],
                    entry["count"],
                ])
                imported += 1

    if max_record_id > last_record_id:
        _save_state({"last_record_id": max_record_id})

    with _lock:
        total = _import_status["total_imported"] + imported

    _set_status(
        available=True,
        requires_admin=False,
        last_import_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        last_imported_count=imported,
        total_imported=total,
        last_error=None,
    )

    if imported:
        print(f"[LOGIN-IMPORT] Imported {imported} login event group(s)")
    return {"imported": imported, "error": None}


def start_login_import_thread():
    def loop():
        import time

        _set_status(running=True)
        while True:
            try:
                import_login_events()
            except Exception as e:
                _set_status(last_error=str(e))
                print(f"[LOGIN-IMPORT] Error: {e}")
            time.sleep(POLL_INTERVAL_SEC)

    threading.Thread(target=loop, daemon=True).start()
