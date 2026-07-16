import ctypes
import os
import platform
import threading
import time
from datetime import datetime
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from scanner.scanner_engine import load_scan_config, scan_file
from monitor.endpoint_monitor import log_endpoint_alert

SCAN_COOLDOWN_SEC = 2
SCAN_MEMORY_TTL_SEC = 60
CONFIG_POLL_SEC = 5
SETTLE_SEC = 0.75
IGNORED_SUFFIXES = {".crdownload", ".download", ".part", ".tmp"}

# Ransomware tripwires: a hidden canary file per watched folder that nothing
# legitimate should ever touch, plus burst detection over modifications of
# pre-existing files (mass creation, e.g. unzipping, is deliberately ignored).
CANARY_FILENAME = "!doors_canary_do_not_modify.txt"
CANARY_CONTENT = (
    "Doors AI ransomware canary file.\n"
    "Do not modify or delete. Any change to this file raises a critical alert.\n"
)
BURST_WINDOW_SEC = 15
BURST_THRESHOLD_FILES = 20
RECENT_CREATE_TTL_SEC = 120

CANARY_GRACE_SEC = 10

_burst_lock = threading.Lock()
_burst_events = {}
_recently_created = {}
_canary_grace = {}

_recent_scans = {}
_lock = threading.Lock()
_status_lock = threading.Lock()
_watcher_status = {
    "thread_running": False,
    "observer_running": False,
    "active_watches": 0,
    "watched_folders": [],
    "last_config_check": None,
    "last_error": None,
}


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _set_status(**updates):
    with _status_lock:
        _watcher_status.update(updates)


def get_file_watcher_status():
    with _status_lock:
        return _watcher_status.copy()


def _should_scan(signature):
    now = time.time()
    with _lock:
        expired = [
            key for key, last_seen in _recent_scans.items()
            if now - last_seen > SCAN_MEMORY_TTL_SEC
        ]
        for key in expired:
            _recent_scans.pop(key, None)

        last = _recent_scans.get(signature, 0)
        if now - last < SCAN_COOLDOWN_SEC:
            return False
        _recent_scans[signature] = now
    return True


def _file_signature(path):
    stat = path.stat()
    return f"{str(path.resolve()).lower()}:{stat.st_size}:{stat.st_mtime_ns}"


def ensure_canary(folder):
    """Create the hidden canary file in a watched folder if it is missing."""
    canary = Path(folder) / CANARY_FILENAME
    try:
        # Our own writes to the canary fire watchdog events too; the grace
        # window keeps them from raising a false alert.
        with _burst_lock:
            _canary_grace[str(canary).lower()] = time.time()

        if not canary.exists():
            canary.write_text(CANARY_CONTENT, encoding="utf-8")
        if platform.system() == "Windows":
            FILE_ATTRIBUTE_HIDDEN = 0x02
            ctypes.windll.kernel32.SetFileAttributesW(str(canary), FILE_ATTRIBUTE_HIDDEN)
    except Exception as e:
        print(f"[RANSOMWARE] Could not place canary in {folder}: {e}")


def _canary_in_grace(path):
    with _burst_lock:
        placed = _canary_grace.get(str(path).lower(), 0)
    return time.time() - placed < CANARY_GRACE_SEC


def _is_canary(path):
    return Path(path).name.lower() == CANARY_FILENAME.lower()


def _note_created(path):
    now = time.time()
    with _burst_lock:
        _recently_created[str(path).lower()] = now
        for key, seen in list(_recently_created.items()):
            if now - seen > RECENT_CREATE_TTL_SEC:
                _recently_created.pop(key, None)


def _record_burst_event(path):
    """Track modify/delete events on pre-existing files; alert on a burst."""
    key = str(path).lower()
    now = time.time()

    with _burst_lock:
        if key in _recently_created:
            return

        _burst_events[key] = now
        for event_key, seen in list(_burst_events.items()):
            if now - seen > BURST_WINDOW_SEC:
                _burst_events.pop(event_key, None)

        distinct = len(_burst_events)

    if distinct >= BURST_THRESHOLD_FILES:
        log_endpoint_alert(
            "ransomware",
            "high",
            "mass-file-modification",
            f"{distinct} pre-existing files modified or deleted within {BURST_WINDOW_SEC}s",
            "Mass file modification burst detected",
        )


def _handle_canary_event(path, action):
    if _canary_in_grace(path):
        return

    log_endpoint_alert(
        "ransomware",
        "critical",
        CANARY_FILENAME,
        f"Canary file {action}: {path}",
        f"Ransomware canary {action} - possible encryption activity",
    )
    parent = Path(path).parent
    if parent.is_dir():
        ensure_canary(parent)


class _DownloadHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return
        _note_created(event.src_path)
        self._handle(event.src_path)

    def on_moved(self, event):
        if event.is_directory:
            return
        if _is_canary(event.src_path):
            _handle_canary_event(event.src_path, "renamed")
            return
        _note_created(event.dest_path)
        self._handle(event.dest_path)

    def on_modified(self, event):
        if event.is_directory:
            return
        if _is_canary(event.src_path):
            _handle_canary_event(event.src_path, "modified")
            return
        if Path(event.src_path).suffix.lower() in IGNORED_SUFFIXES:
            return
        _record_burst_event(event.src_path)

    def on_deleted(self, event):
        if event.is_directory:
            return
        if _is_canary(event.src_path):
            _handle_canary_event(event.src_path, "deleted")
            return
        if Path(event.src_path).suffix.lower() in IGNORED_SUFFIXES:
            return
        _record_burst_event(event.src_path)

    def _handle(self, src_path):
        path = Path(src_path)
        if path.suffix.lower() in IGNORED_SUFFIXES:
            return

        if _is_canary(path):
            return

        if not path.is_file():
            return

        time.sleep(SETTLE_SEC)
        if not path.is_file():
            return

        try:
            resolved = str(path.resolve())
            signature = _file_signature(path)
        except OSError:
            return

        if not _should_scan(signature):
            return

        print(f"[SCANNER] New file detected: {resolved}")
        scan_file(resolved)


def _start_observer(config):
    observer = Observer()
    watched = 0
    watched_folders = []

    for folder in config["watch_folders"]:
        if os.path.isdir(folder):
            if config.get("ransomware_canaries", True):
                ensure_canary(folder)
            observer.schedule(
                _DownloadHandler(),
                folder,
                recursive=bool(config.get("recursive_watch", False)),
            )
            watched += 1
            watched_folders.append(folder)
            print(f"[SCANNER] Watching: {folder}")
        else:
            print(f"[SCANNER] Skipping missing folder: {folder}")

    if watched:
        observer.start()
        print(f"[SCANNER] Active watched folders: {watched}")
    else:
        print("[SCANNER] No valid watch folders configured.")

    _set_status(
        observer_running=bool(watched),
        active_watches=watched,
        watched_folders=watched_folders,
        last_error=None,
    )

    return observer if watched else None


def start_file_watcher_thread():
    def loop():
        observer = None
        active_signature = None
        _set_status(thread_running=True)

        while True:
            try:
                _set_status(last_config_check=_now())
                config = load_scan_config()
                signature = (
                    tuple(config["watch_folders"]),
                    bool(config.get("recursive_watch", False)),
                )

                if signature != active_signature:
                    if observer:
                        observer.stop()
                        observer.join()
                        _set_status(observer_running=False, active_watches=0)

                    observer = _start_observer(config)
                    active_signature = signature
            except Exception as e:
                _set_status(last_error=str(e))
                print(f"[SCANNER] Watcher error: {e}")

            time.sleep(CONFIG_POLL_SEC)

    threading.Thread(target=loop, daemon=True).start()
