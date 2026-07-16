"""Background scheduler for periodic scans and feed refreshes.

Both jobs are opt-in (off by default) so nothing runs on a timer - especially
no network calls - unless the user turns it on. Intervals are configurable.
"""

import json
import threading
import time
from datetime import datetime
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
SCHED_CONFIG = ROOT_DIR / "scheduler_config.json"
TICK_SEC = 300

DEFAULTS = {
    "auto_scan": False,
    "scan_interval_hours": 6,
    "last_scan": 0,
    "auto_feeds": False,
    "feed_interval_hours": 24,
    "last_feeds": 0,
    "last_scan_time": None,
    "last_feeds_time": None,
}

_lock = threading.Lock()


def load_scheduler_config():
    cfg = DEFAULTS.copy()
    if SCHED_CONFIG.exists():
        try:
            with open(SCHED_CONFIG, "r", encoding="utf-8") as f:
                cfg.update(json.load(f))
        except Exception as e:
            print(f"[SCHED] Could not read config: {e}")
    return cfg


def save_scheduler_config(cfg):
    with _lock:
        try:
            with open(SCHED_CONFIG, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2)
        except Exception as e:
            print(f"[SCHED] Could not save config: {e}")


def set_scheduler_option(key, value):
    cfg = load_scheduler_config()
    if key in ("auto_scan", "auto_feeds"):
        cfg[key] = bool(value)
    elif key in ("scan_interval_hours", "feed_interval_hours"):
        try:
            cfg[key] = max(1, int(value))
        except (TypeError, ValueError):
            pass
    save_scheduler_config(cfg)


def _run_scans(cfg):
    from scanner.scanner_engine import load_scan_config, scan_folder

    watch = load_scan_config().get("watch_folders", [])
    total = 0
    for folder in watch:
        try:
            summary = scan_folder(folder, recursive=False)
            total += summary.get("scanned", 0)
        except Exception as e:
            print(f"[SCHED] Scheduled scan of {folder} failed: {e}")
    cfg["last_scan"] = time.time()
    cfg["last_scan_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[SCHED] Scheduled scan checked {total} file(s)")


def _run_feeds(cfg):
    from monitor.threat_feeds import load_feeds_config, update_feodo, update_ipsum, update_malware_hashes

    try:
        update_ipsum()
        update_feodo()
        if load_feeds_config().get("malwarebazaar_auth_key"):
            update_malware_hashes()
    except Exception as e:
        print(f"[SCHED] Scheduled feed refresh failed: {e}")
    cfg["last_feeds"] = time.time()
    cfg["last_feeds_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("[SCHED] Scheduled feed refresh complete")


def start_scheduler_thread():
    def loop():
        while True:
            try:
                cfg = load_scheduler_config()
                now = time.time()
                changed = False

                if cfg["auto_scan"] and now - cfg.get("last_scan", 0) >= cfg["scan_interval_hours"] * 3600:
                    _run_scans(cfg)
                    changed = True

                if cfg["auto_feeds"] and now - cfg.get("last_feeds", 0) >= cfg["feed_interval_hours"] * 3600:
                    _run_feeds(cfg)
                    changed = True

                if changed:
                    save_scheduler_config(cfg)
            except Exception as e:
                print(f"[SCHED] Scheduler error: {e}")
            time.sleep(TICK_SEC)

    threading.Thread(target=loop, daemon=True).start()
