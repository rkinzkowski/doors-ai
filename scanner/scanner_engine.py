import csv
import hashlib
import json
import os
import shutil
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd


ROOT_DIR = Path(__file__).resolve().parents[1]
CONFIG_FILE = ROOT_DIR / "scanner_config.json"
HASH_DB = ROOT_DIR / "malware_hashes.csv"
SCAN_LOG = ROOT_DIR / "scanner_logs.csv"
MODEL_PATH = ROOT_DIR / "scanner" / "models" / "rf_model.pkl"
QUARANTINE_FOLDER = ROOT_DIR / "scanner" / "quarantine"
SCAN_LOG_HEADERS = ["filename", "sha256", "result", "reason", "timestamp"]

DEFAULT_CONFIG = {
    "watch_folders": [str(Path.home() / "Downloads")],
    "recursive_watch": False,
    "log_safe_files": False,
    "manual_scan_limit": 1000,
}

_model = None


def normalize_folder(path):
    return str(Path(os.path.expandvars(os.path.expanduser(path))).resolve())


def load_scan_config():
    if not CONFIG_FILE.exists():
        save_scan_config(DEFAULT_CONFIG)
        return DEFAULT_CONFIG.copy()

    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            loaded = json.load(f)
    except Exception as e:
        print(f"[SCANNER] Failed to load scanner config: {e}")
        return DEFAULT_CONFIG.copy()

    config = DEFAULT_CONFIG.copy()
    config.update(loaded)
    config["watch_folders"] = [
        normalize_folder(folder)
        for folder in config.get("watch_folders", [])
        if folder
    ]
    return config


def save_scan_config(config):
    cleaned = DEFAULT_CONFIG.copy()
    cleaned.update(config)
    cleaned["watch_folders"] = sorted(set(
        normalize_folder(folder)
        for folder in cleaned.get("watch_folders", [])
        if folder
    ))

    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cleaned, f, indent=2)


def ensure_scan_log():
    if not SCAN_LOG.exists() or SCAN_LOG.stat().st_size == 0:
        with open(SCAN_LOG, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(SCAN_LOG_HEADERS)


def get_model():
    global _model

    if _model is None:
        _model = joblib.load(MODEL_PATH)

    return _model


def load_hash_db():
    if not HASH_DB.exists() or HASH_DB.stat().st_size == 0:
        with open(HASH_DB, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(["sha256", "description"])
        return set()

    try:
        df = pd.read_csv(HASH_DB)
        if "sha256" not in df.columns:
            return set()
        return {
            str(value).strip().lower()
            for value in df["sha256"].dropna()
            if len(str(value).strip()) == 64
        }
    except Exception as e:
        print(f"[SCANNER] Could not load hash DB: {e}")
        return set()


def add_to_hash_db(sha256, description="AI flagged file"):
    sha256 = sha256.strip().lower()
    if not sha256 or sha256 in load_hash_db():
        return

    with open(HASH_DB, "a", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow([sha256, description])

    print(f"[SCANNER] Learned malicious hash: {sha256}")


def log_scan(filename, sha256, result, reason):
    ensure_scan_log()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(SCAN_LOG, "a", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow([filename, sha256, result, reason, timestamp])


def compute_sha256(filepath):
    digest = hashlib.sha256()

    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def extract_features(filepath):
    with open(filepath, "rb") as f:
        data = f.read()

    if not data:
        return [0, 0, 0, 0]

    byte_counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probabilities = byte_counts / len(data)
    entropy = -sum(p * np.log2(p) for p in probabilities if p > 0)
    ascii_chars = sum(32 <= b <= 126 for b in data)

    return [
        len(data),
        entropy,
        len(set(data)),
        ascii_chars / len(data),
    ]


def quarantine_file(path):
    QUARANTINE_FOLDER.mkdir(parents=True, exist_ok=True)
    source = Path(path)
    target = QUARANTINE_FOLDER / source.name

    if target.exists():
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target = QUARANTINE_FOLDER / f"{source.stem}_{stamp}{source.suffix}"

    shutil.move(str(source), str(target))
    print(f"[SCANNER] Quarantined {source.name}")


def scan_file(filepath, log_safe=None, quarantine=True):
    config = load_scan_config()
    should_log_safe = config["log_safe_files"] if log_safe is None else log_safe
    path = Path(filepath)

    if not path.exists() or not path.is_file():
        return {"result": "skipped", "reason": "not_a_file", "path": str(path)}

    if QUARANTINE_FOLDER in path.parents:
        return {"result": "skipped", "reason": "already_quarantined", "path": str(path)}

    try:
        sha256 = compute_sha256(path)
        filename = path.name

        if sha256 in load_hash_db():
            log_scan(filename, sha256, "malicious", "Known malware hash")
            if quarantine:
                quarantine_file(path)
            return {"result": "malicious", "reason": "Known malware hash", "sha256": sha256}

        prediction = get_model().predict([extract_features(path)])[0]

        if prediction == 1:
            log_scan(filename, sha256, "malicious", "AI malware classifier")
            add_to_hash_db(sha256)
            if quarantine:
                quarantine_file(path)
            return {"result": "malicious", "reason": "AI malware classifier", "sha256": sha256}

        if should_log_safe:
            log_scan(filename, sha256, "safe", "No threat detected")

        return {"result": "safe", "reason": "No threat detected", "sha256": sha256}

    except Exception as e:
        log_scan(path.name, "unknown", "error", str(e))
        print(f"[SCANNER] Failed to scan {path}: {e}")
        return {"result": "error", "reason": str(e), "path": str(path)}


def iter_scan_files(folder, recursive=False):
    base = Path(folder)
    pattern = "**/*" if recursive else "*"

    for path in base.glob(pattern):
        if path.is_file():
            yield path


def scan_folder(folder, recursive=False, limit=None, quarantine=False):
    config = load_scan_config()
    scan_limit = int(limit or config.get("manual_scan_limit", 1000))
    scanned = 0
    alerts = 0
    errors = 0

    for path in iter_scan_files(folder, recursive=recursive):
        if scanned >= scan_limit:
            break

        result = scan_file(path, log_safe=False, quarantine=quarantine)
        scanned += 1

        if result["result"] == "malicious":
            alerts += 1
        elif result["result"] == "error":
            errors += 1

    return {"scanned": scanned, "alerts": alerts, "errors": errors, "limit": scan_limit}
