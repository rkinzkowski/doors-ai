import csv
import hashlib
import json
import os
import platform
import shutil
import subprocess
import zipfile
from datetime import datetime
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
CONFIG_FILE = ROOT_DIR / "scanner_config.json"
HASH_DB = ROOT_DIR / "malware_hashes.csv"
TRUSTED_HASH_DB = ROOT_DIR / "trusted_hashes.csv"
SCAN_LOG = ROOT_DIR / "scanner_logs.csv"
MODEL_PATH = ROOT_DIR / "scanner" / "models" / "rf_model.pkl"
MODEL_VERSION_FILE = ROOT_DIR / "scanner" / "models" / "rf_model.version"
CURRENT_MODEL_VERSION = "3"
QUARANTINE_FOLDER = ROOT_DIR / "scanner" / "quarantine"
QUARANTINE_META_SUFFIX = ".meta.json"
SCAN_LOG_HEADERS = ["filename", "sha256", "result", "reason", "timestamp"]
HASH_DB_HEADERS = ["sha256", "description"]
TRUSTED_HASH_HEADERS = ["sha256", "filename", "timestamp"]
KNOWN_HASH_REASON = "Known malware hash"
HEURISTIC_REASON = "Heuristic classifier review recommended"
FEATURE_SAMPLE_BYTES = 5 * 1024 * 1024
SHA256_HEX_LENGTH = 64
HEX_DIGITS = set("0123456789abcdef")
HEURISTIC_MIN_CONFIDENCE = 0.9

# Portable-executable style formats: check the digital signature first,
# fall back to the heuristic classifier only for unsigned binaries.
EXECUTABLE_EXTENSIONS = {".com", ".dll", ".exe", ".msi", ".scr"}

# Plain-text script formats: entropy features are meaningless here, so scan
# the content for known-hostile command patterns instead.
SCRIPT_EXTENSIONS = {".bat", ".cmd", ".js", ".ps1", ".vbs", ".hta", ".wsf"}

# Archives are inherently high-entropy, which the old model mistook for
# packed malware. Inspect the member list instead of the raw bytes.
ARCHIVE_EXTENSIONS = {".zip"}

# Macro-enabled Office formats: worth a review alert when they show up in a
# downloads folder, since macros remain a top malware delivery vehicle.
MACRO_EXTENSIONS = {".docm", ".dotm", ".xlsm", ".xltm", ".pptm", ".potm", ".ppsm"}

SUSPICIOUS_SCRIPT_PATTERNS = [
    "frombase64string(",
    "-encodedcommand",
    "-enc ",
    "downloadstring(",
    "downloadfile(",
    "invoke-expression",
    "iex(",
    "iex ",
    "invoke-obfuscation",
    "hidden -nop",
    "-windowstyle hidden",
    "bitsadmin /transfer",
    "certutil -urlcache",
    "certutil.exe -urlcache",
    "new-object net.webclient",
    "wscript.shell",
    "shellexecute(",
    "createobject(\"wscript.shell\")",
    "activexobject(\"wscript.shell\")",
    "reg add hkcu\\software\\microsoft\\windows\\currentversion\\run",
    "schtasks /create",
    "vssadmin delete shadows",
]

# File extensions attackers disguise as documents inside archives.
DOUBLE_EXTENSION_BAIT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg", ".png"}
ARCHIVE_EXECUTABLE_MEMBERS = {".exe", ".scr", ".com", ".bat", ".cmd", ".js", ".vbs", ".hta", ".ps1"}

DEFAULT_CONFIG = {
    "watch_folders": [str(Path.home() / "Downloads")],
    "recursive_watch": False,
    "log_safe_files": False,
    "manual_scan_limit": 1000,
    "ransomware_canaries": True,
}

_model = None
_hash_db_cache = None
_hash_db_mtime = None
_trusted_cache = None
_trusted_mtime = None
_signature_cache = {}
_recent_scan_results = {}
SCAN_RESULT_COOLDOWN_SEC = 60
_scan_status = {
    "last_scan_time": None,
    "last_scan_path": None,
    "last_scan_result": None,
    "last_scan_reason": None,
    "total_scans": 0,
}


def normalize_folder(path):
    return str(Path(os.path.expandvars(os.path.expanduser(path))).resolve())


def get_scan_status():
    return _scan_status.copy()


def scan_response(target_path, result, reason, **extra):
    _scan_status.update({
        "last_scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "last_scan_path": str(target_path),
        "last_scan_result": result,
        "last_scan_reason": reason,
        "total_scans": _scan_status["total_scans"] + 1,
    })

    response = {"result": result, "reason": reason}
    response.update(extra)
    return response


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


def ensure_hash_db():
    if not HASH_DB.exists() or HASH_DB.stat().st_size == 0:
        with open(HASH_DB, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(HASH_DB_HEADERS)


def ensure_model():
    import joblib
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)

    if MODEL_PATH.exists() and MODEL_VERSION_FILE.exists():
        if MODEL_VERSION_FILE.read_text(encoding="utf-8").strip() == CURRENT_MODEL_VERSION:
            return

    # Placeholder model: default to safe unless features look strongly malicious.
    # Benign samples deliberately include compressed/installer profiles
    # (entropy ~8, all 256 byte values, ASCII ratio ~0.37) so that ordinary
    # ZIPs and installers no longer match the "packed malware" fingerprint.
    benign_samples = [
        # Text / config files
        [1024, 4.5, 180, 0.85],
        [4096, 5.2, 220, 0.78],
        # Ordinary binaries
        [65536, 6.1, 240, 0.72],
        [512000, 7.0, 250, 0.65],
        # Compressed archives and packed installers (previously misflagged)
        [50000, 7.9, 255, 0.40],
        [200000, 7.99, 256, 0.37],
        [1000000, 8.0, 256, 0.36],
        [5000000, 7.98, 256, 0.38],
        [50000000, 7.99, 256, 0.37],
    ]
    # Malicious profile: small, near-max entropy AND almost no printable
    # bytes — unlike compressed archives, whose deflate streams keep a
    # printable-byte ratio near 0.37.
    malicious_samples = [
        [8192, 7.8, 255, 0.12],
        [32768, 7.9, 256, 0.08],
        [120000, 7.95, 256, 0.05],
    ]

    X = np.array(benign_samples * 20 + malicious_samples * 20)
    y = np.array([0] * (len(benign_samples) * 20) + [1] * (len(malicious_samples) * 20))
    model = RandomForestClassifier(n_estimators=50, random_state=42)
    model.fit(X, y)
    joblib.dump(model, MODEL_PATH)
    MODEL_VERSION_FILE.write_text(CURRENT_MODEL_VERSION, encoding="utf-8")
    print(f"[SCANNER] Created placeholder model at {MODEL_PATH}")


def get_model():
    global _model

    if _model is None:
        import joblib

        ensure_model()
        _model = joblib.load(MODEL_PATH)

    return _model


def load_hash_db():
    global _hash_db_cache, _hash_db_mtime

    ensure_hash_db()

    if HASH_DB.stat().st_size == 0:
        _hash_db_cache = set()
        _hash_db_mtime = HASH_DB.stat().st_mtime
        return _hash_db_cache

    mtime = HASH_DB.stat().st_mtime
    if _hash_db_cache is not None and _hash_db_mtime == mtime:
        return _hash_db_cache

    try:
        with open(HASH_DB, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            _hash_db_cache = {
                value
                for row in reader
                for value in [normalize_sha256(row.get("sha256", ""))]
                if value
            }
        _hash_db_mtime = mtime
        return _hash_db_cache
    except Exception as e:
        print(f"[SCANNER] Could not load hash DB: {e}")
        return set()


def normalize_sha256(value):
    value = str(value or "").strip().lower()
    if len(value) != SHA256_HEX_LENGTH:
        return ""
    if any(char not in HEX_DIGITS for char in value):
        return ""
    return value


def add_to_hash_db(sha256, description="Manual malware hash"):
    global _hash_db_cache, _hash_db_mtime

    sha256 = normalize_sha256(sha256)
    if not sha256 or sha256 in load_hash_db():
        return

    with open(HASH_DB, "a", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow([sha256, description])

    _hash_db_cache = load_hash_db()
    _hash_db_mtime = HASH_DB.stat().st_mtime
    print(f"[SCANNER] Learned malicious hash: {sha256}")


def ensure_trusted_db():
    if not TRUSTED_HASH_DB.exists() or TRUSTED_HASH_DB.stat().st_size == 0:
        with open(TRUSTED_HASH_DB, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(TRUSTED_HASH_HEADERS)


def load_trusted_hashes():
    global _trusted_cache, _trusted_mtime

    ensure_trusted_db()

    mtime = TRUSTED_HASH_DB.stat().st_mtime
    if _trusted_cache is not None and _trusted_mtime == mtime:
        return _trusted_cache

    try:
        with open(TRUSTED_HASH_DB, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            _trusted_cache = {
                value
                for row in reader
                for value in [normalize_sha256(row.get("sha256", ""))]
                if value
            }
        _trusted_mtime = mtime
        return _trusted_cache
    except Exception as e:
        print(f"[SCANNER] Could not load trusted hashes: {e}")
        return set()


def add_trusted_hash(sha256, filename=""):
    global _trusted_cache, _trusted_mtime

    sha256 = normalize_sha256(sha256)
    if not sha256 or sha256 in load_trusted_hashes():
        return

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(TRUSTED_HASH_DB, "a", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow([sha256, filename, timestamp])

    _trusted_cache = None
    load_trusted_hashes()
    print(f"[SCANNER] Marked hash as trusted: {sha256}")


def _should_log_scan(sha256, result, reason):
    key = f"{sha256}:{result}:{reason}"
    now = datetime.now().timestamp()
    last = _recent_scan_results.get(key, 0)
    if now - last < SCAN_RESULT_COOLDOWN_SEC:
        return False
    _recent_scan_results[key] = now
    return True


def log_scan(filename, sha256, result, reason):
    if not _should_log_scan(sha256, result, reason):
        return

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
    import numpy as np

    path = Path(filepath)
    file_size = path.stat().st_size

    with open(path, "rb") as f:
        data = f.read(FEATURE_SAMPLE_BYTES)

    if not data:
        return [file_size, 0, 0, 0]

    byte_counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probabilities = byte_counts / len(data)
    entropy = -sum(p * np.log2(p) for p in probabilities if p > 0)
    ascii_chars = sum(32 <= b <= 126 for b in data)

    return [
        file_size,
        entropy,
        len(set(data)),
        ascii_chars / len(data),
    ]


QUARANTINE_XOR_KEY = 0x5A
QUARANTINE_STORED_SUFFIX = ".quarantined"


def _xor_copy(src, dst, key):
    """Copy src to dst byte-flipping every byte, so the result can't run."""
    table = bytes(b ^ key for b in range(256))
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        for chunk in iter(lambda: fin.read(1024 * 1024), b""):
            fout.write(chunk.translate(table))


def quarantine_file(path, sha256=None, reason=""):
    QUARANTINE_FOLDER.mkdir(parents=True, exist_ok=True)
    source = Path(path)

    # Store neutralized: the real bytes are XOR-scrambled and the name gets a
    # harmless suffix, so nothing in the quarantine folder can execute.
    stored_name = source.name + QUARANTINE_STORED_SUFFIX
    target = QUARANTINE_FOLDER / stored_name
    if target.exists():
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target = QUARANTINE_FOLDER / f"{source.stem}_{stamp}{source.suffix}{QUARANTINE_STORED_SUFFIX}"

    original_path = str(source.resolve())
    try:
        _xor_copy(source, target, QUARANTINE_XOR_KEY)
        source.unlink()
    except Exception as e:
        print(f"[SCANNER] Could not neutralize {source.name}, falling back to move: {e}")
        if target.exists():
            target.unlink(missing_ok=True)
        target = QUARANTINE_FOLDER / source.name
        shutil.move(str(source), str(target))

    metadata = {
        "original_path": original_path,
        "original_name": source.name,
        "sha256": sha256 or "",
        "reason": reason,
        "quarantined_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "neutralized": target.name.endswith(QUARANTINE_STORED_SUFFIX),
        "xor_key": QUARANTINE_XOR_KEY,
    }
    meta_path = target.with_name(target.name + QUARANTINE_META_SUFFIX)
    try:
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)
    except Exception as e:
        print(f"[SCANNER] Could not write quarantine metadata for {target.name}: {e}")

    print(f"[SCANNER] Quarantined and neutralized {source.name}")
    return target


def _quarantine_entry_path(filename):
    """Resolve a quarantined file by basename, rejecting path traversal."""
    name = os.path.basename(str(filename or "").strip())
    if not name or name.endswith(QUARANTINE_META_SUFFIX):
        return None

    candidate = (QUARANTINE_FOLDER / name).resolve()
    if candidate.parent != QUARANTINE_FOLDER.resolve() or not candidate.is_file():
        return None
    return candidate


def _read_quarantine_metadata(target):
    meta_path = target.with_name(target.name + QUARANTINE_META_SUFFIX)
    if not meta_path.exists():
        return {}
    try:
        with open(meta_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def list_quarantined_files():
    if not QUARANTINE_FOLDER.is_dir():
        return []

    entries = []
    for target in sorted(QUARANTINE_FOLDER.iterdir()):
        if not target.is_file() or target.name.endswith(QUARANTINE_META_SUFFIX):
            continue

        metadata = _read_quarantine_metadata(target)
        entries.append({
            "filename": target.name,
            "original_name": metadata.get("original_name", target.name),
            "size": target.stat().st_size,
            "original_path": metadata.get("original_path", ""),
            "sha256": metadata.get("sha256", ""),
            "reason": metadata.get("reason", ""),
            "quarantined_at": metadata.get("quarantined_at", ""),
            "neutralized": metadata.get("neutralized", False),
        })

    entries.sort(key=lambda item: item["quarantined_at"], reverse=True)
    return entries


def restore_quarantined_file(filename):
    target = _quarantine_entry_path(filename)
    if target is None:
        return False, "File not found in quarantine"

    metadata = _read_quarantine_metadata(target)
    original = metadata.get("original_path", "")

    if original:
        destination = Path(original)
    else:
        name = metadata.get("original_name") or target.name.replace(QUARANTINE_STORED_SUFFIX, "")
        destination = Path.home() / "Downloads" / name

    if destination.exists():
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        destination = destination.with_name(
            f"{destination.stem}_restored_{stamp}{destination.suffix}"
        )

    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        if metadata.get("neutralized"):
            # Reverse the XOR to reconstruct the original bytes.
            _xor_copy(target, destination, int(metadata.get("xor_key", QUARANTINE_XOR_KEY)))
            target.unlink()
        else:
            shutil.move(str(target), str(destination))
    except Exception as e:
        return False, f"Restore failed: {e}"

    meta_path = target.with_name(target.name + QUARANTINE_META_SUFFIX)
    if meta_path.exists():
        try:
            meta_path.unlink()
        except OSError:
            pass

    print(f"[SCANNER] Restored {target.name} to {destination}")
    return True, str(destination)


def delete_quarantined_file(filename):
    target = _quarantine_entry_path(filename)
    if target is None:
        return False, "File not found in quarantine"

    try:
        target.unlink()
    except Exception as e:
        return False, f"Delete failed: {e}"

    meta_path = target.with_name(target.name + QUARANTINE_META_SUFFIX)
    if meta_path.exists():
        try:
            meta_path.unlink()
        except OSError:
            pass

    print(f"[SCANNER] Deleted quarantined file {target.name}")
    return True, target.name


PUBLISHERS_FILE = ROOT_DIR / "publishers.json"
_DEFAULT_PUBLISHERS = {"allow": [], "deny": [], "strict": False}


def load_publisher_lists():
    lists = {"allow": [], "deny": [], "strict": False}
    if PUBLISHERS_FILE.exists():
        try:
            with open(PUBLISHERS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            lists["allow"] = [str(p) for p in data.get("allow", [])]
            lists["deny"] = [str(p) for p in data.get("deny", [])]
            lists["strict"] = bool(data.get("strict", False))
        except Exception as e:
            print(f"[SCANNER] Could not read publisher lists: {e}")
    return lists


def save_publisher_lists(lists):
    try:
        with open(PUBLISHERS_FILE, "w", encoding="utf-8") as f:
            json.dump(lists, f, indent=2)
    except Exception as e:
        print(f"[SCANNER] Could not save publisher lists: {e}")


def update_publisher_list(action, publisher):
    """action: allow | deny | remove-allow | remove-deny."""
    publisher = str(publisher or "").strip()
    if not publisher:
        return
    lists = load_publisher_lists()
    for bucket in ("allow", "deny"):
        lists[bucket] = [p for p in lists[bucket] if p.lower() != publisher.lower()]
    if action == "allow":
        lists["allow"].append(publisher)
    elif action == "deny":
        lists["deny"].append(publisher)
    save_publisher_lists(lists)


def set_publisher_strict(strict):
    lists = load_publisher_lists()
    lists["strict"] = bool(strict)
    save_publisher_lists(lists)


def _publisher_cn(subject):
    """Pull the common name (CN=) out of an X.509 subject string."""
    for part in str(subject or "").split(","):
        part = part.strip()
        if part.upper().startswith("CN="):
            return part[3:].strip().strip('"')
    return subject.strip() if subject else ""


def check_authenticode_signature(path):
    """Return (status, publisher) for a PE file.

    status is 'valid', 'unsigned', 'invalid', or 'unknown'; publisher is the
    signing certificate's common name (empty if none).
    """
    if platform.system() != "Windows":
        return "unknown", ""

    try:
        escaped = str(path).replace("'", "''")
        completed = subprocess.run(
            [
                "powershell", "-NoProfile", "-NonInteractive", "-Command",
                f"$s = Get-AuthenticodeSignature -LiteralPath '{escaped}'; "
                f"\"$($s.Status)|$($s.SignerCertificate.Subject)\"",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        raw = completed.stdout.strip()
    except Exception as e:
        print(f"[SCANNER] Signature check failed for {path}: {e}")
        return "unknown", ""

    status, _, subject = raw.partition("|")
    status = status.strip().lower()
    publisher = _publisher_cn(subject)

    if status == "valid":
        return "valid", publisher
    if status == "notsigned":
        return "unsigned", ""
    if status in {"hashmismatch", "nottrusted"}:
        return "invalid", publisher
    return "unknown", publisher


def scan_script_content(path):
    """Return a reason string if the script contains hostile patterns."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read(FEATURE_SAMPLE_BYTES).lower()
    except Exception:
        return None

    for pattern in SUSPICIOUS_SCRIPT_PATTERNS:
        if pattern in content:
            return f"Suspicious script content: {pattern.strip()}"
    return None


def inspect_archive(path):
    """Return a reason string if the archive's member list looks hostile."""
    try:
        with zipfile.ZipFile(path) as archive:
            encrypted_executable = False
            for member in archive.infolist():
                member_path = Path(member.filename)
                suffix = member_path.suffix.lower()

                if suffix in ARCHIVE_EXECUTABLE_MEMBERS:
                    inner = member_path.stem
                    inner_suffix = Path(inner).suffix.lower()
                    if inner_suffix in DOUBLE_EXTENSION_BAIT:
                        return (
                            f"Archive contains disguised executable: {member.filename}"
                        )
                    if member.flag_bits & 0x1:
                        encrypted_executable = True

            if encrypted_executable:
                return "Password-protected archive containing executables"
    except zipfile.BadZipFile:
        return None
    except Exception as e:
        print(f"[SCANNER] Archive inspection failed for {path}: {e}")
        return None

    return None


def run_heuristic_classifier(path):
    """Return True only when the model is highly confident the file is malicious."""
    features = extract_features(path)
    probabilities = get_model().predict_proba([features])[0]
    malicious_index = list(get_model().classes_).index(1) if 1 in get_model().classes_ else None
    if malicious_index is None:
        return False
    return probabilities[malicious_index] >= HEURISTIC_MIN_CONFIDENCE


def contains_vba_macros(path):
    """Modern Office files are zips; macros live in vbaProject.bin."""
    try:
        with zipfile.ZipFile(path) as archive:
            return any(
                name.lower().endswith("vbaproject.bin")
                for name in archive.namelist()
            )
    except (zipfile.BadZipFile, OSError):
        return False


def analyze_file(path):
    """Classify by file type. Returns (result, reason) — result is 'safe' or 'suspicious'."""
    suffix = path.suffix.lower()

    if suffix in MACRO_EXTENSIONS:
        if contains_vba_macros(path):
            return "suspicious", "Office document contains macros - open only if you trust the sender"
        return "safe", "No threat detected"

    if suffix in SCRIPT_EXTENSIONS:
        reason = scan_script_content(path)
        if reason:
            return "suspicious", reason
        return "safe", "No threat detected"

    if suffix in ARCHIVE_EXTENSIONS:
        reason = inspect_archive(path)
        if reason:
            return "suspicious", reason
        return "safe", "No threat detected"

    if suffix in EXECUTABLE_EXTENSIONS:
        signature, publisher = check_authenticode_signature(path)
        if signature == "valid":
            lists = load_publisher_lists()
            if publisher and publisher.lower() in {p.lower() for p in lists["deny"]}:
                return "suspicious", f"Signed by a blocked publisher: {publisher}"
            if lists.get("strict") and publisher and publisher.lower() not in {p.lower() for p in lists["allow"]}:
                return "suspicious", f"Signed by an unapproved publisher: {publisher}"
            if publisher:
                return "safe", f"Valid signature - {publisher}"
            return "safe", "Valid digital signature"
        if signature == "invalid":
            return "suspicious", "Digital signature invalid (possible tampering)"
        # Unsigned or unknown: fall back to the heuristic model.
        if run_heuristic_classifier(path):
            return "suspicious", HEURISTIC_REASON
        return "safe", "No threat detected"

    return "safe", "No threat detected"


def scan_file(filepath, log_safe=None, quarantine=True):
    config = load_scan_config()
    should_log_safe = config["log_safe_files"] if log_safe is None else log_safe
    path = Path(filepath).expanduser().resolve()

    if not path.exists() or not path.is_file():
        return scan_response(path, "skipped", "not_a_file", path=str(path))

    if QUARANTINE_FOLDER in path.parents:
        return scan_response(path, "skipped", "already_quarantined", path=str(path))

    try:
        sha256 = compute_sha256(path)
        filename = path.name

        if sha256 in load_hash_db():
            log_scan(filename, sha256, "malicious", KNOWN_HASH_REASON)
            if quarantine:
                quarantine_file(path, sha256=sha256, reason=KNOWN_HASH_REASON)
            return scan_response(path, "malicious", KNOWN_HASH_REASON, sha256=sha256)

        if sha256 in load_trusted_hashes():
            if should_log_safe:
                log_scan(filename, sha256, "safe", "Trusted hash")
            return scan_response(path, "safe", "Trusted hash", sha256=sha256)

        result, reason = analyze_file(path)

        if result == "suspicious":
            log_scan(filename, sha256, "suspicious", reason)
            return scan_response(path, "suspicious", reason, sha256=sha256)

        if should_log_safe:
            log_scan(filename, sha256, "safe", reason)

        return scan_response(path, "safe", reason, sha256=sha256)

    except Exception as e:
        log_scan(path.name, "unknown", "error", str(e))
        print(f"[SCANNER] Failed to scan {path}: {e}")
        return scan_response(path, "error", str(e), path=str(path))


def find_file_in_watch_folders(filename, sha256=None):
    """Locate a file by basename in the configured watch folders.

    When a sha256 is provided the match must also hash to it, so a stale
    log row can never quarantine a different file with the same name.
    """
    name = os.path.basename(str(filename or "").strip())
    if not name:
        return None

    config = load_scan_config()
    for folder in config.get("watch_folders", []):
        candidate = Path(folder) / name
        if not candidate.is_file():
            continue
        if sha256:
            try:
                if compute_sha256(candidate) != normalize_sha256(sha256):
                    continue
            except OSError:
                continue
        return candidate

    return None


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

        if result["result"] in {"malicious", "suspicious"}:
            alerts += 1
        elif result["result"] == "error":
            errors += 1

    return {"scanned": scanned, "alerts": alerts, "errors": errors, "limit": scan_limit}
