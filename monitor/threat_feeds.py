"""Threat-intelligence feed importers.

Two user-triggered importers that pull PLAIN-TEXT threat data (never sample
binaries) into the local databases:

  * IPsum       -> suspicious IP addresses -> threat_list.csv
  * MalwareBazaar -> known-malware SHA256 fingerprints -> malware_hashes.csv

Both are opt-in and run only when the user clicks Update. IPsum needs no
account. MalwareBazaar requires a free Auth-Key the user obtains themselves
from the abuse.ch portal and pastes into the dashboard.
"""

import csv
import io
import json
import re
from datetime import datetime
from pathlib import Path

import requests

ROOT_DIR = Path(__file__).resolve().parents[1]
THREAT_LOG = ROOT_DIR / "threat_list.csv"
HASH_DB = ROOT_DIR / "malware_hashes.csv"
FEEDS_CONFIG = ROOT_DIR / "feeds_config.json"

IPSUM_URL = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
BAZAAR_RECENT_URL = "https://mb-api.abuse.ch/v2/files/exports/{key}/recent.csv"
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"
FEODO_REASON = "Feodo Tracker (botnet C2)"
FEODO_CONFIDENCE = 90
IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

THREAT_HEADERS = ["ip", "reason", "confidence", "timestamp"]
HASH_HEADERS = ["sha256", "description"]
IPSUM_REASON_PREFIX = "IPsum threat feed"
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
REQUEST_TIMEOUT = 30

DEFAULT_FEEDS_CONFIG = {
    "ipsum_min_lists": 3,
    "malwarebazaar_auth_key": "",
    "ipsum_last_sync": None,
    "ipsum_last_count": 0,
    "bazaar_last_sync": None,
    "bazaar_last_count": 0,
    "feodo_last_sync": None,
    "feodo_last_count": 0,
}


def load_feeds_config():
    config = DEFAULT_FEEDS_CONFIG.copy()
    if FEEDS_CONFIG.exists():
        try:
            with open(FEEDS_CONFIG, "r", encoding="utf-8") as f:
                config.update(json.load(f))
        except Exception as e:
            print(f"[FEEDS] Could not read config: {e}")
    return config


def save_feeds_config(config):
    try:
        with open(FEEDS_CONFIG, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
    except Exception as e:
        print(f"[FEEDS] Could not save config: {e}")


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _confidence_from_count(count):
    # Any IP on the feed is suspicious; more lists -> higher confidence.
    return max(1, min(100, 50 + count * 5))


def update_ipsum(min_lists=None):
    """Fetch IPsum, keep IPs on >= min_lists blocklists, merge into threat_list.csv."""
    config = load_feeds_config()
    if min_lists is None:
        min_lists = int(config.get("ipsum_min_lists", 3))
    min_lists = max(1, min(8, int(min_lists)))

    try:
        response = requests.get(IPSUM_URL, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
    except Exception as e:
        return {"ok": False, "error": f"Could not reach IPsum: {e}"}

    feed_rows = []
    for line in response.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 2:
            continue
        ip, raw_count = parts
        try:
            count = int(raw_count)
        except ValueError:
            continue
        if count < min_lists:
            continue
        feed_rows.append((ip, count))

    if not feed_rows:
        return {"ok": False, "error": "IPsum returned no usable rows (format may have changed)."}

    # Preserve any non-feed (manual) entries; replace the feed-sourced set.
    preserved = []
    if THREAT_LOG.exists():
        try:
            with open(THREAT_LOG, newline="", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    reason = (row.get("reason") or "")
                    if not reason.startswith(IPSUM_REASON_PREFIX):
                        preserved.append(row)
        except Exception as e:
            print(f"[FEEDS] Could not read existing threat list: {e}")

    preserved_ips = {row.get("ip") for row in preserved}
    timestamp = _now()
    added = 0

    with open(THREAT_LOG, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(THREAT_HEADERS)
        for row in preserved:
            writer.writerow([
                row.get("ip", ""),
                row.get("reason", ""),
                row.get("confidence", ""),
                row.get("timestamp", ""),
            ])
        for ip, count in feed_rows:
            if ip in preserved_ips:
                continue  # a manual entry wins over the feed
            writer.writerow([
                ip,
                f"{IPSUM_REASON_PREFIX} ({count} blocklists)",
                _confidence_from_count(count),
                timestamp,
            ])
            added += 1

    config["ipsum_min_lists"] = min_lists
    config["ipsum_last_sync"] = timestamp
    config["ipsum_last_count"] = added
    save_feeds_config(config)

    print(f"[FEEDS] IPsum import: {added} IPs at tier >= {min_lists}")
    return {"ok": True, "count": added, "min_lists": min_lists}


def _merge_ip_feed(feed_entries, reason_prefix, last_sync_key, last_count_key):
    """Rewrite threat_list.csv: keep other feeds/manual rows, replace this feed's set."""
    preserved = []
    if THREAT_LOG.exists():
        try:
            with open(THREAT_LOG, newline="", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    if not (row.get("reason") or "").startswith(reason_prefix):
                        preserved.append(row)
        except Exception as e:
            print(f"[FEEDS] Could not read existing threat list: {e}")

    preserved_ips = {row.get("ip") for row in preserved}
    timestamp = _now()
    added = 0

    with open(THREAT_LOG, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(THREAT_HEADERS)
        for row in preserved:
            writer.writerow([row.get("ip", ""), row.get("reason", ""),
                             row.get("confidence", ""), row.get("timestamp", "")])
        for ip, reason, confidence in feed_entries:
            if ip in preserved_ips:
                continue
            writer.writerow([ip, reason, confidence, timestamp])
            added += 1

    config = load_feeds_config()
    config[last_sync_key] = timestamp
    config[last_count_key] = added
    save_feeds_config(config)
    return added


def update_feodo():
    """Fetch Feodo Tracker's recommended botnet C2 IP list into threat_list.csv."""
    try:
        response = requests.get(FEODO_URL, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
    except Exception as e:
        return {"ok": False, "error": f"Could not reach Feodo Tracker: {e}"}

    entries = []
    for line in response.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        ip = line.split(",")[0].strip()
        if IPV4_RE.match(ip):
            entries.append((ip, FEODO_REASON, FEODO_CONFIDENCE))

    if not entries:
        return {"ok": False, "error": "Feodo Tracker returned no usable IPs (format may have changed)."}

    added = _merge_ip_feed(entries, FEODO_REASON, "feodo_last_sync", "feodo_last_count")
    print(f"[FEEDS] Feodo import: {added} C2 IPs")
    return {"ok": True, "count": added}


def _extract_sha256_rows(csv_text):
    """Robustly pull (sha256, description) from a MalwareBazaar CSV export."""
    rows = []
    reader = csv.reader(io.StringIO(csv_text))
    for fields in reader:
        if not fields or fields[0].lstrip().startswith("#"):
            continue
        sha = next((f.strip().strip('"') for f in fields if SHA256_RE.match(f.strip().strip('"'))), None)
        if not sha:
            continue
        # Signature/family is usually a later column; fall back to a generic
        # note. Skip mime types ("/"), filenames ("."), and hex-only fields.
        signature = ""
        for f in fields:
            val = f.strip().strip('"')
            if not val or val == sha or SHA256_RE.match(val):
                continue
            if "/" in val or "." in val or ":" in val:
                continue
            if len(val) < 40 and any(c.isalpha() for c in val):
                signature = val
        rows.append((sha.lower(), signature))
    return rows


def update_malware_hashes(auth_key=None):
    """Fetch recent MalwareBazaar hashes and merge into malware_hashes.csv."""
    config = load_feeds_config()
    auth_key = (auth_key if auth_key is not None else config.get("malwarebazaar_auth_key", "")).strip()

    if not auth_key:
        return {"ok": False, "error": "auth_required"}

    try:
        response = requests.get(
            BAZAAR_RECENT_URL.format(key=auth_key),
            timeout=REQUEST_TIMEOUT,
        )
    except Exception as e:
        return {"ok": False, "error": f"Could not reach MalwareBazaar: {e}"}

    if response.status_code in (401, 403):
        return {"ok": False, "error": "auth_rejected"}
    if response.status_code != 200:
        return {"ok": False, "error": f"MalwareBazaar returned HTTP {response.status_code}"}

    feed_rows = _extract_sha256_rows(response.text)
    if not feed_rows:
        return {"ok": False, "error": "No hashes found in the export (format may have changed)."}

    existing = set()
    if HASH_DB.exists():
        try:
            with open(HASH_DB, newline="", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    sha = (row.get("sha256") or "").strip().lower()
                    if SHA256_RE.match(sha):
                        existing.add(sha)
        except Exception as e:
            print(f"[FEEDS] Could not read hash DB: {e}")

    new_hashes = [(sha, sig) for sha, sig in feed_rows if sha not in existing]

    if not HASH_DB.exists() or HASH_DB.stat().st_size == 0:
        with open(HASH_DB, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(HASH_HEADERS)

    with open(HASH_DB, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        for sha, sig in new_hashes:
            desc = f"MalwareBazaar{': ' + sig if sig else ''}"
            writer.writerow([sha, desc])

    # Persist the key so future syncs work, and record the result.
    config["malwarebazaar_auth_key"] = auth_key
    config["bazaar_last_sync"] = _now()
    config["bazaar_last_count"] = len(new_hashes)
    save_feeds_config(config)

    print(f"[FEEDS] MalwareBazaar import: {len(new_hashes)} new hashes")
    return {"ok": True, "count": len(new_hashes), "seen": len(feed_rows)}
