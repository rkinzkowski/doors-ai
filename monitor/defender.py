"""Windows Defender second opinion.

Reads Defender's own protection state and detected-threat history via
PowerShell (Get-MpComputerStatus / Get-MpThreat) and surfaces it in the
dashboard, so Doors AI complements the built-in antivirus instead of
ignoring it. Read-only; nothing is changed in Defender.
"""

import json
import platform
import subprocess
import threading
import time

CACHE_TTL_SEC = 60

# Defender SeverityID -> Doors AI severity badge.
_SEVERITY_MAP = {1: "low", 2: "medium", 4: "high", 5: "critical"}

_PS_SCRIPT = (
    "$ErrorActionPreference='SilentlyContinue';"
    "$s = Get-MpComputerStatus;"
    "$t = Get-MpThreat | Select-Object ThreatName, SeverityID, IsActive,"
    " @{n='Resources';e={ ($_.Resources -join '; ') }};"
    "[pscustomobject]@{"
    " AntivirusEnabled=[bool]$s.AntivirusEnabled;"
    " RealTimeProtectionEnabled=[bool]$s.RealTimeProtectionEnabled;"
    " SignatureAge=$s.AntivirusSignatureAge;"
    " Threats=@($t)"
    "} | ConvertTo-Json -Depth 4 -Compress"
)

_lock = threading.Lock()
_cache = {"time": 0, "data": None}


def _query_defender():
    if platform.system() != "Windows":
        return {"available": False, "error": "Windows only"}

    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", _PS_SCRIPT],
            capture_output=True, text=True, errors="replace", timeout=45,
        )
    except Exception as e:
        return {"available": False, "error": str(e)}

    out = (completed.stdout or "").strip()
    if not out:
        return {"available": False, "error": "Defender cmdlets returned nothing (may need Windows Defender / admin)."}

    try:
        raw = json.loads(out)
    except json.JSONDecodeError:
        return {"available": False, "error": "Could not parse Defender output."}

    threats_raw = raw.get("Threats") or []
    if isinstance(threats_raw, dict):
        threats_raw = [threats_raw]

    threats = []
    for t in threats_raw:
        sev_id = t.get("SeverityID")
        threats.append({
            "name": t.get("ThreatName", "Unknown"),
            "severity": _SEVERITY_MAP.get(sev_id, "medium"),
            "active": bool(t.get("IsActive")),
            "resources": t.get("Resources", ""),
        })

    # Active/critical first.
    threats.sort(key=lambda x: (not x["active"], x["severity"] != "critical", x["severity"] != "high"))

    return {
        "available": True,
        "error": None,
        "antivirus_enabled": bool(raw.get("AntivirusEnabled")),
        "realtime_enabled": bool(raw.get("RealTimeProtectionEnabled")),
        "signature_age_days": raw.get("SignatureAge"),
        "threats": threats,
    }


def get_defender_status():
    now = time.time()
    with _lock:
        if now - _cache["time"] < CACHE_TTL_SEC and _cache["data"] is not None:
            return _cache["data"]

    data = _query_defender()

    with _lock:
        _cache["time"] = now
        _cache["data"] = data
    return data
