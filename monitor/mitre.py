"""MITRE ATT&CK technique tagging.

Maps Doors AI's detection reasons to ATT&CK technique IDs so alerts read as
a recognizable attack narrative. Pure keyword mapping over the reason strings
the detectors already produce - no external data, no lookups.
"""

# (substring to match in a reason, technique id, short technique name)
# Order matters: more specific / contextual matches come first so a generic
# interpreter name (e.g. "powershell") doesn't shadow a behavioral detection.
_TECHNIQUE_RULES = [
    ("behavioral", "T1204.002", "User Execution: Malicious File"),
    ("spawned", "T1204.002", "User Execution: Malicious File"),
    ("frombase64string", "T1140", "Deobfuscate/Decode Files or Information"),
    ("encodedcommand", "T1027", "Obfuscated Files or Information"),
    ("-enc", "T1027", "Obfuscated Files or Information"),
    ("invoke-obfuscation", "T1027", "Obfuscated Files or Information"),
    ("downloadstring", "T1105", "Ingress Tool Transfer"),
    ("downloadfile", "T1105", "Ingress Tool Transfer"),
    ("invoke-webrequest", "T1105", "Ingress Tool Transfer"),
    ("certutil", "T1105", "Ingress Tool Transfer"),
    ("bitsadmin", "T1197", "BITS Jobs"),
    ("mimikatz", "T1003", "OS Credential Dumping"),
    ("lazagne", "T1555", "Credentials from Password Stores"),
    ("regsvr32", "T1218.010", "System Binary Proxy Execution: Regsvr32"),
    ("rundll32", "T1218.011", "System Binary Proxy Execution: Rundll32"),
    ("mshta", "T1218.005", "System Binary Proxy Execution: Mshta"),
    ("wscript", "T1059.005", "Command and Scripting: Visual Basic"),
    ("cscript", "T1059.005", "Command and Scripting: Visual Basic"),
    ("powershell", "T1059.001", "Command and Scripting: PowerShell"),
    ("macro", "T1204.002", "User Execution: Malicious File"),
    ("non-standard location", "T1036", "Masquerading"),
    ("masquerad", "T1036", "Masquerading"),
    ("disguised executable", "T1036.008", "Masquerading: Double File Extension"),
    ("vssadmin delete", "T1490", "Inhibit System Recovery"),
    ("canary", "T1486", "Data Encrypted for Impact"),
    ("mass file modification", "T1486", "Data Encrypted for Impact"),
    ("ransomware", "T1486", "Data Encrypted for Impact"),
    ("run key", "T1547.001", "Boot/Logon Autostart: Registry Run Keys"),
    ("registry entry", "T1547.001", "Boot/Logon Autostart: Registry Run Keys"),
    ("startup", "T1547.001", "Boot/Logon Autostart: Startup Folder"),
    ("scheduled task", "T1053.005", "Scheduled Task"),
    ("service", "T1543.003", "Create or Modify System Process: Service"),
    ("known malware hash", "T1204.002", "User Execution: Malicious File"),
    ("signature invalid", "T1036", "Masquerading"),
    ("brute force", "T1110", "Brute Force"),
    ("failed", "T1110", "Brute Force"),
]


def tag_technique(*texts):
    """Return {'id','name','label'} for the first matching technique, or None."""
    haystack = " ".join(str(t or "") for t in texts).lower()
    for needle, tid, name in _TECHNIQUE_RULES:
        if needle in haystack:
            return {"id": tid, "name": name, "label": f"{tid} {name}"}
    return None


def technique_id(*texts):
    tag = tag_technique(*texts)
    return tag["id"] if tag else ""
