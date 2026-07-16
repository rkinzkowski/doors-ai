"""Incident correlation.

Groups individual alerts that happen close together in time into a single
"incident" with a plain-language summary and a timeline, so a multi-step
attack reads as one story instead of scattered rows across the dashboard.
"""

from datetime import datetime

from monitor.events_db import get_events

WINDOW_SEC = 600  # events within 10 minutes of each other belong together
_SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _parse(ts):
    try:
        return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return None


def _narrative(kinds):
    has_file = any(k.startswith("file:") for k in kinds)
    has_proc = "process" in kinds
    has_persist = any(k.startswith("endpoint:") and "ransom" not in k for k in kinds)
    has_ransom = any("ransom" in k for k in kinds)

    if has_ransom:
        return "Possible ransomware activity - files or a tripwire were touched. Treat this as urgent."
    if has_file and has_proc and has_persist:
        return "A suspicious file, a suspicious program, and a system-startup change happened together - a classic attack chain."
    if has_file and has_proc:
        return "A suspicious file was followed by a suspicious program running - worth a close look."
    if has_proc and has_persist:
        return "A suspicious program ran and something was added to your startup - it may be trying to stick around."
    if has_file:
        return "One or more suspicious files were flagged in this window."
    if has_proc:
        return "One or more suspicious programs were flagged in this window."
    if has_persist:
        return "Your startup programs, tasks, or services changed in this window."
    return "Several related alerts happened close together."


def get_incidents(days=7, max_incidents=25):
    events = get_events(days=days)  # newest first
    # Work oldest-first so clustering reads naturally.
    events = list(reversed(events))

    incidents = []
    current = None
    last_dt = None

    for ev in events:
        dt = _parse(ev["ts"])
        if dt is None:
            continue
        if current is None or (last_dt and (dt - last_dt).total_seconds() > WINDOW_SEC):
            current = {"events": [], "kinds": set()}
            incidents.append(current)
        current["events"].append(ev)
        current["kinds"].add(ev["kind"])
        last_dt = dt

    out = []
    for inc in incidents:
        evs = inc["events"]
        severity = max((e["severity"] for e in evs), key=lambda s: _SEV_RANK.get(s, 0), default="low")
        out.append({
            "start": evs[0]["ts"],
            "end": evs[-1]["ts"],
            "count": len(evs),
            "severity": severity,
            "kinds": sorted(inc["kinds"]),
            "summary": _narrative(inc["kinds"]),
            "events": evs,
        })

    # Most recent incidents first.
    out.sort(key=lambda i: i["end"], reverse=True)
    return out[:max_incidents]
