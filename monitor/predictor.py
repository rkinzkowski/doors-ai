"""The Predictive Engine (Phase 4a) - local, always-on, no API key.

Turns the event history and current state into forward-looking predictions:
where an attack is in its playbook and what's likely next, whether risk is
trending up, and which not-yet-flagged things are worth watching. Pure
functions over already-collected data, so it's fully testable and needs no
network access.
"""

from datetime import datetime

from monitor.mitre import tag_technique

# --- Kill chain (attacker playbook), in the order stages usually happen ------
# stage key -> (order, plain-language label)
STAGES = {
    "initial-access":       (1, "Getting in"),
    "execution":            (2, "Running unknown code"),
    "persistence":          (3, "Setting up to survive restarts"),
    "privilege-escalation": (4, "Gaining more control"),
    "defense-evasion":      (5, "Hiding from protection"),
    "credential-access":    (6, "Stealing passwords"),
    "discovery":            (7, "Scoping out your PC and network"),
    "lateral-movement":     (8, "Spreading to other devices"),
    "collection":           (9, "Gathering your files"),
    "command-and-control":  (10, "Phoning home to an attacker"),
    "exfiltration":         (11, "Sending your data out"),
    "impact":               (12, "Doing damage (ransomware, deletion)"),
}

# MITRE technique id -> kill-chain stage.
_TECHNIQUE_STAGE = {
    "T1204.002": "execution", "T1059.001": "execution", "T1059.005": "execution",
    "T1547.001": "persistence", "T1053.005": "persistence", "T1543.003": "persistence",
    "T1027": "defense-evasion", "T1140": "defense-evasion", "T1036": "defense-evasion",
    "T1036.008": "defense-evasion", "T1218.005": "defense-evasion",
    "T1218.010": "defense-evasion", "T1218.011": "defense-evasion",
    "T1003": "credential-access", "T1555": "credential-access", "T1110": "credential-access",
    "T1105": "command-and-control", "T1197": "command-and-control",
    "T1486": "impact", "T1490": "impact",
}

# Event kind -> stage, used when there's no MITRE tag.
_KIND_STAGE = {
    "file:malicious": "initial-access", "file:suspicious": "initial-access",
    "process": "execution",
    "endpoint:registry": "persistence", "endpoint:startup": "persistence",
    "endpoint:task": "persistence", "endpoint:service": "persistence",
    "endpoint:ransomware": "impact", "ransomware": "impact",
    "network:connection": "command-and-control",
    "network:new-destination": "command-and-control",
    "network:arp-spoof": "credential-access",
    "network:exposure": "discovery", "network:new-device": "discovery",
}

# Given the furthest stage reached, what typically comes next.
_NEXT_STAGE = {
    "initial-access": [("execution", "Downloaded files are usually run next.")],
    "execution": [("persistence", "After running, malware usually sets itself to start with Windows.")],
    "persistence": [
        ("credential-access", "Once it's dug in, stealing saved passwords is a common next step."),
        ("discovery", "It often looks around your PC and network next."),
    ],
    "privilege-escalation": [("defense-evasion", "With more control, it tries to hide from protection.")],
    "defense-evasion": [("credential-access", "After hiding, stealing passwords is a frequent goal.")],
    "credential-access": [
        ("lateral-movement", "With stolen passwords, attackers spread to other devices."),
        ("exfiltration", "Or they start sending your data out."),
    ],
    "discovery": [("lateral-movement", "After mapping the network, spreading to other devices is typical.")],
    "lateral-movement": [("collection", "Once spread, they gather files to steal.")],
    "collection": [("exfiltration", "Gathered files are usually sent out next.")],
    "command-and-control": [
        ("exfiltration", "A phone-home channel is often used to send your data out."),
        ("impact", "Or to trigger damage like ransomware."),
    ],
    "exfiltration": [("impact", "After stealing data, attackers sometimes do damage to cover tracks.")],
}

_SEV_BY_STAGE = {
    "impact": "critical", "exfiltration": "critical",
    "credential-access": "high", "lateral-movement": "high",
    "command-and-control": "high", "collection": "high",
    "privilege-escalation": "high", "defense-evasion": "medium",
    "discovery": "medium", "persistence": "medium",
    "execution": "medium", "initial-access": "low",
}

_WATCH_FOR = {
    "credential-access": "programs touching lsass.exe, or tools like mimikatz",
    "lateral-movement": "new sign-ins, or connections to other devices on your network",
    "discovery": "new devices appearing, or unusual network scanning",
    "command-and-control": "programs connecting to unfamiliar or flagged addresses",
    "exfiltration": "large or unusual uploads from an unknown program",
    "impact": "the ransomware tripwire, or many files changing at once",
    "persistence": "new startup programs, scheduled tasks, or services",
    "execution": "unfamiliar programs running, especially from Downloads or Temp",
}


# Routine change-detection kinds: worth logging, but NOT evidence of an attack.
# A browser reaching a new site, a new device on Wi-Fi, or a software install
# adding a scheduled task are all normal. Excluding them stops the engine from
# crying wolf on an ordinary, healthy PC.
_INFORMATIONAL_KINDS = {"network:new-destination", "network:new-device", "network:exposure"}
_PERSISTENCE_KINDS = {"endpoint:registry", "endpoint:startup", "endpoint:task", "endpoint:service"}


def _is_threat_event(event):
    """True only for events that genuinely indicate malice (not routine changes)."""
    kind = event.get("kind", "")
    severity = (event.get("severity") or "").lower()
    if kind in _INFORMATIONAL_KINDS:
        return False
    if kind in _PERSISTENCE_KINDS:
        # A plain new startup entry is usually a software install. Only count it
        # toward an attack when it carried a hostile indicator (marked critical).
        return severity == "critical"
    # file:*, process, ransomware, flagged connections, ARP spoofing.
    return True


def _stage_of(event):
    tag = tag_technique(event.get("title"), event.get("detail"), event.get("kind"))
    if tag and tag["id"] in _TECHNIQUE_STAGE:
        return _TECHNIQUE_STAGE[tag["id"]]
    kind = event.get("kind", "")
    if kind in _KIND_STAGE:
        return _KIND_STAGE[kind]
    base = kind.split(":")[0]
    for k, stage in _KIND_STAGE.items():
        if k.split(":")[0] == base:
            return stage
    return None


def _parse(ts):
    try:
        return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return None


def predict_kill_chain(events):
    """Map recent events onto the attacker playbook and forecast the next move."""
    seen = {}  # stage -> count
    for ev in events:
        stage = _stage_of(ev)
        if stage:
            seen[stage] = seen.get(stage, 0) + 1

    if not seen:
        return {"active": False, "stages_seen": [], "furthest": None,
                "predicted_next": [], "severity": "low"}

    stages_seen = sorted(
        ({"stage": s, "label": STAGES[s][1], "order": STAGES[s][0], "count": n}
         for s, n in seen.items()),
        key=lambda x: x["order"],
    )
    furthest = max(stages_seen, key=lambda x: x["order"])

    predicted = []
    for nxt, why in _NEXT_STAGE.get(furthest["stage"], []):
        if nxt in seen:
            continue  # already happened; don't predict backwards
        predicted.append({
            "label": STAGES[nxt][1], "why": why,
            "watch_for": _WATCH_FOR.get(nxt, ""),
        })

    # An attack "chain" is meaningful once two or more distinct stages appear.
    active = len(seen) >= 2
    return {
        "active": active,
        "stages_seen": stages_seen,
        "furthest": furthest,
        "predicted_next": predicted[:2],
        "severity": _SEV_BY_STAGE.get(furthest["stage"], "low") if active else "low",
    }


def predict_trajectory(daily_counts):
    """Are alerts accelerating, steady, or calming down?"""
    counts = [d["count"] for d in daily_counts]
    if len(counts) < 6 or sum(counts) == 0:
        return {"direction": "steady", "recent": sum(counts[-3:]) if counts else 0,
                "prior": 0, "detail": "Not enough history yet to spot a trend."}

    recent = sum(counts[-3:])
    prior = sum(counts[-6:-3])

    if recent > max(prior * 1.5, prior + 2):
        direction, detail = "worsening", "Alerts are picking up compared with the days before - worth a closer look."
    elif recent * 1.5 < prior or (prior >= 2 and recent == 0):
        direction, detail = "improving", "Fewer alerts than the days before - things are calming down."
    else:
        direction, detail = "steady", "Alert levels are holding steady."

    return {"direction": direction, "recent": recent, "prior": prior, "detail": detail}


def score_watchlist(connections, network):
    """Pre-emptive scoring: things not (yet) flagged as threats but worth watching."""
    items = []

    for c in (connections or {}).get("connections", []):
        if c.get("flagged"):
            continue  # already an alert, not a prediction
        reasons, risk = [], 0
        if c.get("new") and c.get("public"):
            risk += 45
            reasons.append("first time this program has reached this server")
        proc = (c.get("process") or "").lower()
        if c.get("public") and (not proc or proc == "unknown"):
            risk += 25
            reasons.append("the program behind it couldn't be identified")
        if risk >= 45:
            items.append({
                "name": c.get("process") or "Unknown program",
                "kind": "connection",
                "detail": f"talking to {c.get('remote_ip')}",
                "risk": min(risk, 95), "reasons": reasons,
            })

    seen_ports = set()
    for p in (network or {}).get("ports", []):
        if p.get("recognized") or p.get("port") in seen_ports:
            continue
        if p.get("binding") == "all interfaces":
            seen_ports.add(p.get("port"))
            items.append({
                "name": p.get("process") or "Unknown program",
                "kind": "open port",
                "detail": f"accepting connections on port {p.get('port')}",
                "risk": 55,
                "reasons": ["an unrecognized program is reachable from your network"],
            })

    items.sort(key=lambda x: -x["risk"])
    return items[:8]


def _threat_daily_counts(threat_events, days=14):
    """Per-day counts of *threat* events (not routine changes) for the trend."""
    from datetime import timedelta
    today = datetime.now().date()
    start = today - timedelta(days=days - 1)
    buckets = {}
    for ev in threat_events:
        dt = _parse(ev.get("ts"))
        if dt and dt.date() >= start:
            buckets[dt.date()] = buckets.get(dt.date(), 0) + 1
    return [{"count": buckets.get(start + timedelta(days=i), 0)} for i in range(days)]


def get_predictions(events, connections, network):
    from datetime import timedelta
    threat_events = [e for e in events if _is_threat_event(e)]

    cutoff = datetime.now() - timedelta(days=3)
    recent_threats = [e for e in threat_events if (_parse(e.get("ts")) or datetime.min) >= cutoff]

    kill_chain = predict_kill_chain(recent_threats)
    trajectory = predict_trajectory(_threat_daily_counts(threat_events))
    watchlist = score_watchlist(connections, network)

    # One plain-language headline.
    if kill_chain["active"] and kill_chain["predicted_next"]:
        summary = (
            f"An attack pattern is developing ({kill_chain['furthest']['label'].lower()}). "
            f"Likely next: {kill_chain['predicted_next'][0]['label'].lower()}."
        )
    elif kill_chain["active"]:
        summary = f"Some attack-like activity was seen ({kill_chain['furthest']['label'].lower()})."
    elif trajectory["direction"] == "worsening":
        summary = "No active attack, but alerts are trending up - keep an eye on things."
    elif watchlist:
        summary = f"Nothing alarming, but {len(watchlist)} item(s) are worth a look before they become a problem."
    else:
        summary = "No attack patterns or worrying trends. You're in good shape."

    return {
        "kill_chain": kill_chain,
        "trajectory": trajectory,
        "watchlist": watchlist,
        "summary": summary,
    }
