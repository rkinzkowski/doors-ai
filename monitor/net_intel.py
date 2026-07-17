"""Phase 3 network intelligence — all passive, local reads.

- Active connections cross-checked against the local threat list (catches
  malware phoning home to a known-bad address)
- DNS resolver cache, flagging suspicious domains
- Firewall state and a local vulnerability / self-exposure assessment
- New-device detection against a remembered baseline of the home network

Nothing is scanned or transmitted; every function reads state that already
exists on this machine.
"""

import csv
import ipaddress
import json
import platform
import re
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path

import psutil
import requests

ROOT_DIR = Path(__file__).resolve().parents[1]
THREAT_LOG = ROOT_DIR / "threat_list.csv"
DEVICE_BASELINE = ROOT_DIR / "network_devices_baseline.json"
CONN_BASELINE = ROOT_DIR / "connection_baseline.json"
NET_STATE = ROOT_DIR / "net_state.json"

CONN_POLL_SEC = 60
DNS_TTL_SEC = 60

# TLDs and patterns disproportionately used for throwaway malware domains.
SUSPICIOUS_TLDS = {".xyz", ".top", ".tk", ".gq", ".ml", ".cf", ".ga",
                   ".work", ".click", ".loan", ".rest", ".zip", ".mov"}
_RANDOM_LABEL = re.compile(r"[a-z0-9]{16,}")

_threat_cache = {"mtime": 0, "ips": {}}
_dns_cache = {"time": 0, "records": [], "error": None}
_conn_seen = {}
_ipapi_cache = {}
_enrichment_enabled = False
_lock = threading.Lock()


def set_enrichment_enabled(value):
    global _enrichment_enabled
    _enrichment_enabled = bool(value)


def enrichment_enabled():
    return _enrichment_enabled


def ip_reputation(ip):
    """Opt-in: look up an IP's ISP + whether it's a proxy/hosting/data-center."""
    if ip in _ipapi_cache:
        return _ipapi_cache[ip]
    out = {}
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,proxy,hosting,isp,org,countryCode",
            timeout=5,
        )
        d = r.json()
        if d.get("status") == "success":
            out = {"proxy": d.get("proxy"), "hosting": d.get("hosting"),
                   "isp": d.get("isp", ""), "org": d.get("org", ""),
                   "country": d.get("countryCode", "")}
    except Exception:
        out = {}
    _ipapi_cache[ip] = out
    return out


def _load_threat_ips():
    try:
        st = THREAT_LOG.stat()
    except OSError:
        return {}
    if st.st_mtime == _threat_cache["mtime"] and _threat_cache["ips"]:
        return _threat_cache["ips"]
    ips = {}
    try:
        with open(THREAT_LOG, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                ip = (row.get("ip") or "").strip()
                if ip:
                    ips[ip] = row.get("reason") or "On your threat list"
    except Exception as e:
        print(f"[NETINTEL] Could not read threat list: {e}")
    _threat_cache.update(mtime=st.st_mtime, ips=ips)
    return ips


def _is_public(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_reserved
                    or addr.is_multicast or addr.is_link_local)
    except ValueError:
        return False


def get_active_connections(limit=200):
    """Established outbound/inbound connections with owning process; bad ones flagged."""
    threats = _load_threat_ips()
    rows = []
    seen = set()

    try:
        conns = psutil.net_connections(kind="inet")
    except Exception as e:
        return {"connections": [], "flagged": [], "error": str(e)}

    for c in conns:
        if c.status != psutil.CONN_ESTABLISHED or not c.raddr:
            continue
        rip = c.raddr.ip
        key = (rip, c.raddr.port, c.pid)
        if key in seen:
            continue
        seen.add(key)

        proc = ""
        if c.pid:
            try:
                proc = psutil.Process(c.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        reason = threats.get(rip, "")
        rows.append({
            "remote_ip": rip,
            "remote_port": c.raddr.port,
            "process": proc,
            "pid": c.pid or "",
            "public": _is_public(rip),
            "flagged": bool(reason),
            "reason": reason,
        })

    baseline = _load_conn_baseline() or set()
    for r in rows:
        r["new"] = r["public"] and f"{(r['process'] or '').lower()}|{r['remote_ip']}" not in baseline
        r["isp"] = ""
        if _enrichment_enabled and r["flagged"]:
            rep = ip_reputation(r["remote_ip"])
            r["isp"] = rep.get("isp", "")
            if rep.get("proxy"):
                r["isp"] += " (proxy/VPN)"
            elif rep.get("hosting"):
                r["isp"] += " (data center)"

    rows.sort(key=lambda r: (not r["flagged"], not r["new"], not r["public"]))
    flagged = [r for r in rows if r["flagged"]]
    return {"connections": rows[:limit], "flagged": flagged,
            "new_count": sum(1 for r in rows if r["new"]), "error": None}


def _load_conn_baseline():
    if not CONN_BASELINE.exists():
        return None
    try:
        with open(CONN_BASELINE, "r", encoding="utf-8") as f:
            return set(json.load(f))
    except Exception:
        return None


def _save_conn_baseline(pairs):
    try:
        with open(CONN_BASELINE, "w", encoding="utf-8") as f:
            json.dump(sorted(pairs), f)
    except Exception as e:
        print(f"[NETINTEL] Could not save connection baseline: {e}")


def reset_conn_baseline():
    try:
        if CONN_BASELINE.exists():
            CONN_BASELINE.unlink()
        return True
    except Exception:
        return False


def _current_public_pairs():
    pairs = set()
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.status == psutil.CONN_ESTABLISHED and c.raddr and _is_public(c.raddr.ip):
                proc = ""
                if c.pid:
                    try:
                        proc = psutil.Process(c.pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                pairs.add(f"{proc.lower()}|{c.raddr.ip}")
    except Exception:
        pass
    return pairs


def _load_net_state():
    if NET_STATE.exists():
        try:
            with open(NET_STATE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def _save_net_state(state):
    try:
        with open(NET_STATE, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
    except Exception:
        pass


def check_arp_spoof():
    """Alert if the router's hardware address (MAC) changes - a MITM signature."""
    from monitor.network_monitor import get_network_snapshot
    gw = _gateway_ip()
    if not gw:
        return
    devices = get_network_snapshot().get("devices", [])
    gw_mac = next((d["mac"] for d in devices if d.get("ip") == gw), "")
    if not gw_mac:
        return

    state = _load_net_state()
    known = state.get("gateway_mac", "")
    if not known:
        state["gateway_ip"] = gw
        state["gateway_mac"] = gw_mac
        _save_net_state(state)
        return

    if gw_mac != known:
        try:
            from monitor.events_db import record_event
            record_event("network:arp-spoof", "critical",
                         "Your router's hardware ID changed",
                         f"Gateway {gw} was {known}, now {gw_mac} - possible Wi-Fi man-in-the-middle attack")
        except Exception:
            pass
        try:
            from monitor.notify import notify
            notify("Doors AI: Network warning",
                   "Your router's hardware ID changed - possible man-in-the-middle attack.", key="arp-spoof")
        except Exception:
            pass
        state["gateway_mac"] = gw_mac
        _save_net_state(state)


def check_connections_now():
    """Background pass: alert on bad addresses, brand-new destinations, and ARP spoofing."""
    data = get_active_connections()
    for c in data.get("flagged", []):
        sig = f"{c['remote_ip']}:{c['pid']}"
        now = time.time()
        with _lock:
            if now - _conn_seen.get(sig, 0) < 600:
                continue
            _conn_seen[sig] = now
        title = f"{c['process'] or 'A program'} contacted a flagged address"
        detail = f"{c['remote_ip']}:{c['remote_port']} - {c['reason']}"
        try:
            from monitor.events_db import record_event
            record_event("network:connection", "high", title, detail)
        except Exception:
            pass
        try:
            from monitor.notify import notify
            notify("Doors AI: Suspicious connection", f"{title} ({c['remote_ip']})", key=sig)
        except Exception:
            pass

    # New-destination detection: first time a program reaches a new server.
    pairs = _current_public_pairs()
    baseline = _load_conn_baseline()
    if baseline is None:
        _save_conn_baseline(pairs)
    else:
        new = pairs - baseline
        if new:
            for pair in list(new)[:10]:
                proc, _, ip = pair.partition("|")
                try:
                    from monitor.events_db import record_event
                    record_event("network:new-destination", "low",
                                 f"{proc or 'A program'} reached a new server for the first time", ip)
                except Exception:
                    pass
            _save_conn_baseline(baseline | pairs)

    try:
        check_arp_spoof()
    except Exception as e:
        print(f"[NETINTEL] ARP check error: {e}")

    try:
        check_exposure_change()
    except Exception as e:
        print(f"[NETINTEL] Exposure check error: {e}")


def check_exposure_change():
    """Alert when a program starts accepting network connections it wasn't before."""
    from monitor.network_monitor import get_network_snapshot
    ports = get_network_snapshot().get("ports", [])
    exposed = {f"{p['port']}|{(p.get('process') or '').lower()}"
               for p in ports if p.get("binding") == "all interfaces"}

    state = _load_net_state()
    if "exposed_ports" not in state:
        state["exposed_ports"] = sorted(exposed)
        _save_net_state(state)
        return

    known = set(state.get("exposed_ports", []))
    new = exposed - known
    if new:
        for item in new:
            port, _, proc = item.partition("|")
            try:
                from monitor.events_db import record_event
                record_event("network:exposure", "high",
                             f"{proc or 'A program'} started accepting network connections",
                             f"Port {port} is now reachable from your network")
            except Exception:
                pass
        state["exposed_ports"] = sorted(known | exposed)
        _save_net_state(state)


# Common remote-access / service ports to check in an opt-in device scan.
SCAN_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 80: "Web", 135: "Windows RPC",
    139: "NetBIOS", 443: "Secure web", 445: "SMB file sharing",
    3389: "Remote Desktop", 5900: "VNC", 8080: "Web (alt)",
}


def scan_host(ip):
    """Opt-in: check one device on your own network for open common ports.

    Active (sends connection attempts) - only ever called from a user click.
    """
    import socket
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"ok": False, "error": "That isn't a valid address."}
    if not (addr.is_private or addr.is_loopback):
        return {"ok": False, "error": "Only devices on your own network can be checked."}

    open_ports = []
    for port, name in SCAN_PORTS.items():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.4)
        try:
            if s.connect_ex((ip, port)) == 0:
                open_ports.append({"port": port, "name": name})
        except Exception:
            pass
        finally:
            s.close()
    return {"ok": True, "ip": ip, "open": open_ports}


def start_connection_monitor_thread():
    def loop():
        while True:
            try:
                check_connections_now()
            except Exception as e:
                print(f"[NETINTEL] Connection monitor error: {e}")
            time.sleep(CONN_POLL_SEC)

    threading.Thread(target=loop, daemon=True).start()


def _domain_suspicious(domain):
    d = domain.lower().rstrip(".")
    for tld in SUSPICIOUS_TLDS:
        if d.endswith(tld):
            return f"Unusual domain ending ({tld})"
    first_label = d.split(".")[0]
    if _RANDOM_LABEL.search(first_label):
        return "Random-looking domain name"
    return ""


def get_dns_cache(limit=150):
    """Read the local DNS resolver cache (ipconfig /displaydns)."""
    now = time.time()
    with _lock:
        if now - _dns_cache["time"] < DNS_TTL_SEC and _dns_cache["records"]:
            return {"records": _dns_cache["records"], "error": _dns_cache["error"]}

    if platform.system() != "Windows":
        return {"records": [], "error": "Windows only"}

    try:
        completed = subprocess.run(
            ["ipconfig", "/displaydns"],
            capture_output=True, text=True, errors="replace", timeout=20,
        )
    except Exception as e:
        return {"records": [], "error": str(e)}

    names = []
    seen = set()
    for line in completed.stdout.splitlines():
        if "Record Name" in line and ":" in line:
            name = line.split(":", 1)[1].strip()
            key = name.lower()
            if name and key not in seen and "." in name:
                seen.add(key)
                names.append(name)

    records = []
    for name in names[:limit]:
        reason = _domain_suspicious(name)
        records.append({"domain": name, "suspicious": bool(reason), "reason": reason})
    records.sort(key=lambda r: not r["suspicious"])

    with _lock:
        _dns_cache.update(time=now, records=records, error=None)
    return {"records": records, "error": None}


def get_firewall_status():
    """Windows Firewall on/off state per profile."""
    if platform.system() != "Windows":
        return {"profiles": [], "error": "Windows only"}
    try:
        completed = subprocess.run(
            ["netsh", "advfirewall", "show", "allprofiles", "state"],
            capture_output=True, text=True, errors="replace", timeout=20,
        )
    except Exception as e:
        return {"profiles": [], "error": str(e)}

    profiles = []
    current = None
    for line in completed.stdout.splitlines():
        low = line.strip().lower()
        if "profile settings" in low:
            current = line.strip().split(" ")[0]
        elif low.startswith("state") and current:
            on = "on" in low
            profiles.append({"name": current, "on": on})
            current = None
    return {"profiles": profiles, "error": None}


def assess_vulnerabilities(network, defender):
    """Combine local signals into plain-language self-exposure findings."""
    from monitor.catalog import describe_port

    findings = []
    fw = get_firewall_status()
    for prof in fw.get("profiles", []):
        if not prof["on"]:
            findings.append({
                "severity": "high",
                "title": f"Firewall is OFF for the {prof['name']} network",
                "what": "Your firewall is the wall that blocks unwanted connections from reaching this PC. With it off, anything on this network can try to reach you directly.",
                "fix": "Turn Windows Firewall back on in Windows Security.",
            })

    seen_ports = set()
    for port in network.get("ports", []):
        if port["severity"] == "high" and port["binding"] != "localhost only" and port["port"] not in seen_ports:
            seen_ports.add(port["port"])
            info = describe_port(port["port"], port.get("process", ""), port.get("service", ""))
            findings.append({
                "severity": "high",
                "title": f"{info['label']} is reachable from your network",
                "what": info["description"],
                "fix": f"Turn off port {port['port']} if you don't use it.",
            })

    if defender and defender.get("available"):
        if not defender.get("antivirus_enabled"):
            findings.append({"severity": "critical", "title": "Windows Defender antivirus is off",
                             "what": "Windows' built-in antivirus is your baseline protection. With it off, known malware can run unchecked.",
                             "fix": "Turn it on in Windows Security."})
        elif not defender.get("realtime_enabled"):
            findings.append({"severity": "high", "title": "Defender real-time protection is off",
                             "what": "Real-time protection is the part of the antivirus that checks files as they open. Without it, threats are only caught during a manual scan.",
                             "fix": "Turn on real-time protection in Windows Security."})

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: order.get(f["severity"], 9))
    return findings


def _load_device_baseline():
    if DEVICE_BASELINE.exists():
        try:
            with open(DEVICE_BASELINE, "r", encoding="utf-8") as f:
                return set(json.load(f))
        except Exception:
            return None
    return None


def _save_device_baseline(macs):
    try:
        with open(DEVICE_BASELINE, "w", encoding="utf-8") as f:
            json.dump(sorted(macs), f, indent=2)
    except Exception as e:
        print(f"[NETINTEL] Could not save device baseline: {e}")


def _human_bytes(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def get_network_activity():
    """System-wide data totals + programs ranked by active connections.

    Per-process byte metering needs a capture driver (see PHASE3.md #8); until
    then, active-connection count is an honest proxy for 'how busy' a program is.
    """
    try:
        io = psutil.net_io_counters()
        total_sent, total_recv = io.bytes_sent, io.bytes_recv
    except Exception:
        total_sent = total_recv = 0

    counts = {}
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.status != psutil.CONN_ESTABLISHED or not c.raddr or not c.pid:
                continue
            try:
                name = psutil.Process(c.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                name = "unknown"
            entry = counts.setdefault(name, {"name": name, "external": 0, "total": 0})
            entry["total"] += 1
            if _is_public(c.raddr.ip):
                entry["external"] += 1
    except Exception:
        pass

    programs = sorted(counts.values(), key=lambda p: (-p["external"], -p["total"]))
    return {
        "total_sent": _human_bytes(total_sent),
        "total_recv": _human_bytes(total_recv),
        "programs": programs[:15],
    }


_hostname_cache = {}
_hostname_pending = set()


def _resolve_hostname_async(ip):
    def worker():
        import socket
        host = ""
        try:
            host = socket.gethostbyaddr(ip)[0]
        except Exception:
            host = ""
        with _lock:
            _hostname_cache[ip] = host
            _hostname_pending.discard(ip)
    with _lock:
        if ip in _hostname_cache or ip in _hostname_pending:
            return
        _hostname_pending.add(ip)
    threading.Thread(target=worker, daemon=True).start()


def _gateway_ip():
    """Best-effort: the .1 of the private subnet is almost always the router."""
    try:
        completed = subprocess.run(["ipconfig"], capture_output=True, text=True,
                                   errors="replace", timeout=10)
        for line in completed.stdout.splitlines():
            if "default gateway" in line.lower() and ":" in line:
                gw = line.split(":", 1)[1].strip()
                if gw and gw.count(".") == 3:
                    return gw
    except Exception:
        pass
    return ""


def enrich_devices(devices):
    """Add a plain-language identity to each device (maker, kind, gateway)."""
    from monitor.catalog import describe_device
    gw = _gateway_ip()
    for d in devices:
        ip = d.get("ip", "")
        info = describe_device(d.get("vendor", ""), ip, is_gateway=(ip == gw))
        d["identity"] = info["kind"]
        d["recognized"] = info["known"]
        d["is_gateway"] = ip == gw
        # Friendly hostname (reverse DNS), resolved in the background and cached.
        d["hostname"] = _hostname_cache.get(ip, "")
        if ip and ip not in _hostname_cache:
            _resolve_hostname_async(ip)
    return devices


def check_new_devices(devices):
    """Return list of devices whose MAC wasn't in the known-network baseline."""
    macs = {d["mac"] for d in devices if d.get("mac")}
    if not macs:
        return []

    known = _load_device_baseline()
    if known is None:
        _save_device_baseline(macs)
        return []

    new = [d for d in devices if d.get("mac") and d["mac"] not in known]
    if new:
        _save_device_baseline(known | macs)
        for d in new:
            label = d.get("vendor") or "Unknown device"
            try:
                from monitor.events_db import record_event
                record_event("network:new-device", "medium",
                             f"New device on your network: {label}",
                             f"{d['ip']} ({d['mac']})")
            except Exception:
                pass
    return new


def reset_device_baseline():
    try:
        if DEVICE_BASELINE.exists():
            DEVICE_BASELINE.unlink()
        return True
    except Exception:
        return False
