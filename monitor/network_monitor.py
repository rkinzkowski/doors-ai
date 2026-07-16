"""Local network visibility — Phase 3 starting point.

Everything here is a passive read of local state: the OS ARP cache for
device discovery and this machine's own listening sockets for attack
surface. No packets are sent, nothing is scanned, nothing is downloaded —
no DNS lookups either.
"""

import re
import subprocess
import threading
import time

import psutil

CACHE_TTL_SEC = 30

# Ports worth a second look when they are open on a personal machine.
REVIEW_PORTS = {
    21: ("FTP", "high"),
    22: ("SSH", "medium"),
    23: ("Telnet", "high"),
    135: ("Windows RPC", "medium"),
    139: ("NetBIOS", "medium"),
    445: ("SMB file sharing", "high"),
    1433: ("MS SQL", "medium"),
    3306: ("MySQL", "medium"),
    3389: ("Remote Desktop", "high"),
    5432: ("PostgreSQL", "medium"),
    5900: ("VNC remote control", "high"),
    5985: ("WinRM", "high"),
    5986: ("WinRM TLS", "medium"),
}

_ARP_ROW = re.compile(
    r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F-]{17})\s+(\w+)", re.MULTILINE
)

_lock = threading.Lock()
_cache = {"time": 0, "devices": [], "ports": [], "error": None}


def _is_noise_address(ip, mac):
    if mac.lower() == "ff-ff-ff-ff-ff-ff":
        return True
    first_octet = int(ip.split(".")[0])
    if 224 <= first_octet <= 239 or first_octet == 255:
        return True
    if ip.endswith(".255"):
        return True
    return False


def _collect_devices():
    """Parse the OS ARP cache — devices this machine has recently talked to."""
    try:
        completed = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=15,
        )
    except Exception as e:
        return [], f"arp query failed: {e}"

    devices = []
    seen = set()

    for match in _ARP_ROW.finditer(completed.stdout or ""):
        ip, mac, entry_type = match.groups()
        mac = mac.lower()

        if _is_noise_address(ip, mac) or ip in seen:
            continue
        seen.add(ip)

        devices.append({
            "ip": ip,
            "mac": mac,
            "type": entry_type.lower(),
        })

    devices.sort(key=lambda d: tuple(int(part) for part in d["ip"].split(".")))
    return devices, None


def _collect_listening_ports():
    """This machine's own listening sockets and the processes behind them."""
    ports = []
    seen = set()

    try:
        connections = psutil.net_connections(kind="inet")
    except Exception as e:
        return [], f"socket enumeration failed: {e}"

    for conn in connections:
        if conn.status != psutil.CONN_LISTEN or not conn.laddr:
            continue

        port = conn.laddr.port
        address = conn.laddr.ip
        key = (address, port)
        if key in seen:
            continue
        seen.add(key)

        process_name = ""
        exe_path = ""
        if conn.pid:
            try:
                proc = psutil.Process(conn.pid)
                process_name = proc.name()
                exe_path = proc.exe() or ""
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        service, severity = REVIEW_PORTS.get(port, ("", "low"))

        loopback = address in ("127.0.0.1", "::1")
        if address in ("0.0.0.0", "::"):
            binding = "all interfaces"
        elif loopback:
            binding = "localhost only"
        else:
            binding = "LAN interface"

        # A review-list port reachable only from this machine is less concerning.
        if severity != "low" and loopback:
            severity = "medium" if severity == "high" else "low"

        ports.append({
            "port": port,
            "address": address,
            "binding": binding,
            "pid": conn.pid or "",
            "process": process_name,
            "exe": exe_path,
            "service": service,
            "severity": severity,
        })

    ports.sort(key=lambda p: (p["severity"] != "high", p["severity"] != "medium", p["port"]))
    return ports, None


def get_network_snapshot():
    """Cached snapshot so dashboard refreshes stay fast."""
    now = time.time()

    with _lock:
        if now - _cache["time"] < CACHE_TTL_SEC:
            return {
                "devices": _cache["devices"],
                "ports": _cache["ports"],
                "error": _cache["error"],
            }

    devices, device_error = _collect_devices()
    ports, port_error = _collect_listening_ports()
    error = device_error or port_error

    with _lock:
        _cache.update({
            "time": now,
            "devices": devices,
            "ports": ports,
            "error": error,
        })

    return {"devices": devices, "ports": ports, "error": error}
