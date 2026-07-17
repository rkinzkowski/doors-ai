"""Plain-language explanations for the things Doors AI shows.

Turns technical items (port numbers, process names, scheduled-task strings,
device makers) into sentences an ordinary person can read. When something
isn't recognized it's reported as such rather than guessed at - and an
unrecognized item is itself worth a look, which the UI reflects.
"""

import re

# --- Ports -----------------------------------------------------------------
# port -> (friendly name, what it is / why it matters)
PORT_CATALOG = {
    21: ("FTP", "An old way to transfer files. Rarely needed today and not encrypted - risky if open."),
    22: ("SSH", "Remote command-line access, common on Linux/Mac and dev tools."),
    23: ("Telnet", "A very old remote-access method with no encryption. Should almost never be open."),
    135: ("Windows RPC", "A core Windows service that lets programs talk to each other. Normal on Windows, but shouldn't be reachable from the wider internet."),
    139: ("NetBIOS", "Older Windows file/printer sharing. Legacy - usually safe on a home network but not needed from outside."),
    445: ("SMB file sharing", "Lets other computers open shared files and printers on this PC. Useful in an office, but it's the #1 way ransomware spreads between machines - turn it off if you don't share files."),
    1433: ("Microsoft SQL Server", "A database server. Only expected if you run database software."),
    3306: ("MySQL", "A database server. Only expected if you run database software."),
    3389: ("Remote Desktop (RDP)", "Lets someone control this PC's full desktop from elsewhere. Powerful and heavily targeted by attackers - keep it off unless you deliberately use it."),
    5432: ("PostgreSQL", "A database server. Only expected if you run database software."),
    5900: ("VNC", "Remote screen-sharing/control. Keep it off unless you use it on purpose."),
    5985: ("WinRM", "Windows remote management. Powerful; shouldn't be open to the network unless you manage this PC remotely."),
    5986: ("WinRM (secure)", "Encrypted Windows remote management."),
    3702: ("Device discovery", "Windows uses this to find nearby printers and shared devices."),
    5040: ("Windows network discovery", "Helps Windows find other devices on your network."),
    5353: ("Local device discovery (mDNS)", "How your PC finds printers, speakers, and Chromecasts on the network."),
    1900: ("UPnP", "Lets apps and smart devices auto-open network paths. Convenient but can widen your exposure."),
}

# --- Processes -------------------------------------------------------------
# lowercased exe name -> plain description
PROCESS_CATALOG = {
    "system": "The core of Windows itself (the kernel). Always running - you can't and shouldn't stop it.",
    "system idle process": "Not a real program - it's how Windows shows unused processor time.",
    "svchost.exe": "A shared Windows helper that runs many background services. Normal - but because it's so common, malware sometimes copies its name, so the folder it runs from matters.",
    "services.exe": "The Windows service manager. Core system program.",
    "lsass.exe": "Handles Windows sign-ins and passwords. Core system program - a frequent target, so anything imitating it is serious.",
    "wininit.exe": "Starts up core Windows services at boot. Core system program.",
    "winlogon.exe": "Manages signing in and out of Windows. Core system program.",
    "csrss.exe": "A core Windows system process. Always running.",
    "smss.exe": "The Windows session starter. Core system program.",
    "spoolsv.exe": "The Windows print service. Normal if you use printers.",
    "explorer.exe": "The Windows desktop, taskbar, and file browser. Normal.",
    "dwm.exe": "Draws the Windows desktop and window effects. Normal.",
    "conhost.exe": "The window that hosts command-line programs. Normal.",
    "runtimebroker.exe": "Manages permissions for Windows Store apps. Normal.",
    "taskhostw.exe": "Runs background Windows tasks. Normal.",
    "dllhost.exe": "Hosts small Windows components. Normal, but occasionally misused - check its location if unsure.",
    "searchindexer.exe": "Builds the index that makes Windows search fast. Normal.",
    "ctfmon.exe": "Handles keyboard input and languages. Normal.",
    "fontdrvhost.exe": "Loads fonts for the display. Normal.",
    "python.exe": "The Python programming language. Doors AI itself runs on Python, so on port 5000 this is almost certainly Doors AI.",
    "pythonw.exe": "A Python program running without a window.",
    "node.exe": "Node.js - runs apps and local development servers built with web technology. Common with coding tools and many desktop apps (Discord, VS Code, etc.).",
    "discord.exe": "The Discord chat and voice app.",
    "steam.exe": "The Steam game store and launcher.",
    "steamwebhelper.exe": "The web/browser part of the Steam app.",
    "epicgameslauncher.exe": "The Epic Games store and launcher.",
    "chrome.exe": "The Google Chrome web browser.",
    "msedge.exe": "The Microsoft Edge web browser.",
    "firefox.exe": "The Mozilla Firefox web browser.",
    "brave.exe": "The Brave web browser.",
    "code.exe": "Visual Studio Code, a popular code editor.",
    "onedrive.exe": "Microsoft OneDrive cloud file sync.",
    "onedrive.sync.service.exe": "The background part of OneDrive cloud sync.",
    "teams.exe": "Microsoft Teams chat and meetings.",
    "spotify.exe": "The Spotify music app.",
    "lghub.exe": "Logitech G HUB, for Logitech mice/keyboards/headsets.",
    "lghub_updater.exe": "The updater for Logitech G HUB.",
    "nvcontainer.exe": "Part of NVIDIA graphics driver software.",
    "radeonsoftware.exe": "AMD Radeon graphics control software.",
    "wrwtssvc.exe": "Wondershare software helper (from a Wondershare app you've installed).",
    "msmpeng.exe": "Windows Defender's antivirus engine. This is your built-in protection working.",
    "securityhealthservice.exe": "The Windows Security app's background service.",
}


def describe_port(port, process="", service=""):
    """Return {label, description, known} for a listening port."""
    proc = (process or "").strip()
    if port in PORT_CATALOG:
        label, desc = PORT_CATALOG[port]
        return {"label": label, "description": desc, "known": True}

    pinfo = describe_process(proc)
    if pinfo["known"]:
        return {"label": service or proc or f"Port {port}",
                "description": f"{pinfo['description']} It's listening on port {port}.",
                "known": True}

    return {
        "label": service or (proc or f"Port {port}"),
        "description": (
            f"Port {port} is open, held by "
            f"{proc or 'an unrecognized program'}. Doors AI doesn't recognize this one - "
            "if you don't know why it's here, it's worth looking up or shutting down."
        ),
        "known": False,
    }


def describe_process(name):
    """Return {description, known} for a process name."""
    key = (name or "").strip().lower()
    if key in PROCESS_CATALOG:
        return {"description": PROCESS_CATALOG[key], "known": True}
    if not key:
        return {"description": "No program name was available for this item.", "known": False}
    return {
        "description": (
            f"'{name}' isn't in Doors AI's list of known programs. That doesn't mean it's bad - "
            "lots of legitimate apps aren't listed - but if you don't recognize the name, it's worth "
            "searching it online before trusting it."
        ),
        "known": False,
    }


# --- Scheduled tasks / registry / startup ----------------------------------
_SID = re.compile(r"S-\d-\d+(?:-\d+)+")
_GUID = re.compile(r"\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?")
_LONGNUM = re.compile(r"-?\d{6,}")

_CATEGORY_PLAIN = {
    "registry": ("startup program",
                 "A program set to launch automatically when Windows starts (via the registry). Malware loves this spot because it runs every time you turn on your PC."),
    "startup": ("startup item",
                "A program in your Startup folder that launches automatically when you sign in."),
    "task": ("scheduled task",
             "A job Windows runs automatically - on a timer, at sign-in, or when something happens. Legitimate apps use these, but so does malware to keep coming back."),
    "service": ("background service",
                "A program that runs in the background, often before you even sign in. Core to Windows, but a place attackers try to hide."),
    "ransomware": ("ransomware warning",
                   "A sign that something may be trying to encrypt or tamper with your files. Treat as urgent."),
}


def clean_change_name(raw):
    """Strip SIDs, GUIDs, and long numbers from a task/registry path into a readable name."""
    text = str(raw or "")
    text = _SID.sub("", text)
    text = _GUID.sub("", text)
    text = _LONGNUM.sub("", text)
    parts = [p.strip(" -") for p in re.split(r"[\\/]", text) if p.strip(" -")]
    # Keep the most descriptive trailing pieces, drop empties/dupes.
    seen, keep = set(), []
    for p in parts:
        low = p.lower()
        if low and low not in seen:
            seen.add(low)
            keep.append(p)
    return " -> ".join(keep[-3:]) if keep else "(unnamed)"


def describe_endpoint_change(category, name, detail=""):
    """Return {clean_name, what, recognized} for a system-change row."""
    kind, blurb = _CATEGORY_PLAIN.get(category.split(":")[-1] if category else "",
                                      ("system change", "Something in how your PC starts up or runs changed."))
    readable = clean_change_name(name)
    known_proc = describe_process(_guess_exe(name + " " + detail))["known"]
    return {
        "clean_name": readable,
        "kind": kind,
        "what": blurb,
        "recognized": known_proc,
    }


def _guess_exe(text):
    m = re.search(r"([\w.-]+\.exe)", text or "", re.IGNORECASE)
    return m.group(1) if m else ""


# --- Devices ---------------------------------------------------------------
_VENDOR_KIND = {
    "philips hue": "a smart light or its hub",
    "google": "a Google device (Nest, Chromecast, or Home speaker)",
    "google nest": "a Google Nest device (speaker, display, or thermostat)",
    "amazon": "an Amazon device (Echo, Fire TV, or Kindle)",
    "roku": "a Roku streaming device",
    "sonos": "a Sonos speaker",
    "raspberry pi": "a Raspberry Pi mini-computer",
    "espressif (iot)": "a small smart-home / IoT gadget",
    "apple": "an Apple device (iPhone, iPad, Mac, or Apple TV)",
    "samsung": "a Samsung device (phone, TV, or appliance)",
    "tp-link": "a TP-Link router, extender, or smart plug",
    "ubiquiti": "Ubiquiti networking gear (router or access point)",
    "vmware": "a VMware virtual machine",
    "virtualbox": "a VirtualBox virtual machine",
    "parallels": "a Parallels virtual machine",
}


def describe_device(vendor, ip, is_gateway=False):
    """Return {kind, known} describing a network device in plain terms."""
    if is_gateway:
        return {"kind": "Your router / gateway (how this network reaches the internet)", "known": True}
    v = (vendor or "").strip().lower()
    if v in _VENDOR_KIND:
        return {"kind": f"Likely {_VENDOR_KIND[v]}", "known": True}
    if vendor:
        return {"kind": f"A device made by {vendor}", "known": True}
    return {
        "kind": "Unrecognized device - if you don't know what this is, it's worth identifying (check what's connected to your Wi-Fi).",
        "known": False,
    }
