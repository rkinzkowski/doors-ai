# Phase 3 — Network Security: plan + improvements

Same format as [IMPROVEMENTS.md](IMPROVEMENTS.md): what it is, why, effort
(S/M/L), and status. Everything built stays **local and passive** — no active
intrusion, no downloads, nothing malicious saved to disk (per your standing
rule). Anything that would send packets to other machines is opt-in and marked.

---

## Roadmap Phase 3 items

| Item | Status | Notes |
|---|---|---|
| Device discovery | ✅ **Built + enhanced** | ARP inventory, now with maker (MAC vendor) + new-device alerts |
| Traffic monitoring | ✅ **Built (passive)** | Active connections cross-checked against your threat list; full packet capture is proposed below |
| DNS analysis | ✅ **Built** | Reads the local DNS cache, flags suspicious domains |
| Threat-intel integration | ✅ **Built** | Connections + DNS checked against IPsum/Feodo/manual threat list |
| Vulnerability assessment | ✅ **Built** | "Weak Spots" self-check (firewall, exposed ports, Defender) feeding the score |
| Port scanning | ✅ **Built (opt-in)** | Your own ports done; opt-in check of one device on your network added |
| VPN/proxy detection | ✅ **Built (opt-in)** | Optional ISP/proxy/hosting lookup for flagged addresses |

**Improvement proposals #1–#7 and #9 are now built.** #8 (packet capture) is
parked — see below. The proposals section is kept for reference.

---

## New improvement proposals (beyond the roadmap)

### ⭐ Top picks

**1. Connection baseline + "new remote server" alerts · M**
Learn which external servers your programs normally talk to, then flag the
*first* time a program reaches a brand-new destination — the network version of
the startup-baseline that already works well. Catches quiet data exfil and
new malware callbacks even when the address isn't on any blocklist yet.

**2. ARP-spoofing / fake-gateway detection · S**
Watch for your router's address suddenly showing a different hardware ID — the
signature of a man-in-the-middle attack on your Wi-Fi. Pure local ARP reading.

**3. Per-program data usage · M**
Show how much each program is sending/receiving. A backup tool using lots of
upload is normal; an unknown process doing the same is a red flag for data theft.

### Solid additions

**4. Opt-in LAN port scan · M** *(active — needs your click)*
On demand, check a device on *your own* network for open remote-access ports
(RDP, VNC, SSH). Clearly gated behind a confirm, scoped to your subnet, never
automatic — it does send packets, so it stays your decision.

**5. Reverse-DNS / hostnames for devices · S**
Resolve friendly names for the devices on your network so "192.168.1.42"
becomes "kitchen-echo," making unknown devices easier to spot.

**6. Live VPN/proxy enrichment · S** *(opt-in network call)*
Optionally check flagged IPs against a hosting/proxy signal, so you can tell a
home user apart from a data-center relay. Off by default.

**7. Scheduled external-exposure test · M** *(opt-in)*
Periodically confirm nothing on your PC is actually reachable from the public
internet (not just the LAN), and alert if that changes.

### Bigger / later

**8. Full packet-level traffic monitoring · L — PARKED**
Deep inspection of actual traffic (not just connection endpoints), including
true per-program byte metering. Evaluated 2026-07-17: this requires a packet
capture driver (Npcap) — a download plus an admin-level install — which your
"nothing installed until we can protect against everything" rule keeps parked.
Everything else in Phase 3 was built without it. Green-light the Npcap install
whenever you want this and it becomes a quick add.

**9. Auto-contain a bad connection · M**
One-click (or automatic) firewall block of a program caught talking to a known
command-server, plus killing the process. Builds on the existing block/terminate
actions.

---

## Suggested order
Connection baseline (#1) and ARP-spoof detection (#2) are the highest-value,
lowest-friction next steps and both stay fully passive. Per-program data usage
(#3) pairs naturally with #1. The opt-in scan (#4) and exposure test (#7) come
after, once you decide how much active probing you want on your own network.
