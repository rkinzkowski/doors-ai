# Doors AI — Improvement Proposals

Ideas beyond the original Phase 1–5 roadmap, written for you to review and
pick from. Each entry says **what it is**, **why it's worth it**, and a rough
**effort** (S / M / L). Nothing here is started — it's a menu, not a plan.

I've grouped them and put my honest top recommendations first.

---

## ⭐ Top picks (most value for the effort)

### 1. Incident correlation — turn 6 tables into 1 story  · effort M
Right now each guard reports into its own table. Real attacks touch several at
once: a file lands in Downloads → a new program runs → it adds a startup entry,
all within a minute. Today you'd see three unrelated rows in three sections.

**The idea:** a correlation layer that groups alerts sharing a time window and
a common thread (same file, same program, same address) into a single
**Incident** with a timeline. One line — "Suspicious download launched a program
that added itself to startup" — instead of three clues you have to connect
yourself. This is the concrete version of the "attack chain correlation" you
listed for later, and it's the single biggest usability win available.

### 2. Move from CSV files to a local SQLite database  · effort M
The threat list just hit 16,000 rows, and every sign-in check scans that whole
file. CSVs also make history and trends painful (we archive and rotate them by
hand). SQLite is one file, no server, already built into Python — it gives you
instant indexed lookups, real history that survives rotation, and the ability
to ask questions like "alerts per day this month." **This one quietly unlocks
several ideas below (trends, reports, correlation at scale).** Worth doing early
before more features pile onto the CSV approach.

### 3. Desktop notifications for serious alerts  · effort S
The dashboard only helps when you're looking at it. A ransomware canary trip or
a critical process alert should reach you immediately. **The idea:** a Windows
toast notification (and optionally a tray icon) the moment a high/critical alert
fires, so Doors AI protects you in the background instead of needing a babysitter.

### 4. Harden the dashboard itself  · effort S–M
This is a security tool that can terminate programs, block addresses, and delete
files — but any web page open in your browser could quietly POST those commands
to `localhost:5000` (there's no request-forgery protection), and there's no
login. **The idea:** add CSRF tokens to the action buttons, an optional
passphrase lock, and keep it firmly bound to localhost. A security app should be
the hardest thing on the machine to abuse, not the easiest.

---

## Detection depth

### 5. MITRE ATT&CK tagging  · effort S–M
Tag each detection with its ATT&CK technique (e.g. "T1547 – Registry Run Key",
"T1486 – Data Encrypted for Impact"). Turns a list of alerts into a recognizable
attack narrative, and is the shared language real security teams use. Mostly a
mapping table over detections you already have.

### 6. VirusTotal enrichment (opt-in)  · effort S
When a file or hash is flagged, look it up on VirusTotal's free API and show how
many of ~70 engines call it malicious. **Only the fingerprint is sent, never the
file** — low privacy cost, high confidence gain. Needs your own free API key,
same pattern as the MalwareBazaar key.

### 7. More abuse.ch feeds  · effort S
You're already set up for abuse.ch. With the same Auth-Key you could add
**URLhaus** (malicious URLs) and **Feodo Tracker** (botnet command-and-control
IPs). Small additions that widen coverage a lot.

### 8. Windows Defender as a second opinion  · effort S
Surface Defender's own detections (via `Get-MpThreatDetection`) inside the
dashboard, so Doors AI complements the built-in protection instead of ignoring
it. One unified view of everything flagging on the machine.

### 9. Publisher allow/deny list for signed programs  · effort S
Signed ≠ trustworthy — the game trainers in your Downloads pass on valid
signatures. Let a trusted publisher list decide, and optionally flag programs
signed by publishers you've never approved.

---

## Response & resilience

### 10. Neutralize quarantined files  · effort S
Quarantine currently just *moves* a file — a determined program could still run
it from the quarantine folder. Store quarantined files scrambled (e.g. renamed
and byte-flipped) so they physically can't execute until you deliberately
restore them. A meaningful safety upgrade for very little code.

### 11. Scheduled scans & auto-refreshing feeds  · effort S
Refresh the threat feeds on a schedule (respecting each source's update cadence)
and run a full watched-folder scan on a timer, so protection stays current
without you clicking Update.

---

## Insight & reporting

### 12. Trend charts & score history  · effort M *(needs #2)*
Plot the security score over time and alerts per day, so you can see whether your
posture is improving or something's escalating. Natural once data lives in SQLite.

### 13. Weekly security report  · effort S–M *(pairs with #2)*
A one-page "here's your week" summary — what got blocked, what needs attention,
score trend — viewable in the dashboard or exported as a PDF/HTML file.

---

## Onboarding & polish

### 14. First-run setup wizard  · effort S
A short guided setup on first launch: pick folders to protect, establish the
system baseline, explain each guard in a sentence. Makes it approachable for
someone who isn't you.

---

## My suggested order

If it were mine, I'd do **#3 (notifications)** and **#4 (hardening)** first —
they're quick and close real gaps — then **#2 (SQLite)** as the foundation, then
**#1 (incident correlation)** as the flagship feature, enriching along the way
with **#5 (MITRE)** and **#6 (VirusTotal)**. Everything else slots in behind that.

Tell me which ones speak to you and I'll flesh them out.
