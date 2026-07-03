# Doors AI

**An ML-powered endpoint threat detection dashboard that watches logins, files, and running processes from one place.**

<!-- TODO: add a dashboard screenshot here -->
<!-- ![Doors AI dashboard](docs/dashboard.png) -->

---

## Overview

Doors AI is a self-hosted security monitoring tool with a Flask dashboard that unifies three independent detection engines — login anomaly detection, file malware scanning, and live process monitoring. Each engine reports to a single dashboard where you can review alerts, whitelist known-good items, run manual scans, and optionally block offending IPs at the firewall.

Built as a hands-on project to explore how classic security signals and machine learning combine in practice.

## Detection engines

**1. Login anomaly detection**
Trains an Isolation Forest (scikit-learn) over login attempt counts, location, and user agent to flag unusual sign-ins. Each IP is enriched with:
- Geolocation lookup (ipinfo.io)
- VPN/proxy detection from both a local list and a live API (ip-api.com)
- A local threat-intelligence score from a maintained threat list

An IP is flagged if the model marks it anomalous, it resolves to a VPN/proxy, or its threat score crosses a threshold. Flagged IPs can be auto-blocked via the OS firewall (`netsh` on Windows, `iptables` on Linux) when enabled.

**2. File malware scanner**
Watches configured folders for files, computes a SHA-256 hash of each, and checks it against a known-malware hash set. Unknown files are classified by a Random Forest trained on file features — size, byte entropy, unique-byte count, and ASCII ratio. Verdicts and reasons are logged.

**3. Process monitor**
Runs in a background thread (psutil), scanning live processes every 30 seconds. Matches process names and command lines against fileless-malware indicators: known offensive tooling and suspicious patterns such as encoded PowerShell, `-enc`, `DownloadString`, obfuscation, and LOLBins like `rundll32` / `regsvr32`. Supports a whitelist and one-click process termination.

## Tech stack

- **Language:** Python
- **Web:** Flask
- **ML / data:** scikit-learn, pandas, numpy, joblib
- **System / network:** psutil, requests, watchdog, iso3166

## Getting started

```bash
# 1. Clone
git clone https://github.com/rkinzkowski/doors-ai.git
cd doors-ai

# 2. Create a virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. (Optional) Create local files from the examples. The app auto-creates
#    sensible defaults on first run, so copy these only to customize or demo.
#    (Windows: use `copy` instead of `cp`)
cp scanner_config.example.json scanner_config.json    # set your own watch folder
cp malware_hashes.example.csv malware_hashes.csv      # seed the known-bad hash list
cp threat_list.example.csv threat_list.csv            # demo threat-intel data

# 5. Train the starter model (creates scanner/models/rf_model.pkl)
python train_model.py

# 6. Run the full system (dashboard + real-time folder watcher)
python run.py

#    Or just the dashboard (manual scans + process monitor, no live watcher)
python app.py
```

Then open `http://localhost:5000`.

### Configuration

- Watch folders and scan options live in `scanner_config.json` (created from the example above).
- Auto-blocking is **off by default**. Enable it with the environment variable `DOORS_AUTO_BLOCK_IPS=1` (requires firewall privileges). See `.env.example`.
- Log files (`logs.csv`, `scanner_logs.csv`, `process_logs.csv`) are created automatically on first run. Use the dashboard's simulate button to generate demo login data.
- Files the scanner flags are moved to `scanner/quarantine/` (gitignored, so real quarantined files never get committed).

## Note

This is a learning project, not production security software. The ML is intentionally simple — the Random Forest trains on a small sample feature set and the Isolation Forest is fit per run — so the detections are illustrative rather than authoritative. Built for defensive, educational use on systems you own.

## License

MIT <!-- TODO: add a LICENSE file if you want this -->
<img width="2483" height="1184" alt="image" src="https://github.com/user-attachments/assets/97fa79a7-8da8-4e72-865f-14f123410a60" />
<img width="2484" height="1108" alt="image" src="https://github.com/user-attachments/assets/ab263274-ab50-4ebb-b8b3-4250a86510d8" />
