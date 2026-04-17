# LTHT — Linux Threat Hunt Toolkit

Automated Linux log analyzer with MITRE ATT&CK mapping. Parses auth.log, syslog, bash_history, and cron logs to detect brute force attacks, privilege escalation, reverse shells, persistence mechanisms, and more.

## Features
- Log Parsing — 4 Linux log formats with regex-based pattern matching
- 9 Detection Rules — Brute force, priv esc, reverse shells, recon, persistence, log tampering, exfil, firewall tampering
- MITRE ATT&CK Mapping — 17+ techniques across 10 tactics
- Risk Scoring — Each finding scored 0-100
- Professional Reports — HTML and JSON with executive summary
- Zero Dependencies — Pure Python 3

## Quick Start
git clone https://github.com/Sh8rlock/LTHT.git
cd LTHT
python run_hunt.py --log-dir sample_logs/

## Author
Larry Odeyemi — Cybersecurity & Cloud Infrastructure Engineer
