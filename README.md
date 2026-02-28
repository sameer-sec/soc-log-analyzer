# 🛡️ SOC Log Analyzer & Anomaly Detector

> **Google Cybersecurity Certificate Portfolio Project**  
> Demonstrates: Detection & Response · Python automation · SQL · MITRE ATT&CK · AI-assisted analysis

---

## What It Does

This tool ingests real-world log formats, parses them with Python, detects suspicious patterns using SOC-grade rules, stores findings in SQLite, generates HTML + text reports, and optionally calls the **Google Gemini API** for natural-language threat explanations — exactly like a real SOC analyst would.

```
logs/  →  parse  →  detect  →  SQLite  →  HTML/Text report  →  (email)
                        ↓
                   Gemini AI  →  MITRE ATT&CK explanation
```

---

## Detection Rules (MITRE ATT&CK Mapped)

| Rule | Severity | MITRE Tactic | Technique |
|------|----------|-------------|-----------|
| Brute Force Login (≥5 failures/min) | HIGH | TA0006 Credential Access | T1110.001 |
| Reconnaissance / Directory Scan | MEDIUM | TA0043 Reconnaissance | T1595.003 |
| SQL Injection Attempt | CRITICAL | TA0001 Initial Access | T1190 |
| Path Traversal | HIGH | TA0001 Initial Access | T1190 |
| Reverse Shell / RCE Command | CRITICAL | TA0002 Execution | T1059.004 |
| Backdoor Account (UID=0) | CRITICAL | TA0003 Persistence | T1136.001 |
| Encoded PowerShell (-enc) | HIGH | TA0002 Execution | T1059.001 |
| Windows Event 1102: Log Cleared | CRITICAL | TA0005 Defense Evasion | T1070.001 |
| Windows Event 7045: New Service | HIGH | TA0003 Persistence | T1543.003 |
| Windows Event 4698: Sched. Task | HIGH | TA0003 Persistence | T1053.005 |
| Windows Event 4720/4732: Account | MEDIUM | TA0003/TA0004 | T1136.001 |

---

## Supported Log Formats

- **Apache** access logs (`access.log`)
- **Linux** auth logs (`auth.log`) — SSH, sudo, PAM
- **Windows** Event Logs (CSV export format)

---

## Quick Start

### 1. Install dependencies
```bash
pip install pandas
```

### 2. Run on sample logs
```bash
python main.py
```

### 3. With AI analysis (Gemini)
```bash
export GEMINI_API_KEY=your_api_key_here
python main.py --ai
```
Get your free API key at: https://aistudio.google.com/apikey

### 4. Full pipeline (AI + email)
```bash
export GEMINI_API_KEY=your_key
export SMTP_USER=you@gmail.com
export SMTP_PASSWORD=your_app_password
export ALERT_FROM=you@gmail.com
export ALERT_TO=soc-team@company.com

python main.py --ai --email
```

### 5. Scan your own logs
```bash
python main.py --logs /var/log/apache2/
python main.py --logs /var/log/auth.log
```

---

## CLI Options

```
--logs PATH      Log file or directory to scan (default: logs/samples/)
--ai             Enable Gemini AI analysis for top CRITICAL/HIGH alerts
--email          Send email notification via SMTP
--max-ai N       Max alerts to analyze with AI (default: 5)
--output DIR     Report output directory (default: reports/)
```

---

## Project Structure

```
log-analyzer/
├── main.py                  # CLI entry point
├── requirements.txt
├── config.json.example      # Email config template
├── src/
│   ├── parsers.py           # Apache / auth.log / Windows CSV parsers
│   ├── detectors.py         # All detection rules (regex + pandas)
│   ├── database.py          # SQLite storage layer
│   ├── ai_analyzer.py       # Gemini API integration
│   ├── reporter.py          # HTML + text report generator
│   └── notifier.py          # SMTP email alerts
├── logs/
│   └── samples/
│       ├── apache_access.log
│       ├── auth.log
│       └── windows_events.csv
├── db/
│   └── alerts.db            # SQLite database (auto-created)
└── reports/
    └── report_TIMESTAMP.html
```

---

## AI Analysis (Google Gemini)

When `--ai` is enabled, CRITICAL and HIGH alerts are sent to Gemini with this prompt:

> *"Analyze this log line as a SOC analyst and map it to MITRE ATT&CK if possible."*

The response includes:
- Plain-English explanation of what the attacker is doing
- Severity assessment with justification
- MITRE ATT&CK tactic + technique mapping
- 3 recommended SOC response actions
- False positive considerations

---

## Sample Output

```
[CRITICAL] ALERT-0008 — Backdoor Account Created (UID=0)
  MITRE   : TA0003 - Persistence
  Technique: T1136.001 - Create Local Account
  Detail  : New user with UID=0 (root-equivalent) created
  Time    : 2025-01-15 10:06:00

[HIGH] ALERT-0001 — Brute Force Login Attempt
  MITRE   : TA0006 - Credential Access
  Technique: T1110.001 - Password Guessing
  Detail  : IP 10.0.0.55 had 6 failed logins within 1 minute(s)
  IP      : 10.0.0.55
```

---

## Extending the Tool

- **Add new log formats**: Create a parser function in `src/parsers.py`
- **Add detection rules**: Add a function in `src/detectors.py` and register it in `run_all_detections()`
- **Dashboard**: Connect `db/alerts.db` to Grafana or build a Flask web UI
- **Real-time mode**: Add `--watch` flag using `watchdog` library for live log tailing
- **Threat intel**: Cross-reference `source_ip` against AbuseIPDB or VirusTotal APIs
