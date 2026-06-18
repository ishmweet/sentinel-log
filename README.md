# SentinelLog

**Professional terminal-based security log analyzer for cybersecurity students and aspiring SOC analysts.**

SentinelLog parses authentication logs and Apache access logs, detects suspicious activity using rule-based threat intelligence, and generates reports in the terminal, CSV, or JSON — all from the command line with zero external dependencies beyond `rich`.

```
  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗      ██████╗  ██████╗
  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     ██╔═══██╗██╔════╝
  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     ██║   ██║██║  ███╗
  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     ██║   ██║██║   ██║
  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗╚██████╔╝╚██████╔╝
  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝ ╚═════╝  ╚═════╝
```

---

## Features

- **Auto-detect log type** — drop any auth or Apache log in; SentinelLog figures out the format
- **Brute-force detection** — flags IPs with ≥ 5 failed login attempts, severity scales with count
- **Admin panel scanning detection** — catches recon against `/admin`, `/administrator`, etc.
- **WordPress reconnaissance detection** — `/wp-login.php`, `/wp-admin`, `xmlrpc.php`
- **Sensitive file probing** — `.env`, `config.*`, `phpmyadmin`, `.git`, backup archives, DB dumps
- **SQL injection probe detection** — UNION SELECT, OR 1=1, and other common SQLi patterns
- **Rich SOC-style terminal dashboard** — severity-coloured alert tables, statistics, threat overview
- **CSV export** — timestamped reports ready to open in Excel or grep
- **JSON export** — structured output for feeding into SIEM pipelines or scripts
- **Modular architecture** — parser / detector / analyzer / reporter are all independent modules

---

## Project Structure

```
sentinellog/
├── logs/
│   ├── sample_auth.log        # sample SSH / auth log with brute-force scenarios
│   └── sample_apache.log      # sample Apache log with recon and injection attempts
├── reports/                   # exported CSV / JSON reports land here
├── sentinellog/
│   ├── __init__.py
│   ├── analyzer.py            # orchestration: parse → stats → detect → result
│   ├── parser.py              # auth log parser + Apache Combined Log parser
│   ├── detector.py            # threat detection rules
│   ├── reporter.py            # Rich terminal UI + CSV/JSON export
│   └── utils.py               # Alert dataclass, severity levels, shared helpers
├── main.py                    # CLI entry point (argparse)
├── requirements.txt
├── README.md
└── .gitignore
```

---

## Installation

```bash
git clone https://github.com/yourname/sentinellog.git
cd sentinellog
pip install -r requirements.txt
```

Python 3.12+ is recommended. The only runtime dependency is `rich`.

---

## Usage

### Analyze an auth log

```bash
python3 main.py --file logs/sample_auth.log
```

### Analyze an Apache access log

```bash
python3 main.py --file logs/sample_apache.log
```

### Export to CSV

```bash
python3 main.py --file logs/sample_auth.log --export csv
```

The report lands in `reports/sentinellog_auth_YYYYMMDD_HHMMSS.csv`.

### Export to JSON

```bash
python3 main.py --file logs/sample_apache.log --export json
```

### Custom output directory

```bash
python3 main.py --file logs/sample_auth.log --export csv --output /tmp/my-reports/
```

### Suppress the banner (useful for piping)

```bash
python3 main.py --file logs/sample_auth.log --no-banner
```

### Quiet mode (export only, no terminal output)

```bash
python3 main.py --file logs/sample_auth.log --export json --quiet
```

---

## Detection Rules

| Rule | Log Type | Trigger | Severity |
|------|----------|---------|----------|
| Brute Force | auth | ≥ 5 failed logins from one IP | MEDIUM → HIGH → CRITICAL |
| Admin Panel Scan | apache | Requests to `/admin*`, `/administrator*` | MEDIUM / HIGH |
| WordPress Reconnaissance | apache | Requests to `/wp-login.php`, `/wp-admin`, `xmlrpc.php` | MEDIUM / HIGH |
| Sensitive File Probe | apache | `.env`, `config.*`, `phpmyadmin`, `.git`, backups, DB dumps | MEDIUM / HIGH |
| SQL Injection Probe | apache | UNION SELECT, OR 1=1, DROP, SLEEP(), etc. in URL | HIGH |

**Severity escalation** — most rules escalate severity based on volume. A single `/admin` hit is MEDIUM; five hits from the same IP is HIGH.

---

## Alert Output Format

Each alert contains:

| Field | Description |
|-------|-------------|
| `timestamp` | When the alert was generated (ISO 8601) |
| `alert_type` | Rule that fired (e.g. "Brute Force") |
| `severity` | CRITICAL / HIGH / MEDIUM / LOW / INFO |
| `source_ip` | Offending IP address |
| `description` | Human-readable explanation with context |

### JSON example

```json
{
  "timestamp": "2024-01-15 15:00:00",
  "alert_type": "Brute Force",
  "severity": "CRITICAL",
  "source_ip": "185.220.101.5",
  "description": "12 failed login attempts detected. Usernames tried: admin, guest, password, qwerty, root."
}
```

---

## Programmatic Use

SentinelLog is designed as a proper Python package:

```python
from sentinellog import LogAnalyzer, print_report, export_json

result = LogAnalyzer().analyze("logs/sample_apache.log")
print_report(result)
export_json(result, "reports/")

# Access alerts directly
for alert in result.alerts:
    print(alert.severity, alert.alert_type, alert.source_ip)
```

---

## Future Roadmap

- [ ] GeoIP lookups — annotate IPs with country/ASN via offline MaxMind database
- [ ] Allowlist support — skip known-good IPs from detection
- [ ] Time-window analysis — detect slow-and-low brute-force attempts
- [ ] Nginx log support — extend Apache parser to Nginx combined format
- [ ] Syslog/journald support — parse Linux system logs
- [ ] HTML report — self-contained HTML dashboard export
- [ ] Watch mode — `--watch` flag to tail a live log file
- [ ] Custom rule YAML — let users define their own detection rules without touching Python

---
