# Log Analyzer / Mini SIEM

A Python-based cybersecurity log analyzer with SIEM capabilities. Ingests log files (auth, Apache, syslog, firewall), detects threats using YAML-based correlation rules, and visualizes findings through a web dashboard.

## Features

- **Multi-format log parsing** — auth.log (SSH), Apache access logs, syslog, UFW/iptables firewall logs
- **Normalized event model** — All log formats converted to a common schema for analysis
- **YAML detection rules** — Configurable threshold-based correlation rules with time windows
- **MITRE ATT&CK mapping** — Alerts tagged with technique IDs (T1110, T1190, T1046, T1083, T1548)
- **Real-time syslog receiver** — UDP listener for live log ingestion
- **Web dashboard** — Flask-based UI with Chart.js visualizations, event tables, and alert feed
- **SQLite storage** — Indexed event store with flexible querying

## Detection Rules

| Rule | Severity | MITRE | Trigger |
|---|---|---|---|
| SSH Brute Force | HIGH | T1110 | 5+ failed SSH logins from same IP in 5 min |
| Port Scan | HIGH | T1046 | 10+ firewall blocks from same IP in 1 min |
| SQL Injection | CRITICAL | T1190 | SQLi pattern in HTTP request |
| Directory Traversal | HIGH | T1083 | Path traversal in HTTP request |
| Privilege Escalation | MEDIUM | T1548 | 10+ sudo commands by same user in 2 min |

## Quick Start

```bash
pip install -r requirements.txt

# Generate sample logs
python sample_logs/generate.py

# Analyze logs
python main.py sample_logs/*.log

# Analyze and launch dashboard
python main.py sample_logs/*.log --dashboard

# With live syslog receiver
python main.py sample_logs/*.log --dashboard --listen --port 5514
```

## Running Tests

```bash
python -m pytest tests/ -v
```

## Project Structure

```
├── main.py                  # CLI entry point
├── log_analyzer/
│   ├── parsers/             # Log format parsers (auth, apache, syslog, firewall)
│   ├── normalize/           # Normalized event model
│   ├── ingest/              # File reader + syslog UDP receiver
│   ├── storage/             # SQLite event store
│   ├── detection/           # YAML-based detection engine
│   ├── alerting/            # Alert manager
│   └── dashboard/           # Flask web dashboard
├── rules/                   # YAML detection rule definitions
├── sample_logs/             # Sample log generator
└── tests/                   # Unit + integration tests
```
