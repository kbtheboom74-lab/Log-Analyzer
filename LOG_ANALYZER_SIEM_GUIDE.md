# Log Analyzer / Mini SIEM — Step-by-Step Build Guide

A complete guide to building a cybersecurity Log Analyzer with SIEM (Security Information and Event Management) capabilities in Python.

---

## Project Overview

**What you'll build:** A tool that ingests log files (syslog, auth logs, Apache/Nginx, firewall logs), parses and normalizes events, detects suspicious patterns using correlation rules, and presents findings through a dashboard.

**Tech stack:** Python 3.11+, SQLite (event store), Flask (dashboard), regular expressions (parsing), and optional ELK-style visualization.

---

## Phase 1: Project Setup & Log Ingestion

### Step 1 — Initialize the project structure

```
Log-Analyzer/
├── log_analyzer/
│   ├── __init__.py
│   ├── ingest/          # Log ingestion modules
│   │   ├── __init__.py
│   │   ├── file_reader.py
│   │   └── syslog_receiver.py
│   ├── parsers/         # Log format parsers
│   │   ├── __init__.py
│   │   ├── base.py
│   │   ├── syslog.py
│   │   ├── auth.py
│   │   ├── apache.py
│   │   └── firewall.py
│   ├── normalize/       # Event normalization
│   │   ├── __init__.py
│   │   └── event.py
│   ├── detection/       # Detection rules engine
│   │   ├── __init__.py
│   │   ├── engine.py
│   │   └── rules/
│   │       ├── __init__.py
│   │       ├── brute_force.py
│   │       ├── port_scan.py
│   │       ├── privilege_escalation.py
│   │       └── anomaly.py
│   ├── storage/         # Event storage
│   │   ├── __init__.py
│   │   └── database.py
│   ├── alerting/        # Alert generation
│   │   ├── __init__.py
│   │   └── alerts.py
│   └── dashboard/       # Web dashboard
│       ├── __init__.py
│       ├── app.py
│       ├── templates/
│       └── static/
├── rules/               # YAML detection rule definitions
│   ├── brute_force.yml
│   ├── port_scan.yml
│   └── priv_esc.yml
├── sample_logs/         # Sample log files for testing
├── tests/
├── requirements.txt
├── config.yml
└── main.py
```

### Step 2 — Create the normalized event model

This is the core data structure every log line gets converted into.

```python
# log_analyzer/normalize/event.py
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
import uuid

class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class NormalizedEvent:
    timestamp: datetime
    source_ip: Optional[str]
    dest_ip: Optional[str]
    source_port: Optional[int]
    dest_port: Optional[int]
    protocol: Optional[str]
    action: str              # e.g., "login_failed", "connection_dropped"
    username: Optional[str]
    log_source: str          # e.g., "auth.log", "apache_access"
    raw_log: str
    severity: Severity = Severity.INFO
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tags: list[str] = field(default_factory=list)
```

### Step 3 — Build log parsers

Create a base parser and implement format-specific parsers.

```python
# log_analyzer/parsers/base.py
from abc import ABC, abstractmethod
from log_analyzer.normalize.event import NormalizedEvent

class BaseParser(ABC):
    @abstractmethod
    def can_parse(self, line: str) -> bool:
        """Return True if this parser can handle the log line."""

    @abstractmethod
    def parse(self, line: str) -> NormalizedEvent | None:
        """Parse a log line into a NormalizedEvent."""
```

```python
# log_analyzer/parsers/auth.py — Example: Linux auth.log parser
import re
from datetime import datetime
from .base import BaseParser
from log_analyzer.normalize.event import NormalizedEvent, Severity

class AuthLogParser(BaseParser):
    FAILED_LOGIN = re.compile(
        r"(\w{3}\s+\d+\s[\d:]+)\s(\S+)\ssshd\[\d+\]:\sFailed password for\s"
        r"(invalid user\s)?(\S+)\sfrom\s(\d+\.\d+\.\d+\.\d+)\sport\s(\d+)"
    )
    SUCCESSFUL_LOGIN = re.compile(
        r"(\w{3}\s+\d+\s[\d:]+)\s(\S+)\ssshd\[\d+\]:\sAccepted\s\S+\sfor\s"
        r"(\S+)\sfrom\s(\d+\.\d+\.\d+\.\d+)\sport\s(\d+)"
    )

    def can_parse(self, line: str) -> bool:
        return "sshd[" in line

    def parse(self, line: str) -> NormalizedEvent | None:
        m = self.FAILED_LOGIN.search(line)
        if m:
            return NormalizedEvent(
                timestamp=self._parse_time(m.group(1)),
                source_ip=m.group(5),
                dest_ip=None,
                source_port=int(m.group(6)),
                dest_port=22,
                protocol="ssh",
                action="login_failed",
                username=m.group(4),
                log_source="auth.log",
                raw_log=line,
                severity=Severity.MEDIUM,
                tags=["authentication", "ssh"],
            )
        # ... handle SUCCESSFUL_LOGIN similarly
        return None

    def _parse_time(self, time_str: str) -> datetime:
        return datetime.strptime(f"2026 {time_str}", "%Y %b %d %H:%M:%S")
```

Repeat this pattern for **syslog**, **Apache/Nginx access logs**, and **firewall logs** (iptables/UFW).

### Step 4 — File ingestion

```python
# log_analyzer/ingest/file_reader.py
from pathlib import Path
from log_analyzer.parsers.base import BaseParser
from log_analyzer.normalize.event import NormalizedEvent

class FileReader:
    def __init__(self, parsers: list[BaseParser]):
        self.parsers = parsers

    def read(self, path: Path) -> list[NormalizedEvent]:
        events = []
        with open(path) as f:
            for line in f:
                line = line.strip()
                for parser in self.parsers:
                    if parser.can_parse(line):
                        event = parser.parse(line)
                        if event:
                            events.append(event)
                        break
        return events
```

---

## Phase 2: Storage & Indexing

### Step 5 — SQLite event store

```python
# log_analyzer/storage/database.py
import sqlite3
from log_analyzer.normalize.event import NormalizedEvent

class EventStore:
    def __init__(self, db_path: str = "events.db"):
        self.conn = sqlite3.connect(db_path)
        self._create_tables()

    def _create_tables(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                source_ip TEXT,
                dest_ip TEXT,
                source_port INTEGER,
                dest_port INTEGER,
                protocol TEXT,
                action TEXT NOT NULL,
                username TEXT,
                log_source TEXT,
                severity TEXT,
                raw_log TEXT,
                tags TEXT
            )
        """)
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_source_ip ON events(source_ip)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_action ON events(action)")
        self.conn.commit()

    def store(self, event: NormalizedEvent):
        self.conn.execute(
            "INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (event.event_id, event.timestamp.isoformat(), event.source_ip,
             event.dest_ip, event.source_port, event.dest_port, event.protocol,
             event.action, event.username, event.log_source,
             event.severity.value, event.raw_log, ",".join(event.tags))
        )
        self.conn.commit()

    def query(self, action: str = None, source_ip: str = None,
              since: str = None, limit: int = 100) -> list[dict]:
        sql = "SELECT * FROM events WHERE 1=1"
        params = []
        if action:
            sql += " AND action = ?"
            params.append(action)
        if source_ip:
            sql += " AND source_ip = ?"
            params.append(source_ip)
        if since:
            sql += " AND timestamp >= ?"
            params.append(since)
        sql += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        cur = self.conn.execute(sql, params)
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]
```

---

## Phase 3: Detection Engine

### Step 6 — YAML-based detection rules

```yaml
# rules/brute_force.yml
name: SSH Brute Force
description: Detects multiple failed SSH logins from the same IP
severity: high
conditions:
  action: login_failed
  protocol: ssh
threshold:
  count: 5
  window_seconds: 300
  group_by: source_ip
response: alert
```

### Step 7 — Detection engine

```python
# log_analyzer/detection/engine.py
import yaml
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timedelta
from log_analyzer.normalize.event import NormalizedEvent, Severity

class Alert:
    def __init__(self, rule_name: str, severity: Severity,
                 description: str, evidence: list[NormalizedEvent]):
        self.rule_name = rule_name
        self.severity = severity
        self.description = description
        self.evidence = evidence
        self.timestamp = datetime.now()

class DetectionEngine:
    def __init__(self, rules_dir: str = "rules"):
        self.rules = self._load_rules(rules_dir)
        self.event_windows: dict[str, list] = defaultdict(list)

    def _load_rules(self, rules_dir: str) -> list[dict]:
        rules = []
        for f in Path(rules_dir).glob("*.yml"):
            with open(f) as fh:
                rules.append(yaml.safe_load(fh))
        return rules

    def evaluate(self, event: NormalizedEvent) -> list[Alert]:
        alerts = []
        for rule in self.rules:
            if self._matches_conditions(event, rule.get("conditions", {})):
                alert = self._check_threshold(event, rule)
                if alert:
                    alerts.append(alert)
        return alerts

    def _matches_conditions(self, event: NormalizedEvent, conditions: dict) -> bool:
        for field, value in conditions.items():
            if getattr(event, field, None) != value:
                return False
        return True

    def _check_threshold(self, event: NormalizedEvent, rule: dict) -> Alert | None:
        threshold = rule.get("threshold")
        if not threshold:
            return Alert(rule["name"], Severity(rule["severity"]),
                         rule["description"], [event])

        group_by = threshold["group_by"]
        key = f"{rule['name']}:{getattr(event, group_by, 'unknown')}"
        window = timedelta(seconds=threshold["window_seconds"])
        now = event.timestamp

        self.event_windows[key].append(event)
        self.event_windows[key] = [
            e for e in self.event_windows[key] if now - e.timestamp <= window
        ]

        if len(self.event_windows[key]) >= threshold["count"]:
            alert = Alert(rule["name"], Severity(rule["severity"]),
                          rule["description"], list(self.event_windows[key]))
            self.event_windows[key] = []
            return alert
        return None
```

---

## Phase 4: Alerting

### Step 8 — Alert manager

```python
# log_analyzer/alerting/alerts.py
import json
from datetime import datetime
from log_analyzer.detection.engine import Alert

class AlertManager:
    def __init__(self, alert_log: str = "alerts.json"):
        self.alert_log = alert_log
        self.alerts: list[Alert] = []

    def handle(self, alert: Alert):
        self.alerts.append(alert)
        self._log_alert(alert)
        self._print_alert(alert)

    def _print_alert(self, alert: Alert):
        print(f"\n{'='*60}")
        print(f"  ALERT: {alert.rule_name}")
        print(f"  Severity: {alert.severity.value.upper()}")
        print(f"  Time: {alert.timestamp}")
        print(f"  Description: {alert.description}")
        print(f"  Evidence: {len(alert.evidence)} events")
        if alert.evidence:
            src = alert.evidence[0].source_ip
            print(f"  Source IP: {src}")
        print(f"{'='*60}\n")

    def _log_alert(self, alert: Alert):
        record = {
            "rule": alert.rule_name,
            "severity": alert.severity.value,
            "timestamp": alert.timestamp.isoformat(),
            "description": alert.description,
            "event_count": len(alert.evidence),
        }
        with open(self.alert_log, "a") as f:
            f.write(json.dumps(record) + "\n")
```

---

## Phase 5: Web Dashboard

### Step 9 — Flask dashboard

```python
# log_analyzer/dashboard/app.py
from flask import Flask, render_template, jsonify, request
from log_analyzer.storage.database import EventStore

app = Flask(__name__)
store = EventStore()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/events")
def api_events():
    action = request.args.get("action")
    source_ip = request.args.get("source_ip")
    since = request.args.get("since")
    events = store.query(action=action, source_ip=source_ip, since=since)
    return jsonify(events)

@app.route("/api/stats")
def api_stats():
    cur = store.conn.execute(
        "SELECT action, COUNT(*) as cnt FROM events GROUP BY action ORDER BY cnt DESC"
    )
    actions = [{"action": r[0], "count": r[1]} for r in cur.fetchall()]

    cur = store.conn.execute(
        "SELECT source_ip, COUNT(*) as cnt FROM events "
        "WHERE source_ip IS NOT NULL GROUP BY source_ip ORDER BY cnt DESC LIMIT 10"
    )
    top_ips = [{"ip": r[0], "count": r[1]} for r in cur.fetchall()]

    cur = store.conn.execute(
        "SELECT severity, COUNT(*) as cnt FROM events GROUP BY severity"
    )
    severities = [{"severity": r[0], "count": r[1]} for r in cur.fetchall()]

    return jsonify({"actions": actions, "top_ips": top_ips, "severities": severities})

@app.route("/api/alerts")
def api_alerts():
    import json
    from pathlib import Path
    alerts_file = Path("alerts.json")
    if not alerts_file.exists():
        return jsonify([])
    alerts = [json.loads(line) for line in alerts_file.read_text().splitlines() if line]
    return jsonify(alerts[-50:])
```

Create an `index.html` template with Chart.js for visualizations (event timeline, top IPs bar chart, severity pie chart, live alert feed).

---

## Phase 6: Main Entry Point

### Step 10 — Wire everything together

```python
# main.py
import argparse
from pathlib import Path
from log_analyzer.ingest.file_reader import FileReader
from log_analyzer.parsers.auth import AuthLogParser
from log_analyzer.parsers.apache import ApacheLogParser
from log_analyzer.parsers.syslog import SyslogParser
from log_analyzer.parsers.firewall import FirewallParser
from log_analyzer.storage.database import EventStore
from log_analyzer.detection.engine import DetectionEngine
from log_analyzer.alerting.alerts import AlertManager

def main():
    parser = argparse.ArgumentParser(description="Log Analyzer / Mini SIEM")
    parser.add_argument("logs", nargs="+", help="Log files to analyze")
    parser.add_argument("--rules", default="rules", help="Rules directory")
    parser.add_argument("--dashboard", action="store_true", help="Launch web dashboard")
    args = parser.parse_args()

    parsers = [AuthLogParser(), ApacheLogParser(), SyslogParser(), FirewallParser()]
    reader = FileReader(parsers)
    store = EventStore()
    engine = DetectionEngine(args.rules)
    alert_mgr = AlertManager()

    for log_path in args.logs:
        print(f"[*] Ingesting {log_path}...")
        events = reader.read(Path(log_path))
        print(f"    Parsed {len(events)} events")

        for event in events:
            store.store(event)
            alerts = engine.evaluate(event)
            for alert in alerts:
                alert_mgr.handle(alert)

    print(f"\n[*] Total alerts generated: {len(alert_mgr.alerts)}")

    if args.dashboard:
        from log_analyzer.dashboard.app import app
        print("[*] Starting dashboard at http://127.0.0.1:5000")
        app.run(debug=True)

if __name__ == "__main__":
    main()
```

---

## Phase 7: Testing & Sample Data

### Step 11 — Generate sample logs for testing

Create a script `sample_logs/generate.py` that produces realistic:
- **auth.log** entries (mix of failed/successful SSH logins, sudo usage)
- **Apache access logs** (normal traffic + SQL injection attempts, directory traversal)
- **Firewall logs** (port scans, blocked connections)

### Step 12 — Write tests

- Unit tests for each parser (does it extract fields correctly?)
- Unit tests for the detection engine (does brute-force rule fire after N events?)
- Integration test: feed sample logs end-to-end and verify expected alerts

---

## Phase 8: Enhancements (Stretch Goals)

| Feature | Description |
|---|---|
| **Real-time syslog receiver** | UDP/TCP listener on port 514 for live log ingestion |
| **GeoIP enrichment** | Map source IPs to countries using MaxMind GeoLite2 |
| **MITRE ATT&CK mapping** | Tag alerts with ATT&CK technique IDs (T1110, T1046, etc.) |
| **Sigma rule support** | Import community Sigma detection rules |
| **Email/Slack alerts** | Send notifications on HIGH/CRITICAL alerts |
| **Log rotation & retention** | Auto-archive old events, configurable retention policy |
| **Threat intel feeds** | Check IPs against AbuseIPDB or OTX |
| **Docker deployment** | Containerize with docker-compose |

---

## Build Order Checklist

- [ ] **Week 1:** Project structure, event model, auth.log parser, file reader
- [ ] **Week 2:** Additional parsers (Apache, syslog, firewall), SQLite storage
- [ ] **Week 3:** Detection engine, YAML rules, brute-force + port-scan rules
- [ ] **Week 4:** Alert manager, sample log generator, unit tests
- [ ] **Week 5:** Flask dashboard with Chart.js visualizations
- [ ] **Week 6:** Polish, README, stretch goals, deploy

---

## requirements.txt

```
flask>=3.0
pyyaml>=6.0
pytest>=8.0
```

---

## Usage

```bash
# Analyze log files
python main.py /var/log/auth.log /var/log/apache2/access.log

# Analyze and launch dashboard
python main.py sample_logs/*.log --dashboard
```
