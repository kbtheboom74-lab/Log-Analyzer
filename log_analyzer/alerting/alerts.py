import json
from pathlib import Path
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
        if alert.mitre_id:
            print(f"  MITRE ATT&CK: {alert.mitre_id}")
        print(f"  Evidence: {len(alert.evidence)} events")
        if alert.evidence and alert.evidence[0].source_ip:
            print(f"  Source IP: {alert.evidence[0].source_ip}")
        print(f"{'='*60}\n")

    def _log_alert(self, alert: Alert):
        record = {
            "rule": alert.rule_name,
            "severity": alert.severity.value,
            "timestamp": alert.timestamp.isoformat(),
            "description": alert.description,
            "mitre_id": alert.mitre_id,
            "event_count": len(alert.evidence),
            "source_ip": alert.evidence[0].source_ip if alert.evidence else None,
        }
        with open(self.alert_log, "a") as f:
            f.write(json.dumps(record) + "\n")

    def get_recent(self, limit: int = 50) -> list[dict]:
        path = Path(self.alert_log)
        if not path.exists():
            return []
        lines = path.read_text().splitlines()
        alerts = [json.loads(line) for line in lines if line.strip()]
        return alerts[-limit:]
