import yaml
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from log_analyzer.normalize.event import NormalizedEvent, Severity


@dataclass
class Alert:
    rule_name: str
    severity: Severity
    description: str
    evidence: list[NormalizedEvent]
    timestamp: datetime = field(default_factory=datetime.now)
    mitre_id: str | None = None


class DetectionEngine:
    def __init__(self, rules_dir: str = "rules"):
        self.rules = self._load_rules(rules_dir)
        self.event_windows: dict[str, list[NormalizedEvent]] = defaultdict(list)

    def _load_rules(self, rules_dir: str) -> list[dict]:
        rules = []
        rules_path = Path(rules_dir)
        if not rules_path.exists():
            return rules
        for f in rules_path.glob("*.yml"):
            with open(f) as fh:
                rule = yaml.safe_load(fh)
                if rule:
                    rules.append(rule)
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
        for fld, value in conditions.items():
            event_val = getattr(event, fld, None)
            if isinstance(value, list):
                if event_val not in value:
                    return False
            elif event_val != value:
                return False
        return True

    def _check_threshold(self, event: NormalizedEvent, rule: dict) -> Alert | None:
        threshold = rule.get("threshold")
        if not threshold:
            return Alert(
                rule_name=rule["name"],
                severity=Severity(rule["severity"]),
                description=rule["description"],
                evidence=[event],
                mitre_id=rule.get("mitre_id"),
            )

        group_by = threshold["group_by"]
        group_val = getattr(event, group_by, "unknown")
        key = f"{rule['name']}:{group_val}"
        window = timedelta(seconds=threshold["window_seconds"])
        now = event.timestamp

        self.event_windows[key].append(event)
        self.event_windows[key] = [
            e for e in self.event_windows[key] if now - e.timestamp <= window
        ]

        if len(self.event_windows[key]) >= threshold["count"]:
            alert = Alert(
                rule_name=rule["name"],
                severity=Severity(rule["severity"]),
                description=rule["description"],
                evidence=list(self.event_windows[key]),
                mitre_id=rule.get("mitre_id"),
            )
            self.event_windows[key] = []
            return alert
        return None
