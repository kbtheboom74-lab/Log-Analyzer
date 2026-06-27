import pytest
from datetime import datetime, timedelta
from log_analyzer.detection.engine import DetectionEngine
from log_analyzer.normalize.event import NormalizedEvent, Severity


def make_event(action="login_failed", source_ip="203.0.113.42",
               protocol="ssh", timestamp=None, username=None):
    return NormalizedEvent(
        timestamp=timestamp or datetime.now(),
        source_ip=source_ip,
        dest_ip=None,
        source_port=50000,
        dest_port=22,
        protocol=protocol,
        action=action,
        username=username,
        log_source="test",
        raw_log="test log line",
        severity=Severity.MEDIUM,
    )


class TestDetectionEngine:
    def setup_method(self):
        self.engine = DetectionEngine("rules")

    def test_brute_force_no_alert_below_threshold(self):
        now = datetime.now()
        for i in range(4):
            event = make_event(timestamp=now + timedelta(seconds=i))
            alerts = self.engine.evaluate(event)
        assert all(len(a.evidence) >= 5 for a in alerts) or len(alerts) == 0

    def test_brute_force_alert_at_threshold(self):
        now = datetime.now()
        all_alerts = []
        for i in range(6):
            event = make_event(timestamp=now + timedelta(seconds=i * 10))
            alerts = self.engine.evaluate(event)
            all_alerts.extend(alerts)
        brute_force_alerts = [a for a in all_alerts if a.rule_name == "SSH Brute Force"]
        assert len(brute_force_alerts) >= 1
        assert brute_force_alerts[0].severity == Severity.HIGH

    def test_different_ips_no_alert(self):
        now = datetime.now()
        all_alerts = []
        for i in range(6):
            event = make_event(
                source_ip=f"10.0.0.{i}",
                timestamp=now + timedelta(seconds=i),
            )
            alerts = self.engine.evaluate(event)
            all_alerts.extend(alerts)
        brute_force_alerts = [a for a in all_alerts if a.rule_name == "SSH Brute Force"]
        assert len(brute_force_alerts) == 0

    def test_sqli_immediate_alert(self):
        event = make_event(action="sql_injection_attempt", protocol="http")
        alerts = self.engine.evaluate(event)
        sqli_alerts = [a for a in alerts if a.rule_name == "SQL Injection Attempt"]
        assert len(sqli_alerts) == 1
        assert sqli_alerts[0].mitre_id == "T1190"

    def test_mitre_id_present(self):
        now = datetime.now()
        all_alerts = []
        for i in range(6):
            event = make_event(timestamp=now + timedelta(seconds=i * 10))
            all_alerts.extend(self.engine.evaluate(event))
        brute_force_alerts = [a for a in all_alerts if a.rule_name == "SSH Brute Force"]
        if brute_force_alerts:
            assert brute_force_alerts[0].mitre_id == "T1110"
