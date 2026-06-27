"""End-to-end integration test: generate logs, ingest, detect, verify alerts."""

import subprocess
import sys
from pathlib import Path

import pytest

from log_analyzer.ingest.file_reader import FileReader
from log_analyzer.parsers.auth import AuthLogParser
from log_analyzer.parsers.apache import ApacheLogParser
from log_analyzer.parsers.firewall import FirewallParser
from log_analyzer.parsers.syslog import SyslogParser
from log_analyzer.storage.database import EventStore
from log_analyzer.detection.engine import DetectionEngine
from log_analyzer.alerting.alerts import AlertManager


@pytest.fixture
def sample_logs(tmp_path):
    subprocess.run(
        [sys.executable, "sample_logs/generate.py"],
        check=True,
    )
    return Path("sample_logs")


@pytest.fixture
def store(tmp_path):
    return EventStore(str(tmp_path / "integration.db"))


def test_full_pipeline(sample_logs, store, tmp_path):
    parsers = [AuthLogParser(), ApacheLogParser(), SyslogParser(), FirewallParser()]
    reader = FileReader(parsers)
    engine = DetectionEngine("rules")
    alert_mgr = AlertManager(str(tmp_path / "alerts.json"))

    total_events = 0
    for log_file in sample_logs.glob("*.log"):
        events = reader.read(log_file)
        assert len(events) > 0, f"No events parsed from {log_file}"
        total_events += len(events)
        store.store_batch(events)

        for event in events:
            for alert in engine.evaluate(event):
                alert_mgr.handle(alert)

    assert total_events > 100
    assert len(alert_mgr.alerts) > 0

    stats = store.get_stats()
    assert stats["total_events"] == total_events
    assert len(stats["actions"]) > 1

    recent_alerts = alert_mgr.get_recent()
    assert len(recent_alerts) > 0
    assert "rule" in recent_alerts[0]
    assert "severity" in recent_alerts[0]
