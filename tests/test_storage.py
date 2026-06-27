import os
import pytest
from datetime import datetime
from log_analyzer.storage.database import EventStore
from log_analyzer.normalize.event import NormalizedEvent, Severity


@pytest.fixture
def store(tmp_path):
    return EventStore(str(tmp_path / "test.db"))


def make_event(**kwargs):
    defaults = dict(
        timestamp=datetime.now(),
        source_ip="10.0.0.1",
        dest_ip=None,
        source_port=50000,
        dest_port=22,
        protocol="ssh",
        action="login_failed",
        username="admin",
        log_source="test",
        raw_log="test line",
        severity=Severity.MEDIUM,
        tags=["ssh"],
    )
    defaults.update(kwargs)
    return NormalizedEvent(**defaults)


class TestEventStore:
    def test_store_and_query(self, store):
        event = make_event()
        store.store(event)
        results = store.query()
        assert len(results) == 1
        assert results[0]["source_ip"] == "10.0.0.1"

    def test_store_batch(self, store):
        events = [make_event(source_ip=f"10.0.0.{i}") for i in range(10)]
        store.store_batch(events)
        results = store.query(limit=20)
        assert len(results) == 10

    def test_query_by_action(self, store):
        store.store(make_event(action="login_failed"))
        store.store(make_event(action="login_success"))
        results = store.query(action="login_failed")
        assert len(results) == 1

    def test_get_stats(self, store):
        for _ in range(5):
            store.store(make_event())
        stats = store.get_stats()
        assert stats["total_events"] == 5
        assert len(stats["actions"]) > 0
