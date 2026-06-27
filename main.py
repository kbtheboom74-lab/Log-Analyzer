#!/usr/bin/env python3
"""Log Analyzer / Mini SIEM — Main entry point."""

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
    parser.add_argument("--db", default="events.db", help="Database path")
    parser.add_argument("--dashboard", action="store_true", help="Launch web dashboard")
    parser.add_argument("--listen", action="store_true", help="Start syslog UDP receiver")
    parser.add_argument("--port", type=int, default=5514, help="Syslog receiver port")
    args = parser.parse_args()

    parsers = [AuthLogParser(), ApacheLogParser(), SyslogParser(), FirewallParser()]
    reader = FileReader(parsers)
    store = EventStore(args.db)
    engine = DetectionEngine(args.rules)
    alert_mgr = AlertManager()

    total_events = 0
    for log_path in args.logs:
        path = Path(log_path)
        if not path.exists():
            print(f"[!] File not found: {log_path}")
            continue

        print(f"[*] Ingesting {log_path}...")
        events = reader.read(path)
        print(f"    Parsed {len(events)} events")
        total_events += len(events)

        store.store_batch(events)

        for event in events:
            alerts = engine.evaluate(event)
            for alert in alerts:
                alert_mgr.handle(alert)

    print(f"\n[*] Total events ingested: {total_events}")
    print(f"[*] Total alerts generated: {len(alert_mgr.alerts)}")

    if args.listen:
        from log_analyzer.ingest.syslog_receiver import SyslogReceiver

        def on_event(event):
            store.store(event)
            for alert in engine.evaluate(event):
                alert_mgr.handle(alert)

        receiver = SyslogReceiver(port=args.port, callback=on_event)
        receiver.start()

    if args.dashboard:
        from log_analyzer.dashboard.app import app
        print(f"\n[*] Starting dashboard at http://127.0.0.1:5000")
        app.run(debug=True, use_reloader=False)
    elif args.listen:
        import signal
        print("[*] Listening for syslog events. Press Ctrl+C to stop.")
        signal.pause()


if __name__ == "__main__":
    main()
