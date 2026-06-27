import sqlite3
import threading
from log_analyzer.normalize.event import NormalizedEvent, Severity


class EventStore:
    def __init__(self, db_path: str = "events.db"):
        self.db_path = db_path
        self._local = threading.local()
        self._create_tables()

    @property
    def conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn"):
            self._local.conn = sqlite3.connect(self.db_path)
        return self._local.conn

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
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp)"
        )
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_source_ip ON events(source_ip)"
        )
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_action ON events(action)"
        )
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_severity ON events(severity)"
        )
        self.conn.commit()

    def store(self, event: NormalizedEvent):
        self.conn.execute(
            "INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                event.event_id,
                event.timestamp.isoformat(),
                event.source_ip,
                event.dest_ip,
                event.source_port,
                event.dest_port,
                event.protocol,
                event.action,
                event.username,
                event.log_source,
                event.severity.value,
                event.raw_log,
                ",".join(event.tags),
            ),
        )
        self.conn.commit()

    def store_batch(self, events: list[NormalizedEvent]):
        self.conn.executemany(
            "INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [
                (
                    e.event_id, e.timestamp.isoformat(), e.source_ip,
                    e.dest_ip, e.source_port, e.dest_port, e.protocol,
                    e.action, e.username, e.log_source, e.severity.value,
                    e.raw_log, ",".join(e.tags),
                )
                for e in events
            ],
        )
        self.conn.commit()

    def query(self, action: str = None, source_ip: str = None,
              since: str = None, severity: str = None,
              limit: int = 100) -> list[dict]:
        sql = "SELECT * FROM events WHERE 1=1"
        params: list = []
        if action:
            sql += " AND action = ?"
            params.append(action)
        if source_ip:
            sql += " AND source_ip = ?"
            params.append(source_ip)
        if since:
            sql += " AND timestamp >= ?"
            params.append(since)
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        sql += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        cur = self.conn.execute(sql, params)
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def get_stats(self) -> dict:
        result = {}
        cur = self.conn.execute(
            "SELECT action, COUNT(*) FROM events GROUP BY action ORDER BY COUNT(*) DESC"
        )
        result["actions"] = [{"action": r[0], "count": r[1]} for r in cur.fetchall()]

        cur = self.conn.execute(
            "SELECT source_ip, COUNT(*) FROM events "
            "WHERE source_ip IS NOT NULL GROUP BY source_ip ORDER BY COUNT(*) DESC LIMIT 10"
        )
        result["top_ips"] = [{"ip": r[0], "count": r[1]} for r in cur.fetchall()]

        cur = self.conn.execute(
            "SELECT severity, COUNT(*) FROM events GROUP BY severity"
        )
        result["severities"] = [{"severity": r[0], "count": r[1]} for r in cur.fetchall()]

        cur = self.conn.execute("SELECT COUNT(*) FROM events")
        result["total_events"] = cur.fetchone()[0]

        return result
