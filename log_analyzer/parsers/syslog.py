import re
from datetime import datetime
from .base import BaseParser
from log_analyzer.normalize.event import NormalizedEvent, Severity


class SyslogParser(BaseParser):
    SYSLOG_PATTERN = re.compile(
        r"(\w{3}\s+\d+\s[\d:]+)\s(\S+)\s(\S+?)(?:\[\d+\])?:\s(.*)"
    )

    SEVERITY_KEYWORDS = [
        ("emerg", Severity.CRITICAL),
        ("crit", Severity.CRITICAL),
        ("alert", Severity.HIGH),
        ("error", Severity.HIGH),
        ("fail", Severity.MEDIUM),
        ("warn", Severity.LOW),
    ]

    def can_parse(self, line: str) -> bool:
        return bool(self.SYSLOG_PATTERN.match(line))

    def parse(self, line: str) -> NormalizedEvent | None:
        m = self.SYSLOG_PATTERN.match(line)
        if not m:
            return None

        timestamp_str, hostname, service, message = m.groups()
        severity = Severity.INFO
        for keyword, sev in self.SEVERITY_KEYWORDS:
            if keyword in message.lower():
                severity = sev
                break

        return NormalizedEvent(
            timestamp=self._parse_time(timestamp_str),
            source_ip=None,
            dest_ip=None,
            source_port=None,
            dest_port=None,
            protocol=None,
            action=f"syslog_{service}",
            username=None,
            log_source="syslog",
            raw_log=line,
            severity=severity,
            tags=["syslog", service],
        )

    def _parse_time(self, time_str: str) -> datetime:
        now = datetime.now()
        return datetime.strptime(f"{now.year} {time_str}", "%Y %b %d %H:%M:%S")
