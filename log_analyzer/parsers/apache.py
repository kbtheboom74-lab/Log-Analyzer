import re
from datetime import datetime
from .base import BaseParser
from log_analyzer.normalize.event import NormalizedEvent, Severity


class ApacheLogParser(BaseParser):
    ACCESS_LOG = re.compile(
        r'(\d+\.\d+\.\d+\.\d+)\s\S+\s(\S+)\s'
        r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})\s[^\]]+\]\s'
        r'"(\w+)\s(\S+)\s\S+"\s(\d{3})\s(\d+|-)'
    )

    SQLI_PATTERNS = [
        re.compile(r"(?:union[\s+]+select|or[\s+]+1[\s+]*=[\s+]*1|'\s*or\s*'|drop[\s+]+table)", re.I),
    ]
    TRAVERSAL_PATTERN = re.compile(r"\.\./")
    XSS_PATTERN = re.compile(r"<script", re.I)

    def can_parse(self, line: str) -> bool:
        return bool(self.ACCESS_LOG.match(line))

    def parse(self, line: str) -> NormalizedEvent | None:
        m = self.ACCESS_LOG.match(line)
        if not m:
            return None

        ip, user, ts, method, path, status, size = m.groups()
        username = user if user != "-" else None
        status_code = int(status)

        action = "http_request"
        severity = Severity.INFO
        tags = ["http", method.lower()]

        for pat in self.SQLI_PATTERNS:
            if pat.search(path):
                action = "sql_injection_attempt"
                severity = Severity.CRITICAL
                tags.append("attack")
                tags.append("sqli")
                break

        if self.TRAVERSAL_PATTERN.search(path):
            action = "directory_traversal_attempt"
            severity = Severity.HIGH
            tags.append("attack")
            tags.append("traversal")

        if self.XSS_PATTERN.search(path):
            action = "xss_attempt"
            severity = Severity.HIGH
            tags.append("attack")
            tags.append("xss")

        if status_code >= 500:
            severity = max(severity, Severity.MEDIUM, key=lambda s: list(Severity).index(s))
            tags.append("server_error")
        elif status_code == 403:
            tags.append("forbidden")
        elif status_code == 404:
            tags.append("not_found")

        return NormalizedEvent(
            timestamp=datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S"),
            source_ip=ip,
            dest_ip=None,
            source_port=None,
            dest_port=80,
            protocol="http",
            action=action,
            username=username,
            log_source="apache_access",
            raw_log=line,
            severity=severity,
            tags=tags,
        )
