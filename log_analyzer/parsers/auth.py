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
    SUDO_COMMAND = re.compile(
        r"(\w{3}\s+\d+\s[\d:]+)\s(\S+)\ssudo:\s+(\S+)\s.*COMMAND=(.*)"
    )

    def can_parse(self, line: str) -> bool:
        return "sshd[" in line or "sudo:" in line

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

        m = self.SUCCESSFUL_LOGIN.search(line)
        if m:
            return NormalizedEvent(
                timestamp=self._parse_time(m.group(1)),
                source_ip=m.group(4),
                dest_ip=None,
                source_port=int(m.group(5)),
                dest_port=22,
                protocol="ssh",
                action="login_success",
                username=m.group(3),
                log_source="auth.log",
                raw_log=line,
                severity=Severity.INFO,
                tags=["authentication", "ssh"],
            )

        m = self.SUDO_COMMAND.search(line)
        if m:
            return NormalizedEvent(
                timestamp=self._parse_time(m.group(1)),
                source_ip=None,
                dest_ip=None,
                source_port=None,
                dest_port=None,
                protocol=None,
                action="sudo_command",
                username=m.group(3),
                log_source="auth.log",
                raw_log=line,
                severity=Severity.LOW,
                tags=["privilege_escalation", "sudo"],
            )

        return None

    def _parse_time(self, time_str: str) -> datetime:
        now = datetime.now()
        return datetime.strptime(f"{now.year} {time_str}", "%Y %b %d %H:%M:%S")
