import re
from datetime import datetime
from .base import BaseParser
from log_analyzer.normalize.event import NormalizedEvent, Severity


class FirewallParser(BaseParser):
    IPTABLES_PATTERN = re.compile(
        r"(\w{3}\s+\d+\s[\d:]+)\s(\S+)\skernel:.*?"
        r"(?:IN=(\S*)\s)?(?:OUT=(\S*)\s)?.*?"
        r"SRC=(\d+\.\d+\.\d+\.\d+)\s.*?"
        r"DST=(\d+\.\d+\.\d+\.\d+)\s.*?"
        r"PROTO=(\S+)(?:.*?SPT=(\d+))?(?:.*?DPT=(\d+))?"
    )

    UFW_PATTERN = re.compile(
        r"(\w{3}\s+\d+\s[\d:]+)\s(\S+)\s.*?\[UFW\s(\w+)\].*?"
        r"SRC=(\d+\.\d+\.\d+\.\d+)\s.*?"
        r"DST=(\d+\.\d+\.\d+\.\d+)\s.*?"
        r"PROTO=(\S+)(?:.*?SPT=(\d+))?(?:.*?DPT=(\d+))?"
    )

    def can_parse(self, line: str) -> bool:
        return ("SRC=" in line and "DST=" in line and "PROTO=" in line)

    def parse(self, line: str) -> NormalizedEvent | None:
        m = self.UFW_PATTERN.search(line)
        if m:
            ts, host, ufw_action, src, dst, proto, spt, dpt = m.groups()
            action = f"firewall_{ufw_action.lower()}"
            severity = Severity.MEDIUM if ufw_action == "BLOCK" else Severity.INFO
        else:
            m = self.IPTABLES_PATTERN.search(line)
            if not m:
                return None
            ts, host, _in, _out, src, dst, proto, spt, dpt = m.groups()
            action = "firewall_log"
            severity = Severity.LOW

        return NormalizedEvent(
            timestamp=self._parse_time(ts),
            source_ip=src,
            dest_ip=dst,
            source_port=int(spt) if spt else None,
            dest_port=int(dpt) if dpt else None,
            protocol=proto.lower(),
            action=action,
            username=None,
            log_source="firewall",
            raw_log=line,
            severity=severity,
            tags=["firewall", proto.lower()],
        )

    def _parse_time(self, time_str: str) -> datetime:
        now = datetime.now()
        return datetime.strptime(f"{now.year} {time_str}", "%Y %b %d %H:%M:%S")
