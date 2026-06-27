from pathlib import Path
from log_analyzer.parsers.base import BaseParser
from log_analyzer.normalize.event import NormalizedEvent


class FileReader:
    def __init__(self, parsers: list[BaseParser]):
        self.parsers = parsers

    def read(self, path: Path) -> list[NormalizedEvent]:
        events = []
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                for parser in self.parsers:
                    if parser.can_parse(line):
                        event = parser.parse(line)
                        if event:
                            events.append(event)
                        break
        return events
