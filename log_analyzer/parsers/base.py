from abc import ABC, abstractmethod
from log_analyzer.normalize.event import NormalizedEvent


class BaseParser(ABC):
    @abstractmethod
    def can_parse(self, line: str) -> bool:
        """Return True if this parser can handle the log line."""

    @abstractmethod
    def parse(self, line: str) -> NormalizedEvent | None:
        """Parse a log line into a NormalizedEvent."""
