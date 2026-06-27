import socketserver
import threading
from log_analyzer.parsers.syslog import SyslogParser
from log_analyzer.normalize.event import NormalizedEvent


class SyslogUDPHandler(socketserver.BaseRequestHandler):
    parser = SyslogParser()
    callback = None

    def handle(self):
        data = self.request[0].strip().decode("utf-8", errors="replace")
        for line in data.splitlines():
            if self.parser.can_parse(line):
                event = self.parser.parse(line)
                if event and self.callback:
                    self.callback(event)


class SyslogReceiver:
    def __init__(self, host: str = "0.0.0.0", port: int = 5514,
                 callback=None):
        self.host = host
        self.port = port
        SyslogUDPHandler.callback = callback
        self.server = socketserver.UDPServer(
            (self.host, self.port), SyslogUDPHandler
        )
        self._thread = None

    def start(self):
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()
        print(f"[*] Syslog receiver listening on {self.host}:{self.port} (UDP)")

    def stop(self):
        self.server.shutdown()
