import pytest
from log_analyzer.parsers.auth import AuthLogParser
from log_analyzer.parsers.apache import ApacheLogParser
from log_analyzer.parsers.firewall import FirewallParser
from log_analyzer.parsers.syslog import SyslogParser


class TestAuthLogParser:
    def setup_method(self):
        self.parser = AuthLogParser()

    def test_can_parse_sshd(self):
        line = "Jun 27 10:15:30 server sshd[1234]: Failed password for admin from 192.168.1.1 port 50000 ssh2"
        assert self.parser.can_parse(line)

    def test_can_parse_sudo(self):
        line = "Jun 27 10:15:30 server sudo:   admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/ls"
        assert self.parser.can_parse(line)

    def test_parse_failed_login(self):
        line = "Jun 27 10:15:30 server sshd[1234]: Failed password for admin from 203.0.113.42 port 50000 ssh2"
        event = self.parser.parse(line)
        assert event is not None
        assert event.action == "login_failed"
        assert event.source_ip == "203.0.113.42"
        assert event.username == "admin"
        assert event.dest_port == 22
        assert event.protocol == "ssh"

    def test_parse_failed_login_invalid_user(self):
        line = "Jun 27 10:15:30 server sshd[1234]: Failed password for invalid user hacker from 198.51.100.77 port 40000 ssh2"
        event = self.parser.parse(line)
        assert event is not None
        assert event.action == "login_failed"
        assert event.username == "hacker"

    def test_parse_successful_login(self):
        line = "Jun 27 10:20:00 server sshd[5678]: Accepted publickey for deploy from 10.0.1.15 port 45000 ssh2"
        event = self.parser.parse(line)
        assert event is not None
        assert event.action == "login_success"
        assert event.username == "deploy"

    def test_parse_sudo_command(self):
        line = "Jun 27 10:25:00 server sudo:   root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/cat /etc/shadow"
        event = self.parser.parse(line)
        assert event is not None
        assert event.action == "sudo_command"
        assert event.username == "root"


class TestApacheLogParser:
    def setup_method(self):
        self.parser = ApacheLogParser()

    def test_can_parse(self):
        line = '10.0.1.15 - - [27/Jun/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234'
        assert self.parser.can_parse(line)

    def test_parse_normal_request(self):
        line = '10.0.1.15 - - [27/Jun/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234'
        event = self.parser.parse(line)
        assert event is not None
        assert event.action == "http_request"
        assert event.source_ip == "10.0.1.15"

    def test_parse_sqli(self):
        line = "203.0.113.42 - - [27/Jun/2026:10:00:00 +0000] \"GET /search?q=1'+OR+1=1-- HTTP/1.1\" 200 500"
        event = self.parser.parse(line)
        assert event is not None
        assert event.action == "sql_injection_attempt"
        assert "sqli" in event.tags

    def test_parse_traversal(self):
        line = '203.0.113.42 - - [27/Jun/2026:10:00:00 +0000] "GET /../../etc/passwd HTTP/1.1" 403 200'
        event = self.parser.parse(line)
        assert event is not None
        assert event.action == "directory_traversal_attempt"


class TestFirewallParser:
    def setup_method(self):
        self.parser = FirewallParser()

    def test_can_parse(self):
        line = "Jun 27 10:00:00 fw kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:00:00:00:00:00 SRC=203.0.113.42 DST=10.0.1.1 LEN=60 PROTO=TCP SPT=54321 DPT=22"
        assert self.parser.can_parse(line)

    def test_parse_ufw_block(self):
        line = "Jun 27 10:00:00 fw kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:00:00:00:00:00 SRC=203.0.113.42 DST=10.0.1.1 LEN=60 PROTO=TCP SPT=54321 DPT=22"
        event = self.parser.parse(line)
        assert event is not None
        assert event.action == "firewall_block"
        assert event.source_ip == "203.0.113.42"
        assert event.dest_port == 22

    def test_parse_ufw_allow(self):
        line = "Jun 27 10:00:00 fw kernel: [UFW ALLOW] IN=eth0 OUT= MAC=00:00:00:00:00:00 SRC=10.0.1.15 DST=10.0.1.1 LEN=60 PROTO=TCP SPT=54321 DPT=443"
        event = self.parser.parse(line)
        assert event is not None
        assert event.action == "firewall_allow"


class TestSyslogParser:
    def setup_method(self):
        self.parser = SyslogParser()

    def test_can_parse(self):
        line = "Jun 27 10:00:00 server nginx: connection established"
        assert self.parser.can_parse(line)

    def test_parse_syslog(self):
        line = "Jun 27 10:00:00 server nginx: connection established"
        event = self.parser.parse(line)
        assert event is not None
        assert event.action == "syslog_nginx"
        assert event.log_source == "syslog"

    def test_severity_detection(self):
        line = "Jun 27 10:00:00 server app: critical error in module"
        event = self.parser.parse(line)
        assert event is not None
        assert event.severity.value == "critical"
