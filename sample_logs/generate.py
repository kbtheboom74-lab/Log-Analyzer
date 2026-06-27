#!/usr/bin/env python3
"""Generate realistic sample log files for testing the Log Analyzer."""

import random
from datetime import datetime, timedelta
from pathlib import Path

OUTPUT_DIR = Path(__file__).parent

USERNAMES = ["admin", "root", "deploy", "www-data", "jsmith", "kthompson", "backup"]
ATTACKER_IPS = ["203.0.113.42", "198.51.100.77", "192.0.2.199"]
NORMAL_IPS = ["10.0.1.15", "10.0.1.22", "10.0.2.5", "172.16.0.100"]
WEB_PATHS = [
    "/", "/index.html", "/about", "/api/users", "/login", "/dashboard",
    "/static/style.css", "/images/logo.png", "/api/products", "/contact",
]
SQLI_PATHS = [
    "/search?q=1'+OR+1=1--",
    "/api/users?id=1+UNION+SELECT+username,password+FROM+users--",
    "/login?user=admin'--&pass=x",
]
TRAVERSAL_PATHS = [
    "/../../etc/passwd",
    "/static/../../../etc/shadow",
    "/download?file=../../../var/log/auth.log",
]
XSS_PATHS = [
    "/search?q=<script>alert(1)</script>",
    "/comment?text=<script>document.cookie</script>",
]


def generate_auth_log(num_lines: int = 200) -> str:
    lines = []
    base_time = datetime.now() - timedelta(hours=2)

    for i in range(num_lines):
        ts = base_time + timedelta(seconds=i * random.randint(1, 30))
        ts_str = ts.strftime("%b %d %H:%M:%S")
        host = "webserver01"

        r = random.random()
        if r < 0.4:
            ip = random.choice(ATTACKER_IPS)
            user = random.choice(USERNAMES)
            port = random.randint(40000, 65000)
            lines.append(
                f"{ts_str} {host} sshd[{random.randint(1000,9999)}]: "
                f"Failed password for {user} from {ip} port {port} ssh2"
            )
        elif r < 0.55:
            ip = random.choice(ATTACKER_IPS)
            user = f"user{random.randint(100,999)}"
            port = random.randint(40000, 65000)
            lines.append(
                f"{ts_str} {host} sshd[{random.randint(1000,9999)}]: "
                f"Failed password for invalid user {user} from {ip} port {port} ssh2"
            )
        elif r < 0.75:
            ip = random.choice(NORMAL_IPS)
            user = random.choice(USERNAMES[:3])
            port = random.randint(40000, 65000)
            lines.append(
                f"{ts_str} {host} sshd[{random.randint(1000,9999)}]: "
                f"Accepted publickey for {user} from {ip} port {port} ssh2"
            )
        else:
            user = random.choice(USERNAMES[:3])
            cmd = random.choice([
                "/usr/bin/apt update", "/bin/systemctl restart nginx",
                "/usr/bin/cat /etc/shadow", "/usr/sbin/useradd testuser",
                "/bin/chmod 777 /tmp/exploit.sh",
            ])
            lines.append(
                f"{ts_str} {host} sudo:   {user} : TTY=pts/0 ; "
                f"PWD=/home/{user} ; USER=root ; COMMAND={cmd}"
            )

    return "\n".join(lines) + "\n"


def generate_apache_log(num_lines: int = 200) -> str:
    lines = []
    base_time = datetime.now() - timedelta(hours=2)

    for i in range(num_lines):
        ts = base_time + timedelta(seconds=i * random.randint(1, 15))
        ts_str = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")

        r = random.random()
        if r < 0.7:
            ip = random.choice(NORMAL_IPS + ATTACKER_IPS[:1])
            path = random.choice(WEB_PATHS)
            status = random.choice([200, 200, 200, 301, 304, 404])
            method = "GET"
        elif r < 0.8:
            ip = random.choice(ATTACKER_IPS)
            path = random.choice(SQLI_PATHS)
            status = random.choice([200, 403, 500])
            method = "GET"
        elif r < 0.9:
            ip = random.choice(ATTACKER_IPS)
            path = random.choice(TRAVERSAL_PATHS)
            status = random.choice([403, 404, 200])
            method = "GET"
        else:
            ip = random.choice(ATTACKER_IPS)
            path = random.choice(XSS_PATHS)
            status = 200
            method = "GET"

        size = random.randint(200, 50000)
        lines.append(
            f'{ip} - - [{ts_str}] "{method} {path} HTTP/1.1" {status} {size}'
        )

    return "\n".join(lines) + "\n"


def generate_firewall_log(num_lines: int = 150) -> str:
    lines = []
    base_time = datetime.now() - timedelta(hours=2)

    for i in range(num_lines):
        ts = base_time + timedelta(seconds=i * random.randint(1, 20))
        ts_str = ts.strftime("%b %d %H:%M:%S")
        host = "firewall01"

        src = random.choice(ATTACKER_IPS + NORMAL_IPS[:1])
        dst = "10.0.1.1"
        proto = random.choice(["TCP", "UDP", "TCP", "TCP"])
        spt = random.randint(1024, 65535)
        dpt = random.choice([22, 80, 443, 3306, 5432, 8080, 8443,
                              random.randint(1, 65535)])

        r = random.random()
        if r < 0.6:
            action = "BLOCK"
        else:
            action = "ALLOW"

        lines.append(
            f"{ts_str} {host} kernel: [UFW {action}] "
            f"IN=eth0 OUT= MAC=00:00:00:00:00:00 "
            f"SRC={src} DST={dst} LEN=60 TOS=0x00 PREC=0x00 TTL=64 "
            f"PROTO={proto} SPT={spt} DPT={dpt}"
        )

    return "\n".join(lines) + "\n"


def main():
    OUTPUT_DIR.mkdir(exist_ok=True)

    auth_log = OUTPUT_DIR / "auth.log"
    auth_log.write_text(generate_auth_log())
    print(f"[+] Generated {auth_log}")

    apache_log = OUTPUT_DIR / "apache_access.log"
    apache_log.write_text(generate_apache_log())
    print(f"[+] Generated {apache_log}")

    firewall_log = OUTPUT_DIR / "firewall.log"
    firewall_log.write_text(generate_firewall_log())
    print(f"[+] Generated {firewall_log}")


if __name__ == "__main__":
    main()
