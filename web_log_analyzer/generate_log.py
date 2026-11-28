#!/usr/bin/env python3
"""Generates sample_access.log (synthetic data) to test web_log_analyzer.py."""
import random
from datetime import datetime, timedelta, timezone

random.seed(7)
tz = timezone(timedelta(hours=7))
base = datetime(2026, 11, 27, 9, 0, 0, tzinfo=tz)
rows = []
BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0 Safari/537.36"


def add(ts, ip, path, status, ua=BROWSER, method="GET"):
    stamp = ts.strftime("%d/%b/%Y:%H:%M:%S %z")
    rows.append((ts, f'{ip} - - [{stamp}] "{method} {path} HTTP/1.1" {status} {random.randint(200, 5000)} "-" "{ua}"'))


# Normal visitors
for i in range(40):
    add(base + timedelta(minutes=random.randint(0, 240)), f"192.168.1.{random.randint(10, 30)}",
        random.choice(["/", "/about", "/products?id=3", "/contact", "/css/main.css"]), 200)

# Attacker 1: sqlmap scan
t = base + timedelta(hours=1)
for payload in ["/products?id=1%27%20OR%201%3D1--", "/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users",
                "/products?id=1;SELECT%20SLEEP(5)", "/search?q=%27%20OR%20%271%27%3D%271"]:
    t += timedelta(seconds=2)
    add(t, "203.0.113.50", payload, random.choice([200, 500]), ua="sqlmap/1.7.2#stable (https://sqlmap.org)")

# Attacker 2: directory enumeration + sensitive paths
t = base + timedelta(hours=2)
for name in ["admin", "backup", "login", "test", "old", "dev", "api", "uploads", "private", "db",
             "config", "temp", "files", "data", "secret", "staging", "portal", "panel", "web", "site"]:
    t += timedelta(seconds=1)
    add(t, "198.51.100.7", f"/{name}", 404, ua="gobuster/3.6")
add(t + timedelta(seconds=2), "198.51.100.7", "/.env", 404, ua="gobuster/3.6")
add(t + timedelta(seconds=3), "198.51.100.7", "/phpmyadmin/", 200, ua="gobuster/3.6")

# Attacker 3: path traversal and XSS from a normal-looking browser
t = base + timedelta(hours=3)
add(t, "192.0.2.99", "/download?file=../../../../etc/passwd", 200)
add(t + timedelta(seconds=5), "192.0.2.99", "/download?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd", 403)
add(t + timedelta(seconds=9), "192.0.2.99", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", 200)

rows.sort(key=lambda x: x[0])
with open("sample_access.log", "w") as f:
    f.write("\n".join(line for _, line in rows) + "\n")
print(f"sample_access.log created ({len(rows)} lines)")