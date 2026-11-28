
import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from urllib.parse import unquote_plus

LOG_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+)(?: HTTP/[\d.]+)?" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?'
)

ATTACK_PATTERNS = {
    "SQL Injection": re.compile(
        r"(union(\s|/\*.*?\*/)+(all\s+)?select|select.+from|information_schema|"
        r"'\s*or\s*'?\d|\bor\s+1\s*=\s*1|sleep\s*\(|benchmark\s*\(|"
        r"waitfor\s+delay|;\s*drop\s+table|'--|\bxp_cmdshell)",
        re.I,
    ),
    "XSS": re.compile(
        r"(<\s*script|javascript\s*:|onerror\s*=|onload\s*=|<\s*img[^>]+src|<\s*svg[^>]+on)",
        re.I,
    ),
    "Path Traversal": re.compile(
        r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|boot\.ini|win\.ini|/proc/self)", re.I
    ),
    "Command Injection": re.compile(
        r"(;\s*(cat|ls|id|whoami|wget|curl|nc)\b|\|\s*(cat|id|whoami)\b|`[^`]+`|\$\([^)]+\))",
        re.I,
    ),
}

SCANNER_AGENTS = (
    "sqlmap", "nikto", "nmap", "masscan", "gobuster", "dirbuster", "dirb",
    "wpscan", "nuclei", "acunetix", "nessus", "zgrab", "feroxbuster", "ffuf",
)

SENSITIVE_PATHS = (
    "/.env", "/.git", "/.htaccess", "/wp-login.php", "/wp-admin", "/phpmyadmin",
    "/admin", "/config.php", "/backup", "/server-status", "/.aws", "/id_rsa",
)

INJECTION = {"SQL Injection", "XSS", "Path Traversal", "Command Injection"}


def parse_log(path):
    """Read the log file and return a list of request dicts."""
    entries = []
    with open(path, "r", errors="replace") as f:
        for line in f:
            m = LOG_RE.match(line.strip())
            if not m:
                continue
            try:
                ts = datetime.strptime(m.group("ts"), "%d/%b/%Y:%H:%M:%S %z")
            except ValueError:
                continue
            entries.append({
                "ip": m.group("ip"),
                "ts": ts,
                "method": m.group("method"),
                "path": m.group("path"),
                "status": int(m.group("status")),
                "ua": m.group("ua") or "",
            })
    return sorted(entries, key=lambda e: e["ts"])


def decode(path):
    """URL-decode twice to catch double-encoded payloads (%252e%252e%252f)."""
    return unquote_plus(unquote_plus(path))


def max_in_window(times, window):
    best, left = 0, 0
    for right in range(len(times)):
        while times[right] - times[left] > window:
            left += 1
        best = max(best, right - left + 1)
    return best


def analyze(entries, notfound_threshold, window_min):
    window = timedelta(minutes=window_min)
    per_ip = defaultdict(list)
    for e in entries:
        per_ip[e["ip"]].append(e)

    findings = []
    for ip, reqs in per_ip.items():
        attacks = []   # (category, path, status)
        probes = set()
        scanner = None
        notfound_times = []

        for r in reqs:
            decoded = decode(r["path"])
            for category, pattern in ATTACK_PATTERNS.items():
                if pattern.search(decoded):
                    attacks.append((category, r["path"], r["status"]))
            low = decoded.lower()
            for sp in SENSITIVE_PATHS:
                if low.startswith(sp):
                    probes.add(sp)
            ua = r["ua"].lower()
            if scanner is None:
                scanner = next((s for s in SCANNER_AGENTS if s in ua), None)
            if r["status"] == 404:
                notfound_times.append(r["ts"])

        enum_burst = max_in_window(notfound_times, window)
        reasons = []
        categories = sorted({c for c, _, _ in attacks})
        if categories:
            reasons.append("attack payloads: " + ", ".join(categories))
        if scanner:
            reasons.append(f"scanner user agent: {scanner}")
        if enum_burst >= notfound_threshold:
            reasons.append(f"directory enumeration ({enum_burst} x 404 in {window_min} min)")
        if probes:
            reasons.append("sensitive paths probed: " + ", ".join(sorted(probes)))
        if not reasons:
            continue

        # Injection that got a 2xx/5xx response needs review: the app may be vulnerable.
        needs_review = [a for a in attacks if a[0] in INJECTION and (200 <= a[2] < 300 or a[2] >= 500)]
        if needs_review:
            severity = "HIGH"
        elif categories or scanner:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        findings.append({
            "ip": ip,
            "severity": severity,
            "requests": len(reqs),
            "reasons": reasons,
            "needs_review": [
                {"type": c, "path": p[:120], "status": s} for c, p, s in needs_review[:5]
            ],
            "first_seen": reqs[0]["ts"].isoformat(),
            "last_seen": reqs[-1]["ts"].isoformat(),
        })

    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    findings.sort(key=lambda f: (order[f["severity"]], -f["requests"]))
    return findings


def print_report(entries, findings):
    statuses = Counter(e["status"] // 100 for e in entries)
    print("=" * 62)
    print(" WEB LOG ANALYZER - REPORT")
    print("=" * 62)
    print(f"Requests analyzed : {len(entries)}")
    print(f"Unique IPs        : {len({e['ip'] for e in entries})}")
    print("Status classes    : " + ", ".join(f"{k}xx={v}" for k, v in sorted(statuses.items())))
    print(f"Suspicious IPs    : {len(findings)}\n")

    for f in findings:
        print(f"[{f['severity']}] {f['ip']}  ({f['requests']} requests)")
        for r in f["reasons"]:
            print(f"   - {r}")
        for item in f["needs_review"]:
            print(f"   ! review: {item['type']} -> HTTP {item['status']}  {item['path']}")
        print()

    if any(f["severity"] == "HIGH" for f in findings):
        print("HIGH = injection payload answered with 2xx/5xx. Verify the endpoint is not")
        print("vulnerable (a 200 does not prove exploitation, but it needs review).")
    if findings:
        print("Recommended: block offending IPs (WAF / fail2ban), use parameterized queries,")
        print("validate input, and keep sensitive files out of the web root.")


def main():
    p = argparse.ArgumentParser(description="Detect attack attempts in web server access logs.")
    p.add_argument("logfile", help="path to the access log, e.g. /var/log/nginx/access.log")
    p.add_argument("-n", "--notfound-threshold", type=int, default=15,
                   help="404 count that signals enumeration (default 15)")
    p.add_argument("-w", "--window", type=int, default=5, help="window in minutes (default 5)")
    p.add_argument("--json", metavar="FILE", help="write findings to a JSON file")
    args = p.parse_args()

    try:
        entries = parse_log(args.logfile)
    except OSError as e:
        sys.exit(f"Cannot open file: {e}")
    if not entries:
        sys.exit("No valid log lines found. Is this the combined log format?")

    findings = analyze(entries, args.notfound_threshold, args.window)
    print_report(entries, findings)

    if args.json:
        with open(args.json, "w") as f:
            json.dump(findings, f, indent=2)
        print(f"\nFindings written to {args.json}")


if __name__ == "__main__":
    main()