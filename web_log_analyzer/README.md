# Web Log Analyzer

Detects attack attempts in nginx and Apache access logs. Python standard library only.

## Detections

| Category | Examples |
|----------|----------|
| SQL injection | `UNION SELECT`, `' OR 1=1`, `SLEEP()`, `information_schema` |
| Cross-site scripting | `<script>`, `onerror=`, `javascript:` |
| Path traversal | `../`, `/etc/passwd`, double-encoded variants (`%252e%252e%252f`) |
| Command injection | `; cat`, `\| whoami`, `$(...)` |
| Scanner tools | sqlmap, nikto, gobuster, nuclei, wpscan, and others |
| Directory enumeration | Bursts of 404 responses from a single IP |
| Sensitive path probing | `/.env`, `/.git`, `/phpmyadmin`, `/admin` |

## Usage

```bash
python web_log_analyzer.py /var/log/nginx/access.log
python web_log_analyzer.py access.log -n 15 -w 5 --json findings.json
```

| Option | Description | Default |
|--------|-------------|---------|
| `-n, --notfound-threshold` | 404 count that signals enumeration | 15 |
| `-w, --window` | Time window in minutes | 5 |
| `--json FILE` | Write findings to a JSON file | off |

To try it with synthetic data:

```bash
python generate_sample_log.py
python web_log_analyzer.py sample_access.log
```

## Severity

- **HIGH**: an injection payload received a 2xx or 5xx response. This does not prove exploitation, but the endpoint should be reviewed.
- **MEDIUM**: attack payloads that were rejected, or a known scanner user agent.
- **LOW**: reconnaissance only (enumeration or sensitive path probing).

## How it works

1. Parses each line of the combined log format with a regular expression.
2. URL-decodes each request path twice, to catch double-encoded payloads.
3. Matches decoded paths against attack signatures and sensitive path lists.
4. Detects enumeration with a sliding window over 404 timestamps per IP.
5. Groups findings by IP and assigns a severity.

## Limitations

- Signature-based: obfuscated or novel payloads can be missed, and legitimate requests can occasionally match.
- Only the request line and user agent are inspected. POST bodies are not logged by default.
- User agents are trivially spoofed, so a missing scanner name proves nothing.
- Requires the combined log format.

## Disclaimer

For defensive use only. Run it on logs from systems you own or are authorized to monitor.