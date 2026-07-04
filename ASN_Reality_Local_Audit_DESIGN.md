# DESIGN.md — Local ASN & Reality Domain Audit Tool

## 1. Project Name

`asn-reality-local-audit`

A simple local-only Linux CLI tool for VPS operators.

The tool detects the current server's public IP, resolves its ASN and BGP prefix, then tests a built-in list of candidate camouflage domains suitable for Xray / VLESS / Reality. It outputs a simple terminal report plus optional JSON and Markdown files.

No web dashboard.
No database.
No daemon.
No background service.
No mass scanning.
Only local one-shot diagnosis.

---

## 2. Goal

Build a simple but reliable command-line tool that runs directly on a VPS and answers these questions:

1. What is the current server public IPv4 / IPv6?
2. Which ASN does this IP belong to?
3. What BGP prefix is this IP inside?
4. Is this ASN generally suitable for Xray / VLESS / Reality usage?
5. Which Reality camouflage domains are better candidates for this server?
6. Which `serverName`, `dest`, and `fingerprint` values are recommended?

The tool should be simple enough to run with one command:

```bash
asn-reality-audit
```

---

## 3. Scope

### In Scope

- Detect local server public IPv4.
- Detect local server public IPv6 if available.
- Detect default network interface.
- Query ASN by IP.
- Query BGP prefix by IP.
- Query ASN organization and country.
- Classify ASN type roughly.
- Test built-in Reality camouflage domain candidates.
- Check DNS, TCP 443, TLS handshake, TLS version, ALPN, certificate validity, and latency.
- Score candidate domains.
- Recommend top domains for Reality.
- Generate Reality config suggestions.
- Output terminal report.
- Optional JSON report.
- Optional Markdown report.

### Out of Scope

- Web UI.
- API server.
- Database.
- User account system.
- Continuous monitoring.
- Telegram notification.
- Cloudflare API integration.
- Automatic Xray config overwrite.
- Mass port scanning.
- Scanning IP ranges.
- Testing random third-party IPs.

---

## 4. Target Environment

Primary target:

- Debian 12
- Ubuntu 22.04 / 24.04
- Root or normal user
- Python 3.10+

Preferred:

- Python 3.11+

The tool should work on a minimal VPS.

---

## 5. Recommended Tech Stack

Use Python.

Required libraries:

```toml
httpx>=0.27.0
typer>=0.12.0
rich>=13.7.0
pydantic>=2.7.0
dnspython>=2.6.0
cryptography>=42.0.0
```

Optional:

```toml
tabulate>=0.9.0
```

CLI entry command:

```bash
asn-reality-audit
```

---

## 6. CLI Examples

Default local audit:

```bash
asn-reality-audit
```

Specify IP manually:

```bash
asn-reality-audit --ip 209.248.57.58
```

Generate reports:

```bash
asn-reality-audit --json --markdown --output ./report
```

Use custom domain list:

```bash
asn-reality-audit --domain-list ./domains.txt
```

Show more details:

```bash
asn-reality-audit --verbose
```

Only print top 5 domains:

```bash
asn-reality-audit --top 5
```

---

## 7. CLI Options

```text
--ip TEXT                 Analyze a specific IP instead of auto-detecting local IP
--domain-list PATH        Use custom candidate domain list
--top INTEGER             Number of recommended domains to show, default 10
--json                    Write JSON report
--markdown                Write Markdown report
--output PATH             Output directory, default ./asn-reality-report
--timeout FLOAT           Network timeout in seconds, default 5
--no-ipv6                 Skip IPv6 detection and tests
--verbose                 Show detailed debug information
--version                 Show version
```

---

## 8. Public IP Detection

The tool should detect public IPv4 using multiple providers:

```text
https://api.ipify.org
https://ifconfig.me/ip
https://icanhazip.com
https://ipinfo.io/ip
```

For IPv6:

```text
https://api64.ipify.org
https://ifconfig.co/ip
https://icanhazip.com
```

Rules:

- Query multiple providers.
- Ignore failed providers.
- Prefer majority result.
- If results conflict, show a warning.
- If IPv6 is unavailable, continue with IPv4 only.

Example output:

```text
Public IPv4: 209.248.57.58
Public IPv6: 2405:84c0:8032:3900::1
Default interface: ens3
```

---

## 9. Local Interface Detection

Detect default route and interface.

Linux commands that may be used:

```bash
ip route get 1.1.1.1
ip -6 route get 2606:4700:4700::1111
ip a
```

The tool should parse the result and return:

```json
{
  "default_interface_v4": "ens3",
  "default_interface_v6": "ens3",
  "local_ipv4": "209.248.57.58",
  "local_ipv6": "2405:84c0:8032:3900::1"
}
```

---

## 10. ASN Lookup

Use at least two lookup methods if possible.

Primary options:

### 10.1 Team Cymru Whois

Query format:

```bash
whois -h whois.cymru.com " -v 209.248.57.58"
```

Or implement using TCP directly.

### 10.2 BGPView API

Example endpoint:

```text
https://api.bgpview.io/ip/209.248.57.58
```

### 10.3 RIPEstat API

Example endpoint:

```text
https://stat.ripe.net/data/network-info/data.json?resource=209.248.57.58
```

The tool should normalize data into one model.

Example normalized result:

```json
{
  "ip": "209.248.57.58",
  "asn": 20473,
  "asn_name": "AS-CHOOPA",
  "organization": "The Constant Company, LLC",
  "country": "US",
  "prefix": "209.248.56.0/22",
  "source": ["bgpview", "team_cymru"]
}
```

---

## 11. ASN Type Classification

The tool should classify ASN type roughly.

Possible values:

```text
hyperscaler
cdn
large_cloud
common_vps_provider
small_hosting
reseller_or_unknown
residential_isp
mobile_isp
unknown
```

Simple rule-based examples:

```text
AS16509  -> AWS / hyperscaler
AS15169  -> Google / hyperscaler
AS8075   -> Microsoft / hyperscaler
AS13335  -> Cloudflare / cdn
AS20940  -> Akamai / cdn
AS20473  -> Vultr / common_vps_provider
AS14061  -> DigitalOcean / common_vps_provider
AS63949  -> Linode / common_vps_provider
AS24940  -> Hetzner / common_vps_provider
```

If unknown:

```text
reseller_or_unknown
```

This does not need to be perfect. It only needs to give useful operational guidance.

---

## 12. ASN Suitability Score

Score range:

```text
0 - 100
```

Suggested scoring:

| Factor | Weight |
|---|---:|
| Large stable ASN | 25 |
| Reputable cloud/CDN/provider | 25 |
| Prefix not too small | 15 |
| Organization not suspicious | 15 |
| Country/region stability | 10 |
| Not unknown reseller | 10 |

Example result:

```json
{
  "asn_score": 76,
  "asn_suitability": "medium_good",
  "notes": [
    "Common VPS provider ASN",
    "Large enough to be stable",
    "May still be recognized as datacenter traffic"
  ]
}
```

Suitability levels:

```text
85-100 excellent
70-84  good
55-69  medium
40-54  weak
0-39   poor
```

---

## 13. Built-in Reality Domain Candidates

The tool should include a conservative built-in list.

Recommended initial list:

```text
www.microsoft.com
www.apple.com
www.cloudflare.com
www.akamai.com
www.fastly.com
www.amazon.com
www.mozilla.org
www.github.com
www.ibm.com
www.oracle.com
www.intel.com
www.amd.com
www.nvidia.com
www.docker.com
www.python.org
www.ubuntu.com
www.debian.org
www.lenovo.com
www.dell.com
www.asus.com
```

Do not include:

```text
government domains
bank domains
adult domains
political domains
news domains
small personal blogs
Chinese mainland domains
high-risk or controversial websites
domains that fail TLS validation
```

---

## 14. Domain Test Logic

For every candidate domain, test:

1. DNS resolution.
2. TCP connect to port 443.
3. TLS handshake with SNI.
4. TLS version.
5. ALPN support.
6. Certificate validity.
7. Certificate SAN contains domain.
8. Certificate expiration date.
9. HTTP HEAD request.
10. Latency.

### 14.1 DNS Test

Use `dnspython`.

Collect:

```json
{
  "domain": "www.amd.com",
  "a_records": ["23.45.67.89"],
  "aaaa_records": ["2600:1400::xxxx"]
}
```

### 14.2 TCP Test

Connect to:

```text
DOMAIN:443
```

Timeout default:

```text
5 seconds
```

### 14.3 TLS Test

Use Python `ssl`.

Required checks:

- Handshake success.
- SNI enabled.
- TLS version should be TLS 1.2 or TLS 1.3.
- Prefer TLS 1.3.
- Certificate must not be expired.
- Hostname validation must pass.

### 14.4 ALPN Test

Set ALPN protocols:

```python
["h2", "http/1.1"]
```

Record selected protocol.

### 14.5 HTTP Test

Perform:

```text
HEAD /
```

Accept status codes:

```text
200, 301, 302, 403, 405
```

Because many large sites block automated requests but still have valid TLS.

Reject:

```text
TLS failure
certificate error
connection timeout
DNS failure
```

---

## 15. Domain Score

Score range:

```text
0 - 100
```

Suggested scoring:

| Factor | Weight |
|---|---:|
| DNS resolves successfully | 10 |
| TCP 443 reachable | 15 |
| TLS handshake succeeds | 20 |
| TLS 1.3 supported | 10 |
| Certificate valid | 15 |
| ALPN h2 or http/1.1 | 10 |
| Low latency from VPS | 10 |
| Large reputable domain | 10 |

Domain score rules:

```text
90-100 excellent
80-89  very good
70-79  good
60-69  usable
0-59   not recommended
```

---

## 16. Fingerprint Recommendation

Default fingerprint:

```text
chrome
```

Rules:

```text
www.microsoft.com -> edge or chrome
www.apple.com     -> safari or chrome
www.mozilla.org   -> firefox or chrome
others            -> chrome
```

The output should include one primary recommendation only.

Example:

```json
{
  "domain": "www.microsoft.com",
  "recommended_fingerprint": "edge"
}
```

---

## 17. Reality Recommendation Output

For each top domain, output:

```json
{
  "serverName": "www.amd.com",
  "dest": "www.amd.com:443",
  "fingerprint": "chrome",
  "spiderX": "/"
}
```

Example terminal output:

```text
Top Reality Candidates

1. www.amd.com
   Score: 92/100
   TLS: OK, TLS 1.3
   ALPN: h2
   Latency: 38 ms
   serverName: www.amd.com
   dest: www.amd.com:443
   fingerprint: chrome
   spiderX: /

2. www.microsoft.com
   Score: 89/100
   TLS: OK, TLS 1.3
   ALPN: h2
   Latency: 42 ms
   serverName: www.microsoft.com
   dest: www.microsoft.com:443
   fingerprint: edge
   spiderX: /
```

---

## 18. Xray Reality Snippet

Generate a config snippet only as a suggestion.

Do not overwrite any config files.

Example:

```json
{
  "streamSettings": {
    "network": "tcp",
    "security": "reality",
    "realitySettings": {
      "show": false,
      "dest": "www.amd.com:443",
      "xver": 0,
      "serverNames": [
        "www.amd.com"
      ],
      "privateKey": "<your-private-key>",
      "shortIds": [
        "<your-short-id>"
      ]
    }
  }
}
```

Client suggestion:

```json
{
  "security": "reality",
  "sni": "www.amd.com",
  "fp": "chrome",
  "pbk": "<your-public-key>",
  "sid": "<your-short-id>",
  "spx": "/"
}
```

---

## 19. Output Files

When user passes:

```bash
--json
```

write:

```text
./asn-reality-report/report.json
```

When user passes:

```bash
--markdown
```

write:

```text
./asn-reality-report/report.md
```

---

## 20. JSON Report Format

Example:

```json
{
  "timestamp": "2026-07-04T00:00:00Z",
  "server": {
    "ipv4": "209.248.57.58",
    "ipv6": "2405:84c0:8032:3900::1",
    "interface": "ens3"
  },
  "asn": {
    "number": 20473,
    "name": "AS-CHOOPA",
    "organization": "The Constant Company, LLC",
    "country": "US",
    "prefix": "209.248.56.0/22",
    "type": "common_vps_provider",
    "score": 76,
    "suitability": "good"
  },
  "top_domains": [
    {
      "domain": "www.amd.com",
      "score": 92,
      "dns_ok": true,
      "tcp_443_ok": true,
      "tls_ok": true,
      "tls_version": "TLSv1.3",
      "alpn": "h2",
      "cert_valid": true,
      "latency_ms": 38,
      "serverName": "www.amd.com",
      "dest": "www.amd.com:443",
      "fingerprint": "chrome",
      "spiderX": "/"
    }
  ]
}
```

---

## 21. Markdown Report Format

Example:

```markdown
# ASN Reality Audit Report

## Server

- IPv4: `209.248.57.58`
- IPv6: `2405:84c0:8032:3900::1`
- Interface: `ens3`

## ASN

- ASN: `AS20473`
- Name: `AS-CHOOPA`
- Organization: `The Constant Company, LLC`
- Country: `US`
- Prefix: `209.248.56.0/22`
- Type: `common_vps_provider`
- Score: `76/100`
- Suitability: `good`

## Top Reality Domains

| Rank | Domain | Score | TLS | ALPN | Latency | Fingerprint |
|---:|---|---:|---|---|---:|---|
| 1 | www.amd.com | 92 | TLS 1.3 | h2 | 38 ms | chrome |
| 2 | www.microsoft.com | 89 | TLS 1.3 | h2 | 42 ms | edge |

## Recommended Reality Settings

```json
{
  "serverName": "www.amd.com",
  "dest": "www.amd.com:443",
  "fingerprint": "chrome",
  "spiderX": "/"
}
```

## Notes

This report is only a local network intelligence result. It cannot guarantee that an IP, ASN, or domain will remain reachable from all regions.
```

---

## 22. Project Structure

Keep it simple:

```text
asn-reality-local-audit/
├── README.md
├── DESIGN.md
├── pyproject.toml
├── src/
│   └── asn_reality_audit/
│       ├── __init__.py
│       ├── cli.py
│       ├── ip_detect.py
│       ├── asn_lookup.py
│       ├── domain_test.py
│       ├── scoring.py
│       ├── report.py
│       └── models.py
└── tests/
    ├── test_ip_detect.py
    ├── test_asn_lookup.py
    ├── test_domain_test.py
    └── test_scoring.py
```

No web folder.
No frontend.
No database.

---

## 23. MVP Implementation Order

Implement in this order:

1. CLI skeleton with Typer.
2. Public IPv4 detection.
3. Public IPv6 detection.
4. Default interface detection.
5. ASN lookup by IP.
6. Prefix lookup.
7. Basic ASN type classification.
8. Built-in domain list.
9. Domain DNS test.
10. Domain TCP 443 test.
11. Domain TLS test.
12. Domain scoring.
13. Terminal report.
14. JSON report.
15. Markdown report.
16. Reality recommendation snippet.

---

## 24. Error Handling

Examples:

### IP detection failed

```text
ERROR: Could not detect public IPv4. Please use --ip manually.
```

### ASN lookup failed

```text
WARNING: ASN lookup failed from primary provider. Trying fallback provider.
```

### Domain TLS failed

```text
SKIP: www.example.com failed TLS validation.
```

### No good domain found

```text
WARNING: No high-quality Reality camouflage domain found. Try a custom domain list with --domain-list.
```

---

## 25. Safety Requirements

The tool must:

- Not scan IP ranges.
- Not perform mass scanning.
- Only test built-in domains or user-provided domains.
- Rate-limit network requests.
- Use short timeouts.
- Clearly mark uncertain data.
- Never claim any ASN or domain is guaranteed to avoid blocking.
- Never automatically modify Xray config.
- Never send private server config to remote services except IP/ASN lookup APIs.

---

## 26. README Quick Start

The generated README should include:

```bash
git clone <repo>
cd asn-reality-local-audit
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
asn-reality-audit --json --markdown
```

Example one-line install after release:

```bash
pipx install git+https://github.com/<user>/asn-reality-local-audit.git
asn-reality-audit
```

---

## 27. Final Expected Behavior

When I run:

```bash
asn-reality-audit --json --markdown
```

I should get:

1. A terminal table showing current IP, ASN, prefix, and ASN score.
2. A ranked list of recommended Reality camouflage domains.
3. Suggested `serverName`, `dest`, `fingerprint`, and `spiderX`.
4. `report.json`.
5. `report.md`.

The tool should be simple, local, practical, and production-quality.
