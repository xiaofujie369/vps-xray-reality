# ASN Reality Local Audit

A local-only, one-shot CLI for VPS operators. It detects the server's public IP and
default interface, looks up ASN/BGP information, tests a conservative list of HTTPS
domains, ranks Reality camouflage candidates, and suggests Xray Reality settings.

It has no web UI, database, daemon, monitoring mode, or automatic Xray configuration.
It only probes TCP port 443 on the built-in domains or domains you explicitly provide.

## Supported systems and requirements

- Debian 12, Ubuntu 22.04/24.04, and derivatives or vendor images based on them
- Python 3.11+
- Outbound DNS, HTTPS, and optionally Whois TCP/43 access
- `iproute2` is recommended for default-interface detection; the audit still runs if
  a minimal vendor image does not provide the `ip` command

The program does not depend on `systemd`, a particular package manager, root access,
or distribution-specific Python paths. Ubuntu 22.04 images commonly ship Python 3.10,
so install a vendor-supported Python 3.11+ build before running the installer.

## Install

The portable installer discovers Python 3.11+, creates a private virtual environment
under the current user's home directory, and never invokes `sudo`:

```bash
git clone https://github.com/xiaofujie369/vps-xray-reality.git
cd vps-xray-reality
./scripts/install.sh --local
```

Ensure `~/.local/bin` is in `PATH`, then run `asn-reality-audit --version`.

On minimal Debian/Ubuntu images, Python may be installed without its virtual-environment
support. Install the matching package before rerunning the installer, for example:

```bash
apt-get update
apt-get install -y python3.11-venv
```

The installer checks `ensurepip` before creating anything and prints the package name
matching the selected Python version. A failed installation does not create the command;
after installing the package, simply rerun `./scripts/install.sh --local`.

Manual virtual-environment installation remains available:

```bash
python3.11 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

For development and tests:

```bash
python -m pip install -e ".[dev]"
```

After a GitHub release, a `pipx` installation can use:

```bash
pipx install --python python3.11 git+https://github.com/xiaofujie369/vps-xray-reality.git
```

## Usage

Run the default local audit:

```bash
asn-reality-audit
```

Generate both reports:

```bash
asn-reality-audit --json --markdown --output ./asn-reality-report
```

Audit a specific IP, show five recommendations, and skip IPv6 probes:

```bash
asn-reality-audit --ip 209.248.57.58 --top 5 --no-ipv6
```

Use a custom list containing one domain per line (`#` starts a comment):

```bash
asn-reality-audit --domain-list ./domains.txt --verbose
```

Custom lists are limited to 100 unique names. Run `asn-reality-audit --help` for all
options.

## Long-lived same-prefix domain discovery

The optional discovery mode samples only the current server's BGP prefix and looks for
HTTPS names that have long-lived RDAP registration or Certificate Transparency history.
It is disabled unless `--discover-prefix-domains` is supplied.

Conservative passive discovery (PTR, CT, and RDAP):

```bash
asn-reality-audit \
  --discover-prefix-domains \
  --passive-only \
  --min-domain-age-days 365 \
  --json --markdown
```

Allow bounded prefix probes. This samples at most 64 addresses by default and only
connects to TCP/443, performs one TLS handshake without SNI, and extracts certificate
CN/SAN names. It never probes another port or brute-forces SNI:

```bash
asn-reality-audit \
  --discover-prefix-domains \
  --allow-light-probe \
  --prefix-scan-limit 64 \
  --min-domain-age-days 365 \
  --json --markdown \
  --output ./asn-reality-report
```

Strict exact-prefix mode:

```bash
asn-reality-audit --discover-prefix-domains --same-prefix-only --allow-light-probe
```

To broaden recommendations, `--same-asn-only` also permits names routed elsewhere in
the current ASN, while `--include-external-cdn` permits recognized large CDNs and
hyperscalers. External CDN results are disabled by default.

Relations mean:

- `same_prefix`: at least one resolved address is inside the current BGP prefix.
- `same_asn`: outside the exact prefix but routed by the current ASN.
- `external_cdn`: routed by a recognized major CDN or hyperscaler.
- `unrelated`: none of the above; never recommended by default.

A candidate needs valid current DNS/TLS plus at least one age signal meeting the chosen
threshold. Its separate 0-100 score combines RDAP age, exact-name CT history, current
TLS/certificate/ALPN/HTTP health, latency, and network relation. Scores below 60 are not
recommended.

Example discovery output:

```text
 Long-lived Same Prefix / Same ASN Domain Candidates
 #  Domain           Score   Relation     Age    CT history  TLS      HTTP
 1  old.example.com  88/100  same_prefix  1420d  1300d       TLSv1.3  200

 Prefix: 77.73.14.0/24 | sampled IPs: 64/64 | mode: light_probe
 serverName: old.example.com
 dest: old.example.com:443
 fingerprint: chrome
 spiderX: /
```

## Sample output

```text
                 Server & ASN
 Public IPv4       209.248.57.58
 Public IPv6       not detected
 Default interface ens3
 ASN               AS20473
 Organization      The Constant Company, LLC
 BGP prefix         209.248.56.0/22
 ASN score          90/100 (excellent)

                        Top Reality Candidates
 #  Domain             Score    TLS       ALPN  Latency  Fingerprint
 1  www.amd.com        95/100   TLSv1.3   h2    38.2 ms  chrome
 2  www.microsoft.com  92/100   TLSv1.3   h2    42.0 ms  edge

 Recommended Reality settings
 serverName: www.amd.com
 dest: www.amd.com:443
 fingerprint: chrome
 spiderX: /
```

Actual results depend on the VPS route, resolver, remote server behavior, and time of
the audit. A recommendation is operational guidance, not a reachability guarantee.

## Reports

Reports are only written when their flags are supplied:

- `report.json` is machine-readable. It contains the UTC timestamp, public/local
  interface details, normalized ASN data and sources, ranked domain measurements, and
  suggested server/client Reality snippets.
- `report.md` is a human-readable summary with an ASN section, ranked table, warnings,
  and copyable JSON snippets.

Both default to `./asn-reality-report/`; change this with `--output`. Reports are
written atomically with restrictive temporary-file permissions. Existing report files
in that directory are replaced, but no Xray configuration is read or changed.
Placeholders such as `<your-private-key>` must be filled in by the operator.

## Tests

```bash
python -m pytest
```

The test suite uses deterministic mocks and does not require live network access.
CI runs it on Debian 12, Ubuntu 22.04, and Ubuntu 24.04. It also validates the installer
syntax and runs Ruff, `pip-audit`, and Bandit checks.

## How scoring works

Domain scores follow the design weights: DNS (10), TCP/443 (15), TLS handshake (20),
TLS 1.3 (10), valid matching certificate (15), ALPN (10), latency (10), and domain
reputation (10). Candidates below 60 or without valid TLS/certificates are excluded.
ASN classification and suitability are deliberately rough, rule-based guidance.

## Safety

The program does not scan address ranges or arbitrary ports. It uses short timeouts,
at most four domain workers, and only contacts public-IP/ASN services plus the selected
candidate domains. It never claims that a result will avoid blocking and never modifies
Xray automatically.

Reports contain public network metadata and placeholder Xray settings only; real private
keys are never read. External public-IP and ASN providers necessarily receive the IP
being queried. Run the CLI as an ordinary user unless your environment specifically
requires otherwise.

Discovery has additional safeguards: it is opt-in, defaults to passive methods, samples
64 addresses with a hard maximum of 256, limits concurrency, caps discovered domains,
and only permits direct prefix probes on port 443 after `--allow-light-probe`. It performs
no vulnerability checks, exploit payloads, range expansion, or Xray modification.

Passive data is inherently incomplete. PTR, RDAP, and crt.sh may be unavailable or
rate-limited; registered-domain extraction uses a conservative built-in suffix list
rather than a heavyweight Public Suffix dependency; Wayback evidence and optional
external scanner accelerators are not implemented. Small VPS/reseller prefixes commonly
produce no candidates. No recommendation guarantees reachability or filtering bypass.
