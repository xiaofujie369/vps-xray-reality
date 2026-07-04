from __future__ import annotations

import ipaddress
import re
import socket
import ssl
import time
from datetime import datetime, timezone

import dns.exception
import dns.resolver
import httpx
from cryptography import x509

from .models import DomainResult
from .scoring import score_domain


BUILTIN_DOMAINS = (
    "www.microsoft.com",
    "www.apple.com",
    "www.cloudflare.com",
    "www.akamai.com",
    "www.fastly.com",
    "www.amazon.com",
    "www.mozilla.org",
    "www.github.com",
    "www.ibm.com",
    "www.oracle.com",
    "www.intel.com",
    "www.amd.com",
    "www.nvidia.com",
    "www.docker.com",
    "www.python.org",
    "www.ubuntu.com",
    "www.debian.org",
    "www.lenovo.com",
    "www.dell.com",
    "www.asus.com",
)

ACCEPTED_HTTP_STATUSES = {200, 301, 302, 403, 405}
DOMAIN_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
MAX_CUSTOM_DOMAINS = 100


def recommended_fingerprint(domain: str) -> str:
    if domain == "www.microsoft.com":
        return "edge"
    if domain == "www.apple.com":
        return "safari"
    if domain == "www.mozilla.org":
        return "firefox"
    return "chrome"


def _resolve(domain: str, timeout: float, include_ipv6: bool) -> tuple[list[str], list[str], float]:
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = timeout
    resolver.lifetime = timeout
    started = time.perf_counter()
    records: dict[str, list[str]] = {"A": [], "AAAA": []}
    types = ("A", "AAAA") if include_ipv6 else ("A",)
    for record_type in types:
        try:
            answer = resolver.resolve(domain, record_type, search=False)
            records[record_type] = sorted({item.address for item in answer})[:16]
        except (dns.exception.DNSException, OSError):
            continue
    latency = (time.perf_counter() - started) * 1000
    return records["A"], records["AAAA"], latency


def _address_tuple(address: str) -> tuple[object, ...]:
    if ipaddress.ip_address(address).version == 6:
        return (address, 443, 0, 0)
    return (address, 443)


def _connect(addresses: list[str], timeout: float) -> tuple[socket.socket, str, float]:
    last_error: OSError | None = None
    for address in addresses:
        family = socket.AF_INET6 if ipaddress.ip_address(address).version == 6 else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        started = time.perf_counter()
        try:
            sock.connect(_address_tuple(address))
            return sock, address, (time.perf_counter() - started) * 1000
        except OSError as exc:
            last_error = exc
            sock.close()
    raise last_error or OSError("No resolved address was reachable")


def _san_matches(domain: str, names: list[str]) -> bool:
    domain = domain.lower()
    for name in names:
        pattern = name.lower()
        if pattern == domain:
            return True
        if pattern.startswith("*.") and domain.endswith(pattern[1:]) and domain.count(".") == pattern.count("."):
            return True
    return False


def test_domain(
    domain: str,
    timeout: float = 5.0,
    include_ipv6: bool = True,
    reputable: bool = True,
) -> DomainResult:
    result = DomainResult(
        domain=domain,
        serverName=domain,
        dest=f"{domain}:443",
        fingerprint=recommended_fingerprint(domain),
        spiderX="/",
    )
    try:
        a_records, aaaa_records, dns_latency = _resolve(domain, timeout, include_ipv6)
        result.a_records = a_records
        result.aaaa_records = aaaa_records
        result.dns_latency_ms = round(dns_latency, 1)
        addresses = a_records + aaaa_records
        result.dns_ok = bool(addresses)
        if not addresses:
            result.error = "DNS resolution failed"
            return score_domain(result, reputable)

        tcp_socket, _, tcp_latency = _connect(addresses, timeout)
        tcp_socket.close()
        result.tcp_443_ok = True
        result.tcp_latency_ms = round(tcp_latency, 1)

        raw_socket, _, _ = _connect(addresses, timeout)
        context = ssl.create_default_context()
        context.set_alpn_protocols(["h2", "http/1.1"])
        tls_started = time.perf_counter()
        with context.wrap_socket(raw_socket, server_hostname=domain) as tls_socket:
            result.latency_ms = round((time.perf_counter() - tls_started) * 1000, 1)
            result.tls_ok = True
            result.tls_version = tls_socket.version()
            result.alpn = tls_socket.selected_alpn_protocol()
            der_certificate = tls_socket.getpeercert(binary_form=True)
            parsed = x509.load_der_x509_certificate(der_certificate)
            expires = parsed.not_valid_after_utc
            result.cert_expires_at = expires
            result.cert_valid = expires > datetime.now(timezone.utc)
            try:
                san = parsed.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                names = san.get_values_for_type(x509.DNSName)
                result.cert_san_ok = _san_matches(domain, names)
            except x509.ExtensionNotFound:
                result.cert_san_ok = False

        # Client-side IPv4 source selection, not a listening socket.
        ipv4_unspecified = str(ipaddress.IPv4Address(0))
        transport = httpx.HTTPTransport(local_address=ipv4_unspecified) if not include_ipv6 else None
        with httpx.Client(
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
            transport=transport,
            headers={"User-Agent": "Mozilla/5.0 (compatible; asn-reality-audit/0.1)"},
        ) as client:
            # A streaming HEAD prevents a non-compliant custom server from forcing
            # an unbounded response body into memory.
            with client.stream("HEAD", f"https://{domain}/") as response:
                result.http_status = response.status_code
                result.http_ok = response.status_code in ACCEPTED_HTTP_STATUSES
    except ssl.SSLCertVerificationError as exc:
        result.error = f"TLS certificate validation failed: {exc.verify_message}"
    except (ssl.SSLError, OSError, httpx.HTTPError, ValueError) as exc:
        result.error = f"{type(exc).__name__}: {exc}"
    return score_domain(result, reputable)


def load_domain_list(path: str) -> list[str]:
    domains: list[str] = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            domain = line.strip().lower().rstrip(".")
            if not domain or domain.startswith("#"):
                continue
            try:
                domain = domain.encode("idna").decode("ascii")
            except UnicodeError as exc:
                raise ValueError(f"Invalid domain: {domain}") from exc
            labels = domain.split(".")
            if len(domain) > 253 or len(labels) < 2 or any(not DOMAIN_LABEL.fullmatch(label) for label in labels):
                raise ValueError(f"Invalid domain: {domain}")
            if domain not in domains:
                domains.append(domain)
                if len(domains) > MAX_CUSTOM_DOMAINS:
                    raise ValueError(f"Domain lists are limited to {MAX_CUSTOM_DOMAINS} unique candidates")
    if not domains:
        raise ValueError("Domain list contains no candidates")
    return domains
