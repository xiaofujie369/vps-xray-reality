from __future__ import annotations

import ipaddress
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.exception
import dns.resolver
from cryptography import x509
from cryptography.x509.oid import NameOID

from .ct_lookup import CTResult, query_crtsh
from .domain_age import (
    days_since,
    is_sensitive_domain,
    normalize_domain,
    registered_domain,
)
from .domain_test import recommended_fingerprint, test_domain
from .models import (
    DiscoveryEvidence,
    DiscoveryHTTPResult,
    DiscoveryTLSResult,
    DomainDiscoveryConfig,
    DomainRelation,
    DomainResult,
    LongLivedDomainCandidate,
    RealityRecommendation,
    RejectedDomain,
    SamePrefixDomainDiscovery,
)
from .rdap_lookup import RDAPResult, query_domain_rdap
from .relation import classify_relation
from .scoring import score_long_lived_domain

MAX_DISCOVERED_DOMAINS = 32
MAX_CT_ROOTS = 8
MAX_RDAP_ROOTS = 8
DISCOVERY_WORKERS = 4


def sample_prefix_ips(prefix: str, current_ip: str, limit: int) -> list[str]:
    if not 1 <= limit <= 256:
        raise ValueError("Prefix scan limit must be between 1 and 256")
    network = ipaddress.ip_network(prefix, strict=False)
    current = ipaddress.ip_address(current_ip)
    if current.version != network.version:
        raise ValueError("Current IP and BGP prefix use different address families")

    if network.version == 4 and network.prefixlen <= 30:
        first = int(network.network_address) + 1
        last = int(network.broadcast_address) - 1
    elif network.version == 6 and network.num_addresses > 1:
        first = int(network.network_address) + 1
        last = int(network.broadcast_address)
    else:
        first = int(network.network_address)
        last = int(network.broadcast_address)
    if last < first:
        return []

    selected: list[int] = []

    def add(value: int) -> None:
        if first <= value <= last and value not in selected and len(selected) < limit:
            selected.append(value)

    if current in network:
        add(int(current))
        for distance in range(1, 5):
            add(int(current) - distance)
            add(int(current) + distance)
    for offset in range(8):
        add(first + offset)

    span = last - first
    slots = max(limit, 2)
    for index in range(slots):
        add(first + (span * index // (slots - 1)))
    if len(selected) < limit and span < 1024:
        for value in range(first, last + 1):
            add(value)
    return [str(ipaddress.ip_address(value)) for value in selected]


def reverse_ptr_names(ip: str, timeout: float) -> set[str]:
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = timeout
    resolver.lifetime = timeout
    try:
        answer = resolver.resolve_address(ip)
    except (dns.exception.DNSException, OSError):
        return set()
    names: set[str] = set()
    for item in answer:
        domain = normalize_domain(str(item))
        if domain:
            names.add(domain)
    return names


def certificate_names_from_ip(ip: str, timeout: float) -> set[str]:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(["h2", "http/1.1"])
    try:
        with socket.create_connection((ip, 443), timeout=timeout) as raw_socket:
            raw_socket.settimeout(timeout)
            with context.wrap_socket(raw_socket) as tls_socket:
                certificate = x509.load_der_x509_certificate(tls_socket.getpeercert(binary_form=True))
    except (OSError, ssl.SSLError, ValueError):
        return set()

    return certificate_domains(certificate)


def certificate_domains(certificate: x509.Certificate) -> set[str]:
    """Return normalized SAN DNS names, with CN as a legacy fallback."""

    values: list[str] = []
    try:
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        values.extend(san.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        values.extend(
            attribute.value for attribute in certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        )
    return {domain for value in values if (domain := normalize_domain(value))}


def _discover_names_for_ip(ip: str, config: DomainDiscoveryConfig) -> tuple[set[str], set[str]]:
    ptr = reverse_ptr_names(ip, config.timeout)
    certificate = (
        certificate_names_from_ip(ip, config.timeout)
        if config.allow_light_probe and not config.passive_only
        else set()
    )
    return ptr, certificate


def _collect_ip_discovery(
    sampled_ips: list[str], config: DomainDiscoveryConfig
) -> dict[str, set[str]]:
    sources: dict[str, set[str]] = {}
    with ThreadPoolExecutor(max_workers=min(DISCOVERY_WORKERS, len(sampled_ips))) as executor:
        futures = {}
        for ip in sampled_ips:
            futures[executor.submit(_discover_names_for_ip, ip, config)] = ip
            time.sleep(0.02)
        for future in as_completed(futures):
            try:
                ptr_names, certificate_names = future.result()
            except Exception:
                ptr_names, certificate_names = set(), set()
            for domain in ptr_names:
                sources.setdefault(domain, set()).add("ptr")
            for domain in certificate_names:
                sources.setdefault(domain, set()).add("tls_cert_san")
    return sources


def _ct_enrichment(
    sources: dict[str, set[str]], timeout: float
) -> tuple[dict[str, CTResult], list[str]]:
    roots = sorted({registered_domain(domain) for domain in sources})[:MAX_CT_ROOTS]
    results: dict[str, CTResult] = {}
    errors: list[str] = []
    if not roots:
        return results, errors
    with ThreadPoolExecutor(max_workers=min(3, len(roots))) as executor:
        futures = {executor.submit(query_crtsh, root, timeout): root for root in roots}
        for future in as_completed(futures):
            root = futures[future]
            try:
                result = future.result()
            except Exception as exc:
                result = CTResult(error=f"Certificate Transparency unavailable: {exc}")
            results[root] = result
            if result.error:
                errors.append(result.error)
            for domain in result.domains:
                if len(sources) >= MAX_DISCOVERED_DOMAINS:
                    break
                sources.setdefault(domain, set()).add("certificate_transparency")
    return results, errors


def _probe_discovered_domains(domains: list[str], timeout: float) -> dict[str, DomainResult | Exception]:
    results: dict[str, DomainResult | Exception] = {}
    if not domains:
        return results
    with ThreadPoolExecutor(max_workers=min(DISCOVERY_WORKERS, len(domains))) as executor:
        futures = {}
        for domain in domains:
            futures[executor.submit(test_domain, domain, timeout, True, False)] = domain
            time.sleep(0.03)
        for future in as_completed(futures):
            domain = futures[future]
            try:
                results[domain] = future.result()
            except Exception as exc:
                results[domain] = exc
    return results


def discover_same_prefix_domains(
    current_ip: str,
    prefix: str | None,
    current_asn: int | None,
    config: DomainDiscoveryConfig,
) -> SamePrefixDomainDiscovery:
    report = SamePrefixDomainDiscovery(
        prefix=prefix,
        asn=current_asn,
        scan_limit=config.prefix_scan_limit,
        min_domain_age_days=config.min_domain_age_days,
        mode="light_probe" if config.allow_light_probe and not config.passive_only else "passive",
    )
    if not prefix:
        report.errors.append("BGP prefix is unavailable; prefix discovery was skipped.")
        return report
    try:
        sampled_ips = sample_prefix_ips(prefix, current_ip, config.prefix_scan_limit)
    except ValueError as exc:
        report.errors.append(str(exc))
        return report
    report.sampled_ip_count = len(sampled_ips)

    sources = _collect_ip_discovery(sampled_ips, config)
    rejected: dict[str, str] = {}
    if config.exclude_sensitive:
        for domain in list(sources):
            if is_sensitive_domain(domain):
                rejected[domain] = "sensitive_category"
                del sources[domain]

    ct_results, ct_errors = _ct_enrichment(sources, config.timeout)
    if ct_errors and len(ct_errors) == len(ct_results):
        report.errors.append("Certificate Transparency enrichment was unavailable.")

    if config.exclude_sensitive:
        for domain in list(sources):
            if is_sensitive_domain(domain):
                rejected[domain] = "sensitive_category"
                del sources[domain]

    domains = sorted(sources)[:MAX_DISCOVERED_DOMAINS]
    probes = _probe_discovered_domains(domains, config.timeout)
    asn_cache: dict[str, int | None] = {}
    rdap_results: dict[str, RDAPResult] = {}
    candidates: list[LongLivedDomainCandidate] = []

    for domain in domains:
        probe = probes.get(domain)
        if isinstance(probe, Exception) or probe is None:
            rejected[domain] = "current_probe_failed"
            continue
        if not probe.dns_ok:
            rejected[domain] = "dns_failed"
            continue
        if not probe.tls_ok or not probe.cert_valid or not probe.cert_san_ok:
            rejected[domain] = "invalid_tls"
            continue
        if probe.tls_version not in {"TLSv1.2", "TLSv1.3"}:
            rejected[domain] = "unsupported_tls_version"
            continue

        resolved_ips = probe.a_records + probe.aaaa_records
        network = ipaddress.ip_network(prefix, strict=False)
        in_prefix = any(
            (address := ipaddress.ip_address(value)).version == network.version and address in network
            for value in resolved_ips
        )
        if in_prefix:
            relation = DomainRelation.same_prefix
        elif config.same_asn_only or config.include_external_cdn:
            relation = classify_relation(
                resolved_ips, prefix, current_asn, config.timeout, asn_cache
            )
        else:
            relation = DomainRelation.unrelated
        allowed = relation == DomainRelation.same_prefix
        if relation == DomainRelation.same_asn and config.same_asn_only:
            allowed = True
        if relation == DomainRelation.external_cdn and config.include_external_cdn:
            allowed = True
        if config.same_prefix_only:
            allowed = relation == DomainRelation.same_prefix
        if not allowed:
            rejected[domain] = f"relation_{relation.value}_not_enabled"
            continue

        root = registered_domain(domain)
        ct = ct_results.get(root) or CTResult(error="Certificate Transparency query cap reached")
        if root not in rdap_results:
            if len(rdap_results) < MAX_RDAP_ROOTS:
                rdap_results[root] = query_domain_rdap(root, config.timeout)
            else:
                rdap_results[root] = RDAPResult(error="RDAP query cap reached")
        rdap = rdap_results[root]
        domain_age_days = days_since(rdap.creation_date)
        ct_first_seen = ct.first_seen(domain)
        ct_age_days = days_since(ct_first_seen)
        age_values = [value for value in (domain_age_days, ct_age_days) if value is not None]
        if not age_values:
            rejected[domain] = "insufficient_age_evidence"
            continue
        if max(age_values) < config.min_domain_age_days:
            rejected[domain] = "domain_age_below_threshold"
            continue

        score, rating = score_long_lived_domain(
            probe,
            relation,
            domain_age_days,
            ct_age_days,
            None,
            config.min_domain_age_days,
        )
        if score < 60:
            rejected[domain] = "score_below_recommendation_threshold"
            continue
        candidates.append(
            LongLivedDomainCandidate(
                domain=domain,
                score=score,
                rating=rating,
                relation=relation,
                resolved_ips=resolved_ips,
                domain_age_days=domain_age_days,
                earliest_ct_cert_age_days=ct_age_days,
                tls=DiscoveryTLSResult(
                    success=probe.tls_ok,
                    version=probe.tls_version,
                    alpn=[probe.alpn] if probe.alpn else [],
                    cert_valid=probe.cert_valid and probe.cert_san_ok,
                    issuer=probe.cert_issuer,
                    not_before=probe.cert_not_before,
                    not_after=probe.cert_expires_at,
                ),
                http=DiscoveryHTTPResult(
                    success=probe.http_ok,
                    status_code=probe.http_status,
                    latency_ms=probe.http_latency_ms,
                ),
                recommended_reality=RealityRecommendation(
                    serverName=domain,
                    dest=f"{domain}:443",
                    fingerprint=recommended_fingerprint(domain),
                    spiderX="/",
                ),
                evidence=DiscoveryEvidence(
                    ptr="ptr" in sources.get(domain, set()),
                    tls_cert_san="tls_cert_san" in sources.get(domain, set()),
                    rdap=rdap.source_available and rdap.creation_date is not None,
                    certificate_transparency=ct.source_available and ct_first_seen is not None,
                    current_tls_probe=True,
                    current_http_probe=probe.http_status is not None,
                ),
                errors=[value for value in (rdap.error, ct.error, probe.error) if value],
            )
        )

    report.candidates = sorted(
        candidates,
        key=lambda item: (-item.score, item.http.latency_ms or float("inf"), item.domain),
    )
    report.rejected = [
        RejectedDomain(domain=domain, reason=reason)
        for domain, reason in sorted(rejected.items())
    ]
    if not sources:
        report.errors.append("No candidate hostnames were discovered from sampled prefix addresses.")
    return report
