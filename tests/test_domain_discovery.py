from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from asn_reality_audit.ct_lookup import CTResult
from asn_reality_audit.domain_age import is_sensitive_domain
from asn_reality_audit.domain_discovery import (
    _discover_names_for_ip,
    certificate_domains,
    discover_same_prefix_domains,
    reverse_ptr_names,
    sample_prefix_ips,
)
from asn_reality_audit.models import DomainDiscoveryConfig, DomainResult
from asn_reality_audit.rdap_lookup import RDAPResult


def test_prefix_sampling_is_bounded_and_includes_current_ip() -> None:
    sampled = sample_prefix_ips("77.73.14.0/24", "77.73.14.112", 64)
    assert len(sampled) == 64
    assert sampled[0] == "77.73.14.112"
    assert "77.73.14.0" not in sampled
    assert "77.73.14.255" not in sampled
    assert len(set(sampled)) == len(sampled)


def test_reverse_ptr_hostname_extraction(monkeypatch) -> None:
    class FakeResolver:
        timeout = 0.0
        lifetime = 0.0

        def resolve_address(self, ip: str) -> list[str]:
            assert ip == "192.0.2.10"
            return ["Host.Example.COM.", "not a domain"]

    monkeypatch.setattr("asn_reality_audit.domain_discovery.dns.resolver.Resolver", lambda configure: FakeResolver())
    assert reverse_ptr_names("192.0.2.10", 1.0) == {"host.example.com"}


def test_tls_certificate_san_extraction() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "legacy.example.com")])
    now = datetime.now(UTC).replace(tzinfo=None)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("www.example.com"), x509.DNSName("*.example.net")]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    assert certificate_domains(certificate) == {"www.example.com", "example.net"}


def test_sensitive_domain_filter_is_conservative() -> None:
    assert is_sensitive_domain("online-bank.example")
    assert is_sensitive_domain("agency.gov")
    assert not is_sensitive_domain("www.example.com")


def test_passive_mode_never_runs_direct_certificate_probe(monkeypatch) -> None:
    monkeypatch.setattr(
        "asn_reality_audit.domain_discovery.reverse_ptr_names",
        lambda ip, timeout: {"ptr.example.com"},
    )
    monkeypatch.setattr(
        "asn_reality_audit.domain_discovery.certificate_names_from_ip",
        lambda ip, timeout: (_ for _ in ()).throw(AssertionError("active probe called")),
    )
    ptr, certificates = _discover_names_for_ip(
        "192.0.2.10",
        DomainDiscoveryConfig(passive_only=True, allow_light_probe=True),
    )
    assert ptr == {"ptr.example.com"}
    assert certificates == set()


def test_discovery_builds_old_same_prefix_candidate(monkeypatch) -> None:
    old = datetime.now(UTC) - timedelta(days=900)
    probe = DomainResult(
        domain="old.example.com",
        serverName="old.example.com",
        dest="old.example.com:443",
        fingerprint="chrome",
        dns_ok=True,
        a_records=["77.73.14.80"],
        tcp_443_ok=True,
        tls_ok=True,
        tls_version="TLSv1.3",
        alpn="h2",
        cert_valid=True,
        cert_san_ok=True,
        cert_not_before=old,
        cert_expires_at=datetime.now(UTC) + timedelta(days=30),
        latency_ms=20,
        http_ok=True,
        http_status=200,
        http_latency_ms=25,
    )
    monkeypatch.setattr(
        "asn_reality_audit.domain_discovery._collect_ip_discovery",
        lambda sampled, config: {"old.example.com": {"ptr"}},
    )
    monkeypatch.setattr(
        "asn_reality_audit.domain_discovery._ct_enrichment",
        lambda sources, timeout: (
            {
                "example.com": CTResult(
                    earliest_certificate=old,
                    domain_first_seen=(("old.example.com", old),),
                    source_available=True,
                )
            },
            [],
        ),
    )
    monkeypatch.setattr(
        "asn_reality_audit.domain_discovery._probe_discovered_domains",
        lambda domains, timeout: {"old.example.com": probe},
    )
    monkeypatch.setattr(
        "asn_reality_audit.domain_discovery.query_domain_rdap",
        lambda root, timeout: RDAPResult(creation_date=old, source_available=True),
    )

    result = discover_same_prefix_domains(
        "77.73.14.112",
        "77.73.14.0/24",
        7488,
        DomainDiscoveryConfig(enabled=True, prefix_scan_limit=16),
    )

    assert result.sampled_ip_count == 16
    assert result.candidates[0].domain == "old.example.com"
    assert result.candidates[0].score == 100
    assert result.candidates[0].relation.value == "same_prefix"
