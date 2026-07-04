from asn_reality_audit.models import ASNLookupResult, DomainRelation, DomainResult
from asn_reality_audit.scoring import (
    classify_asn,
    score_asn,
    score_domain,
    score_long_lived_domain,
)


def domain_result(**overrides: object) -> DomainResult:
    values = {
        "domain": "www.example.com",
        "serverName": "www.example.com",
        "dest": "www.example.com:443",
        "fingerprint": "chrome",
        "dns_ok": True,
        "tcp_443_ok": True,
        "tls_ok": True,
        "tls_version": "TLSv1.3",
        "cert_valid": True,
        "cert_san_ok": True,
        "alpn": "h2",
        "latency_ms": 50.0,
    }
    values.update(overrides)
    return DomainResult(**values)


def test_perfect_domain_score() -> None:
    result = score_domain(domain_result())
    assert result.score == 100
    assert result.rating == "excellent"


def test_failed_tls_is_not_recommended() -> None:
    result = score_domain(domain_result(tls_ok=False, tls_version=None, cert_valid=False, cert_san_ok=False))
    assert result.score < 60
    assert result.rating == "not recommended"


def test_known_asn_classification_and_score() -> None:
    lookup = ASNLookupResult(
        ip="8.8.8.8",
        asn=15169,
        asn_name="GOOGLE",
        organization="Google LLC",
        country="US",
        prefix="8.8.8.0/24",
        sources=["test"],
    )
    result = score_asn(lookup)
    assert classify_asn(15169, None) == "hyperscaler"
    assert result.suitability == "excellent"
    assert 0 <= result.score <= 100


def test_long_lived_domain_scoring_rewards_age_and_relation() -> None:
    score, rating = score_long_lived_domain(
        domain_result(http_ok=True),
        DomainRelation.same_prefix,
        domain_age_days=1000,
        ct_age_days=800,
        wayback_age_days=None,
        minimum_age_days=365,
    )
    assert score == 100
    assert rating == "excellent"
