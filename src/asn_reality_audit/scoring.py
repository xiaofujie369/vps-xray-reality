from __future__ import annotations

import ipaddress

from .models import ASNInfo, ASNLookupResult, DomainResult


ASN_TYPES: dict[int, str] = {
    16509: "hyperscaler",
    15169: "hyperscaler",
    8075: "hyperscaler",
    13335: "cdn",
    20940: "cdn",
    54113: "cdn",
    20473: "common_vps_provider",
    14061: "common_vps_provider",
    63949: "common_vps_provider",
    24940: "common_vps_provider",
    16276: "common_vps_provider",
    31898: "large_cloud",
}


def classify_asn(asn: int | None, organization: str | None) -> str:
    if asn in ASN_TYPES:
        return ASN_TYPES[asn]  # type: ignore[index]
    text = (organization or "").lower()
    if any(word in text for word in ("amazon", "google", "microsoft", "oracle cloud")):
        return "hyperscaler"
    if any(word in text for word in ("cloudflare", "akamai", "fastly", "cdn")):
        return "cdn"
    if any(word in text for word in ("hosting", "host", "cloud", "datacenter", "data center")):
        return "small_hosting"
    if any(word in text for word in ("mobile", "wireless", "cellular")):
        return "mobile_isp"
    if any(word in text for word in ("telecom", "broadband", "internet service", "cable")):
        return "residential_isp"
    return "reseller_or_unknown"


def _prefix_score(prefix: str | None) -> int:
    if not prefix:
        return 0
    try:
        network = ipaddress.ip_network(prefix, strict=False)
    except ValueError:
        return 0
    if network.version == 4:
        return 15 if network.prefixlen <= 20 else 10 if network.prefixlen <= 24 else 5 if network.prefixlen <= 28 else 0
    return 15 if network.prefixlen <= 40 else 10 if network.prefixlen <= 48 else 5 if network.prefixlen <= 56 else 0


def score_asn(result: ASNLookupResult) -> ASNInfo:
    asn_type = classify_asn(result.asn, result.organization or result.asn_name)
    stability, reputation = {
        "hyperscaler": (25, 25),
        "cdn": (25, 25),
        "large_cloud": (23, 23),
        "common_vps_provider": (20, 20),
        "residential_isp": (20, 15),
        "mobile_isp": (18, 12),
        "small_hosting": (12, 12),
        "reseller_or_unknown": (5, 5),
    }.get(asn_type, (5, 5))
    prefix_points = _prefix_score(result.prefix)
    organization = result.organization or result.asn_name
    suspicious = any(
        word in (organization or "").lower()
        for word in ("bulletproof", "anonymous", "proxy", "offshore", "vpn")
    )
    organization_points = 0 if suspicious else 15 if organization else 4
    country_points = 10 if result.country else 3
    known_points = 10 if asn_type != "reseller_or_unknown" else 0
    score = min(100, stability + reputation + prefix_points + organization_points + country_points + known_points)
    suitability = (
        "excellent" if score >= 85 else
        "good" if score >= 70 else
        "medium" if score >= 55 else
        "weak" if score >= 40 else
        "poor"
    )
    notes = [
        {
            "hyperscaler": "Large hyperscaler ASN with generally stable routing.",
            "cdn": "Large CDN ASN with generally stable routing.",
            "large_cloud": "Large cloud provider ASN.",
            "common_vps_provider": "Common VPS provider ASN; traffic may be recognized as datacenter traffic.",
            "small_hosting": "Hosting ASN with limited reputation data.",
            "residential_isp": "Likely residential ISP ASN.",
            "mobile_isp": "Likely mobile network ASN.",
            "reseller_or_unknown": "Unknown or reseller ASN classification; treat the score as uncertain.",
        }.get(asn_type, "ASN classification is uncertain.")
    ]
    if not result.prefix:
        notes.append("BGP prefix was not returned by lookup providers.")
    if suspicious:
        notes.append("Organization name contains a higher-risk hosting keyword.")
    return ASNInfo(
        number=result.asn,
        name=result.asn_name,
        organization=result.organization,
        country=result.country,
        prefix=result.prefix,
        type=asn_type,
        score=score,
        suitability=suitability,
        notes=notes,
        sources=result.sources,
    )


def score_domain(result: DomainResult, reputable: bool = True) -> DomainResult:
    score = 0
    score += 10 if result.dns_ok else 0
    score += 15 if result.tcp_443_ok else 0
    score += 20 if result.tls_ok else 0
    score += 10 if result.tls_version == "TLSv1.3" else 0
    score += 15 if result.cert_valid and result.cert_san_ok else 0
    score += 10 if result.alpn in {"h2", "http/1.1"} else 0
    if result.latency_ms is not None:
        score += 10 if result.latency_ms <= 100 else 7 if result.latency_ms <= 250 else 4 if result.latency_ms <= 500 else 0
    score += 10 if reputable else 5
    result.score = min(100, score)
    result.rating = (
        "excellent" if result.score >= 90 else
        "very good" if result.score >= 80 else
        "good" if result.score >= 70 else
        "usable" if result.score >= 60 else
        "not recommended"
    )
    return result
