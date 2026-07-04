import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from asn_reality_audit.models import (
    ASNInfo,
    AuditReport,
    DiscoveryHTTPResult,
    DiscoveryTLSResult,
    DomainRelation,
    DomainResult,
    LongLivedDomainCandidate,
    RealityRecommendation,
    SamePrefixDomainDiscovery,
    ServerInfo,
)
from asn_reality_audit.report import (
    build_xray_suggestions,
    render_markdown,
    write_json_report,
)


def make_report() -> AuditReport:
    domain = DomainResult(
        domain="www.amd.com",
        serverName="www.amd.com",
        dest="www.amd.com:443",
        fingerprint="chrome",
        score=95,
        tls_ok=True,
        tls_version="TLSv1.3",
        cert_valid=True,
        cert_san_ok=True,
        latency_ms=38.0,
    )
    server_snippet, client_snippet = build_xray_suggestions(domain)
    return AuditReport(
        timestamp=datetime(2026, 7, 4, tzinfo=UTC),
        server=ServerInfo(ipv4="8.8.8.8", interface="ens3"),
        asn=ASNInfo(number=15169, name="GOOGLE", score=90, suitability="excellent"),
        top_domains=[domain],
        xray_server=server_snippet,
        xray_client=client_snippet,
    )


def test_json_uses_reality_field_aliases(tmp_path: Path) -> None:
    destination = write_json_report(make_report(), tmp_path)
    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert payload["top_domains"][0]["serverName"] == "www.amd.com"
    assert payload["top_domains"][0]["spiderX"] == "/"


def test_markdown_contains_snippets() -> None:
    markdown = render_markdown(make_report())
    assert "# ASN Reality Audit Report" in markdown
    assert '"privateKey": "<your-private-key>"' in markdown
    assert "www.amd.com" in markdown


@pytest.mark.skipif(os.name == "nt", reason="Creating symlinks is not generally permitted on Windows")
def test_json_report_replaces_symlink_without_following_it(tmp_path: Path) -> None:
    victim = tmp_path / "victim.txt"
    victim.write_text("do not replace", encoding="utf-8")
    output = tmp_path / "report"
    output.mkdir()
    (output / "report.json").symlink_to(victim)

    write_json_report(make_report(), output)

    assert victim.read_text(encoding="utf-8") == "do not replace"
    assert not (output / "report.json").is_symlink()


def test_discovery_report_schema_and_markdown_section(tmp_path: Path) -> None:
    report = make_report()
    report.same_prefix_domain_discovery = SamePrefixDomainDiscovery(
        prefix="8.8.8.0/24",
        asn=15169,
        scan_limit=16,
        sampled_ip_count=16,
        candidates=[
            LongLivedDomainCandidate(
                domain="old.example.com",
                score=88,
                rating="excellent",
                relation=DomainRelation.same_prefix,
                resolved_ips=["8.8.8.10"],
                domain_age_days=1200,
                earliest_ct_cert_age_days=900,
                tls=DiscoveryTLSResult(success=True, version="TLSv1.3", alpn=["h2"], cert_valid=True),
                http=DiscoveryHTTPResult(success=True, status_code=200, latency_ms=20),
                recommended_reality=RealityRecommendation(
                    serverName="old.example.com", dest="old.example.com:443"
                ),
                evidence={},
            )
        ],
    )
    payload = json.loads(write_json_report(report, tmp_path).read_text(encoding="utf-8"))
    discovery = payload["same_prefix_domain_discovery"]
    assert discovery["enabled"] is True
    assert discovery["candidates"][0]["relation"] == "same_prefix"
    markdown = render_markdown(report)
    assert "## Long-lived Same Prefix / Same ASN Domain Candidates" in markdown
    assert "old.example.com:443" in markdown
