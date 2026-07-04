import json
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

from asn_reality_audit.models import ASNInfo, AuditReport, DomainResult, ServerInfo
from asn_reality_audit.report import build_xray_suggestions, render_markdown, write_json_report


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
        timestamp=datetime(2026, 7, 4, tzinfo=timezone.utc),
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
