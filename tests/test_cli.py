from pathlib import Path

from typer.testing import CliRunner

from asn_reality_audit import cli
from asn_reality_audit.models import ASNLookupResult, DomainResult, InterfaceInfo


def test_cli_writes_requested_reports(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        cli,
        "detect_default_interfaces",
        lambda include_ipv6: InterfaceInfo(default_interface_v4="ens3", local_ipv4="192.0.2.10"),
    )
    monkeypatch.setattr(
        cli,
        "lookup_asn",
        lambda ip, timeout: ASNLookupResult(
            ip=ip,
            asn=15169,
            asn_name="GOOGLE",
            organization="Google LLC",
            country="US",
            prefix="8.8.8.0/24",
            sources=["one", "two"],
        ),
    )
    monkeypatch.setattr(
        cli,
        "_probe_domains",
        lambda domains, timeout, include_ipv6, custom: [
            DomainResult(
                domain="www.python.org",
                serverName="www.python.org",
                dest="www.python.org:443",
                fingerprint="chrome",
                score=95,
                dns_ok=True,
                tcp_443_ok=True,
                tls_ok=True,
                tls_version="TLSv1.3",
                alpn="h2",
                cert_valid=True,
                cert_san_ok=True,
                latency_ms=25,
            )
        ],
    )

    output = tmp_path / "report"
    result = CliRunner().invoke(
        cli.app,
        ["--ip", "8.8.8.8", "--json", "--markdown", "--output", str(output)],
    )

    assert result.exit_code == 0, result.output
    assert (output / "report.json").is_file()
    assert (output / "report.md").is_file()
