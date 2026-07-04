from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.json import JSON
from rich.table import Table

from .models import AuditReport, DomainResult


def build_xray_suggestions(domain: DomainResult) -> tuple[dict[str, Any], dict[str, Any]]:
    server = {
        "streamSettings": {
            "network": "tcp",
            "security": "reality",
            "realitySettings": {
                "show": False,
                "dest": domain.dest,
                "xver": 0,
                "serverNames": [domain.server_name],
                "privateKey": "<your-private-key>",
                "shortIds": ["<your-short-id>"],
            },
        }
    }
    client = {
        "security": "reality",
        "sni": domain.server_name,
        "fp": domain.fingerprint,
        "pbk": "<your-public-key>",
        "sid": "<your-short-id>",
        "spx": domain.spider_x,
    }
    return server, client


def print_terminal_report(report: AuditReport, console: Console, verbose: bool = False) -> None:
    server_table = Table(title="Server & ASN", show_header=False, box=None)
    server_table.add_column("Field", style="bold cyan")
    server_table.add_column("Value")
    server_table.add_row("Public IPv4", report.server.ipv4 or "not detected")
    server_table.add_row("Public IPv6", report.server.ipv6 or "not detected")
    server_table.add_row("Default interface", report.server.interface or "not detected")
    server_table.add_row("ASN", f"AS{report.asn.number}" if report.asn.number else "unknown")
    server_table.add_row("ASN name", report.asn.name or "unknown")
    server_table.add_row("Organization", report.asn.organization or "unknown")
    server_table.add_row("Country", report.asn.country or "unknown")
    server_table.add_row("BGP prefix", report.asn.prefix or "unknown")
    server_table.add_row("ASN type", report.asn.type)
    server_table.add_row("ASN score", f"{report.asn.score}/100 ({report.asn.suitability})")
    console.print(server_table)

    domains = Table(title="Top Reality Candidates")
    domains.add_column("#", justify="right")
    domains.add_column("Domain", style="bold")
    domains.add_column("Score", justify="right")
    domains.add_column("TLS")
    domains.add_column("ALPN")
    domains.add_column("Latency", justify="right")
    domains.add_column("Fingerprint")
    for rank, item in enumerate(report.top_domains, 1):
        domains.add_row(
            str(rank),
            item.domain,
            f"{item.score}/100",
            item.tls_version or "failed",
            item.alpn or "—",
            f"{item.latency_ms:.1f} ms" if item.latency_ms is not None else "—",
            item.fingerprint,
        )
    console.print(domains)

    if report.top_domains:
        best = report.top_domains[0]
        console.print("\n[bold green]Recommended Reality settings[/bold green]")
        console.print(
            f"serverName: [cyan]{best.server_name}[/cyan]\n"
            f"dest: [cyan]{best.dest}[/cyan]\n"
            f"fingerprint: [cyan]{best.fingerprint}[/cyan]\n"
            f"spiderX: [cyan]{best.spider_x}[/cyan]"
        )
        if report.xray_server:
            console.print("\n[bold]Suggested Xray server snippet (not applied)[/bold]")
            console.print(JSON.from_data(report.xray_server))
    else:
        console.print("[yellow]No recommended domain passed the minimum score and TLS checks.[/yellow]")

    for warning in report.warnings:
        console.print(f"[yellow]WARNING:[/yellow] {warning}")
    if verbose:
        console.print("\n[dim]ASN notes: " + " ".join(report.asn.notes) + "[/dim]")


def write_json_report(report: AuditReport, output_dir: Path) -> Path:
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    destination = output_dir / "report.json"
    _atomic_write_text(
        destination,
        json.dumps(report.model_dump(mode="json", by_alias=True), indent=2, ensure_ascii=False) + "\n",
    )
    return destination


def _atomic_write_text(destination: Path, content: str) -> None:
    """Write without following an existing report-file symlink.

    NamedTemporaryFile uses restrictive permissions on POSIX. Replacing the final
    pathname atomically also replaces a malicious symlink instead of its target.
    """
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    except Exception:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise


def _display(value: object | None) -> str:
    return str(value) if value is not None else "not detected"


def render_markdown(report: AuditReport) -> str:
    rows = []
    for rank, item in enumerate(report.top_domains, 1):
        latency = f"{item.latency_ms:.1f} ms" if item.latency_ms is not None else "—"
        rows.append(
            f"| {rank} | {item.domain} | {item.score} | {item.tls_version or 'failed'} | "
            f"{item.alpn or '—'} | {latency} | {item.fingerprint} |"
        )
    if not rows:
        rows.append("| — | No qualifying candidate | — | — | — | — | — |")

    best_settings = None
    if report.top_domains:
        best = report.top_domains[0]
        best_settings = {
            "serverName": best.server_name,
            "dest": best.dest,
            "fingerprint": best.fingerprint,
            "spiderX": best.spider_x,
        }
    warnings = "\n".join(f"- {warning}" for warning in report.warnings) or "- None"
    server_snippet = json.dumps(report.xray_server, indent=2) if report.xray_server else "null"
    client_snippet = json.dumps(report.xray_client, indent=2) if report.xray_client else "null"
    settings = json.dumps(best_settings, indent=2) if best_settings else "null"
    return f"""# ASN Reality Audit Report

Generated: `{report.timestamp.isoformat()}`

## Server

- IPv4: `{_display(report.server.ipv4)}`
- IPv6: `{_display(report.server.ipv6)}`
- Interface: `{_display(report.server.interface)}`

## ASN

- ASN: `{'AS' + str(report.asn.number) if report.asn.number else 'unknown'}`
- Name: `{_display(report.asn.name)}`
- Organization: `{_display(report.asn.organization)}`
- Country: `{_display(report.asn.country)}`
- Prefix: `{_display(report.asn.prefix)}`
- Type: `{report.asn.type}`
- Score: `{report.asn.score}/100`
- Suitability: `{report.asn.suitability}`
- Sources: `{', '.join(report.asn.sources) or 'none'}`

## Top Reality Domains

| Rank | Domain | Score | TLS | ALPN | Latency | Fingerprint |
|---:|---|---:|---|---|---:|---|
{chr(10).join(rows)}

## Recommended Reality Settings

```json
{settings}
```

### Suggested Xray server snippet

```json
{server_snippet}
```

### Suggested client settings

```json
{client_snippet}
```

## Warnings

{warnings}

## Notes

This is a one-shot local network intelligence result. It cannot guarantee that an IP,
ASN, or domain will remain reachable from every region. The suggested configuration is
never applied automatically.
"""


def write_markdown_report(report: AuditReport, output_dir: Path) -> Path:
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    destination = output_dir / "report.md"
    _atomic_write_text(destination, render_markdown(report))
    return destination
