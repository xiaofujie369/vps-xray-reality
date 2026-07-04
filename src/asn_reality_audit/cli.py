from __future__ import annotations

import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from . import __version__
from .asn_lookup import lookup_asn
from .domain_test import BUILTIN_DOMAINS, load_domain_list, test_domain
from .ip_detect import detect_default_interfaces, detect_public_ips
from .models import AuditReport, DomainResult, ServerInfo
from .report import build_xray_suggestions, print_terminal_report, write_json_report, write_markdown_report
from .scoring import score_asn


app = typer.Typer(
    name="asn-reality-audit",
    help="Run a local one-shot ASN and Xray Reality domain audit.",
    add_completion=False,
    no_args_is_help=False,
)
console = Console()


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"asn-reality-audit {__version__}")
        raise typer.Exit()


def _probe_domains(
    domains: list[str], timeout: float, include_ipv6: bool, custom: bool
) -> list[DomainResult]:
    results: list[DomainResult] = []
    with Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(f"Testing {len(domains)} Reality domain candidates", total=None)
        with ThreadPoolExecutor(max_workers=min(4, len(domains))) as executor:
            futures = {
                executor.submit(
                    test_domain,
                    domain,
                    timeout,
                    include_ipv6,
                    domain in BUILTIN_DOMAINS if custom else True,
                ): domain
                for domain in domains
            }
            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except Exception as exc:  # Defensive isolation: one candidate must not abort the audit.
                    domain = futures[future]
                    results.append(
                        DomainResult(
                            domain=domain,
                            serverName=domain,
                            dest=f"{domain}:443",
                            fingerprint="chrome",
                            spiderX="/",
                            error=f"Unexpected probe error: {exc}",
                        )
                    )
        progress.update(task, description="Domain tests complete")
    return sorted(results, key=lambda item: (-item.score, item.latency_ms or float("inf"), item.domain))


@app.command()
def main(
    ip: Annotated[str | None, typer.Option("--ip", help="Analyze this IP instead of detecting it.")] = None,
    domain_list: Annotated[Path | None, typer.Option("--domain-list", exists=True, dir_okay=False, readable=True)] = None,
    top: Annotated[int, typer.Option("--top", min=1, max=100, help="Number of recommendations to show.")] = 10,
    json_report: Annotated[bool, typer.Option("--json", help="Write report.json.")] = False,
    markdown: Annotated[bool, typer.Option("--markdown", help="Write report.md.")] = False,
    output: Annotated[Path, typer.Option("--output", file_okay=False, help="Report output directory.")] = Path("asn-reality-report"),
    timeout: Annotated[float, typer.Option("--timeout", min=0.5, max=30.0, help="Per-operation network timeout.")] = 5.0,
    no_ipv6: Annotated[bool, typer.Option("--no-ipv6", help="Skip IPv6 detection and domain addresses.")] = False,
    verbose: Annotated[bool, typer.Option("--verbose", help="Show failed probes and lookup details.")] = False,
    version: Annotated[bool, typer.Option("--version", callback=_version_callback, is_eager=True)] = False,
) -> None:
    """Audit the current server and conservative Reality camouflage candidates."""
    del version
    include_ipv6 = not no_ipv6
    warnings: list[str] = []

    manual_ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    if ip:
        try:
            manual_ip = ipaddress.ip_address(ip)
        except ValueError:
            console.print(f"[red]ERROR:[/red] Invalid IP address: {ip}")
            raise typer.Exit(2)
        if manual_ip.version == 6 and no_ipv6:
            console.print("[red]ERROR:[/red] An IPv6 --ip cannot be used with --no-ipv6.")
            raise typer.Exit(2)

    with console.status("Detecting server network identity..."):
        interfaces = detect_default_interfaces(include_ipv6=include_ipv6)
        if manual_ip:
            ipv4 = manual_ip.compressed if manual_ip.version == 4 else None
            ipv6 = manual_ip.compressed if manual_ip.version == 6 else None
        else:
            detected = detect_public_ips(timeout=timeout, include_ipv6=include_ipv6)
            ipv4, ipv6 = detected.ipv4, detected.ipv6
            warnings.extend(detected.warnings)

    lookup_ip = ipv4 or ipv6
    if not lookup_ip:
        console.print("[red]ERROR:[/red] Could not detect public IPv4 or IPv6. Please use --ip manually.")
        raise typer.Exit(1)

    server = ServerInfo(
        ipv4=ipv4,
        ipv6=ipv6,
        interface=interfaces.default_interface_v4 or interfaces.default_interface_v6,
        interface_v4=interfaces.default_interface_v4,
        interface_v6=interfaces.default_interface_v6,
        local_ipv4=interfaces.local_ipv4,
        local_ipv6=interfaces.local_ipv6,
    )

    with console.status(f"Looking up ASN data for {lookup_ip}..."):
        lookup = lookup_asn(lookup_ip, timeout=timeout)
        asn = score_asn(lookup)
    if not asn.number:
        warnings.append("ASN lookup failed from all providers; ASN fields and score are uncertain.")
    elif len(asn.sources) < 2:
        warnings.append("ASN data came from only one provider and could not be cross-checked.")

    try:
        domains = load_domain_list(str(domain_list)) if domain_list else list(BUILTIN_DOMAINS)
    except (OSError, ValueError) as exc:
        console.print(f"[red]ERROR:[/red] Could not load domain list: {exc}")
        raise typer.Exit(2)
    if len(domains) > 100:
        console.print("[red]ERROR:[/red] Domain lists are limited to 100 unique candidates.")
        raise typer.Exit(2)

    results = _probe_domains(domains, timeout, include_ipv6, custom=domain_list is not None)
    if verbose:
        for result in results:
            if result.error:
                console.print(f"[dim]SKIP/DETAIL: {result.domain}: {result.error}[/dim]")

    qualifying = [
        result for result in results
        if result.score >= 60 and result.tls_ok and result.cert_valid and result.cert_san_ok
    ]
    top_domains = qualifying[:top]
    if not top_domains:
        warnings.append("No high-quality Reality camouflage domain was found. Try a custom --domain-list.")

    xray_server = xray_client = None
    if top_domains:
        xray_server, xray_client = build_xray_suggestions(top_domains[0])
    report = AuditReport(
        timestamp=datetime.now(timezone.utc),
        server=server,
        asn=asn,
        top_domains=top_domains,
        xray_server=xray_server,
        xray_client=xray_client,
        warnings=warnings,
    )
    print_terminal_report(report, console, verbose=verbose)

    written: list[Path] = []
    try:
        if json_report:
            written.append(write_json_report(report, output))
        if markdown:
            written.append(write_markdown_report(report, output))
    except OSError as exc:
        console.print(f"[red]ERROR:[/red] Could not write reports to {output}: {exc}")
        raise typer.Exit(1)
    for path in written:
        console.print(f"[green]Wrote[/green] {path.resolve()}")


if __name__ == "__main__":
    app()
