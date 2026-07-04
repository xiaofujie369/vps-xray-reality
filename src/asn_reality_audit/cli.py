from __future__ import annotations

import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from . import __version__
from .asn_lookup import lookup_asn
from .domain_discovery import discover_same_prefix_domains
from .domain_test import BUILTIN_DOMAINS, load_domain_list, test_domain
from .ip_detect import detect_default_interfaces, detect_public_ips
from .models import AuditReport, DomainDiscoveryConfig, DomainResult, ServerInfo
from .report import (
    build_xray_suggestions,
    print_terminal_report,
    write_json_report,
    write_markdown_report,
)
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
    discover_prefix_domains: Annotated[bool, typer.Option("--discover-prefix-domains", help="Discover long-lived HTTPS domains related to this prefix.")] = False,
    prefix_scan_limit: Annotated[int, typer.Option("--prefix-scan-limit", min=1, max=256, help="Maximum sampled IPs in the current prefix.")] = 64,
    passive_only: Annotated[bool, typer.Option("--passive-only", help="Do not probe sampled IP addresses on TCP/443.")] = False,
    allow_light_probe: Annotated[bool, typer.Option("--allow-light-probe", help="Allow bounded TCP/443 and TLS probes of sampled prefix IPs.")] = False,
    min_domain_age_days: Annotated[int, typer.Option("--min-domain-age-days", min=1, max=36500, help="Minimum RDAP or CT history age.")] = 365,
    same_prefix_only: Annotated[bool, typer.Option("--same-prefix-only", help="Only recommend names resolving inside the current prefix.")] = False,
    same_asn_only: Annotated[bool, typer.Option("--same-asn-only", help="Also allow names resolving elsewhere in the current ASN.")] = False,
    include_external_cdn: Annotated[bool, typer.Option("--include-external-cdn", help="Allow known CDN/hyperscaler relations.")] = False,
    exclude_sensitive: Annotated[bool, typer.Option("--exclude-sensitive/--no-exclude-sensitive", help="Exclude sensitive domain categories.")] = True,
    discovery_timeout: Annotated[float, typer.Option("--discovery-timeout", min=0.5, max=30.0, help="Discovery operation timeout.")] = 5.0,
    verbose: Annotated[bool, typer.Option("--verbose", help="Show failed probes and lookup details.")] = False,
    version: Annotated[bool, typer.Option("--version", callback=_version_callback, is_eager=True)] = False,
) -> None:
    """Audit the current server and conservative Reality camouflage candidates."""
    del version
    include_ipv6 = not no_ipv6
    warnings: list[str] = []
    if passive_only and allow_light_probe:
        console.print("[red]ERROR:[/red] --passive-only and --allow-light-probe cannot be combined.")
        raise typer.Exit(2)
    if same_prefix_only and same_asn_only:
        console.print("[red]ERROR:[/red] --same-prefix-only and --same-asn-only cannot be combined.")
        raise typer.Exit(2)

    manual_ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    if ip:
        try:
            manual_ip = ipaddress.ip_address(ip)
        except ValueError:
            console.print(f"[red]ERROR:[/red] Invalid IP address: {ip}")
            raise typer.Exit(2) from None
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
        raise typer.Exit(2) from None
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

    discovery = None
    if discover_prefix_domains:
        discovery_config = DomainDiscoveryConfig(
            enabled=True,
            prefix_scan_limit=prefix_scan_limit,
            passive_only=passive_only or not allow_light_probe,
            allow_light_probe=allow_light_probe,
            min_domain_age_days=min_domain_age_days,
            same_prefix_only=same_prefix_only,
            same_asn_only=same_asn_only,
            include_external_cdn=include_external_cdn,
            exclude_sensitive=exclude_sensitive,
            timeout=discovery_timeout,
        )
        mode = "light 443/TLS" if allow_light_probe else "passive"
        with console.status(f"Discovering long-lived prefix domains ({mode}, limit {prefix_scan_limit})..."):
            discovery = discover_same_prefix_domains(
                current_ip=lookup_ip,
                prefix=asn.prefix,
                current_asn=asn.number,
                config=discovery_config,
            )
        if not discovery.candidates:
            warnings.append(
                "No long-lived same-prefix domains were found; this is common for small or reseller prefixes."
            )

    report = AuditReport(
        timestamp=datetime.now(UTC),
        server=server,
        asn=asn,
        top_domains=top_domains,
        xray_server=xray_server,
        xray_client=xray_client,
        same_prefix_domain_discovery=discovery,
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
        raise typer.Exit(1) from None
    for path in written:
        console.print(f"[green]Wrote[/green] {path.resolve()}")


if __name__ == "__main__":
    app()
