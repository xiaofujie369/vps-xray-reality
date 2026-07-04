from __future__ import annotations

import ipaddress
import re
import shutil
# Only fixed argv is used below; shell execution is never enabled.
import subprocess  # nosec B404
from collections import Counter

import httpx

from .models import IPDetection, InterfaceInfo


IPV4_PROVIDERS = (
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
    "https://ipinfo.io/ip",
)

IPV6_PROVIDERS = (
    "https://api64.ipify.org",
    "https://ifconfig.co/ip",
    "https://icanhazip.com",
)


def _valid_provider_ip(value: str, version: int) -> str | None:
    try:
        parsed = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if parsed.version != version or not parsed.is_global:
        return None
    return parsed.compressed


def _choose_consensus(observations: dict[str, str]) -> tuple[str | None, bool]:
    if not observations:
        return None, False
    counts = Counter(observations.values())
    winner, _ = counts.most_common(1)[0]
    return winner, len(counts) > 1


def detect_public_ips(timeout: float = 5.0, include_ipv6: bool = True) -> IPDetection:
    observations: dict[int, dict[str, str]] = {4: {}, 6: {}}
    providers = {4: IPV4_PROVIDERS, 6: IPV6_PROVIDERS if include_ipv6 else ()}

    for version, urls in providers.items():
        if not urls:
            continue
        # Binding the address family prevents an IPv6 provider URL from silently
        # reporting the IPv4 egress address (and vice versa).
        # Client-side source-family selection, not a listening socket.
        local_address = (
            str(ipaddress.IPv4Address(0)) if version == 4 else str(ipaddress.IPv6Address(0))
        )
        transport = httpx.HTTPTransport(local_address=local_address)
        with httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            trust_env=False,
            transport=transport,
        ) as client:
            for url in urls:
                try:
                    with client.stream(
                        "GET", url, headers={"User-Agent": "asn-reality-audit/0.1"}
                    ) as response:
                        response.raise_for_status()
                        body = bytearray()
                        for chunk in response.iter_bytes():
                            body.extend(chunk)
                            if len(body) > 256:
                                raise ValueError("Public IP provider response was too large")
                    value = _valid_provider_ip(body.decode("ascii", errors="strict"), version)
                    if value:
                        observations[version][url] = value
                except (httpx.HTTPError, OSError, UnicodeError, ValueError):
                    continue

    ipv4, conflict_v4 = _choose_consensus(observations[4])
    ipv6, conflict_v6 = _choose_consensus(observations[6])
    warnings: list[str] = []
    if conflict_v4:
        warnings.append("Public IPv4 providers returned conflicting results; majority result selected.")
    if conflict_v6:
        warnings.append("Public IPv6 providers returned conflicting results; majority result selected.")
    if include_ipv6 and not ipv6:
        warnings.append("Public IPv6 was not detected; continuing with IPv4 only.")

    return IPDetection(
        ipv4=ipv4,
        ipv6=ipv6,
        ipv4_observations=observations[4],
        ipv6_observations=observations[6],
        warnings=warnings,
    )


def parse_route_output(output: str) -> tuple[str | None, str | None]:
    interface_match = re.search(r"(?:^|\s)dev\s+(\S+)", output)
    source_match = re.search(r"(?:^|\s)src\s+(\S+)", output)
    return (
        interface_match.group(1) if interface_match else None,
        source_match.group(1) if source_match else None,
    )


def _route_get(destination: str, ipv6: bool = False) -> tuple[str | None, str | None]:
    if not shutil.which("ip"):
        return None, None
    command = ["ip"]
    if ipv6:
        command.append("-6")
    command.extend(["route", "get", destination])
    try:
        # Both the executable and destination arguments are constants.
        result = subprocess.run(  # nosec B603
            command,
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None, None
    if result.returncode != 0:
        return None, None
    return parse_route_output(result.stdout)


def detect_default_interfaces(include_ipv6: bool = True) -> InterfaceInfo:
    interface_v4, local_v4 = _route_get("1.1.1.1")
    interface_v6: str | None = None
    local_v6: str | None = None
    if include_ipv6:
        interface_v6, local_v6 = _route_get("2606:4700:4700::1111", ipv6=True)
    return InterfaceInfo(
        default_interface_v4=interface_v4,
        default_interface_v6=interface_v6,
        local_ipv4=local_v4,
        local_ipv6=local_v6,
    )
