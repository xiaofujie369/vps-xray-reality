from __future__ import annotations

import ipaddress
import socket
from typing import Any

import httpx

from .models import ASNLookupResult


def _as_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(str(value).upper().removeprefix("AS"))
    except ValueError:
        return None


def lookup_bgpview(ip: str, timeout: float) -> ASNLookupResult | None:
    url = f"https://api.bgpview.io/ip/{ip}"
    try:
        response = httpx.get(url, timeout=timeout, follow_redirects=True, trust_env=False)
        response.raise_for_status()
        payload = response.json()
        data = payload.get("data") or {}
        prefixes = data.get("prefixes") or []
        prefix_data = prefixes[0] if prefixes else {}
        asn_data = prefix_data.get("asn") or {}
        allocation = data.get("rir_allocation") or {}
        asn = _as_int(asn_data.get("asn"))
        prefix = prefix_data.get("prefix")
        if not asn and not prefix:
            return None
        return ASNLookupResult(
            ip=ip,
            asn=asn,
            asn_name=asn_data.get("name"),
            organization=asn_data.get("description") or asn_data.get("description_short"),
            country=asn_data.get("country_code") or allocation.get("country_code"),
            prefix=prefix,
            sources=["bgpview"],
        )
    except (httpx.HTTPError, ValueError, TypeError, KeyError):
        return None


def lookup_ripe(ip: str, timeout: float) -> ASNLookupResult | None:
    network_url = "https://stat.ripe.net/data/network-info/data.json"
    try:
        response = httpx.get(
            network_url,
            params={"resource": ip},
            timeout=timeout,
            follow_redirects=True,
            trust_env=False,
        )
        response.raise_for_status()
        data = (response.json().get("data") or {})
        asns = data.get("asns") or []
        asn = _as_int(asns[0]) if asns else None
        prefix = data.get("prefix")
        if not asn and not prefix:
            return None

        name: str | None = None
        organization: str | None = None
        country: str | None = None
        if asn:
            try:
                overview = httpx.get(
                    "https://stat.ripe.net/data/as-overview/data.json",
                    params={"resource": f"AS{asn}"},
                    timeout=timeout,
                    follow_redirects=True,
                    trust_env=False,
                )
                if overview.is_success:
                    overview_data = overview.json().get("data") or {}
                    name = overview_data.get("holder")
                    organization = overview_data.get("holder")
            except (httpx.HTTPError, ValueError, TypeError):
                # Keep the already useful prefix/ASN response if enrichment fails.
                pass

        return ASNLookupResult(
            ip=ip,
            asn=asn,
            asn_name=name,
            organization=organization,
            country=country,
            prefix=prefix,
            sources=["ripe_stat"],
        )
    except (httpx.HTTPError, ValueError, TypeError, KeyError, IndexError):
        return None


def lookup_team_cymru(ip: str, timeout: float) -> ASNLookupResult | None:
    query = f"begin\nverbose\n{ip}\nend\n".encode("ascii")
    maximum_response_bytes = 256 * 1024
    try:
        with socket.create_connection(("whois.cymru.com", 43), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(query)
            chunks: list[bytes] = []
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
                if sum(map(len, chunks)) > maximum_response_bytes:
                    return None
        lines = b"".join(chunks).decode("utf-8", errors="replace").splitlines()
        data_line = next(
            (line for line in lines if "|" in line and not line.lstrip().upper().startswith("AS")),
            None,
        )
        if not data_line:
            return None
        fields = [field.strip() for field in data_line.split("|")]
        if len(fields) < 7:
            return None
        asn = _as_int(fields[0])
        if not asn:
            return None
        as_name = fields[7] if len(fields) > 7 else None
        return ASNLookupResult(
            ip=ip,
            asn=asn,
            asn_name=as_name,
            organization=as_name,
            country=fields[3] or None,
            prefix=fields[2] or None,
            sources=["team_cymru"],
        )
    except (OSError, socket.timeout):
        return None


def _merge(results: list[ASNLookupResult], ip: str) -> ASNLookupResult:
    merged = ASNLookupResult(ip=ip)
    for result in results:
        for field in ("asn", "asn_name", "organization", "country", "prefix"):
            if getattr(merged, field) is None and getattr(result, field) is not None:
                setattr(merged, field, getattr(result, field))
        merged.sources.extend(source for source in result.sources if source not in merged.sources)
    return merged


def lookup_asn(ip: str, timeout: float = 5.0) -> ASNLookupResult:
    ipaddress.ip_address(ip)
    results: list[ASNLookupResult] = []
    # HTTP lookups are attempted first because outbound TCP/43 is commonly blocked.
    for lookup in (lookup_bgpview, lookup_ripe, lookup_team_cymru):
        result = lookup(ip, timeout)
        if result:
            results.append(result)
    return _merge(results, ip)
