from __future__ import annotations

import ipaddress

import httpx

from .models import DomainRelation

MAJOR_CDN_ASNS = {
    714, 8075, 13335, 14618, 15169, 16509, 16625, 20940, 31898, 32934,
    36459, 396982, 54113,
}


def routed_asn(ip: str, timeout: float, cache: dict[str, int | None]) -> int | None:
    if ip in cache:
        return cache[ip]
    try:
        response = httpx.get(
            "https://stat.ripe.net/data/network-info/data.json",
            params={"resource": ip},
            timeout=timeout,
            follow_redirects=True,
            trust_env=False,
        )
        response.raise_for_status()
        asns = (response.json().get("data") or {}).get("asns") or []
        value = int(asns[0]) if asns else None
    except (httpx.HTTPError, ValueError, TypeError, KeyError, IndexError):
        value = None
    cache[ip] = value
    return value


def classify_relation(
    resolved_ips: list[str],
    prefix: str,
    current_asn: int | None,
    timeout: float,
    asn_cache: dict[str, int | None],
) -> DomainRelation:
    network = ipaddress.ip_network(prefix, strict=False)
    parsed = [ipaddress.ip_address(value) for value in resolved_ips]
    if any(address.version == network.version and address in network for address in parsed):
        return DomainRelation.same_prefix

    routed = [routed_asn(str(address), timeout, asn_cache) for address in parsed[:4]]
    if current_asn and current_asn in routed:
        return DomainRelation.same_asn
    if any(asn in MAJOR_CDN_ASNS for asn in routed if asn is not None):
        return DomainRelation.external_cdn
    return DomainRelation.unrelated
