from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from functools import lru_cache

import httpx

from .domain_age import normalize_domain, parse_timestamp, registered_domain


@dataclass(frozen=True)
class CTResult:
    earliest_certificate: datetime | None = None
    domains: tuple[str, ...] = field(default_factory=tuple)
    domain_first_seen: tuple[tuple[str, datetime], ...] = field(default_factory=tuple)
    source_available: bool = False
    error: str | None = None

    def first_seen(self, domain: str) -> datetime | None:
        return dict(self.domain_first_seen).get(domain)


def parse_ct_records(records: list[dict[str, object]], root_domain: str) -> CTResult:
    earliest: datetime | None = None
    domains: set[str] = set()
    first_seen: dict[str, datetime] = {}
    for record in records:
        timestamp = parse_timestamp(str(record.get("entry_timestamp") or record.get("not_before") or ""))
        if timestamp and (earliest is None or timestamp < earliest):
            earliest = timestamp
        for value in str(record.get("name_value") or "").splitlines():
            domain = normalize_domain(value)
            if domain and registered_domain(domain) == root_domain:
                domains.add(domain)
                if timestamp and (domain not in first_seen or timestamp < first_seen[domain]):
                    first_seen[domain] = timestamp
    return CTResult(
        earliest_certificate=earliest,
        domains=tuple(sorted(domains)[:50]),
        domain_first_seen=tuple(sorted(first_seen.items())),
        source_available=True,
    )


@lru_cache(maxsize=128)
def query_crtsh(root_domain: str, timeout: float = 5.0) -> CTResult:
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True, trust_env=False) as client:
            with client.stream(
                "GET",
                "https://crt.sh/",
                params={"q": f"%.{root_domain}", "output": "json"},
            ) as response:
                response.raise_for_status()
                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > 5 * 1024 * 1024:
                        raise ValueError("crt.sh response exceeded 5 MiB")
        records = json.loads(body)
        if not isinstance(records, list):
            raise ValueError("crt.sh returned an unexpected JSON shape")
        return parse_ct_records(records, root_domain)
    except (httpx.HTTPError, ValueError, TypeError, json.JSONDecodeError) as exc:
        return CTResult(error=f"Certificate Transparency unavailable: {exc}")
