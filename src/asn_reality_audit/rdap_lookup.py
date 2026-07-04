from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache
from urllib.parse import quote

import httpx

from .domain_age import parse_timestamp


@dataclass(frozen=True)
class RDAPResult:
    creation_date: datetime | None = None
    source_available: bool = False
    error: str | None = None


def creation_date_from_rdap(payload: dict[str, object]) -> datetime | None:
    creation: datetime | None = None
    events = payload.get("events") or []
    if not isinstance(events, list):
        return None
    for event in events:
        if not isinstance(event, dict):
            continue
        action = str(event.get("eventAction") or "").lower()
        if action in {"registration", "registered", "creation"}:
            parsed = parse_timestamp(str(event.get("eventDate") or ""))
            if parsed and (creation is None or parsed < creation):
                creation = parsed
    return creation


@lru_cache(maxsize=128)
def query_domain_rdap(domain: str, timeout: float = 5.0) -> RDAPResult:
    url = f"https://rdap.org/domain/{quote(domain, safe='')}"
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True, trust_env=False) as client:
            with client.stream("GET", url, headers={"Accept": "application/rdap+json"}) as response:
                response.raise_for_status()
                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > 1024 * 1024:
                        raise ValueError("RDAP response exceeded 1 MiB")
        payload = json.loads(body)
        if not isinstance(payload, dict):
            raise ValueError("RDAP returned an unexpected JSON shape")
        creation = creation_date_from_rdap(payload)
        return RDAPResult(creation_date=creation, source_available=True)
    except (httpx.HTTPError, ValueError, TypeError, json.JSONDecodeError) as exc:
        return RDAPResult(error=f"RDAP unavailable: {exc}")
