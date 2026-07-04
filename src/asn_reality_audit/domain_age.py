from __future__ import annotations

import re
from datetime import UTC, datetime

DOMAIN_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
COMMON_SECOND_LEVEL_SUFFIXES = {
    "ac.uk", "co.jp", "co.uk", "com.au", "com.br", "com.cn", "com.hk",
    "com.sg", "com.tw", "gov.uk", "net.au", "net.cn", "org.au", "org.uk",
}
SENSITIVE_TERMS = {
    "adult", "army", "bank", "banking", "bet", "casino", "church", "finance",
    "gambling", "government", "health", "hospital", "malware", "medical", "military",
    "news", "parked", "political", "politics", "porn", "religion", "scam", "xxx",
}


def normalize_domain(value: str) -> str | None:
    domain = value.strip().lower().rstrip(".")
    if domain.startswith("*."):
        domain = domain[2:]
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = domain.split(".")
    if len(domain) > 253 or len(labels) < 2:
        return None
    if any(not DOMAIN_LABEL.fullmatch(label) for label in labels):
        return None
    return domain


def registered_domain(domain: str) -> str:
    labels = domain.lower().rstrip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    suffix = ".".join(labels[-2:])
    return ".".join(labels[-3:]) if suffix in COMMON_SECOND_LEVEL_SUFFIXES else suffix


def is_sensitive_domain(domain: str) -> bool:
    labels = set(re.split(r"[.-]", domain.lower()))
    if labels & SENSITIVE_TERMS:
        return True
    return domain.endswith((".gov", ".gov.uk", ".mil"))


def days_since(value: datetime | None, now: datetime | None = None) -> int | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    current = now or datetime.now(UTC)
    return max(0, (current - value.astimezone(UTC)).days)


def parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
