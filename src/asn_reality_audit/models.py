from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class IPDetection(BaseModel):
    ipv4: str | None = None
    ipv6: str | None = None
    ipv4_observations: dict[str, str] = Field(default_factory=dict)
    ipv6_observations: dict[str, str] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)


class InterfaceInfo(BaseModel):
    default_interface_v4: str | None = None
    default_interface_v6: str | None = None
    local_ipv4: str | None = None
    local_ipv6: str | None = None


class ServerInfo(BaseModel):
    ipv4: str | None = None
    ipv6: str | None = None
    interface: str | None = None
    interface_v4: str | None = None
    interface_v6: str | None = None
    local_ipv4: str | None = None
    local_ipv6: str | None = None


class ASNLookupResult(BaseModel):
    ip: str
    asn: int | None = None
    asn_name: str | None = None
    organization: str | None = None
    country: str | None = None
    prefix: str | None = None
    sources: list[str] = Field(default_factory=list)


class ASNInfo(BaseModel):
    number: int | None = None
    name: str | None = None
    organization: str | None = None
    country: str | None = None
    prefix: str | None = None
    type: str = "reseller_or_unknown"
    score: int = 0
    suitability: str = "poor"
    notes: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)


class DomainResult(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    domain: str
    score: int = 0
    rating: str = "not recommended"
    dns_ok: bool = False
    a_records: list[str] = Field(default_factory=list)
    aaaa_records: list[str] = Field(default_factory=list)
    dns_latency_ms: float | None = None
    tcp_443_ok: bool = False
    tcp_latency_ms: float | None = None
    tls_ok: bool = False
    tls_version: str | None = None
    alpn: str | None = None
    cert_valid: bool = False
    cert_san_ok: bool = False
    cert_expires_at: datetime | None = None
    latency_ms: float | None = None
    http_ok: bool = False
    http_status: int | None = None
    error: str | None = None
    server_name: str = Field(alias="serverName")
    dest: str
    fingerprint: str
    spider_x: str = Field(default="/", alias="spiderX")


class AuditReport(BaseModel):
    timestamp: datetime
    server: ServerInfo
    asn: ASNInfo
    top_domains: list[DomainResult]
    xray_server: dict[str, object] | None = None
    xray_client: dict[str, object] | None = None
    warnings: list[str] = Field(default_factory=list)
