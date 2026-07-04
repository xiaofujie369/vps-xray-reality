from __future__ import annotations

from datetime import datetime
from enum import StrEnum

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
    cert_issuer: str | None = None
    cert_not_before: datetime | None = None
    cert_expires_at: datetime | None = None
    latency_ms: float | None = None
    http_ok: bool = False
    http_status: int | None = None
    http_latency_ms: float | None = None
    error: str | None = None
    server_name: str = Field(alias="serverName")
    dest: str
    fingerprint: str
    spider_x: str = Field(default="/", alias="spiderX")


class DomainRelation(StrEnum):
    same_prefix = "same_prefix"
    same_asn = "same_asn"
    external_cdn = "external_cdn"
    unrelated = "unrelated"


class DomainDiscoveryConfig(BaseModel):
    enabled: bool = False
    prefix_scan_limit: int = 64
    passive_only: bool = False
    allow_light_probe: bool = False
    min_domain_age_days: int = 365
    same_prefix_only: bool = False
    same_asn_only: bool = False
    include_external_cdn: bool = False
    exclude_sensitive: bool = True
    timeout: float = 5.0


class DiscoveryTLSResult(BaseModel):
    success: bool = False
    version: str | None = None
    alpn: list[str] = Field(default_factory=list)
    cert_valid: bool = False
    issuer: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None


class DiscoveryHTTPResult(BaseModel):
    success: bool = False
    status_code: int | None = None
    latency_ms: float | None = None


class DiscoveryEvidence(BaseModel):
    ptr: bool = False
    tls_cert_san: bool = False
    rdap: bool = False
    certificate_transparency: bool = False
    wayback: bool = False
    current_tls_probe: bool = False
    current_http_probe: bool = False


class RealityRecommendation(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    server_name: str = Field(alias="serverName")
    dest: str
    fingerprint: str = "chrome"
    spider_x: str = Field(default="/", alias="spiderX")


class LongLivedDomainCandidate(BaseModel):
    domain: str
    score: int
    rating: str
    relation: DomainRelation
    resolved_ips: list[str] = Field(default_factory=list)
    domain_age_days: int | None = None
    earliest_ct_cert_age_days: int | None = None
    wayback_age_days: int | None = None
    tls: DiscoveryTLSResult
    http: DiscoveryHTTPResult
    recommended_reality: RealityRecommendation
    evidence: DiscoveryEvidence
    errors: list[str] = Field(default_factory=list)


class RejectedDomain(BaseModel):
    domain: str
    reason: str


class SamePrefixDomainDiscovery(BaseModel):
    enabled: bool = True
    prefix: str | None = None
    asn: int | None = None
    scan_limit: int = 64
    sampled_ip_count: int = 0
    min_domain_age_days: int = 365
    mode: str = "passive"
    candidates: list[LongLivedDomainCandidate] = Field(default_factory=list)
    rejected: list[RejectedDomain] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class AuditReport(BaseModel):
    timestamp: datetime
    server: ServerInfo
    asn: ASNInfo
    top_domains: list[DomainResult]
    xray_server: dict[str, object] | None = None
    xray_client: dict[str, object] | None = None
    same_prefix_domain_discovery: SamePrefixDomainDiscovery | None = None
    warnings: list[str] = Field(default_factory=list)
