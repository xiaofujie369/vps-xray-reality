from asn_reality_audit.asn_lookup import _merge
from asn_reality_audit.models import ASNLookupResult


def test_merge_fills_missing_fields_and_tracks_sources() -> None:
    first = ASNLookupResult(ip="8.8.8.8", asn=15169, prefix="8.8.8.0/24", sources=["ripe_stat"])
    second = ASNLookupResult(
        ip="8.8.8.8",
        asn=15169,
        asn_name="GOOGLE",
        organization="Google LLC",
        country="US",
        sources=["team_cymru"],
    )
    merged = _merge([first, second], "8.8.8.8")
    assert merged.asn == 15169
    assert merged.organization == "Google LLC"
    assert merged.prefix == "8.8.8.0/24"
    assert merged.sources == ["ripe_stat", "team_cymru"]
