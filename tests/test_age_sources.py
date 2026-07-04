from datetime import UTC, datetime

from asn_reality_audit.ct_lookup import parse_ct_records
from asn_reality_audit.rdap_lookup import creation_date_from_rdap


def test_ct_history_is_kept_per_exact_normalized_name() -> None:
    result = parse_ct_records(
        [
            {
                "entry_timestamp": "2020-01-02T00:00:00Z",
                "name_value": "old.example.com\n*.example.com",
            },
            {
                "entry_timestamp": "2022-01-02T00:00:00Z",
                "name_value": "new.example.com",
            },
        ],
        "example.com",
    )
    assert result.first_seen("old.example.com") == datetime(2020, 1, 2, tzinfo=UTC)
    assert result.first_seen("new.example.com") == datetime(2022, 1, 2, tzinfo=UTC)


def test_rdap_uses_earliest_registration_event() -> None:
    result = creation_date_from_rdap(
        {
            "events": [
                {"eventAction": "registration", "eventDate": "2020-01-02T00:00:00Z"},
                {"eventAction": "registration", "eventDate": "2019-01-02T00:00:00Z"},
                {"eventAction": "last changed", "eventDate": "2025-01-02T00:00:00Z"},
            ]
        }
    )
    assert result == datetime(2019, 1, 2, tzinfo=UTC)
