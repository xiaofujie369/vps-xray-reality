import pytest

from asn_reality_audit.models import DomainRelation
from asn_reality_audit.relation import classify_relation


def test_relation_same_prefix_requires_no_asn_lookup(monkeypatch) -> None:
    monkeypatch.setattr("asn_reality_audit.relation.routed_asn", lambda *args: pytest.fail("unexpected lookup"))
    assert classify_relation(["77.73.14.80"], "77.73.14.0/24", 7488, 1, {}) == DomainRelation.same_prefix


@pytest.mark.parametrize(
    ("routed", "expected"),
    [(7488, DomainRelation.same_asn), (13335, DomainRelation.external_cdn), (64512, DomainRelation.unrelated)],
)
def test_routed_relation_types(monkeypatch, routed: int, expected: DomainRelation) -> None:
    monkeypatch.setattr("asn_reality_audit.relation.routed_asn", lambda *args: routed)
    assert classify_relation(["203.0.113.10"], "77.73.14.0/24", 7488, 1, {}) == expected
