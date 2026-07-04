from asn_reality_audit.ip_detect import _choose_consensus, _valid_provider_ip, parse_route_output


def test_choose_consensus_prefers_majority() -> None:
    value, conflict = _choose_consensus({"a": "203.0.113.1", "b": "203.0.113.1", "c": "203.0.113.2"})
    assert value == "203.0.113.1"
    assert conflict is True


def test_provider_ip_requires_requested_public_family() -> None:
    assert _valid_provider_ip("8.8.8.8\n", 4) == "8.8.8.8"
    assert _valid_provider_ip("2001:4860:4860::8888", 6) == "2001:4860:4860::8888"
    assert _valid_provider_ip("10.0.0.1", 4) is None
    assert _valid_provider_ip("8.8.8.8", 6) is None


def test_parse_linux_route() -> None:
    interface, source = parse_route_output("1.1.1.1 via 192.0.2.1 dev ens3 src 192.0.2.10 uid 1000")
    assert interface == "ens3"
    assert source == "192.0.2.10"
