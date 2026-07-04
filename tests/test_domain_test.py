from pathlib import Path

import pytest

from asn_reality_audit.domain_test import _san_matches, load_domain_list, recommended_fingerprint


@pytest.mark.parametrize(
    ("domain", "fingerprint"),
    [
        ("www.microsoft.com", "edge"),
        ("www.apple.com", "safari"),
        ("www.mozilla.org", "firefox"),
        ("www.amd.com", "chrome"),
    ],
)
def test_fingerprint_rules(domain: str, fingerprint: str) -> None:
    assert recommended_fingerprint(domain) == fingerprint


def test_load_domain_list_deduplicates_and_ignores_comments(tmp_path: Path) -> None:
    source = tmp_path / "domains.txt"
    source.write_text("# candidates\nWWW.EXAMPLE.COM\nwww.example.com.\nwww.python.org\n", encoding="utf-8")
    assert load_domain_list(str(source)) == ["www.example.com", "www.python.org"]


def test_san_match_supports_one_label_wildcards() -> None:
    assert _san_matches("www.example.com", ["*.example.com"])
    assert not _san_matches("nested.www.example.com", ["*.example.com"])


def test_domain_list_has_a_hard_size_limit(tmp_path: Path) -> None:
    source = tmp_path / "domains.txt"
    source.write_text("\n".join(f"host{i}.example.com" for i in range(101)), encoding="utf-8")
    with pytest.raises(ValueError, match="limited to 100"):
        load_domain_list(str(source))
