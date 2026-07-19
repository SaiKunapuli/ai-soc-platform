"""Tests for the MITRE coverage-report logic."""

from scripts.coverage_report import ALL_TACTICS, _is_exercised, build_coverage


def test_subtechnique_counts_as_exercised_via_parent() -> None:
    # running T1003.001 should mark the parent T1003 as exercised, and vice versa
    assert _is_exercised("T1003", {"T1003.001"})
    assert _is_exercised("T1003.001", {"T1003"})
    assert not _is_exercised("T1059", {"T1003"})


def test_build_coverage_groups_by_tactic() -> None:
    cov = build_coverage(exercised={"T1003.001"})
    # credential access is covered by lsass features and now marked exercised
    ca = cov["by_tactic"].get("Credential Access", [])
    assert any(e["technique_id"] == "T1003.001" and e["exercised"] for e in ca)
    assert cov["technique_count"] > 0


def test_gaps_are_valid_tactics_not_covered() -> None:
    cov = build_coverage()
    for g in cov["gaps"]:
        assert g in ALL_TACTICS
        assert g not in cov["by_tactic"]
