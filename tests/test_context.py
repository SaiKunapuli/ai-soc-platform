"""Tests for the offline enrichment-context helpers."""

from pathlib import Path

from aisoc.enrichment.context import (
    IpReputation,
    build_context,
    format_context,
    known_tool_hits,
    lolbas_hits,
)


def test_known_tool_hits_match_by_basename_and_path() -> None:
    hits = known_tool_hits([r"C:\Program Files\Windhawk\windhawk.exe", "CHROME.EXE"])
    assert "windhawk.exe" in hits and "chrome.exe" in hits
    assert "Windhawk" in hits["windhawk.exe"]


def test_lolbas_hits_dedup_and_sorted() -> None:
    names = [r"C:\Windows\System32\certutil.exe", "certutil.exe", "rundll32.exe", "chrome.exe"]
    assert lolbas_hits(names) == ["certutil.exe", "rundll32.exe"]


def test_build_context_splits_benign_and_escalation() -> None:
    ctx = build_context(["windhawk.exe", "regsvr32.exe"])
    assert any("windhawk" in b for b in ctx["benign_indicators"])
    assert any("regsvr32" in e for e in ctx["escalation_indicators"])


def test_build_context_empty_when_nothing_recognized() -> None:
    ctx = build_context(["totally-unknown-thing.exe"])
    assert ctx["benign_indicators"] == [] and ctx["escalation_indicators"] == []
    assert "No recognized" in format_context(ctx)


def test_ip_reputation_missing_file_is_noop() -> None:
    ti = IpReputation(path=Path("does/not/exist.txt"))
    assert ti.hits(["1.2.3.4"]) == []


def test_ip_reputation_matches_blocklist(tmp_path) -> None:
    bl = tmp_path / "ip_blocklist.txt"
    bl.write_text("# abuse.ch feodo\n45.66.77.88\n203.0.113.9\n", encoding="utf-8")
    ti = IpReputation(path=bl)
    assert ti.hits(["45.66.77.88", "8.8.8.8"]) == ["45.66.77.88"]
    ctx = build_context([], ips=["203.0.113.9"], ti=ti)
    assert any("threat-intel blocklist" in e for e in ctx["escalation_indicators"])
