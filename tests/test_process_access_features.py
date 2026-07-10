"""Process-access (Sysmon EID 10) feature tests — the credential-dump / injection signal."""

import pandas as pd

from aisoc.features import process_access_features as paf


def test_is_dangerous_access_bits() -> None:
    assert paf.is_dangerous_access("0x1010")    # VM_READ | query  -> mimikatz lsass read
    assert paf.is_dangerous_access("0x1fffff")  # full access
    assert paf.is_dangerous_access("0x0020")    # VM_WRITE          -> injection
    assert paf.is_dangerous_access("0x0002")    # CREATE_THREAD     -> injection
    assert not paf.is_dangerous_access("0x1000")  # query-limited-info only (benign)
    assert not paf.is_dangerous_access("0x0400")  # query-information only (benign)
    assert not paf.is_dangerous_access("")
    assert not paf.is_dangerous_access("notahex")


def test_lsass_dump_lights_up() -> None:
    # a tool opening lsass.exe with VM_READ rights = classic credential dumping
    rows = [
        {"timestamp": "2026-07-08T10:01:00Z", "agent.name": "H1",
         paf.COL_SOURCE: r"C:\Tools\mimikatz.exe",
         paf.COL_TARGET: r"C:\Windows\System32\lsass.exe", paf.COL_GRANTED: "0x1010"},
        {"timestamp": "2026-07-08T10:01:30Z", "agent.name": "H1",
         paf.COL_SOURCE: r"C:\Windows\System32\svchost.exe",
         paf.COL_TARGET: r"C:\Windows\System32\lsass.exe", paf.COL_GRANTED: "0x1000"},  # benign query
    ]
    feats = paf.extract(pd.DataFrame(rows))
    assert len(feats) == 1
    r = feats.iloc[0]
    assert r["proc_access_count"] == 2
    assert r["lsass_access_count"] == 2      # both target lsass
    assert r["sensitive_access_count"] == 2
    assert r["high_access_count"] == 1       # only the 0x1010 open is dangerous
    assert r["distinct_access_targets"] == 1


def test_benign_window_is_quiet() -> None:
    rows = [
        {"timestamp": "2026-07-08T11:00:00Z", "agent.name": "H1",
         paf.COL_SOURCE: r"C:\app.exe", paf.COL_TARGET: r"C:\other.exe", paf.COL_GRANTED: "0x1000"},
    ]
    r = paf.extract(pd.DataFrame(rows)).iloc[0]
    assert r["lsass_access_count"] == 0 and r["high_access_count"] == 0


def test_empty_input_returns_columns() -> None:
    feats = paf.extract(pd.DataFrame())
    assert list(feats.columns) == ["host", "window_start"] + paf.FEATURE_COLUMNS
    assert feats.empty
