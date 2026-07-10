"""Registry (Sysmon EID 12/13) feature tests — the persistence signal."""

import pandas as pd

from aisoc.features import registry_features as rf


def test_autorun_key_is_flagged() -> None:
    rows = [
        {"timestamp": "2026-07-08T10:00:00Z", "agent.name": "H1",
         rf.COL_TARGET: r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Evil"},
        {"timestamp": "2026-07-08T10:01:00Z", "agent.name": "H1",
         rf.COL_TARGET: r"HKLM\SYSTEM\CurrentControlSet\Services\BadSvc\ImagePath"},
        {"timestamp": "2026-07-08T10:02:00Z", "agent.name": "H1",
         rf.COL_TARGET: r"HKCU\Software\Vendor\App\Settings\Theme"},  # benign
    ]
    r = rf.extract(pd.DataFrame(rows)).iloc[0]
    assert r["registry_mod_count"] == 3
    assert r["autorun_mod_count"] == 2       # Run key + new service
    assert r["distinct_reg_keys"] == 3


def test_is_autorun_matches_persistence_locations() -> None:
    assert rf._is_autorun(r"HKLM\...\CurrentVersion\Run\x")
    assert rf._is_autorun(r"HKLM\SYSTEM\CurrentControlSet\Services\Foo")
    assert rf._is_autorun(r"HKLM\...\Image File Execution Options\sethc.exe\Debugger")
    assert not rf._is_autorun(r"HKCU\Software\App\Config")


def test_empty_input_returns_columns() -> None:
    feats = rf.extract(pd.DataFrame())
    assert list(feats.columns) == ["host", "window_start"] + rf.FEATURE_COLUMNS
    assert feats.empty
