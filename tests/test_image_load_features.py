"""Image-load (Sysmon EID 7) feature tests — the unsigned-DLL signal."""

import pandas as pd

from aisoc.features import image_load_features as ilf


def test_unsigned_module_is_counted() -> None:
    rows = [
        {"timestamp": "2026-07-08T10:00:00Z", "agent.name": "H1",
         ilf.COL_LOADED: r"C:\Windows\System32\kernel32.dll",
         ilf.COL_SIGNED: "true", ilf.COL_SIGSTATUS: "Valid"},
        {"timestamp": "2026-07-08T10:00:30Z", "agent.name": "H1",
         ilf.COL_LOADED: r"C:\Users\bob\AppData\Local\Temp\evil.dll",
         ilf.COL_SIGNED: "false", ilf.COL_SIGSTATUS: "Unavailable"},
    ]
    r = ilf.extract(pd.DataFrame(rows)).iloc[0]
    assert r["image_load_count"] == 2
    assert r["unsigned_load_count"] == 1     # only the temp .dll
    assert r["distinct_modules"] == 2


def test_missing_signature_info_not_flagged() -> None:
    # if the collection pipeline omits signature fields, don't flag as unsigned
    rows = [
        {"timestamp": "2026-07-08T10:00:00Z", "agent.name": "H1",
         ilf.COL_LOADED: r"C:\x\a.dll", ilf.COL_SIGNED: "", ilf.COL_SIGSTATUS: ""},
    ]
    r = ilf.extract(pd.DataFrame(rows)).iloc[0]
    assert r["unsigned_load_count"] == 0


def test_empty_input_returns_columns() -> None:
    feats = ilf.extract(pd.DataFrame())
    assert list(feats.columns) == ["host", "window_start"] + ilf.FEATURE_COLUMNS
    assert feats.empty
