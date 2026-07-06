"""Feature extraction on synthetic Sysmon-shaped events.

Two 10-minute windows on one host: a quiet one (browser activity) and a noisy one
(encoded PowerShell from Word + a burst of discovery commands) mimicking T1059.001.
"""

import pandas as pd
import pytest

from aisoc.features import process_features as pf
from aisoc.features.windows import label_windows

ENCODED_PS = (
    "powershell.exe -NoProfile -EncodedCommand "
    "JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtAA=="
)


def event(ts: str, image: str, parent: str, cmdline: str) -> dict:
    return {
        "timestamp": ts,
        pf.COL_HOST: "DESKTOP-01",
        pf.COL_IMAGE: image,
        pf.COL_PARENT: parent,
        pf.COL_CMDLINE: cmdline,
    }


CHROME = r"C:\Program Files\Google\Chrome\chrome.exe"
EXPLORER = r"C:\Windows\explorer.exe"
WORD = r"C:\Program Files\Microsoft Office\WINWORD.EXE"
POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
CMD = r"C:\Windows\System32\cmd.exe"


@pytest.fixture
def events() -> pd.DataFrame:
    quiet = [
        event(f"2026-07-06T10:0{i}:00Z", CHROME, EXPLORER, "chrome.exe --restore-session")
        for i in range(3)
    ]
    noisy = [
        event("2026-07-06T10:11:00Z", POWERSHELL, WORD, ENCODED_PS),
        event("2026-07-06T10:12:00Z", CMD, POWERSHELL, "cmd.exe /c whoami /all"),
        event("2026-07-06T10:12:20Z", CMD, POWERSHELL, "cmd.exe /c systeminfo"),
        event("2026-07-06T10:12:40Z", CMD, POWERSHELL, "cmd.exe /c net user"),
    ]
    return pd.DataFrame(quiet + noisy)


@pytest.fixture
def features(events: pd.DataFrame) -> pd.DataFrame:
    return pf.extract(events)


def test_one_row_per_host_window(features: pd.DataFrame) -> None:
    assert len(features) == 2
    assert set(pf.FEATURE_COLUMNS) <= set(features.columns)


def test_quiet_window_is_quiet(features: pd.DataFrame) -> None:
    quiet = features.iloc[0]
    assert quiet["proc_count"] == 3
    assert quiet["ps_count"] == 0
    assert quiet["encoded_cmd"] == 0


def test_attack_window_features(features: pd.DataFrame) -> None:
    noisy = features.iloc[1]
    assert noisy["ps_count"] == 4  # powershell + 3x cmd
    assert noisy["encoded_cmd"] == 1
    assert noisy["new_parent_child"] >= 2  # word->powershell, powershell->cmd
    assert noisy["burst_rate"] == 3  # three cmds within minute 10:12
    assert noisy["rare_proc_score"] > features.iloc[0]["rare_proc_score"]


def test_label_windows_marks_only_the_attack(features: pd.DataFrame) -> None:
    labels = pd.DataFrame(
        [
            {
                "start_utc": "2026-07-06T10:11:00Z",
                "end_utc": "2026-07-06T10:13:00Z",
                "host": "DESKTOP-01",
                "technique_id": "T1059.001",
                "test_number": 1,
                "notes": "synthetic",
            }
        ]
    )
    is_attack = label_windows(features, labels)
    assert list(is_attack) == [False, True]
