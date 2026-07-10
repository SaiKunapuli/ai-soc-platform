"""Registry-modification features from Sysmon EID 12 (key create/delete) + EID 13 (value set).

Registry changes are the backbone of Windows PERSISTENCE and some defense evasion:
an attacker writes a Run key or a new service so their code survives reboot
(T1547.001 / T1543.003), or hijacks execution via Image File Execution Options.
These show up as EID 12/13 — invisible to the process/network/DNS families.

Per (host, window):
- registry_mod_count    total registry create/set/delete events
- autorun_mod_count     modifications to autostart / persistence locations
- distinct_reg_keys     distinct registry keys touched
"""

import pandas as pd

from aisoc.features.windows import assign_windows

COL_HOST = "agent.name"
COL_TARGET = "data.win.eventdata.targetObject"

# Autostart / persistence registry locations, matched as lowercase substrings of
# the full key path. Deliberately coarse — enough to flag the classic footholds.
AUTORUN_MARKERS = (
    r"\currentversion\run",                    # Run / RunOnce
    r"\currentversion\policies\explorer\run",
    r"\currentcontrolset\services",            # new/hijacked service
    r"\winlogon",                              # shell / userinit hijack
    r"\image file execution options",          # IFEO debugger hijack
    r"\currentversion\explorer\shell folders",
)

FEATURE_COLUMNS = [
    "registry_mod_count",
    "autorun_mod_count",
    "distinct_reg_keys",
]


def _is_autorun(path: str) -> bool:
    p = path.lower()
    return any(m in p for m in AUTORUN_MARKERS)


def extract(registry_events: pd.DataFrame) -> pd.DataFrame:
    """Sysmon EID 12/13 events -> one feature row per (host, window)."""
    if registry_events is None or registry_events.empty:
        return pd.DataFrame(columns=["host", "window_start"] + FEATURE_COLUMNS)

    ev = assign_windows(registry_events)
    if COL_TARGET not in ev:
        ev[COL_TARGET] = ""
    ev[COL_TARGET] = ev[COL_TARGET].fillna("").astype(str)
    ev["is_autorun"] = ev[COL_TARGET].map(_is_autorun)

    g = ev.groupby([COL_HOST, "window_start"])
    out = pd.DataFrame(
        {
            "registry_mod_count": g.size(),
            "autorun_mod_count": g["is_autorun"].sum(),
            "distinct_reg_keys": g[COL_TARGET].nunique(),
        }
    ).reset_index()
    return out.rename(columns={COL_HOST: "host"})
