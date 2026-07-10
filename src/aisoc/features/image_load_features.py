"""Image-load features from Sysmon EID 7 (a module/DLL loaded into a process).

Loading an UNSIGNED or unusual DLL is the signal for DLL search-order hijacking /
side-loading (T1574.002) and for malicious code brought in as a library rather
than as its own process. EID 7 is high-volume, so these are count/ratio features.

Per (host, window):
- image_load_count      total modules loaded
- unsigned_load_count   modules that are unsigned or whose signature isn't valid
- distinct_modules      distinct modules loaded
"""

import pandas as pd

from aisoc.features.windows import assign_windows

COL_HOST = "agent.name"
COL_LOADED = "data.win.eventdata.imageLoaded"
COL_SIGNED = "data.win.eventdata.signed"
COL_SIGSTATUS = "data.win.eventdata.signatureStatus"

FEATURE_COLUMNS = [
    "image_load_count",
    "unsigned_load_count",
    "distinct_modules",
]


def extract(image_load_events: pd.DataFrame) -> pd.DataFrame:
    """Sysmon EID 7 events -> one feature row per (host, window)."""
    if image_load_events is None or image_load_events.empty:
        return pd.DataFrame(columns=["host", "window_start"] + FEATURE_COLUMNS)

    ev = assign_windows(image_load_events)
    for col in (COL_LOADED, COL_SIGNED, COL_SIGSTATUS):
        if col not in ev:
            ev[col] = ""
        ev[col] = ev[col].fillna("").astype(str)

    signed_true = ev[COL_SIGNED].str.lower().eq("true")
    sig_valid = ev[COL_SIGSTATUS].str.lower().eq("valid")
    # "unsigned" = signature info present AND it says not-signed / not-valid.
    # If both fields are blank (some collection pipelines omit them), treat as
    # unknown rather than unsigned, to avoid flagging everything.
    has_sig_info = (ev[COL_SIGNED] != "") | (ev[COL_SIGSTATUS] != "")
    ev["is_unsigned"] = has_sig_info & ~(signed_true | sig_valid)

    g = ev.groupby([COL_HOST, "window_start"])
    out = pd.DataFrame(
        {
            "image_load_count": g.size(),
            "unsigned_load_count": g["is_unsigned"].sum(),
            "distinct_modules": g[COL_LOADED].nunique(),
        }
    ).reset_index()
    return out.rename(columns={COL_HOST: "host"})
