"""Authentication-behavior features (Windows logon events). Phase 2.5 — after process features.

Per (user, host, window):
- login_count           successful logons (EID 4624)
- failed_count          failed logons (EID 4625)
- failed_ratio          failed / (success + failed)
- distinct_source_ips   unique source IPs (lateral-movement signal, T1021)
- distinct_hosts        unique workstations touched
- new_source_ip         count of first-seen IPs for this user (credential spraying)

Columns expected from the indexer (Sysmon or Windows Event Log via Wazuh):
- agent.name                    host
- data.win.eventdata.targetUserName  user
- data.win.eventdata.ipAddress       source IP
- data.win.eventdata.workstationName workstation
- data.win.system.eventID      4624 (success) or 4625 (failure)
"""

import pandas as pd

from aisoc.features.windows import assign_windows

COL_HOST = "agent.name"
COL_USER = "data.win.eventdata.targetUserName"
COL_IP = "data.win.eventdata.ipAddress"
COL_WORKSTATION = "data.win.eventdata.workstationName"

FEATURE_COLUMNS = [
    "login_count",
    "failed_count",
    "failed_ratio",
    "distinct_source_ips",
    "distinct_hosts",
    "new_source_ip",
]


def extract(auth_events: pd.DataFrame) -> pd.DataFrame:
    """Windows logon events → one feature row per (user, host, window).

    Rarity (new_source_ip) is computed within the given batch — a persistent
    per-user IP-history store (like BaselineStore) would improve this for
    production, but batch-level is a reasonable Phase 2.5 start.
    """
    if auth_events is None or auth_events.empty:
        return pd.DataFrame(columns=["user", "host", "window_start"] + FEATURE_COLUMNS)

    events = assign_windows(auth_events).sort_values("timestamp")

    # Normalise columns
    for col in (COL_USER, COL_IP, COL_WORKSTATION):
        if col not in events:
            events[col] = ""
        events[col] = events[col].fillna("").astype(str)

    events["user"] = events[COL_USER].str.lower()
    has_event_id = "data.win.system.eventID" in events.columns
    events["is_failure"] = (
        events["data.win.system.eventID"].astype(str).eq("4625")
        if has_event_id
        else pd.Series(False, index=events.index)
    )

    # First occurrence of an IP for this user (batch-level rarity)
    events["is_new_ip"] = (
        events.groupby(["user", COL_IP]).cumcount() == 0
    )

    grouped = events.groupby([COL_HOST, "user", "window_start"])
    total = grouped.size()
    failed = grouped["is_failure"].sum()

    features = pd.DataFrame(
        {
            "login_count": total - failed,
            "failed_count": failed,
            "failed_ratio": failed / total.replace(0, 1),
            "distinct_source_ips": grouped[COL_IP].nunique(),
            "distinct_hosts": grouped[COL_WORKSTATION].nunique(),
            "new_source_ip": grouped["is_new_ip"].sum(),
        }
    )
    features.index.names = ["host", "user", "window_start"]
    return features.reset_index()
