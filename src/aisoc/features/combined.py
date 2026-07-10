"""Combine process + network + auth feature families into one per-(host, window) vector.

The detector trains and scores on this joint set, so an anomaly can be driven by
process behavior, network behavior, auth behavior, or (most powerfully) the
combination — e.g. encoded PowerShell AND a burst of connections to a high-entropy
domain AND a spike in failed logons from a new source IP.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pandas as pd

from aisoc.features import auth_features as af
from aisoc.features import image_load_features as ilf
from aisoc.features import network_features as nf
from aisoc.features import process_access_features as paf
from aisoc.features import process_features as pf
from aisoc.features import registry_features as rf
from aisoc.features.windows import assign_windows

if TYPE_CHECKING:
    from aisoc.features.process_history import ProcessHistoryStore

FEATURE_COLUMNS = (
    pf.FEATURE_COLUMNS
    + nf.FEATURE_COLUMNS
    + af.FEATURE_COLUMNS
    + paf.FEATURE_COLUMNS
    + rf.FEATURE_COLUMNS
    + ilf.FEATURE_COLUMNS
)


def build(
    process_events: pd.DataFrame,
    network_events: pd.DataFrame | None = None,
    dns_events: pd.DataFrame | None = None,
    auth_events: pd.DataFrame | None = None,
    process_access_events: pd.DataFrame | None = None,
    registry_events: pd.DataFrame | None = None,
    image_load_events: pd.DataFrame | None = None,
    process_history: ProcessHistoryStore | None = None,
) -> pd.DataFrame:
    """Extract all families and outer-join on (host, window_start).

    Auth features are produced per (user, host, window) and then aggregated
    per (host, window) to match the host-level architecture of the other families.
    Count-based features (logins, failures) are summed across users; uniqueness-based
    features (distinct IPs, hosts, new IPs) are recomputed from raw events to avoid
    overcounting when users on the same host share IPs or workstations.

    When `process_history` is provided, rare_proc_score and new_parent_child
    use persistent per-host history rather than batch-only computation.
    """
    proc = pf.extract(process_events, history=process_history)
    # After extraction, record this batch so future runs benefit from the history
    if process_history is not None:
        process_history.record_batch(process_events)
    net = nf.extract(
        network_events if network_events is not None else pd.DataFrame(),
        dns_events,
    )
    merged = proc.merge(net, on=["host", "window_start"], how="outer")

    # Process-access (Sysmon EID 10): the credential-access / injection dimension.
    pax = paf.extract(
        process_access_events if process_access_events is not None else pd.DataFrame()
    )
    if not pax.empty:
        merged = merged.merge(pax, on=["host", "window_start"], how="outer")

    # Registry (EID 12/13): persistence. Image load (EID 7): unsigned-DLL / hijack.
    reg = rf.extract(registry_events if registry_events is not None else pd.DataFrame())
    if not reg.empty:
        merged = merged.merge(reg, on=["host", "window_start"], how="outer")
    img = ilf.extract(image_load_events if image_load_events is not None else pd.DataFrame())
    if not img.empty:
        merged = merged.merge(img, on=["host", "window_start"], how="outer")

    # Auth: extract per (user, host, window), then aggregate to per (host, window).
    # Count features are summed; uniqueness features are recomputed from raw events
    # because summing per-user nunique() overcounts when users share IPs/hosts.
    if auth_events is not None and not auth_events.empty:
        auth = af.extract(auth_events)
        if not auth.empty:
            # Sum-based features — counts aggregate cleanly across users
            auth_agg = auth.groupby(["host", "window_start"]).agg(
                login_count=("login_count", "sum"),
                failed_count=("failed_count", "sum"),
            ).reset_index()
            # Recompute ratio from aggregate sums (averaging per-user ratios is wrong)
            total = auth_agg["login_count"] + auth_agg["failed_count"]
            auth_agg["failed_ratio"] = (auth_agg["failed_count"] / total.replace(0, 1)).fillna(0.0)

            # Uniqueness features — compute from raw events grouped by (host, window)
            # to avoid overcounting when users share IPs or workstations.
            raw = assign_windows(auth_events)
            for col in (af.COL_IP, af.COL_WORKSTATION):
                if col not in raw:
                    raw[col] = ""
                raw[col] = raw[col].fillna("").astype(str)
            raw["user"] = raw[af.COL_USER].str.lower()
            raw["is_new_ip"] = (
                raw.groupby(["user", raw[af.COL_IP]]).cumcount() == 0
            )
            host_agg = raw.groupby([af.COL_HOST, "window_start"]).agg(
                distinct_source_ips=(af.COL_IP, "nunique"),
                distinct_hosts=(af.COL_WORKSTATION, "nunique"),
                new_source_ip=("is_new_ip", "sum"),
            ).reset_index()
            host_agg = host_agg.rename(columns={af.COL_HOST: "host"})

            auth_agg = auth_agg.merge(host_agg, on=["host", "window_start"], how="outer")
            merged = merged.merge(auth_agg, on=["host", "window_start"], how="outer")

    for col in FEATURE_COLUMNS:
        if col not in merged:
            merged[col] = 0.0
    merged[FEATURE_COLUMNS] = merged[FEATURE_COLUMNS].fillna(0.0)
    return merged[["host", "window_start"] + FEATURE_COLUMNS]
