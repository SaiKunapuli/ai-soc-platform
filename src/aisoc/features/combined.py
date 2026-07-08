"""Combine process + network feature families into one per-(host, window) vector.

The detector trains and scores on this joint set, so an anomaly can be driven by
process behavior, network behavior, or (most powerfully) the combination — e.g.
encoded PowerShell AND a burst of connections to a high-entropy domain.
"""

import pandas as pd

from aisoc.features import network_features as nf
from aisoc.features import process_features as pf

FEATURE_COLUMNS = pf.FEATURE_COLUMNS + nf.FEATURE_COLUMNS


def build(
    process_events: pd.DataFrame,
    network_events: pd.DataFrame | None = None,
    dns_events: pd.DataFrame | None = None,
) -> pd.DataFrame:
    """Extract both families and outer-join on (host, window_start).

    A window present in one family but not the other gets 0 for the missing
    features (no processes / no connections that window), which is the right
    default for count-based features.
    """
    proc = pf.extract(process_events)
    net = nf.extract(
        network_events if network_events is not None else pd.DataFrame(),
        dns_events,
    )
    merged = proc.merge(net, on=["host", "window_start"], how="outer")
    for col in FEATURE_COLUMNS:
        if col not in merged:
            merged[col] = 0.0
    merged[FEATURE_COLUMNS] = merged[FEATURE_COLUMNS].fillna(0.0)
    return merged[["host", "window_start"] + FEATURE_COLUMNS]
