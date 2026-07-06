"""Time-window aggregation helpers shared by all feature families."""

import pandas as pd

from aisoc.config import settings


def bucket_by_entity(
    events: pd.DataFrame,
    entity_col: str,
    timestamp_col: str = "timestamp",
    window_minutes: int | None = None,
) -> pd.core.groupby.DataFrameGroupBy:
    """Group events into fixed windows per entity (host or user).

    Returns a groupby over (entity, window_start); feature modules aggregate on top.
    """
    window = window_minutes or settings.window_minutes
    events = events.copy()
    events[timestamp_col] = pd.to_datetime(events[timestamp_col], utc=True, format="mixed")
    events["window_start"] = events[timestamp_col].dt.floor(f"{window}min")
    return events.groupby([entity_col, "window_start"])


def label_windows(features: pd.DataFrame, labels: pd.DataFrame, pad_seconds: int = 60) -> pd.Series:
    """Mark feature windows that overlap an Atomic Red Team run (simulations/labels.csv).

    Ground truth for evaluation: True where window overlaps [start_utc - pad, end_utc + pad].
    TODO(phase 2): implement overlap join.
    """
    raise NotImplementedError
