"""Time-window aggregation helpers shared by all feature families."""

import pandas as pd

from aisoc.config import settings


def assign_windows(
    events: pd.DataFrame,
    timestamp_col: str = "timestamp",
    window_minutes: int | None = None,
) -> pd.DataFrame:
    """Return a copy of events with parsed timestamps and a window_start column."""
    window = window_minutes or settings.window_minutes
    events = events.copy()
    events[timestamp_col] = pd.to_datetime(events[timestamp_col], utc=True, format="mixed")
    events["window_start"] = events[timestamp_col].dt.floor(f"{window}min")
    return events


def bucket_by_entity(
    events: pd.DataFrame,
    entity_col: str,
    timestamp_col: str = "timestamp",
    window_minutes: int | None = None,
):
    """Group events into fixed windows per entity (host or user).

    Returns a groupby over (entity, window_start); feature modules aggregate on top.
    """
    events = assign_windows(events, timestamp_col=timestamp_col, window_minutes=window_minutes)
    return events.groupby([entity_col, "window_start"])


def label_windows(
    features: pd.DataFrame,
    labels: pd.DataFrame,
    pad_seconds: int = 60,
    window_minutes: int | None = None,
) -> pd.Series:
    """Mark feature windows that overlap an Atomic Red Team run (simulations/labels.csv).

    Ground truth for evaluation: True where [window_start, window_start + window)
    overlaps any label's [start_utc - pad, end_utc + pad]. Pad absorbs event-timestamp
    lag. Time-overlap only — sufficient for the single-host lab; add host matching
    when a second endpoint exists.
    """
    window = window_minutes or settings.window_minutes
    window_start = pd.to_datetime(features["window_start"], utc=True)
    window_end = window_start + pd.Timedelta(minutes=window)
    pad = pd.Timedelta(seconds=pad_seconds)

    is_attack = pd.Series(False, index=features.index)
    for _, label in labels.iterrows():
        start = pd.to_datetime(label["start_utc"], utc=True) - pad
        end = pd.to_datetime(label["end_utc"], utc=True) + pad
        is_attack |= (window_start < end) & (window_end > start)
    return is_attack
