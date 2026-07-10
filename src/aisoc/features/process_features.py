"""Process-behavior features from Sysmon Event ID 1 (process creation).

Phase 2's one and only feature family. Per (host, window):

- proc_count            total process creations
- ps_count              script-host launches (PowerShell/cmd/wscript/mshta)
- encoded_cmd           command lines with -enc flags or high-entropy args
- max_cmd_entropy       highest command-line Shannon entropy (base64/obfuscation spikes)
- max_cmd_len           longest command line (encoded payloads are long)
- rare_proc_score       mean rarity of image names vs. this host's history
- new_parent_child      never-before-seen parent->child image pairs
- burst_rate            max creations in any 1-min sub-bucket (detects tool spray)

max_cmd_entropy / max_cmd_len are continuous discriminators for obfuscated
commands: a single encoded PowerShell payload is diluted as a count, but its
entropy and length are strong per-window maxima.
"""

import math
from collections import Counter
from typing import TYPE_CHECKING

import pandas as pd

from aisoc.features.windows import assign_windows

if TYPE_CHECKING:
    from aisoc.features.process_history import ProcessHistoryStore

SCRIPT_HOSTS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"}
ENCODED_FLAGS = ("-enc", "-encodedcommand", "-e ")
# ~4.5 bits/char is typical for paths and flags; base64 blobs run >= 5.5
ENTROPY_THRESHOLD = 5.5

# Flattened columns as produced by IndexerClient.fetch_sysmon_process_events
COL_HOST = "agent.name"
COL_IMAGE = "data.win.eventdata.image"
COL_PARENT = "data.win.eventdata.parentImage"
COL_CMDLINE = "data.win.eventdata.commandLine"

FEATURE_COLUMNS = [
    "proc_count",
    "ps_count",
    "encoded_cmd",
    "max_cmd_entropy",
    "max_cmd_len",
    "rare_proc_score",
    "new_parent_child",
    "burst_rate",
]


def command_line_entropy(cmdline: str) -> float:
    """Shannon entropy of the command line — base64 blobs score high."""
    if not cmdline:
        return 0.0
    counts = Counter(cmdline)
    total = len(cmdline)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def extract(
    process_events: pd.DataFrame,
    history: "ProcessHistoryStore | None" = None,
) -> pd.DataFrame:
    """Sysmon EID-1 events → one feature row per (host, window).

    When `history` is a ProcessHistoryStore, rarity and first-seen signals are
    computed against persistent per-host history (accumulated across pipeline runs)
    rather than just the current batch. Without history, falls back to batch-level
    computation (the original behaviour).
    """
    if process_events is None or process_events.empty:
        return pd.DataFrame(columns=["host", "window_start"] + FEATURE_COLUMNS)

    events = assign_windows(process_events).sort_values("timestamp")
    for col in (COL_IMAGE, COL_PARENT, COL_CMDLINE):
        if col not in events:
            events[col] = ""
        events[col] = events[col].fillna("").astype(str)

    events["image_name"] = events[COL_IMAGE].str.lower().str.split("\\").str[-1]
    events["parent_name"] = events[COL_PARENT].str.lower().str.split("\\").str[-1]
    events["is_script_host"] = events["image_name"].isin(SCRIPT_HOSTS)

    events["cmd_entropy"] = events[COL_CMDLINE].map(command_line_entropy)
    events["cmd_len"] = events[COL_CMDLINE].str.len().astype(float)
    has_flag = events[COL_CMDLINE].str.lower().map(
        lambda c: any(flag in c for flag in ENCODED_FLAGS)
    )
    events["is_encoded"] = has_flag | (events["cmd_entropy"] > ENTROPY_THRESHOLD)

    # Rarity of an image on its host: ~1 for a singleton, 0 for most common.
    # With history: combines persistent store counts + batch counts.
    if history is not None:
        # Build in-memory lookup of historical counts per host
        hist_counts: dict[str, dict[str, int]] = {}
        hist_max: dict[str, int] = {}
        for host in events[COL_HOST].unique():
            h = str(host)
            counts = history.host_image_counts(h)
            hist_counts[h] = counts
            hist_max[h] = max(counts.values()) if counts else 0

        def _rarity(row) -> float:
            h = str(row[COL_HOST])
            img = str(row["image_name"])
            hist = hist_counts.get(h, {}).get(img, 0)
            # Batch count for this image on this host (computed via groupby below)
            batch = int(row["_batch_count"])
            total = hist + batch
            host_max = max(hist_max.get(h, 0), int(row["_batch_max"]))
            if host_max == 0:
                return 0.0
            return 1.0 - total / host_max

        # Pre-load known pairs per host into a set for O(1) lookup (avoid
        # per-row SQL queries when the batch has thousands of events).
        known_pairs: dict[str, set[tuple[str, str]]] = {}
        for host in events[COL_HOST].unique():
            known_pairs[str(host)] = history.host_known_pairs(str(host))

        def _is_new(row) -> bool:
            h = str(row[COL_HOST])
            parent = str(row["parent_name"])
            child = str(row["image_name"])
            batch_first = bool(row["_batch_first"])
            # New pair = never seen in history AND first occurrence in this batch
            return batch_first and (parent, child) not in known_pairs.get(h, set())

        # Compute batch-level aggregates needed for rarity + new_pair
        events["_batch_count"] = events.groupby(
            [COL_HOST, "image_name"]
        )[COL_HOST].transform("size")
        batch_max = events.groupby(COL_HOST)["_batch_count"].transform("max")
        events["_batch_max"] = batch_max
        # Batch-first: first occurrence of a pair within this batch
        events["_batch_first"] = (
            events.groupby([COL_HOST, "parent_name", "image_name"]).cumcount() == 0
        )

        events["rarity"] = events.apply(_rarity, axis=1)
        events["is_new_pair"] = events.apply(_is_new, axis=1)
        # Clean up temporary columns
        events = events.drop(columns=["_batch_count", "_batch_max", "_batch_first"])
    else:
        # Batch-only mode (original)
        image_counts = events.groupby([COL_HOST, "image_name"])[COL_HOST].transform("size")
        host_max = image_counts.groupby(events[COL_HOST]).transform("max")
        events["rarity"] = 1.0 - image_counts / host_max
        events["is_new_pair"] = (
            events.groupby([COL_HOST, "parent_name", "image_name"]).cumcount() == 0
        )

    events["minute"] = events["timestamp"].dt.floor("1min")
    per_minute = events.groupby([COL_HOST, "window_start", "minute"]).size()
    burst = per_minute.groupby([COL_HOST, "window_start"]).max()

    grouped = events.groupby([COL_HOST, "window_start"])
    features = pd.DataFrame(
        {
            "proc_count": grouped.size(),
            "ps_count": grouped["is_script_host"].sum(),
            "encoded_cmd": grouped["is_encoded"].sum(),
            "max_cmd_entropy": grouped["cmd_entropy"].max(),
            "max_cmd_len": grouped["cmd_len"].max(),
            "rare_proc_score": grouped["rarity"].mean(),
            "new_parent_child": grouped["is_new_pair"].sum(),
            "burst_rate": burst,
        }
    )
    features.index.names = ["host", "window_start"]
    return features.reset_index()
