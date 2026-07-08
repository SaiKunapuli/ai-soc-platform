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

import pandas as pd

from aisoc.features.windows import assign_windows

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


def extract(process_events: pd.DataFrame) -> pd.DataFrame:
    """Sysmon EID-1 events → one feature row per (host, window).

    Rarity and first-seen are computed within the given batch, so pass baseline
    history and the scoring period together.
    TODO(phase 3): back rarity/first-seen with a persistent per-host history store
    so scoring doesn't need the whole history in memory.
    """
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

    # Rarity of an image on its host: ~1 for a singleton, 0 for the host's most common image
    image_counts = events.groupby([COL_HOST, "image_name"])[COL_HOST].transform("size")
    host_max = image_counts.groupby(events[COL_HOST]).transform("max")
    events["rarity"] = 1.0 - image_counts / host_max

    # First occurrence of a (parent, child) pair on this host (events are time-sorted)
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
