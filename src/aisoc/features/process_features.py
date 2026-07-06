"""Process-behavior features from Sysmon Event ID 1 (process creation).

Phase 2's one and only feature family. Per (host, window):

- proc_count            total process creations
- ps_count              PowerShell/cmd/wscript launches
- encoded_cmd           any command line with -enc/-e/-EncodedCommand or high-entropy args
- rare_proc_score       mean rarity of image paths vs. this host's history
- new_parent_child      count of never-before-seen parent->child image pairs
- burst_rate            max creations in any 1-min sub-bucket (detects tool spray)
"""

import math
from collections import Counter

import pandas as pd

from aisoc.features.windows import bucket_by_entity

SCRIPT_HOSTS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"}
ENCODED_FLAGS = ("-enc", "-encodedcommand", "-e ")


def command_line_entropy(cmdline: str) -> float:
    """Shannon entropy of the command line — base64 blobs score high."""
    if not cmdline:
        return 0.0
    counts = Counter(cmdline)
    total = len(cmdline)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def extract(process_events: pd.DataFrame) -> pd.DataFrame:
    """Sysmon EID-1 events → one feature row per (host, window).

    Expects the flattened columns produced by IndexerClient.fetch_sysmon_process_events
    (e.g. ``data.win.eventdata.image``, ``data.win.eventdata.commandLine``,
    ``data.win.eventdata.parentImage``, ``agent.name``).

    TODO(phase 2): implement the aggregations listed in the module docstring,
    using bucket_by_entity(events, entity_col="agent.name").
    """
    raise NotImplementedError
