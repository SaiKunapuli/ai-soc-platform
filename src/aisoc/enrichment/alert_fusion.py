"""Fusion: (entity, window) + Wazuh rule alerts + ML score → EnrichedAlert.

Alerting policy (see 03 - Design Decisions, #10): an anomaly score alone never
becomes an alert. An EnrichedAlert is emitted when either
  a) a Wazuh rule alert of level >= RULE_LEVEL_THRESHOLD exists in the window
     (ML score attached as context, even if low), or
  b) the ML score exceeds the entity's baseline percentile threshold AND there is
     corroboration (any rule alert in the window, or the same entity deviating in
     N consecutive windows).
"""

from datetime import datetime

from aisoc.enrichment.schemas import EnrichedAlert

RULE_LEVEL_THRESHOLD = 7
ML_PERCENTILE_THRESHOLD = 95.0
CONSECUTIVE_WINDOWS_FOR_ML_ONLY = 3


def fuse_window(
    host: str,
    window_start: datetime,
    window_end: datetime,
    rule_alerts: list,  # list[RuleAlert] for this (host, window)
    ml_detection,  # MlDetection | None
) -> EnrichedAlert | None:
    """Apply the alerting policy above; return an EnrichedAlert or None.

    TODO(phase 3): implement. Compose detected_behavior from rule descriptions +
    top ML features; merge MITRE from rule passthrough + mitre.map_ml_detection.
    """
    raise NotImplementedError
