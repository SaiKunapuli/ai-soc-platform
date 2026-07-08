"""Fusion: (entity, window) + Wazuh rule alerts + ML score → EnrichedAlert.

Alerting policy (see docs/03-design-decisions.md, #10): an anomaly score alone
never becomes an alert. An EnrichedAlert is emitted when either
  a) a Wazuh rule alert of level >= RULE_LEVEL_THRESHOLD exists in the window
     (ML score attached as context, even if low), or
  b) the ML score exceeds the entity's baseline percentile threshold AND there is
     corroboration (any rule alert in the window, or the same entity deviating in
     N consecutive windows — see fuse_stream).
"""

from datetime import datetime

from aisoc.enrichment import mitre
from aisoc.enrichment.schemas import (
    EnrichedAlert,
    MitreTechnique,
    MlDetection,
    RuleAlert,
    Severity,
)

RULE_LEVEL_THRESHOLD = 7
ML_PERCENTILE_THRESHOLD = 95.0
CONSECUTIVE_WINDOWS_FOR_ML_ONLY = 3


def _merge_mitre(rule_alerts: list[RuleAlert], ml: MlDetection | None) -> list[MitreTechnique]:
    """Rule passthrough + ML feature-based mapping, deduped by technique_id."""
    seen: dict[str, MitreTechnique] = {}
    for ra in rule_alerts:
        for t in ra.mitre:
            seen.setdefault(t.technique_id, t)
    if ml:
        for t in mitre.map_ml_detection(ml.top_features):
            seen.setdefault(t.technique_id, t)
    return list(seen.values())


def _describe(rule_alerts: list[RuleAlert], ml: MlDetection | None, ml_anomalous: bool) -> str:
    """One-line human summary from the strongest rule + notable ML features."""
    parts: list[str] = []
    if rule_alerts:
        top = max(rule_alerts, key=lambda ra: ra.level)
        parts.append(top.description)
    if ml_anomalous and ml and ml.top_features:
        parts.append("anomalous: " + ", ".join(ml.top_features))
    return "; ".join(parts) or "anomalous behavior"


def _heuristic_severity(
    rule_alerts: list[RuleAlert], ml: MlDetection | None, ml_anomalous: bool
) -> Severity:
    """Provisional severity from the *agreement* of the two detection layers.

    The whole thesis: a signal from one layer alone is not enough to page. A
    noisy high-level Wazuh rule (e.g. "executable dropped in a malware folder",
    level 15) fires constantly on normal dev tooling — so a significant rule
    with a *normal* ML score is only MEDIUM (investigate, don't escalate).
    HIGH/CRITICAL require the rule AND the behavioral anomaly to concur.
    Copilot may still override with its own judgement.
    """
    max_level = max((ra.level for ra in rule_alerts), default=0)
    significant = max_level >= RULE_LEVEL_THRESHOLD  # >= 7
    if significant and ml_anomalous:
        return Severity.CRITICAL if max_level >= 12 else Severity.HIGH
    if significant or ml_anomalous:
        return Severity.MEDIUM
    return Severity.LOW


def fuse_window(
    host: str,
    window_start: datetime,
    window_end: datetime,
    rule_alerts: list[RuleAlert],
    ml_detection: MlDetection | None,
    user: str | None = None,
    ml_corroborated: bool = False,
) -> EnrichedAlert | None:
    """Apply the alerting policy; return an EnrichedAlert or None.

    ml_corroborated carries the "repeated deviation" signal that only a
    higher-level view can compute (see fuse_stream). Within a single window,
    corroboration also comes from any rule alert being present.
    """
    significant_rule = any(ra.level >= RULE_LEVEL_THRESHOLD for ra in rule_alerts)
    ml_anomalous = (
        ml_detection is not None
        and ml_detection.baseline_percentile is not None
        and ml_detection.baseline_percentile >= ML_PERCENTILE_THRESHOLD
    )
    corroborated = bool(rule_alerts) or ml_corroborated

    if not (significant_rule or (ml_anomalous and corroborated)):
        return None

    return EnrichedAlert(
        host=host,
        user=user,
        window_start=window_start,
        window_end=window_end,
        detected_behavior=_describe(rule_alerts, ml_detection, ml_anomalous),
        rule_alerts=rule_alerts,
        ml=ml_detection,
        mitre=_merge_mitre(rule_alerts, ml_detection),
        severity=_heuristic_severity(rule_alerts, ml_detection, ml_anomalous),
    )


def fuse_stream(windows: list[dict]) -> list[EnrichedAlert]:
    """Fuse a chronological list of per-window records into alerts.

    Each record: {host, window_start, window_end, rule_alerts, ml_detection, user?}.
    Tracks consecutive anomalous windows per entity so that a sustained ML
    deviation (>= CONSECUTIVE_WINDOWS_FOR_ML_ONLY) counts as corroboration even
    with no rule alert.
    """
    streak: dict[str, int] = {}
    alerts: list[EnrichedAlert] = []

    for w in sorted(windows, key=lambda r: r["window_start"]):
        host = w["host"]
        ml = w.get("ml_detection")
        anomalous = (
            ml is not None
            and ml.baseline_percentile is not None
            and ml.baseline_percentile >= ML_PERCENTILE_THRESHOLD
        )
        streak[host] = streak.get(host, 0) + 1 if anomalous else 0
        ml_corroborated = streak[host] >= CONSECUTIVE_WINDOWS_FOR_ML_ONLY

        alert = fuse_window(
            host=host,
            window_start=w["window_start"],
            window_end=w["window_end"],
            rule_alerts=w.get("rule_alerts", []),
            ml_detection=ml,
            user=w.get("user"),
            ml_corroborated=ml_corroborated,
        )
        if alert:
            alerts.append(alert)
    return alerts
