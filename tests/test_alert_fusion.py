"""Fusion policy tests — the rules that decide when a score becomes an alert."""

from datetime import datetime, timedelta, timezone

from aisoc.enrichment import alert_fusion as af
from aisoc.enrichment.schemas import MitreTechnique, MlDetection, RuleAlert, Severity

T0 = datetime(2026, 7, 6, 12, 0, tzinfo=timezone.utc)
WIN = timedelta(minutes=10)


def rule(level: int, tech: str = "T1059.001") -> RuleAlert:
    return RuleAlert(
        rule_id="92052",
        description="Encoded PowerShell detected",
        level=level,
        timestamp=T0,
        mitre=[MitreTechnique(technique_id=tech, name="PowerShell", tactic="Execution")],
    )


def ml(pct: float | None, features=("encoded_cmd",)) -> MlDetection:
    return MlDetection(anomaly_score=0.9, baseline_percentile=pct, top_features=list(features))


def fuse(rule_alerts, ml_detection, ml_corroborated=False):
    return af.fuse_window(
        host="H1",
        window_start=T0,
        window_end=T0 + WIN,
        rule_alerts=rule_alerts,
        ml_detection=ml_detection,
        ml_corroborated=ml_corroborated,
    )


def test_high_level_rule_alone_emits() -> None:
    alert = fuse([rule(12)], ml_detection=ml(10.0))  # low ML percentile
    assert alert is not None
    assert alert.rule_alerts[0].level == 12


def test_anomalous_ml_alone_is_suppressed() -> None:
    # 99th percentile but no rule, no streak corroboration -> NOT an alert
    assert fuse([], ml_detection=ml(99.0)) is None


def test_anomalous_ml_with_rule_corroboration_emits() -> None:
    # low-level rule (below significant threshold) but present -> corroborates ML
    alert = fuse([rule(3)], ml_detection=ml(99.0))
    assert alert is not None


def test_anomalous_ml_with_streak_corroboration_emits() -> None:
    alert = fuse([], ml_detection=ml(99.0), ml_corroborated=True)
    assert alert is not None


def test_quiet_window_no_alert() -> None:
    assert fuse([rule(3)], ml_detection=ml(40.0)) is None


def test_significant_rule_without_anomaly_is_only_medium() -> None:
    # the core fix: a noisy level-15 rule with a NORMAL ml score is MEDIUM, not HIGH
    alert = fuse([rule(15)], ml_detection=ml(40.0))
    assert alert.severity == Severity.MEDIUM


def test_rule_and_anomaly_agreement_escalates() -> None:
    assert fuse([rule(8)], ml_detection=ml(99.0)).severity == Severity.HIGH
    assert fuse([rule(12)], ml_detection=ml(99.0)).severity == Severity.CRITICAL


def test_mitre_merges_rule_and_ml() -> None:
    # rule gives T1059.001; ML feature 'new_parent_child' maps to T1055
    alert = fuse([rule(12)], ml_detection=ml(99.0, features=["new_parent_child"]))
    ids = {t.technique_id for t in alert.mitre}
    assert {"T1059.001", "T1055"} <= ids


def test_stream_streak_triggers_ml_only_alert() -> None:
    # three consecutive anomalous windows, no rules -> 3rd emits on streak
    windows = [
        {"host": "H1", "window_start": T0 + i * WIN, "window_end": T0 + (i + 1) * WIN,
         "rule_alerts": [], "ml_detection": ml(99.0)}
        for i in range(3)
    ]
    alerts = af.fuse_stream(windows)
    assert len(alerts) == 1  # only the 3rd window clears the streak threshold
    assert alerts[0].window_start == T0 + 2 * WIN
