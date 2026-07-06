"""Contract tests for the system-wide schemas."""

from datetime import datetime, timedelta

from aisoc.enrichment.schemas import EnrichedAlert, MlDetection, Severity


def make_alert(**overrides) -> EnrichedAlert:
    now = datetime.utcnow()
    defaults = dict(
        host="DESKTOP-01",
        user="john_doe",
        window_start=now - timedelta(minutes=10),
        window_end=now,
        detected_behavior="unusual PowerShell execution + external IP connection",
        ml=MlDetection(anomaly_score=0.92, top_features=["encoded_cmd", "rare_proc_score"]),
    )
    defaults.update(overrides)
    return EnrichedAlert(**defaults)


def test_enriched_alert_roundtrips_through_json() -> None:
    alert = make_alert()
    restored = EnrichedAlert.model_validate_json(alert.model_dump_json())
    assert restored == alert


def test_severity_serializes_as_string() -> None:
    alert = make_alert(severity=Severity.HIGH)
    assert '"severity":"high"' in alert.model_dump_json().replace(" ", "")


def test_anomaly_score_bounds_enforced() -> None:
    import pytest

    with pytest.raises(ValueError):
        MlDetection(anomaly_score=1.5)
