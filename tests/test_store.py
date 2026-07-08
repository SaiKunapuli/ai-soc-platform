"""AlertStore round-trip tests (temp DB, no network)."""

from aisoc.api.store import AlertStore
from aisoc.copilot.sample_alert import all_samples, sample_encoded_powershell_alert
from aisoc.enrichment.schemas import CopilotAnalysis, Severity


def test_save_and_get_alert(tmp_path) -> None:
    store = AlertStore(tmp_path / "t.db")
    alert = sample_encoded_powershell_alert()
    store.save_alert(alert)
    got = store.get_alert(alert.alert_id)
    assert got == alert


def test_list_orders_and_returns_all(tmp_path) -> None:
    store = AlertStore(tmp_path / "t.db")
    for a in all_samples():
        store.save_alert(a)
    listed = store.list_alerts()
    assert len(listed) == 3


def test_missing_alert_is_none(tmp_path) -> None:
    store = AlertStore(tmp_path / "t.db")
    assert store.get_alert("nope") is None


def test_analysis_round_trip(tmp_path) -> None:
    store = AlertStore(tmp_path / "t.db")
    alert = sample_encoded_powershell_alert()
    store.save_alert(alert)
    analysis = CopilotAnalysis(
        explanation="x", attack_interpretation="y", severity=Severity.HIGH,
        severity_rationale="z", investigation_steps=["a"], containment_recommendations=["b"],
        iocs=["DESKTOP-STQNCN4"],
    )
    store.save_analysis(alert.alert_id, analysis)
    assert store.get_analysis(alert.alert_id) == analysis
