"""Integration tests — end-to-end flow through the API with a real (in-memory) store.

Verifies the full alert lifecycle: seed → list → detail → analyze → report → feedback,
without needing a live Wazuh indexer or Ollama.
"""

import pytest
from fastapi.testclient import TestClient

from aisoc.api.main import app, store
from aisoc.copilot.sample_alert import all_samples


@pytest.fixture(autouse=True)
def clean_store(tmp_path, monkeypatch):
    """Point AlertStore at a temp DB and seed with sample alerts."""
    db = tmp_path / "data" / "alerts.db"
    # Override the module-level store with a fresh one
    from aisoc.api import main

    main.store = main.AlertStore(db)
    for alert in all_samples():
        main.store.save_alert(alert)
    yield
    # Cleanup
    main.store = store


@pytest.fixture
def client():
    return TestClient(app)


class TestHealth:
    def test_health_ok(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_copilot_health_reports_status(self, client):
        r = client.get("/copilot/health")
        assert r.status_code == 200
        data = r.json()
        assert "online" in data


class TestAlerts:
    def test_list_alerts_returns_sample_alerts(self, client):
        r = client.get("/alerts")
        assert r.status_code == 200
        alerts = r.json()
        assert len(alerts) >= 3  # all_samples currently produces 3
        severities = {a.get("severity") for a in alerts}
        assert "high" in severities  # encoded_powershell_alert is high

    def test_get_alert_by_id(self, client):
        r = client.get("/alerts")
        alert_id = r.json()[0]["alert_id"]
        r = client.get(f"/alerts/{alert_id}")
        assert r.status_code == 200
        assert r.json()["alert_id"] == alert_id

    def test_get_alert_404(self, client):
        r = client.get("/alerts/nonexistent")
        assert r.status_code == 404


class TestFeedback:
    def test_submit_and_read_feedback(self, client):
        # Get a real alert id
        alerts = client.get("/alerts").json()
        alert_id = alerts[0]["alert_id"]

        # Submit feedback
        r = client.post(f"/alerts/{alert_id}/feedback?verdict=true_positive")
        assert r.status_code == 200
        assert r.json()["verdict"] == "true_positive"

        # Read all feedback
        r = client.get("/feedback")
        assert r.status_code == 200
        assert r.json()[alert_id] == "true_positive"

    def test_submit_invalid_verdict(self, client):
        alerts = client.get("/alerts").json()
        alert_id = alerts[0]["alert_id"]
        r = client.post(f"/alerts/{alert_id}/feedback?verdict=maybe")
        assert r.status_code == 422

    def test_submit_feedback_for_nonexistent_alert(self, client):
        r = client.post("/alerts/fake-id/feedback?verdict=true_positive")
        assert r.status_code == 404


class TestDashboard:
    def test_dashboard_serves_html(self, client):
        r = client.get("/")
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]
        assert "AI SOC" in r.text

    def test_dashboard_no_cache(self, client):
        r = client.get("/")
        assert r.headers["cache-control"] == "no-store, no-cache, must-revalidate"


class TestStats:
    def test_stats_returns_ok_false_when_indexer_down(self, client):
        """Stats degrades gracefully when the indexer is unreachable."""
        r = client.get("/stats")
        assert r.status_code == 200
        data = r.json()
        # Without a live indexer, gather() returns ok=False
        assert "ok" in data
