"""API route/method tests (no Ollama needed).

Regression guard: the dashboard POSTs to /report; that endpoint must accept POST.
A missing alert returns 404 *after* method routing, so these assert the verb
contract without ever invoking the copilot.
"""

from fastapi.testclient import TestClient

from aisoc.api.main import app

client = TestClient(app)


def test_health_ok() -> None:
    assert client.get("/health").json()["status"] == "ok"


def test_list_alerts_ok() -> None:
    assert client.get("/alerts").status_code == 200


def test_stats_ok_and_degrades_gracefully() -> None:
    # /stats returns 200 even if the indexer is unreachable (ok:false), never 500
    r = client.get("/stats")
    assert r.status_code == 200
    assert "ok" in r.json()


def test_report_accepts_post_not_get() -> None:
    # regression: /report used to be GET-only, so the dashboard's POST 405'd
    assert client.get("/alerts/missing/report").status_code == 405
    assert client.post("/alerts/missing/report").status_code == 404  # route ok, alert absent


def test_analyze_accepts_post_missing_alert_404() -> None:
    assert client.get("/alerts/missing/analyze").status_code == 405
    assert client.post("/alerts/missing/analyze").status_code == 404
