"""FastAPI app. Run with: uvicorn aisoc.api.main:app --reload

The dashboard is the primary consumer. Copilot analysis runs on demand (POST
/analyze) so listing alerts stays fast and doesn't require Ollama to be up.
"""

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from aisoc import __version__
from aisoc.api.store import AlertStore
from aisoc.copilot import analyst, report
from aisoc.enrichment.schemas import CopilotAnalysis, EnrichedAlert

app = FastAPI(title="AI SOC Platform", version=__version__)
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)
store = AlertStore()

DASHBOARD_HTML = Path(__file__).resolve().parents[3] / "dashboard" / "index.html"


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    """Serve the single-page dashboard (same origin as the API — no CORS needed).

    no-store so the browser always fetches the current HTML (the file changes
    often during development and stale caches are confusing).
    """
    return FileResponse(
        DASHBOARD_HTML,
        headers={"Cache-Control": "no-store, no-cache, must-revalidate", "Pragma": "no-cache"},
    )


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "version": __version__}


@app.get("/stats")
def stats() -> dict:
    """Live telemetry for the dashboard (event rates, type mix, feed, health)."""
    from aisoc.api import stats as stats_mod

    return stats_mod.gather()


@app.get("/alerts")
def list_alerts() -> list[EnrichedAlert]:
    """Recent enriched alerts, newest first."""
    return store.list_alerts()


@app.get("/alerts/{alert_id}")
def get_alert(alert_id: str) -> EnrichedAlert:
    alert = store.get_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="alert not found")
    return alert


@app.get("/alerts/{alert_id}/analysis")
def get_analysis(alert_id: str) -> CopilotAnalysis:
    """Cached copilot analysis, if one has been run."""
    analysis = store.get_analysis(alert_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="not analyzed yet — POST /analyze first")
    return analysis


@app.post("/alerts/{alert_id}/analyze")
def analyze_alert(alert_id: str) -> CopilotAnalysis:
    """Run the LLM copilot on one alert and cache the result. Needs Ollama up."""
    alert = store.get_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="alert not found")
    try:
        analysis = analyst.analyze(alert)
    except Exception as exc:  # Ollama down / model missing
        raise HTTPException(status_code=503, detail=f"copilot unavailable: {exc}") from exc
    store.save_analysis(alert_id, analysis)
    return analysis


@app.post("/alerts/{alert_id}/report")
def get_report(alert_id: str) -> dict:
    """Full markdown incident report; analyzes first if not already done.

    POST because it may run the LLM and cache the analysis (side effects).
    """
    alert = store.get_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="alert not found")
    analysis = store.get_analysis(alert_id)
    try:
        if analysis is None:
            analysis = analyst.analyze(alert)
            store.save_analysis(alert_id, analysis)
        incident = report.generate(alert, analysis)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"copilot unavailable: {exc}") from exc
    return {"markdown": incident.markdown}
