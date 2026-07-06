"""FastAPI app. Run with: uvicorn aisoc.api.main:app --reload"""

from fastapi import FastAPI, HTTPException

from aisoc import __version__
from aisoc.enrichment.schemas import CopilotAnalysis, EnrichedAlert

app = FastAPI(title="AI SOC Platform", version=__version__)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "version": __version__}


@app.get("/alerts")
def list_alerts() -> list[EnrichedAlert]:
    """Recent enriched alerts, newest first.

    TODO(phase 5): back with an alert store (sqlite is fine) populated by the
    fusion pipeline.
    """
    raise HTTPException(status_code=501, detail="not implemented yet (phase 5)")


@app.get("/alerts/{alert_id}")
def get_alert(alert_id: str) -> EnrichedAlert:
    raise HTTPException(status_code=501, detail="not implemented yet (phase 5)")


@app.post("/alerts/{alert_id}/analyze")
def analyze_alert(alert_id: str) -> CopilotAnalysis:
    """Run the LLM copilot on one alert (aisoc.copilot.analyst.analyze)."""
    raise HTTPException(status_code=501, detail="not implemented yet (phase 5)")
