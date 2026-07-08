# Dashboard (Phase 5)

Custom single-page dashboard — self-contained `index.html` (inline CSS/JS, no build
step, no external assets). Served by the FastAPI backend at `/`, so it's same-origin
with the API and talks straight to `/alerts` and `/alerts/{id}/analyze`.

Design: clean dark card layout with a **Jarvis-style animated radar** as the hero —
a rotating sweep, concentric rings, and severity-colored blips whose distance from the
core reflects urgency. The core shows overall posture (SECURE / GUARDED / ELEVATED /
CRITICAL) derived from the live alert mix.

## Run

From the repo root, with the venv active and Ollama running:

```powershell
python scripts/seed_alerts.py            # once, for demo alerts
uvicorn aisoc.api.main:app --port 8000
```

Then open **http://localhost:8000/** (the dashboard is served by the API itself —
no separate process).

## Layout

- **KPI row** — total alerts + counts per severity
- **Threat Posture radar** — animated HUD, live posture + per-alert blips
- **Active Alerts** — severity-sorted, click to inspect
- **Detail panel** — host/user, ML anomaly bar, MITRE chips, Wazuh rule table, and
  **Run AI Analysis** → posts to the copilot and renders the structured report inline
- Auto-refreshes alerts every 15s; live clock

## Notes

- `app.py` (Streamlit) is the **legacy** first-pass dashboard, superseded by
  `index.html`. Kept for reference; safe to delete.
- Analysis runs on demand so listing stays fast and doesn't need Ollama up.
- First "Run AI Analysis" click is slow while Ollama loads the model into RAM.
