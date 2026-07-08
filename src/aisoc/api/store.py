"""SQLite-backed store for enriched alerts and their copilot analyses.

Lightweight persistence behind the API/dashboard. The fusion pipeline writes
alerts here; the API reads them; the analyze endpoint writes analyses back.
Stdlib sqlite3 only — no extra dependency. DB lives under data/ (gitignored).
"""

import sqlite3
from pathlib import Path

from aisoc.enrichment.schemas import CopilotAnalysis, EnrichedAlert

DEFAULT_DB = Path("data/alerts.db")


class AlertStore:
    def __init__(self, path: Path | str = DEFAULT_DB) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init(self) -> None:
        with self._connect() as c:
            c.execute(
                """CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    host TEXT,
                    severity TEXT,
                    created_at TEXT,
                    window_start TEXT,
                    detected_behavior TEXT,
                    alert_json TEXT NOT NULL
                )"""
            )
            c.execute(
                """CREATE TABLE IF NOT EXISTS analyses (
                    alert_id TEXT PRIMARY KEY,
                    analysis_json TEXT NOT NULL
                )"""
            )

    def save_alert(self, alert: EnrichedAlert) -> None:
        with self._connect() as c:
            c.execute(
                "INSERT OR REPLACE INTO alerts VALUES (?,?,?,?,?,?,?)",
                (
                    alert.alert_id,
                    alert.host,
                    alert.severity.value if alert.severity else None,
                    alert.created_at.isoformat(),
                    alert.window_start.isoformat(),
                    alert.detected_behavior,
                    alert.model_dump_json(),
                ),
            )

    def list_alerts(self, limit: int = 100) -> list[EnrichedAlert]:
        with self._connect() as c:
            rows = c.execute(
                "SELECT alert_json FROM alerts ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [EnrichedAlert.model_validate_json(r["alert_json"]) for r in rows]

    def get_alert(self, alert_id: str) -> EnrichedAlert | None:
        with self._connect() as c:
            row = c.execute(
                "SELECT alert_json FROM alerts WHERE alert_id=?", (alert_id,)
            ).fetchone()
        return EnrichedAlert.model_validate_json(row["alert_json"]) if row else None

    def save_analysis(self, alert_id: str, analysis: CopilotAnalysis) -> None:
        with self._connect() as c:
            c.execute(
                "INSERT OR REPLACE INTO analyses VALUES (?,?)",
                (alert_id, analysis.model_dump_json()),
            )

    def get_analysis(self, alert_id: str) -> CopilotAnalysis | None:
        with self._connect() as c:
            row = c.execute(
                "SELECT analysis_json FROM analyses WHERE alert_id=?", (alert_id,)
            ).fetchone()
        return CopilotAnalysis.model_validate_json(row["analysis_json"]) if row else None
