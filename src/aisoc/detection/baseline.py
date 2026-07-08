"""Per-entity baseline store.

Anomaly scores only mean something relative to an entity's own history. This module
tracks, per entity (host/user), the distribution of past scores so the enrichment
layer can ask: "is this window above this entity's 95th percentile?"

SQLite-backed (stdlib, no extra dependency). Unlike the pipeline's within-batch
percentile, this accumulates history ACROSS runs, so a single freshly-scored window
can be ranked against everything the entity has done before — the streaming shape a
real deployment needs. Natural home for concept-drift checks later.
"""

import sqlite3
from pathlib import Path

DEFAULT_DB = Path("data/baselines.db")

# With no history for an entity we can't rank it; return neutral rather than
# treating a first-seen entity as maximally anomalous (which would false-positive).
NEUTRAL_PERCENTILE = 50.0


class BaselineStore:
    def __init__(self, path: Path | str = DEFAULT_DB) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as c:
            c.execute(
                "CREATE TABLE IF NOT EXISTS scores "
                "(entity TEXT NOT NULL, window_start TEXT NOT NULL, score REAL NOT NULL, "
                "PRIMARY KEY (entity, window_start))"
            )
            c.execute("CREATE INDEX IF NOT EXISTS ix_entity ON scores(entity)")

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path)

    def record(self, entity: str, window_start: str, score: float) -> None:
        with self._connect() as c:
            c.execute(
                "INSERT OR REPLACE INTO scores VALUES (?,?,?)",
                (entity, str(window_start), float(score)),
            )

    def record_many(self, entity: str, rows) -> None:
        """Bulk record (window_start, score) pairs for one entity."""
        with self._connect() as c:
            c.executemany(
                "INSERT OR REPLACE INTO scores VALUES (?,?,?)",
                [(entity, str(w), float(s)) for w, s in rows],
            )

    def percentile(self, entity: str, score: float) -> float:
        """Where does this score fall in the entity's history? (0-100).

        Fraction of the entity's historical scores at or below `score`, x100.
        Returns NEUTRAL_PERCENTILE if the entity has no history yet.
        """
        with self._connect() as c:
            total, below = c.execute(
                "SELECT COUNT(*), COALESCE(SUM(CASE WHEN score <= ? THEN 1 ELSE 0 END), 0) "
                "FROM scores WHERE entity = ?",
                (float(score), entity),
            ).fetchone()
        if not total:
            return NEUTRAL_PERCENTILE
        return 100.0 * below / total

    def count(self, entity: str) -> int:
        with self._connect() as c:
            return c.execute(
                "SELECT COUNT(*) FROM scores WHERE entity = ?", (entity,)
            ).fetchone()[0]

    def reset(self) -> None:
        """Drop all history. Call on retrain — old scores came from a different
        model and must not be mixed with the new model's scores."""
        with self._connect() as c:
            c.execute("DELETE FROM scores")
