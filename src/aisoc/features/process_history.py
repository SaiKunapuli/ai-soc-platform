"""Per-host process history store.

Tracks which process images and parent→child pairs have been seen on each
host, so the feature extractor can compute rarity and first-seen signals
against persistent history rather than just the current batch.

SQLite-backed (stdlib, no extra dependency). Same pattern as BaselineStore.
"""

import sqlite3
from pathlib import Path

import pandas as pd

DEFAULT_DB = Path("data/process_history.db")

# These match process_features.py column constants — imported locally
# to avoid circular imports (process_features uses string annotation for
# ProcessHistoryStore, so this import is safe).
_COL_IMAGE = "data.win.eventdata.image"
_COL_PARENT = "data.win.eventdata.parentImage"


class ProcessHistoryStore:
    def __init__(self, path: Path | str = DEFAULT_DB) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as c:
            c.execute(
                "CREATE TABLE IF NOT EXISTS process_counts "
                "(host TEXT NOT NULL, image_name TEXT NOT NULL, "
                "count INTEGER NOT NULL DEFAULT 0, "
                "PRIMARY KEY (host, image_name))"
            )
            c.execute(
                "CREATE TABLE IF NOT EXISTS parent_child_pairs "
                "(host TEXT NOT NULL, parent_name TEXT NOT NULL, child_name TEXT NOT NULL, "
                "PRIMARY KEY (host, parent_name, child_name))"
            )

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path)

    # ── Query (read before feature extraction) ────────────────────────

    def image_count(self, host: str, image_name: str) -> int:
        """How many times has this image been seen on this host?"""
        with self._connect() as c:
            row = c.execute(
                "SELECT count FROM process_counts WHERE host=? AND image_name=?",
                (host, image_name),
            ).fetchone()
        return row[0] if row else 0

    def host_max_count(self, host: str) -> int:
        """The highest image count for any image on this host."""
        with self._connect() as c:
            row = c.execute(
                "SELECT COALESCE(MAX(count), 0) FROM process_counts WHERE host=?",
                (host,),
            ).fetchone()
        return row[0]

    def is_new_pair(self, host: str, parent_name: str, child_name: str) -> bool:
        """True if this parent→child pair has never been seen before on this host."""
        with self._connect() as c:
            row = c.execute(
                "SELECT 1 FROM parent_child_pairs WHERE host=? AND parent_name=? AND child_name=?",
                (host, parent_name, child_name),
            ).fetchone()
        return row is None

    # ── Record (write after feature extraction) ───────────────────────

    def record_batch(self, events: pd.DataFrame) -> None:
        """Increment image counts and record new parent→child pairs from a batch.

        Accepts raw events straight from the indexer (columns like
        ``data.win.eventdata.image``) and derives ``image_name``/``parent_name``
        internally so callers don't need to preprocess.
        """
        if events is None or events.empty:
            return

        host_col = "agent.name"
        if host_col not in events.columns:
            return

        # Derive image_name / parent_name from raw columns (same logic as pf.extract)
        img_col = _COL_IMAGE if _COL_IMAGE in events.columns else "image_name"
        parent_col = _COL_PARENT if _COL_PARENT in events.columns else "parent_name"

        events = events.copy()
        events["image_name"] = events[img_col].fillna("").astype(str).str.lower().str.split("\\").str[-1]
        events["parent_name"] = events[parent_col].fillna("").astype(str).str.lower().str.split("\\").str[-1]

        # Group by (host, image_name) and count occurrences in this batch
        counts = events.groupby([host_col, "image_name"]).size()
        pairs = events.groupby([host_col, "parent_name", "image_name"]).size()

        with self._connect() as c:
            for (host, img), n in counts.items():
                c.execute(
                    "INSERT INTO process_counts (host, image_name, count) VALUES (?,?,?) "
                    "ON CONFLICT(host, image_name) DO UPDATE SET count = count + excluded.count",
                    (str(host), str(img), int(n)),
                )
            for (host, parent, child), _ in pairs.items():
                c.execute(
                    "INSERT OR IGNORE INTO parent_child_pairs (host, parent_name, child_name) "
                    "VALUES (?,?,?)",
                    (str(host), str(parent), str(child)),
                )

    def reset(self) -> None:
        """Drop all history. Call on retrain so old baselines don't pollute."""
        with self._connect() as c:
            c.execute("DELETE FROM process_counts")
            c.execute("DELETE FROM parent_child_pairs")

    def host_image_counts(self, host: str) -> dict[str, int]:
        """All (image_name → count) pairs for a host. Used during feature extraction."""
        with self._connect() as c:
            rows = c.execute(
                "SELECT image_name, count FROM process_counts WHERE host=?",
                (host,),
            ).fetchall()
        return {r[0]: r[1] for r in rows}

    def host_known_pairs(self, host: str) -> set[tuple[str, str]]:
        """All (parent_name, child_name) pairs ever seen for a host.

        Returns a set for O(1) lookup during feature extraction.
        """
        with self._connect() as c:
            rows = c.execute(
                "SELECT parent_name, child_name FROM parent_child_pairs WHERE host=?",
                (host,),
            ).fetchall()
        return {(r[0], r[1]) for r in rows}
