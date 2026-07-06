"""Per-entity baseline store.

Anomaly scores only mean something relative to an entity's own history. This module
tracks, per entity (host/user), the distribution of past scores so the enrichment
layer can ask: "is this window above this entity's 95th percentile?"

TODO(phase 3): implement — a parquet/sqlite-backed rolling score history is plenty.
Also the natural home for concept-drift checks later (has the baseline itself shifted?).
"""


class BaselineStore:
    def record(self, entity: str, window_start: str, score: float) -> None:
        raise NotImplementedError

    def percentile(self, entity: str, score: float) -> float:
        """Where does this score fall in the entity's history? (0-100)"""
        raise NotImplementedError
