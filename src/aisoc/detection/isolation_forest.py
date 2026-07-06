"""Isolation Forest anomaly detector over windowed behavioral features."""

from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


class AnomalyDetector:
    """Fit on normal-usage windows; score any window 0 (normal) → 1 (most anomalous)."""

    def __init__(self, contamination: float | str = "auto", random_state: int = 42) -> None:
        self._scaler = StandardScaler()
        self._model = IsolationForest(
            n_estimators=200, contamination=contamination, random_state=random_state
        )
        self._feature_names: list[str] = []

    def fit(self, features: pd.DataFrame) -> "AnomalyDetector":
        """Train on baseline (assumed-normal) feature windows."""
        self._feature_names = list(features.columns)
        self._model.fit(self._scaler.fit_transform(features))
        return self

    def score(self, features: pd.DataFrame) -> np.ndarray:
        """Normalized anomaly score per window: 0 = normal, 1 = most anomalous.

        sklearn's score_samples returns higher = more normal; invert and min-max
        normalize against the training score range.
        TODO(phase 2): store training score range at fit time for stable normalization.
        """
        features = features[self._feature_names]
        raw = self._model.score_samples(self._scaler.transform(features))
        return (raw.max() - raw) / (raw.max() - raw.min() + 1e-9)

    def top_contributing_features(self, window: pd.Series, k: int = 3) -> list[str]:
        """The k features most responsible for a window's anomaly score.

        Needed by the copilot layer — "anomalous because encoded_cmd + rare_proc_score".
        TODO(phase 3): implement (simple z-score vs. training mean works fine here).
        """
        raise NotImplementedError

    def save(self, path: Path) -> None:
        joblib.dump({"scaler": self._scaler, "model": self._model, "features": self._feature_names}, path)

    @classmethod
    def load(cls, path: Path) -> "AnomalyDetector":
        state = joblib.load(path)
        detector = cls()
        detector._scaler = state["scaler"]
        detector._model = state["model"]
        detector._feature_names = state["features"]
        return detector
