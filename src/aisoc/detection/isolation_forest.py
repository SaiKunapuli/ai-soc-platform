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
        # training-score range, stored so scores are stable across calls (not
        # renormalized per batch)
        self._smin: float = 0.0
        self._smax: float = 1.0

    def fit(self, features: pd.DataFrame) -> "AnomalyDetector":
        """Train on baseline (assumed-normal) feature windows."""
        self._feature_names = list(features.columns)
        scaled = self._scaler.fit_transform(features)
        self._model.fit(scaled)
        raw = self._model.score_samples(scaled)
        self._smin, self._smax = float(raw.min()), float(raw.max())
        return self

    def score(self, features: pd.DataFrame) -> np.ndarray:
        """Normalized anomaly score per window: 0 = normal, 1 = most anomalous.

        sklearn's score_samples returns higher = more normal. We invert and min-max
        normalize against the *training* score range (stored at fit) so a given
        window always gets the same score regardless of what else is in the batch.
        Windows more anomalous than anything seen in training clip to 1.0.
        """
        raw = self._model.score_samples(self._scaler.transform(features[self._feature_names]))
        span = self._smax - self._smin + 1e-9
        return np.clip((self._smax - raw) / span, 0.0, 1.0)

    def top_contributing_features(self, window: pd.Series, k: int = 3) -> list[str]:
        """The k features whose values deviate most from the training baseline.

        Uses standardized deviation (|z|) via the fitted scaler's mean/scale, so
        "why is this window anomalous" is answered in feature terms — e.g.
        ["encoded_cmd", "rare_proc_score"]. Drives MITRE mapping + the copilot.
        """
        x = window[self._feature_names].to_numpy(dtype=float)
        z = np.abs((x - self._scaler.mean_) / (self._scaler.scale_ + 1e-9))
        order = np.argsort(z)[::-1][:k]
        return [self._feature_names[i] for i in order if z[i] > 0]

    def save(self, path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "scaler": self._scaler,
                "model": self._model,
                "features": self._feature_names,
                "smin": self._smin,
                "smax": self._smax,
            },
            path,
        )

    @classmethod
    def load(cls, path: Path) -> "AnomalyDetector":
        state = joblib.load(path)
        detector = cls()
        detector._scaler = state["scaler"]
        detector._model = state["model"]
        detector._feature_names = state["features"]
        detector._smin = state.get("smin", 0.0)
        detector._smax = state.get("smax", 1.0)
        return detector
