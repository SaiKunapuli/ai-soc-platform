"""AnomalyDetector tests on synthetic normal/outlier windows."""

import numpy as np
import pandas as pd

from aisoc.detection.isolation_forest import AnomalyDetector
from aisoc.features.process_features import FEATURE_COLUMNS


def _normal(n: int = 60, seed: int = 0) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    return pd.DataFrame({
        "proc_count": rng.integers(3, 10, n),
        "ps_count": rng.integers(0, 2, n),
        "encoded_cmd": np.zeros(n),
        "max_cmd_entropy": rng.uniform(3.5, 4.8, n),
        "max_cmd_len": rng.integers(20, 150, n),
        "rare_proc_score": rng.uniform(0, 0.2, n),
        "new_parent_child": rng.integers(0, 2, n),
        "burst_rate": rng.integers(1, 3, n),
    })[FEATURE_COLUMNS]


_OUTLIER = pd.DataFrame([{
    "proc_count": 60, "ps_count": 9, "encoded_cmd": 4,
    "max_cmd_entropy": 5.9, "max_cmd_len": 640,
    "rare_proc_score": 0.9, "new_parent_child": 7, "burst_rate": 15,
}])[FEATURE_COLUMNS]


def test_outlier_scores_higher_than_typical_normal() -> None:
    det = AnomalyDetector().fit(_normal())
    normal = det.score(_normal(40, seed=1))
    outlier = det.score(_OUTLIER)[0]
    assert outlier > np.median(normal)          # above the typical normal window
    assert (normal < outlier).mean() >= 0.6     # more anomalous than most normal windows


def test_scores_are_bounded() -> None:
    det = AnomalyDetector().fit(_normal())
    s = det.score(pd.concat([_normal(10, seed=3), _OUTLIER], ignore_index=True))
    assert s.min() >= 0.0 and s.max() <= 1.0


def test_top_features_flags_the_deviant_one() -> None:
    det = AnomalyDetector().fit(_normal())
    window = pd.Series({
        "proc_count": 6, "ps_count": 1, "encoded_cmd": 5,
        "max_cmd_entropy": 4.2, "max_cmd_len": 60,
        "rare_proc_score": 0.1, "new_parent_child": 1, "burst_rate": 2,
    })
    assert "encoded_cmd" in det.top_contributing_features(window, k=2)


def test_save_load_preserves_scores(tmp_path) -> None:
    det = AnomalyDetector().fit(_normal())
    x = _normal(5, seed=2)
    p = tmp_path / "m.joblib"
    det.save(p)
    reloaded = AnomalyDetector.load(p)
    assert np.allclose(det.score(x), reloaded.score(x))
