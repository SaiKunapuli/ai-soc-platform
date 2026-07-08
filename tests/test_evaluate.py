"""Detection-metric tests with hand-computed expectations."""

import pandas as pd

from aisoc.detection.evaluate import evaluate


def test_perfect_separation() -> None:
    scores = pd.Series([0.10, 0.15, 0.20, 0.90, 0.95])
    labels = pd.Series([False, False, False, True, True])
    m = evaluate(scores, labels, threshold_pct=60)
    assert m["precision"] == 1.0 and m["recall"] == 1.0 and m["f1"] == 1.0
    assert m["roc_auc"] == 1.0


def test_partial_detection() -> None:
    # one attack scores low (missed), one benign scores high (false positive)
    scores = pd.Series([0.10, 0.20, 0.30, 0.50, 0.90])
    labels = pd.Series([False, False, True, False, True])
    m = evaluate(scores, labels, threshold_pct=70)  # threshold ~0.46
    assert m["recall"] == 0.5      # caught 1 of 2 attacks
    assert m["precision"] == 0.5   # 1 of 2 flags was a real attack


def test_no_attack_windows_returns_note() -> None:
    m = evaluate(pd.Series([0.1, 0.2, 0.3]), pd.Series([False, False, False]))
    assert "note" in m
    assert "precision" not in m


def test_metrics_are_bounded() -> None:
    m = evaluate(pd.Series([0.1, 0.9, 0.4, 0.7]), pd.Series([False, True, False, True]))
    for key in ("precision", "recall", "f1", "roc_auc", "pr_auc"):
        assert 0.0 <= m[key] <= 1.0
