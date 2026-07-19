"""Detection-metric tests with hand-computed expectations."""

import pandas as pd

from aisoc.detection.evaluate import evaluate, format_sweep, sweep


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


def test_confusion_and_fpr() -> None:
    # threshold_pct=70 over 5 scores -> cutoff ~0.46, flags the two >=0.5.
    # attacks: idx2 (0.30, missed) and idx4 (0.90, caught). benign: 0.10/0.20/0.50.
    scores = pd.Series([0.10, 0.20, 0.30, 0.50, 0.90])
    labels = pd.Series([False, False, True, False, True])
    m = evaluate(scores, labels, threshold_pct=70)
    assert (m["tp"], m["fp"], m["tn"], m["fn"]) == (1, 1, 2, 1)
    assert m["fpr"] == round(1 / 3, 3)  # 1 benign flagged out of 3 benign windows


def test_fpr_zero_when_no_false_positives() -> None:
    scores = pd.Series([0.10, 0.15, 0.20, 0.90, 0.95])
    labels = pd.Series([False, False, False, True, True])
    m = evaluate(scores, labels, threshold_pct=60)
    assert m["fpr"] == 0.0 and m["fp"] == 0


def test_sweep_covers_each_threshold() -> None:
    scores = pd.Series([0.1, 0.2, 0.3, 0.4, 0.9])
    labels = pd.Series([False, False, False, False, True])
    rows = sweep(scores, labels, pcts=(80, 90, 95))
    assert [r["threshold_pct"] for r in rows] == [80, 90, 95]
    # looser threshold flags at least as many windows as a stricter one
    flagged = [r["flagged"] for r in rows]
    assert flagged == sorted(flagged, reverse=True)
    assert "pct" in format_sweep(rows) and "FPR" in format_sweep(rows)
