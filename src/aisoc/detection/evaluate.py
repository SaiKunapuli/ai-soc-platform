"""Evaluate anomaly detection against labeled attack windows.

Given per-window anomaly scores and boolean attack labels (from Atomic Red Team
runs recorded in simulations/labels.csv), compute how well the detector separates
attack windows from normal ones. This is the Phase 2 exit-criterion machinery.
"""

import pandas as pd
from sklearn.metrics import (
    average_precision_score,
    precision_recall_fscore_support,
    roc_auc_score,
)


def evaluate(scores, labels, threshold_pct: float = 95.0) -> dict:
    """Detection metrics for one scored, labeled set of windows.

    An alert fires when a window's score is at/above the ``threshold_pct``
    percentile of all scores in the set (the same self-baselining idea the
    pipeline uses). Threshold-free ranking quality is also reported via ROC-AUC
    and PR-AUC, which don't depend on where the cutoff is placed.

    Returns a dict of metrics; keys depend on whether both classes are present.
    """
    scores = pd.Series(list(scores), dtype=float).reset_index(drop=True)
    labels = pd.Series(list(labels)).reset_index(drop=True).astype(bool)

    result: dict = {
        "windows": int(len(scores)),
        "attack_windows": int(labels.sum()),
        "threshold_pct": threshold_pct,
    }
    if labels.sum() == 0:
        result["note"] = "no attack windows in range — cannot compute detection metrics"
        return result

    thr = float(scores.quantile(threshold_pct / 100.0))
    pred = scores >= thr
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, pred, average="binary", zero_division=0
    )
    result.update(
        {
            "threshold_score": round(thr, 4),
            "flagged": int(pred.sum()),
            "precision": round(float(precision), 3),
            "recall": round(float(recall), 3),
            "f1": round(float(f1), 3),
        }
    )
    # ranking metrics need both classes present
    if labels.nunique() == 2:
        result["roc_auc"] = round(float(roc_auc_score(labels, scores)), 3)
        result["pr_auc"] = round(float(average_precision_score(labels, scores)), 3)
    return result


def format_report(metrics: dict) -> str:
    """Human-readable metrics block."""
    lines = [
        f"windows evaluated : {metrics['windows']}",
        f"attack windows    : {metrics['attack_windows']}",
    ]
    if "note" in metrics:
        lines.append(f"note              : {metrics['note']}")
        return "\n".join(lines)
    lines += [
        f"alert threshold   : {metrics['threshold_pct']:.0f}th pct "
        f"(score >= {metrics['threshold_score']})",
        f"windows flagged   : {metrics['flagged']}",
        f"precision         : {metrics['precision']}",
        f"recall            : {metrics['recall']}",
        f"f1                : {metrics['f1']}",
    ]
    if "roc_auc" in metrics:
        lines += [
            f"ROC-AUC           : {metrics['roc_auc']}  (ranking quality, threshold-free)",
            f"PR-AUC            : {metrics['pr_auc']}",
        ]
    return "\n".join(lines)
