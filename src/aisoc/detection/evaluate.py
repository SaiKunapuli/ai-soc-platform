"""Evaluate anomaly detection against labeled attack windows.

Given per-window anomaly scores and boolean attack labels (from Atomic Red Team
runs recorded in simulations/labels.csv, or a Mordor scenario), compute how well
the detector separates attack windows from normal ones. This is the Phase 2
exit-criterion machinery.

Two things a SOC actually cares about live side by side here:
  * recall   — of the real attacks, how many did we catch?
  * FPR      — of the benign windows, how many did we wrongly alert on?
An anomaly detector is only useful if recall stays high while FPR stays LOW;
recall alone (the "15/15 coverage" number) hides the false-alarm cost, so we
report both, the raw confusion counts behind them, and a threshold sweep so an
operating point can be chosen deliberately rather than pinned at the 95th pct.
"""

import pandas as pd
from sklearn.metrics import (
    average_precision_score,
    precision_recall_fscore_support,
    roc_auc_score,
)


def _confusion(labels: pd.Series, pred: pd.Series) -> dict:
    """Raw confusion counts + the two rates that trade off against each other."""
    tp = int((pred & labels).sum())
    fp = int((pred & ~labels).sum())
    tn = int((~pred & ~labels).sum())
    fn = int((~pred & labels).sum())
    benign = fp + tn
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        # false-positive rate: of all benign windows, the fraction we alerted on.
        "fpr": round(fp / benign, 3) if benign else 0.0,
    }


def evaluate(scores, labels, threshold_pct: float = 95.0) -> dict:
    """Detection metrics for one scored, labeled set of windows.

    An alert fires when a window's score is at/above the ``threshold_pct``
    percentile of all scores in the set (the same self-baselining idea the
    pipeline uses). Alongside precision/recall we report the confusion counts
    and the false-positive rate — the alert-fatigue cost the coverage number
    hides. Threshold-free ranking quality is also reported via ROC-AUC and
    PR-AUC, which don't depend on where the cutoff is placed.

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
    result.update(_confusion(labels, pred))
    # ranking metrics need both classes present
    if labels.nunique() == 2:
        result["roc_auc"] = round(float(roc_auc_score(labels, scores)), 3)
        result["pr_auc"] = round(float(average_precision_score(labels, scores)), 3)
    return result


def sweep(scores, labels, pcts=(80, 85, 90, 92.5, 95, 97.5, 99)) -> list[dict]:
    """Evaluate at several alert thresholds so the recall/FPR trade-off is visible.

    Returns one metrics dict per percentile. Picking an operating point is a
    business decision (how many false alarms an analyst will tolerate to avoid a
    miss); this exposes the curve instead of hard-coding the 95th percentile.
    """
    return [evaluate(scores, labels, threshold_pct=p) for p in pcts]


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
        f"confusion         : TP={metrics['tp']} FP={metrics['fp']} "
        f"TN={metrics['tn']} FN={metrics['fn']}",
        f"precision         : {metrics['precision']}",
        f"recall            : {metrics['recall']}  (attacks caught)",
        f"false-positive rate: {metrics['fpr']}  (benign windows wrongly alerted)",
        f"f1                : {metrics['f1']}",
    ]
    if "roc_auc" in metrics:
        lines += [
            f"ROC-AUC           : {metrics['roc_auc']}  (ranking quality, threshold-free)",
            f"PR-AUC            : {metrics['pr_auc']}",
        ]
    return "\n".join(lines)


def format_sweep(rows: list[dict]) -> str:
    """Render a sweep() result as a threshold/recall/FPR trade-off table."""
    header = f"{'pct':>6} {'flagged':>8} {'recall':>8} {'precision':>10} {'FPR':>7} {'f1':>6}"
    out = [header, "-" * len(header)]
    for m in rows:
        if "recall" not in m:
            continue
        out.append(
            f"{m['threshold_pct']:>6} {m['flagged']:>8} {m['recall']:>8} "
            f"{m['precision']:>10} {m['fpr']:>7} {m['f1']:>6}"
        )
    return "\n".join(out)
