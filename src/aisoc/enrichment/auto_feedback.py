"""Auto-classification of alerts for self-learning feedback loop.

Instead of requiring a human analyst to mark every alert as TP/FP/benign, this
module applies conservative heuristics to auto-classify likely-benign alerts.
The model then retrains with this feedback, continuously improving without
manual intervention.

Key principle: heuristics are *conservative* — they only auto-mark when the
evidence is strong. A wrong auto-classification is worse than a missed one
(because it teaches the model to ignore real attacks).

BehaviorTracker: persistent store of behavior signatures across pipeline runs
so recurring patterns are recognized without manual labeling.
"""

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from aisoc.enrichment.schemas import EnrichedAlert

DEFAULT_DB = Path("data/behavior_patterns.db")

# ── Heuristic thresholds ──────────────────────────────────────────────
MIN_OCCURRENCES_FOR_REPEAT = 3      # same pattern must appear >=3 times
LOW_ML_SCORE_THRESHOLD = 0.25       # ML score below this = low confidence
LOW_ML_PERCENTILE = 75.0            # percentile below this = not anomalous
WAZUH_ONLY_ML_SCORE = 0.15          # ML score below this = normal (noisy Wazuh)
NO_HIGH_RULES = 7                   # no Wazuh rules at/above this level
BLOCKING_RULE_LEVEL = 12            # never auto-classify if any rule >= this level

# ── Behavior signature ─────────────────────────────────────────────────
SIGNATURE_LENGTH = 80               # chars from detected_behavior used as key


class BehaviorTracker:
    """Tracks behavior patterns across pipeline runs.

    When the same (host, behavior) appears repeatedly without a human analyst
    confirming it as a true positive, the system can auto-classify it as benign.
    """

    def __init__(self, path: Path | str = DEFAULT_DB) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path)

    def _init(self) -> None:
        with self._connect() as c:
            c.execute(
                "CREATE TABLE IF NOT EXISTS behavior_patterns ("
                "  host TEXT NOT NULL,"
                "  behavior_sig TEXT NOT NULL,"
                "  first_seen TEXT NOT NULL,"
                "  last_seen TEXT NOT NULL,"
                "  occurrence_count INTEGER DEFAULT 1,"
                "  auto_benign INTEGER DEFAULT 0,"
                "  human_tp_count INTEGER DEFAULT 0,"
                "  PRIMARY KEY (host, behavior_sig)"
                ")"
            )
            c.execute(
                "CREATE TABLE IF NOT EXISTS auto_feedback_log ("
                "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "  alert_id TEXT NOT NULL,"
                "  verdict TEXT NOT NULL,"
                "  rule_name TEXT NOT NULL,"
                "  created_at TEXT NOT NULL"
                ")"
            )

    # ── Pattern tracking ──────────────────────────────────────────────

    def record_alert(
        self, host: str, detected_behavior: str
    ) -> None:
        """Record an alert's behavior pattern. Call after each pipeline run."""
        sig = _behavior_signature(detected_behavior)
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as c:
            c.execute(
                "INSERT INTO behavior_patterns (host, behavior_sig, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?) "
                "ON CONFLICT(host, behavior_sig) DO UPDATE SET "
                "  occurrence_count = occurrence_count + 1,"
                "  last_seen = excluded.last_seen",
                (host, sig, now, now),
            )

    def get_pattern_count(self, host: str, detected_behavior: str) -> int:
        """How many times has this (host, behavior) been seen?"""
        sig = _behavior_signature(detected_behavior)
        with self._connect() as c:
            row = c.execute(
                "SELECT occurrence_count FROM behavior_patterns "
                "WHERE host=? AND behavior_sig=?",
                (host, sig),
            ).fetchone()
        return row[0] if row else 0

    def is_known_benign(self, host: str, detected_behavior: str) -> bool:
        """Has this pattern been auto-classified as benign?"""
        sig = _behavior_signature(detected_behavior)
        with self._connect() as c:
            row = c.execute(
                "SELECT auto_benign FROM behavior_patterns "
                "WHERE host=? AND behavior_sig=?",
                (host, sig),
            ).fetchone()
        return bool(row and row[0])

    def mark_pattern_benign(self, host: str, detected_behavior: str) -> None:
        """Mark a pattern as auto-classified benign."""
        sig = _behavior_signature(detected_behavior)
        with self._connect() as c:
            c.execute(
                "UPDATE behavior_patterns SET auto_benign=1 "
                "WHERE host=? AND behavior_sig=?",
                (host, sig),
            )

    def has_human_tp(self, host: str, detected_behavior: str) -> bool:
        """Has a human ever marked any alert with this pattern as TP?"""
        sig = _behavior_signature(detected_behavior)
        with self._connect() as c:
            row = c.execute(
                "SELECT human_tp_count FROM behavior_patterns "
                "WHERE host=? AND behavior_sig=?",
                (host, sig),
            ).fetchone()
        return bool(row and row[0] > 0)

    def record_human_tp(self, host: str, detected_behavior: str) -> None:
        """Record that a human confirmed this pattern as a real attack.

        Once marked TP, the pattern will NEVER be auto-classified as benign.
        """
        sig = _behavior_signature(detected_behavior)
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as c:
            c.execute(
                "INSERT INTO behavior_patterns (host, behavior_sig, first_seen, last_seen, "
                "human_tp_count) VALUES (?, ?, ?, ?, 1) "
                "ON CONFLICT(host, behavior_sig) DO UPDATE SET "
                "  human_tp_count = human_tp_count + 1",
                (host, sig, now, now),
            )

    # ── Auto-feedback log ─────────────────────────────────────────────

    def log_auto_feedback(self, alert_id: str, verdict: str, rule_name: str) -> None:
        """Record that we auto-classified an alert."""
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as c:
            c.execute(
                "INSERT INTO auto_feedback_log (alert_id, verdict, rule_name, created_at) "
                "VALUES (?, ?, ?, ?)",
                (alert_id, verdict, rule_name, now),
            )

    def auto_feedback_count(self) -> int:
        """How many auto-feedback entries have been logged total?"""
        with self._connect() as c:
            row = c.execute("SELECT COUNT(*) FROM auto_feedback_log").fetchone()
        return row[0] if row else 0

    def new_auto_feedback_since(self, since_count: int) -> int:
        """Count auto-feedback entries since a previous total."""
        return max(0, self.auto_feedback_count() - since_count)

    def reset(self) -> None:
        """Drop all behavior data. Call on full retrain."""
        with self._connect() as c:
            c.execute("DELETE FROM behavior_patterns")
            # Don't clear auto_feedback_log — it's a permanent record


def _behavior_signature(detected_behavior: str) -> str:
    """Normalize the detected_behavior into a stable signature key.

    Strips trailing ML features (the "anomalous: ..." suffix) so patterns
    match on the Wazuh rule description, not on which features happened to
    deviate this time.
    """
    text = detected_behavior.split("; anomalous:")[0].strip().lower()
    return text[:SIGNATURE_LENGTH]


def has_significant_rules(rule_alerts, min_level: int = NO_HIGH_RULES) -> bool:
    """True if any Wazuh rule in the alert is at/above min_level."""
    return any(r.level >= min_level for r in (rule_alerts or []))


def has_blocking_rules(rule_alerts) -> bool:
    """True if any Wazuh rule is at/above the blocking threshold.

    Very high-level rules (>=12) indicate a serious detection that should
    never be auto-suppressed, regardless of ML score.
    """
    return any(r.level >= BLOCKING_RULE_LEVEL for r in (rule_alerts or []))


def auto_classify(
    alert: EnrichedAlert,
    tracker: BehaviorTracker,
) -> tuple[str, str] | None:
    """Auto-classify an alert using conservative heuristics.

    Returns (verdict, rule_name) or None if the alert can't be auto-classified.
    verdict is one of "benign" or "false_positive".

    Rules are applied in order of confidence:
    1. High-level Wazuh guard: if any rule >= level 12, never auto-classify
    2. Repeat pattern (strongest signal): same behavior seen >=3 times,
       never confirmed TP by human -> benign
    3. Low ML confidence: model barely cares and Wazuh rules aren't serious -> benign
    4. Wazuh-only noise: significant Wazuh rules but ML score is near-zero -> benign
    """
    host = alert.host
    behavior = alert.detected_behavior
    ml = alert.ml

    # ── Guard: high-level Wazuh rules block auto-classification ───────
    # A level 12+ rule (e.g. confirmed exploit, credential dump) is too
    # serious to auto-suppress, even if the ML model says it's normal.
    if has_blocking_rules(alert.rule_alerts):
        return None

    # ── Rule 1: Repeat pattern ────────────────────────────────────────
    # If this exact behavior has appeared in multiple windows and no human
    # has ever called it a real attack, it's almost certainly benign noise.
    if tracker.has_human_tp(host, behavior):
        # Human confirmed this is a real attack — never auto-override
        return None

    count = tracker.get_pattern_count(host, behavior)
    if count >= MIN_OCCURRENCES_FOR_REPEAT:
        # This is the Nth occurrence — auto-mark as benign
        tracker.mark_pattern_benign(host, behavior)
        return ("benign", f"repeat_pattern(x{count})")

    if tracker.is_known_benign(host, behavior):
        return ("benign", "known_benign")

    # ── Rule 2: Low ML confidence ─────────────────────────────────────
    # Model says "barely anomalous" AND no significant Wazuh rules.
    # This is the common case of minor deviations that Wazuh doesn't care about.
    if (
        ml is not None
        and ml.anomaly_score < LOW_ML_SCORE_THRESHOLD
        and (ml.baseline_percentile or 100) < LOW_ML_PERCENTILE
        and not has_significant_rules(alert.rule_alerts)
    ):
        return ("benign", "low_ml_confidence")

    # ── Rule 3: Wazuh-only noise ──────────────────────────────────────
    # Wazuh rules fired but the ML model says this is completely normal.
    # Classic false positive: noisy rule on normal behavior.
    # NOTE: blocked by the guard above if any rule >= level 12.
    if (
        ml is not None
        and ml.anomaly_score < WAZUH_ONLY_ML_SCORE
        and alert.rule_alerts
    ):
        return ("benign", "wazuh_only_noise")

    return None
