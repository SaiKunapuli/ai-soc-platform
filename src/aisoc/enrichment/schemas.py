"""System-wide data contracts. Change these deliberately — every layer depends on them."""

from datetime import datetime
from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class MitreTechnique(BaseModel):
    technique_id: str  # e.g. "T1059.001"
    name: str = ""  # e.g. "PowerShell"
    tactic: str = ""  # e.g. "Execution"


class RuleAlert(BaseModel):
    """One Wazuh rule alert, trimmed to what downstream layers need."""

    rule_id: str
    description: str
    level: int  # Wazuh 0-15 scale
    timestamp: datetime
    mitre: list[MitreTechnique] = []  # passthrough from rule.mitre.* when present
    raw_id: str = ""  # indexer _id, for drill-down


class MlDetection(BaseModel):
    """ML anomaly result for one (entity, window)."""

    model_name: str = "isolation_forest"
    anomaly_score: float = Field(ge=0.0, le=1.0)
    baseline_percentile: float | None = None  # vs. this entity's own history
    top_features: list[str] = []  # e.g. ["encoded_cmd", "rare_proc_score"]
    feature_snapshot: dict[str, float] = {}


class EnrichedAlert(BaseModel):
    """The fused detection object — the system-wide contract."""

    alert_id: str = Field(default_factory=lambda: uuid4().hex)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    host: str
    user: str | None = None
    window_start: datetime
    window_end: datetime
    detected_behavior: str  # one-line human summary, e.g. "unusual PowerShell + new external IP"
    rule_alerts: list[RuleAlert] = []
    ml: MlDetection | None = None
    mitre: list[MitreTechnique] = []
    severity: Severity | None = None  # set by copilot (or fusion heuristic as fallback)


class CopilotAnalysis(BaseModel):
    """Structured output the LLM must produce for an EnrichedAlert.

    Grounding rule: every indicator cited here must exist in the input alert —
    validated in aisoc.copilot.analyst, not trusted.
    """

    explanation: str  # plain-language: what happened and why it's unusual
    attack_interpretation: str  # likely scenario across the kill chain
    severity: Severity
    severity_rationale: str
    investigation_steps: list[str]
    containment_recommendations: list[str]
    iocs: list[str] = []  # only values present in the input alert


class IncidentReport(BaseModel):
    """SOC-ticket-style report rendered from an alert + its analysis."""

    alert_id: str
    title: str
    summary: str
    timeline: list[str]
    iocs: list[str]
    mitre: list[MitreTechnique]
    recommended_response: list[str]
    markdown: str  # full rendered report
