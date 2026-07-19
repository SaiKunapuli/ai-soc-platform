"""Layer 5: fuse Wazuh rule alerts + ML scores into EnrichedAlert, map to MITRE ATT&CK.

EnrichedAlert (schemas.py) is the contract of the whole system — everything upstream
produces it, everything downstream (copilot, API, dashboard) consumes it.
"""

from aisoc.enrichment.auto_feedback import (
    BehaviorTracker,
    auto_classify,
    has_blocking_rules,
    has_significant_rules,
)
from aisoc.enrichment.schemas import CopilotAnalysis, EnrichedAlert, MitreTechnique, Severity

__all__ = [
    "BehaviorTracker",
    "CopilotAnalysis",
    "EnrichedAlert",
    "MitreTechnique",
    "Severity",
    "auto_classify",
    "has_blocking_rules",
    "has_significant_rules",
]
