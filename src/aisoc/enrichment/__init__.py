"""Layer 5: fuse Wazuh rule alerts + ML scores into EnrichedAlert, map to MITRE ATT&CK.

EnrichedAlert (schemas.py) is the contract of the whole system — everything upstream
produces it, everything downstream (copilot, API, dashboard) consumes it.
"""

from aisoc.enrichment.schemas import CopilotAnalysis, EnrichedAlert, MitreTechnique, Severity

__all__ = ["CopilotAnalysis", "EnrichedAlert", "MitreTechnique", "Severity"]
