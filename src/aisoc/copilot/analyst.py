"""LLM analysis of an EnrichedAlert, with IOC grounding + deterministic extraction."""

import re

from aisoc.copilot import prompts
from aisoc.copilot.llm import LLMClient
from aisoc.enrichment.schemas import CopilotAnalysis, EnrichedAlert

_EXE_RE = re.compile(r"[\w.-]+\.exe", re.IGNORECASE)


def analyze(alert: EnrichedAlert, llm: LLMClient | None = None) -> CopilotAnalysis:
    """Run the copilot on one alert; returns validated, grounded analysis."""
    llm = llm or LLMClient()
    raw = llm.generate_json(
        system=prompts.ANALYST_SYSTEM,
        prompt=prompts.ANALYST_TASK.format(alert_json=alert.model_dump_json(indent=2)),
        schema=CopilotAnalysis.model_json_schema(),
    )
    analysis = CopilotAnalysis.model_validate(raw)
    return analysis.model_copy(update={"iocs": _resolve_iocs(analysis, alert)})


def _alert_iocs(alert: EnrichedAlert) -> list[str]:
    """Indicators pulled straight from the alert structure — always reliable,
    never dependent on the model. Host, user, triggering rule IDs, and any
    process image names named in the behavior summary.
    """
    values = [alert.host]
    if alert.user:
        values.append(alert.user)
    values += [ra.rule_id for ra in alert.rule_alerts]
    values += _EXE_RE.findall(alert.detected_behavior)
    out: list[str] = []
    for v in values:
        if v and v not in out:
            out.append(v)
    return out


def _resolve_iocs(analysis: CopilotAnalysis, alert: EnrichedAlert) -> list[str]:
    """Deterministic alert IOCs, plus any model-cited IOC that is actually present
    in the alert (grounding). Hallucinated indicators are dropped — in a SOC tool
    a wrong IOC is worse than a missing one.
    """
    alert_text = alert.model_dump_json()
    resolved = _alert_iocs(alert)
    for ioc in analysis.iocs:
        if ioc and ioc in alert_text and ioc not in resolved:
            resolved.append(ioc)
    return resolved
