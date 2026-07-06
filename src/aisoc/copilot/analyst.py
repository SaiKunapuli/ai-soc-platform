"""LLM analysis of an EnrichedAlert, with IOC grounding validation."""

from aisoc.copilot import prompts
from aisoc.copilot.llm import LLMClient
from aisoc.enrichment.schemas import CopilotAnalysis, EnrichedAlert


def analyze(alert: EnrichedAlert, llm: LLMClient | None = None) -> CopilotAnalysis:
    """Run the copilot on one alert; returns validated, grounded analysis."""
    llm = llm or LLMClient()
    raw = llm.generate_json(
        system=prompts.ANALYST_SYSTEM,
        prompt=prompts.ANALYST_TASK.format(alert_json=alert.model_dump_json(indent=2)),
        schema=CopilotAnalysis.model_json_schema(),
    )
    analysis = CopilotAnalysis.model_validate(raw)
    return _ground_iocs(analysis, alert)


def _ground_iocs(analysis: CopilotAnalysis, alert: EnrichedAlert) -> CopilotAnalysis:
    """Drop any IOC the model cited that does not appear in the input alert.

    Hallucinated indicators in a SOC tool are worse than none. Membership test is
    a substring check against the serialized alert — coarse but safe in the
    conservative direction (can only drop, never add).
    """
    alert_text = alert.model_dump_json()
    grounded = [ioc for ioc in analysis.iocs if ioc and ioc in alert_text]
    return analysis.model_copy(update={"iocs": grounded})
