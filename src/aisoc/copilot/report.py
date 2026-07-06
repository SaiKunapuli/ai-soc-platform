"""Render an alert + analysis into a SOC-ticket-style incident report."""

from aisoc.copilot import prompts
from aisoc.copilot.llm import LLMClient
from aisoc.enrichment.schemas import CopilotAnalysis, EnrichedAlert, IncidentReport


def generate(
    alert: EnrichedAlert, analysis: CopilotAnalysis, llm: LLMClient | None = None
) -> IncidentReport:
    """Produce the full Markdown incident report.

    TODO(phase 4): build the deterministic sections (timeline from rule_alerts
    timestamps, IOC list, MITRE table) in code, and use the LLM only for the
    Summary prose — less to hallucinate, easier to trust.
    """
    raise NotImplementedError
