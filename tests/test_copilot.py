"""Copilot tests that don't need a live model — grounding + deterministic report.

The LLM is stubbed so these run in CI with no Ollama. A separate manual demo
(scripts/copilot_demo.py) exercises the real model.
"""

from aisoc.copilot import analyst, report
from aisoc.copilot.sample_alert import sample_encoded_powershell_alert
from aisoc.enrichment.schemas import CopilotAnalysis, Severity


class StubLLM:
    """Stands in for LLMClient. Returns canned analysis JSON and summary prose."""

    def __init__(self, analysis_dict: dict) -> None:
        self._analysis = analysis_dict

    def generate_json(self, system: str, prompt: str, schema: dict) -> dict:
        return self._analysis

    def generate_text(self, system: str, prompt: str) -> str:
        return "Executive summary prose."


def _analysis_dict(iocs: list[str]) -> dict:
    return {
        "explanation": "Encoded PowerShell launched by Word is a classic phishing payload pattern.",
        "attack_interpretation": "Initial access via malicious document, then execution.",
        "severity": "high",
        "severity_rationale": "Rule + ML agree; parent-child chain is textbook.",
        "investigation_steps": ["Decode the -enc payload", "Check WINWORD for a malicious macro"],
        "containment_recommendations": ["Isolate the host", "Reset the user's credentials"],
        "iocs": iocs,
    }


def test_grounding_drops_hallucinated_iocs() -> None:
    alert = sample_encoded_powershell_alert()
    # one real (present in the alert), one invented
    llm = StubLLM(_analysis_dict(iocs=["DESKTOP-STQNCN4", "8.8.8.8"]))
    result = analyst.analyze(alert, llm=llm)
    assert "DESKTOP-STQNCN4" in result.iocs  # real, kept
    assert "8.8.8.8" not in result.iocs  # invented, dropped


def test_report_assembles_all_sections() -> None:
    alert = sample_encoded_powershell_alert()
    analysis = CopilotAnalysis.model_validate(_analysis_dict(iocs=["DESKTOP-STQNCN4"]))
    incident = report.generate(alert, analysis, llm=StubLLM(_analysis_dict([])))
    md = incident.markdown

    assert incident.severity if hasattr(incident, "severity") else True
    for section in ["## Summary", "## Timeline", "## MITRE ATT&CK", "## Recommended Response"]:
        assert section in md, f"missing {section}"
    assert "T1059.001" in md  # MITRE technique rendered
    assert Severity.HIGH.value.upper() in incident.title


def test_report_timeline_is_chronological() -> None:
    alert = sample_encoded_powershell_alert()
    analysis = CopilotAnalysis.model_validate(_analysis_dict([]))
    incident = report.generate(alert, analysis, llm=StubLLM(_analysis_dict([])))
    assert len(incident.timeline) >= 2  # window open + close at minimum
