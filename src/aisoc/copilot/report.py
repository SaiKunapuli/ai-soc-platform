"""Render an alert + analysis into a SOC-ticket-style incident report.

Design choice: build every factual section deterministically in code (timeline,
IOCs, MITRE table) and use the LLM only for the prose Summary. Facts the model
can't touch can't be hallucinated.
"""

from aisoc.copilot import prompts
from aisoc.copilot.llm import LLMClient
from aisoc.enrichment.schemas import CopilotAnalysis, EnrichedAlert, IncidentReport


def _timeline(alert: EnrichedAlert) -> list[str]:
    """Ordered event list from the alert's own timestamps — no LLM involved."""
    events: list[tuple] = [
        (alert.window_start, f"Detection window opens on {alert.host}"),
    ]
    for ra in alert.rule_alerts:
        events.append((ra.timestamp, f"Wazuh rule {ra.rule_id} (level {ra.level}): {ra.description}"))
    if alert.ml:
        events.append(
            (alert.window_start, f"ML anomaly score {alert.ml.anomaly_score:.2f}"
             + (f" ({alert.ml.baseline_percentile:.0f}th pct for this entity)"
                if alert.ml.baseline_percentile is not None else ""))
        )
    events.append((alert.window_end, "Detection window closes"))
    return [f"- `{ts.isoformat()}` - {text}" for ts, text in sorted(events, key=lambda e: e[0])]


def _mitre_table(alert: EnrichedAlert) -> list[str]:
    if not alert.mitre:
        return ["_No MITRE techniques mapped._"]
    rows = ["| Technique | Name | Tactic |", "|---|---|---|"]
    rows += [f"| {t.technique_id} | {t.name or '-'} | {t.tactic or '-'} |" for t in alert.mitre]
    return rows


def generate(
    alert: EnrichedAlert, analysis: CopilotAnalysis, llm: LLMClient | None = None
) -> IncidentReport:
    """Produce the full Markdown incident report (deterministic sections + LLM summary)."""
    llm = llm or LLMClient()

    summary = llm.generate_text(
        system=prompts.REPORT_SUMMARY_SYSTEM,
        prompt=(
            f"Host: {alert.host}. Behavior: {alert.detected_behavior}. "
            f"Interpretation: {analysis.attack_interpretation}"
        ),
    ).strip()

    title = f"[{analysis.severity.value.upper()}] {alert.detected_behavior} on {alert.host}"
    timeline = _timeline(alert)
    response_steps = analysis.containment_recommendations

    markdown = "\n".join(
        [
            f"# Incident Report - {title}",
            f"\n**Alert ID:** `{alert.alert_id}`  ",
            f"**Host:** {alert.host}  ",
            f"**User:** {alert.user or 'n/a'}  ",
            f"**Severity:** {analysis.severity.value.upper()} - {analysis.severity_rationale}",
            "\n## Summary\n",
            summary,
            "\n## Timeline\n",
            *timeline,
            "\n## Analysis\n",
            analysis.explanation,
            "\n## Indicators of Compromise\n",
            *([f"- `{ioc}`" for ioc in analysis.iocs] or ["_None extracted._"]),
            "\n## MITRE ATT&CK Mapping\n",
            *_mitre_table(alert),
            "\n## Investigation Steps\n",
            *[f"{i}. {s}" for i, s in enumerate(analysis.investigation_steps, 1)],
            "\n## Recommended Response\n",
            *[f"{i}. {s}" for i, s in enumerate(response_steps, 1)],
        ]
    )

    return IncidentReport(
        alert_id=alert.alert_id,
        title=title,
        summary=summary,
        timeline=timeline,
        iocs=analysis.iocs,
        mitre=alert.mitre,
        recommended_response=response_steps,
        markdown=markdown,
    )
