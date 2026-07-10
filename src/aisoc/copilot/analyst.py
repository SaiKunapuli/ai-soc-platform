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
        prompt=prompts.ANALYST_TASK.format(
            alert_json=alert.model_dump_json(indent=2),
            fusion_severity=(alert.severity.value if alert.severity else "unknown"),
            ml_interpretation=_interpret_ml(alert),
        ),
        schema=CopilotAnalysis.model_json_schema(),
    )
    analysis = CopilotAnalysis.model_validate(raw)
    return analysis.model_copy(update={"iocs": _resolve_iocs(analysis, alert)})


def _interpret_ml(alert: EnrichedAlert) -> str:
    """Translate the ML detection into plain-English hints WITH benign alternatives.

    This is the grounding that stops the model from over-reading raw features: it
    states what each driving signal means and its common benign explanation, and
    resolves the key credential-access ambiguity (query-only lsass access vs. a
    memory read) explicitly so the model can't confuse a monitoring tool for mimikatz.
    """
    ml = alert.ml
    if ml is None:
        return "No ML anomaly signal for this window; the alert is rule-driven only."
    snap = ml.feature_snapshot or {}

    def val(k: str) -> float:
        try:
            return float(snap.get(k, 0) or 0)
        except (TypeError, ValueError):
            return 0.0

    pct = ml.baseline_percentile
    lines = [
        f"Anomaly score {ml.anomaly_score:.2f}"
        + (f", {pct:.0f}th percentile for this host" if pct is not None else "")
        + " (>=95th = unusual for THIS host, not necessarily malicious).",
        f"Driven mainly by: {', '.join(ml.top_features) or 'n/a'}.",
    ]

    if val("lsass_access_count") > 0:
        if val("high_access_count") > 0:
            lines.append(
                f"CREDENTIAL-ACCESS SIGNAL: {int(val('lsass_access_count'))} lsass access(es), "
                f"{int(val('high_access_count'))} requesting memory-read/inject rights -> this IS the "
                "credential-dumping / injection signature and warrants investigation."
            )
        else:
            lines.append(
                f"lsass accessed {int(val('lsass_access_count'))}x but high_access_count=0 -> "
                "QUERY-ONLY access (no memory-read rights). Normal for monitoring/security software; "
                "this is NOT credential dumping."
            )
    if val("unsigned_load_count") > 0:
        lines.append(
            f"{int(val('unsigned_load_count'))} unsigned DLL load(s). Possible side-loading, but many "
            "legitimate apps (customization/dev tools, some games, installers) load unsigned modules - "
            "identify the loading process before concluding malice."
        )
    if val("autorun_mod_count") > 0:
        lines.append(
            f"{int(val('autorun_mod_count'))} autostart/persistence registry modification(s) - could be "
            "persistence, or routine software (updaters/installers) writing Run keys."
        )
    if val("external_conn_count") > 0:
        lines.append(
            f"{int(val('external_conn_count'))} external connection(s) to {int(val('distinct_dest_ips'))} "
            "distinct IP(s) - could be C2/exfil, or normal browsing/downloads/updates."
        )
    if val("encoded_cmd") > 0 or val("max_cmd_entropy") > 5.5:
        lines.append(
            "High-entropy / encoded command line present - a real obfuscation signal, but also used by "
            "some legitimate installers and management scripts."
        )
    return "\n".join(lines)


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
