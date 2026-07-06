"""MITRE ATT&CK mapping.

Wazuh rule alerts already carry rule.mitre.{id,tactic,technique} — those pass through
in ingestion. This module only maps ML-originated detections: which behavioral features
drove the anomaly → which techniques are plausible.
"""

from aisoc.enrichment.schemas import MitreTechnique

# Feature-driven heuristics for ML-only detections. Deliberately coarse — the point is
# to give the copilot and analyst a starting hypothesis, not a verdict.
FEATURE_TECHNIQUE_MAP: dict[str, MitreTechnique] = {
    "encoded_cmd": MitreTechnique(
        technique_id="T1059.001", name="PowerShell", tactic="Execution"
    ),
    "ps_count": MitreTechnique(
        technique_id="T1059", name="Command and Scripting Interpreter", tactic="Execution"
    ),
    "new_parent_child": MitreTechnique(
        technique_id="T1055", name="Process Injection", tactic="Defense Evasion"
    ),
    "failed_ratio": MitreTechnique(
        technique_id="T1110", name="Brute Force", tactic="Credential Access"
    ),
    "new_source_ip": MitreTechnique(
        technique_id="T1078", name="Valid Accounts", tactic="Initial Access"
    ),
    "distinct_hosts": MitreTechnique(
        technique_id="T1021", name="Remote Services", tactic="Lateral Movement"
    ),
}


def map_ml_detection(top_features: list[str]) -> list[MitreTechnique]:
    """Map an ML detection's top contributing features to candidate techniques."""
    seen: dict[str, MitreTechnique] = {}
    for feature in top_features:
        technique = FEATURE_TECHNIQUE_MAP.get(feature)
        if technique:
            seen[technique.technique_id] = technique
    return list(seen.values())
