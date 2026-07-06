"""A realistic EnrichedAlert fixture for exercising the copilot before the ML
pipeline emits real ones. Mirrors what alert_fusion will eventually produce for a
T1059.001-style encoded-PowerShell detection.
"""

from datetime import datetime, timedelta, timezone

from aisoc.enrichment.schemas import (
    EnrichedAlert,
    MitreTechnique,
    MlDetection,
    RuleAlert,
)


def sample_encoded_powershell_alert() -> EnrichedAlert:
    end = datetime.now(timezone.utc)
    start = end - timedelta(minutes=10)
    return EnrichedAlert(
        host="DESKTOP-STQNCN4",
        user="srikar",
        window_start=start,
        window_end=end,
        detected_behavior="encoded PowerShell spawned by WINWORD.EXE, then cmd discovery burst",
        rule_alerts=[
            RuleAlert(
                rule_id="92052",
                description="Powershell execution with encoded command detected",
                level=12,
                timestamp=start + timedelta(minutes=1),
                mitre=[MitreTechnique(technique_id="T1059.001", name="PowerShell", tactic="Execution")],
                raw_id="archive-abc123",
            ),
        ],
        ml=MlDetection(
            anomaly_score=0.94,
            baseline_percentile=99.2,
            top_features=["encoded_cmd", "new_parent_child", "ps_count"],
            feature_snapshot={
                "proc_count": 41.0,
                "ps_count": 7.0,
                "encoded_cmd": 1.0,
                "rare_proc_score": 0.71,
                "new_parent_child": 4.0,
                "burst_rate": 6.0,
            },
        ),
        mitre=[
            MitreTechnique(technique_id="T1059.001", name="PowerShell", tactic="Execution"),
            MitreTechnique(technique_id="T1055", name="Process Injection", tactic="Defense Evasion"),
        ],
    )
