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
    Severity,
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
        severity=Severity.HIGH,  # heuristic from fusion (rule level 12 + anomalous ML)
    )


def sample_unusual_network_alert() -> EnrichedAlert:
    """Medium: anomalous outbound volume + a low-level rule corroborating the ML."""
    end = datetime.now(timezone.utc) - timedelta(hours=1)
    start = end - timedelta(minutes=10)
    return EnrichedAlert(
        host="DESKTOP-STQNCN4",
        user="srikar",
        window_start=start,
        window_end=end,
        detected_behavior="unusual outbound data volume to a first-seen external IP",
        rule_alerts=[
            RuleAlert(
                rule_id="87201",
                description="Outbound connection to uncommon destination",
                level=5,
                timestamp=start + timedelta(minutes=2),
            )
        ],
        ml=MlDetection(
            anomaly_score=0.83,
            baseline_percentile=96.5,
            top_features=["new_source_ip", "bytes_sent"],
            feature_snapshot={"bytes_sent": 48200000.0, "new_source_ip": 1.0},
        ),
        mitre=[MitreTechnique(technique_id="T1071", name="Application Layer Protocol", tactic="Command and Control")],
        severity=Severity.MEDIUM,
    )


def sample_scheduled_task_alert() -> EnrichedAlert:
    """Low: a single moderate persistence rule, ML not anomalous — likely benign admin."""
    end = datetime.now(timezone.utc) - timedelta(hours=3)
    start = end - timedelta(minutes=10)
    return EnrichedAlert(
        host="DESKTOP-STQNCN4",
        user="srikar",
        window_start=start,
        window_end=end,
        detected_behavior="scheduled task created via schtasks",
        rule_alerts=[
            RuleAlert(
                rule_id="92213",
                description="Scheduled task creation",
                level=8,
                timestamp=start + timedelta(minutes=1),
                mitre=[MitreTechnique(technique_id="T1053.005", name="Scheduled Task", tactic="Persistence")],
            )
        ],
        ml=MlDetection(anomaly_score=0.34, baseline_percentile=61.0, top_features=[]),
        mitre=[MitreTechnique(technique_id="T1053.005", name="Scheduled Task", tactic="Persistence")],
        severity=Severity.LOW,
    )


def all_samples() -> list[EnrichedAlert]:
    return [
        sample_encoded_powershell_alert(),
        sample_unusual_network_alert(),
        sample_scheduled_task_alert(),
    ]
