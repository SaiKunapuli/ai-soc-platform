"""MITRE ATT&CK coverage report: which techniques the ML layer can flag, grouped
by tactic, and which have actually been exercised by a labeled attack run.

The anomaly layer targets UNKNOWN threats, but it still maps its signals to
candidate techniques (aisoc.enrichment.mitre). This shows that coverage against
the ATT&CK enterprise tactics so gaps are visible: a tactic with no ML feature is
a place to add a Wazuh/Sigma rule (the KNOWN-threat layer) or an Atomic Red Team
test (validation). It is a planning aid, not a detection claim.

    python -m scripts.coverage_report
"""

import argparse
from pathlib import Path

import pandas as pd

from aisoc.enrichment.mitre import FEATURE_TECHNIQUE_MAP

# ATT&CK enterprise tactics in kill-chain order.
ALL_TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]

LABEL_FILES = [Path("simulations/labels.csv"), Path("simulations/mordor_labels.csv")]


def exercised_techniques(label_files: list[Path] | None = None) -> set[str]:
    """Technique IDs that have actually been run (from label CSVs)."""
    out: set[str] = set()
    for path in label_files or LABEL_FILES:
        if not path.exists():
            continue
        df = pd.read_csv(path)
        if "technique_id" in df.columns:
            out |= {str(t).strip() for t in df["technique_id"].dropna() if str(t).startswith("T")}
    return out


def _is_exercised(technique_id: str, exercised: set[str]) -> bool:
    """A technique counts as exercised if it or its parent/sub-technique ran."""
    base = technique_id.split(".")[0]
    return any(e == technique_id or e.split(".")[0] == base for e in exercised)


def build_coverage(exercised: set[str] | None = None) -> dict:
    """Group ML-covered techniques by tactic and note which were exercised.

    Returns {tactic: [{technique_id, name, features, exercised}]} plus a list of
    tactics with no ML coverage at all (the gaps).
    """
    exercised = exercised or set()
    techniques: dict[str, dict] = {}
    for feature, tech in FEATURE_TECHNIQUE_MAP.items():
        entry = techniques.setdefault(
            tech.technique_id,
            {"technique_id": tech.technique_id, "name": tech.name,
             "tactic": tech.tactic, "features": []},
        )
        entry["features"].append(feature)

    by_tactic: dict[str, list[dict]] = {}
    for entry in techniques.values():
        entry["exercised"] = _is_exercised(entry["technique_id"], exercised)
        by_tactic.setdefault(entry["tactic"], []).append(entry)

    gaps = [t for t in ALL_TACTICS if t not in by_tactic]
    return {"by_tactic": by_tactic, "gaps": gaps, "technique_count": len(techniques)}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--no-labels", action="store_true",
                    help="ignore label CSVs (show coverage only, not what's been exercised)")
    args = ap.parse_args()

    exercised = set() if args.no_labels else exercised_techniques()
    cov = build_coverage(exercised)

    covered_tactics = [t for t in ALL_TACTICS if t in cov["by_tactic"]]
    print(f"\n{'=' * 60}")
    print("MITRE ATT&CK COVERAGE (ML anomaly layer)")
    print(f"{'=' * 60}")
    print(f"{cov['technique_count']} techniques across "
          f"{len(covered_tactics)}/{len(ALL_TACTICS)} tactics\n")

    for tactic in covered_tactics:
        print(f"{tactic}:")
        for e in sorted(cov["by_tactic"][tactic], key=lambda x: x["technique_id"]):
            mark = "[run]" if e["exercised"] else "[   ]"
            feats = ", ".join(sorted(e["features"]))
            print(f"  {mark} {e['technique_id']:<11} {e['name']:<34} <- {feats}")
        print()

    if cov["gaps"]:
        print("Tactics with NO ML coverage (add Wazuh/Sigma rules or atomics here):")
        for g in cov["gaps"]:
            print(f"  - {g}")
    print("\n[run] = exercised by a labeled attack; [   ] = mapped but not yet validated.")


if __name__ == "__main__":
    main()
