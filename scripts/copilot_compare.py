"""Compare model configurations for the copilot on one enriched alert.

Configs:
  7B         analysis + report both qwen2.5:7b-instruct   (fast)
  14B        analysis + report both qwen2.5:14b-instruct  (smartest)
  14B+7B     analysis 14B, report 7B  (smart reasoning, fast prose)

Each analysis is computed once and reused, so we run 2 analyses + 3 reports.
Full reports are written to the scratchpad for side-by-side reading.
"""

import time
from pathlib import Path

from aisoc.copilot import analyst, report
from aisoc.copilot.llm import LLMClient
from aisoc.copilot.sample_alert import sample_encoded_powershell_alert

M7 = "qwen2.5:7b-instruct"
M14 = "qwen2.5:14b-instruct"
OUT = Path(__file__).resolve().parent.parent / "scratch_reports"


def timed(fn):
    t = time.perf_counter()
    result = fn()
    return result, time.perf_counter() - t


def main() -> None:
    OUT.mkdir(exist_ok=True)
    alert = sample_encoded_powershell_alert()
    llm7, llm14 = LLMClient(model=M7), LLMClient(model=M14)

    print("running analyses (this is the slow part)...")
    analysis7, t_a7 = timed(lambda: analyst.analyze(alert, llm=llm7))
    analysis14, t_a14 = timed(lambda: analyst.analyze(alert, llm=llm14))

    configs = [
        ("7B", analysis7, llm7, t_a7),
        ("14B", analysis14, llm14, t_a14),
        ("14B+7B", analysis14, llm7, t_a14),
    ]

    rows = []
    for name, analysis, report_llm, t_analysis in configs:
        incident, t_report = timed(lambda: report.generate(alert, analysis, llm=report_llm))
        (OUT / f"report_{name}.md").write_text(incident.markdown, encoding="utf-8")
        rows.append(
            {
                "config": name,
                "analysis_s": round(t_analysis, 1),
                "report_s": round(t_report, 1),
                "total_s": round(t_analysis + t_report, 1),
                "severity": analysis.severity.value,
                "iocs": analysis.iocs,
                "steps": len(analysis.investigation_steps),
                "rationale": analysis.severity_rationale,
            }
        )

    print(f"\n{'config':<9}{'sev':<8}{'analysis':<10}{'report':<9}{'total':<8}{'iocs'}")
    print("-" * 70)
    for r in rows:
        print(
            f"{r['config']:<9}{r['severity']:<8}{str(r['analysis_s'])+'s':<10}"
            f"{str(r['report_s'])+'s':<9}{str(r['total_s'])+'s':<8}{r['iocs']}"
        )

    print("\n--- severity rationale by config ---")
    for r in rows:
        print(f"[{r['config']}] {r['rationale']}")

    print(f"\nfull reports written to: {OUT}")


if __name__ == "__main__":
    main()
