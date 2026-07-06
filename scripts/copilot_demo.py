"""End-to-end copilot demo: enriched alert -> LLM analysis -> incident report.

Usage:
    python scripts/copilot_demo.py            # uses configured model
    python scripts/copilot_demo.py qwen2.5:14b-instruct   # override model
"""

import sys
import time

from aisoc.copilot import analyst, report
from aisoc.copilot.llm import LLMClient
from aisoc.copilot.sample_alert import sample_encoded_powershell_alert


def main() -> None:
    model = sys.argv[1] if len(sys.argv) > 1 else None
    llm = LLMClient(model=model)
    alert = sample_encoded_powershell_alert()

    print(f"# Model: {llm.model}\n# Alert: {alert.detected_behavior}\n")

    t0 = time.perf_counter()
    analysis = analyst.analyze(alert, llm=llm)
    t1 = time.perf_counter()
    print(f"--- analysis in {t1 - t0:.1f}s ---")
    print(f"severity: {analysis.severity.value} — {analysis.severity_rationale}")
    print(f"iocs (grounded): {analysis.iocs}\n")

    incident = report.generate(alert, analysis, llm=llm)
    t2 = time.perf_counter()
    print(f"--- report in {t2 - t1:.1f}s ---\n")
    print(incident.markdown)


if __name__ == "__main__":
    main()
