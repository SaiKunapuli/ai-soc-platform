# Detection Evaluation

How well does this system actually catch attacks? That question has **two halves**,
and it's important to keep them separate — conflating them is how security tools
end up overclaiming.

| Question | "Can we **see** it?" (coverage) | "Does it **stand out**?" (detection) |
|---|---|---|
| What it measures | Do our sensors + features produce a signal on the attack? | Does the anomaly score rank the attack above normal activity? |
| Bounded by | Telemetry breadth + feature engineering | Quality of the learned per-host baseline |
| Evaluated with | **Mordor / OTRF Security-Datasets** (this doc) | **Live baseline** on the monitored host (accumulating) |
| Status | ✅ measured, strong | ⏳ first real number via `scorecard.py`; trustworthy number pending live-host attacks |

You cannot detect what you cannot see, so **coverage is the prerequisite**. This
document reports the coverage result; the detection-quality half depends on the live
baseline and is tracked in the roadmap.

---

## Coverage evaluation — OTRF Security-Datasets ("Mordor")

### Method
[OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) provides
pre-recorded Sysmon + Windows event logs from simulated attacks, each capture
mapped to a MITRE ATT&CK technique. `scripts/load_mordor_data.py` converts the
native Sysmon JSON into the pipeline's schema, runs it through the same feature
extractors used on live data, and reports which detection features fire per
scenario. 15 scenarios were selected across 7 tactics.

A scenario "produces a signal" when at least one behavioral feature is non-zero —
i.e., the attack left a footprint in telemetry we ingest and features we compute.

### Result: 15 / 15 scenarios produced a technique-appropriate signal

| Tactic | Representative scenarios | Feature signals that fired |
|---|---|---|
| Credential Access | lsass dump (dumpert syscalls, comsvcs MiniDump) | `lsass_access_count`, `high_access_count`, `sensitive_access_count` |
| Persistence | service modification, userinit, WMI, run keys | `autorun_mod_count`, `registry_mod_count` |
| Defense Evasion | process herpaderping, DLL side-loading | `high_access_count`, `unsigned_load_count` |
| Lateral Movement | ADFS config export, SMB copy | `external_conn_count`, `distinct_dest_ips` |
| Discovery | LDAP domain-group recon, SharpView | `max_cmd_entropy`, `registry_mod_count` |
| Execution | PowerShell HTTP listener | `max_cmd_entropy`, `high_access_count` |
| Privilege Escalation | service mod, runas | `new_parent_child`, `registry_mod_count` |

The signals match the technique in every case — lsass-dump scenarios light up the
credential-access features, persistence scenarios light up the registry features,
and so on.

### The telemetry-coverage journey (why 15/15 is meaningful)
The system started ingesting only **three** Sysmon event types — process creation
(EID 1), network connection (3), DNS (22). Against those alone, most of these
scenarios were **invisible**: LSASS dumping is a *handle open* (EID 10), persistence
is a *registry write* (EID 12/13), side-loading is an *unsigned module load* (EID 7)
— none of which we collected. An early Mordor run ingested **6 events** out of 900+
in a capture.

Adding three feature families (process-access, registry, image-load) and enabling
the corresponding Sysmon events raised ingestion on the same capture from **6 → 705
events** and moved coverage from partial-blindness to **15/15**.

---

## Honest limitations

1. **Coverage is not statistical detection.** "A feature fired" means the attack is
   *visible*, not that it *stands out from normal*. Some of these features
   (`registry_mod_count`, `new_parent_child`) are non-zero during ordinary use too.
   The anomaly-detection claim requires the live baseline.

2. **Mordor captures are attack-heavy.** Each scenario is a short capture that is
   almost entirely the attack, with little benign background. So it is unsuitable for
   a precision/recall or false-positive number — there is barely any "normal" in the
   data to measure false positives against. It answers *coverage*, not *FP rate*.

3. **Cross-environment baselines don't transfer.** A model trained on the monitored
   host's "normal" cannot be meaningfully applied to Mordor's lab-VM captures (and
   vice-versa); the notions of "normal" differ. Mordor is therefore used to validate
   *features and visibility*, evaluated within-capture, not to score with the live
   model.

4. **The LLM copilot over-escalates (open issue).** Run against real pipeline alerts,
   the local 7B model rated benign activity (e.g. the Windhawk customization tool,
   which legitimately injects and loads unsigned DLLs) as CRITICAL / "isolate the
   host," and even produced a wrong recommendation ("run Mimikatz to investigate").
   As prompted, the copilot amplifies alert fatigue rather than reducing it. It needs
   the ML *interpretation* fed in explicitly, a stronger assume-benign-until-
   corroborated instruction, and likely the 14B model. Tracked as a fix item.

---

## Live-pipeline observations (the detection half, in progress)

On the monitored host, `run_pipeline.py` produces alerts, and the severity-by-
agreement fusion behaves correctly: noisy high-level Wazuh rules on benign dev
tooling stay MEDIUM, and only rule+anomaly agreement escalates to HIGH/CRITICAL.

The CRITICAL alerts observed so far are **false positives with understandable
causes** — a legit tool that mimics attack behavior (Windhawk), a network burst
(gaming/downloads), benign lsass queries — and are inflated by **cold-start**: the
new feature families were enabled only recently, so the baseline has almost no
history for them, making any activity look anomalous. These are expected to subside
as the baseline accumulates and via the analyst feedback loop
(`scripts/retrain_from_feedback.py`). This is exactly the alert-triage / tuning work
that dominates a real SOC.

---

## What "done" looks like
- ✅ **Coverage**: 15/15 across 7 tactics (this doc).
- ⏳ **Detection quality**: retrain on a clean ~1-week baseline, then re-run
  `scripts/evaluate.py` for precision/recall against the labeled attack windows.
- ⏳ **False-positive rate**: reduce via baseline accumulation + feedback-loop
  retraining; whitelist known-benign tools.
- ⏳ **Copilot trustworthiness**: prompt + grounding rework so triage *reduces*
  rather than amplifies alert load.
