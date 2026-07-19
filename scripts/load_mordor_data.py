"""Load Mordor/OTRF Security-Datasets into the aisoc pipeline.

The Mordor project (github.com/OTRF/Security-Datasets) provides pre-recorded
Sysmon and Windows Event Logs from simulated attacks, organised by MITRE ATT&CK
technique. Each scenario is a .zip containing JSON files with real Sysmon events.

Mordor provides individual attack scenarios (short, attack-heavy captures) -
ideal for evaluating detection against known techniques, not for training a
long-run behavioral baseline.

This script reads extracted Mordor JSON files, maps native Sysmon field names
to the pipeline's column format, builds combined features, and evaluates the
model against the known-attack windows.

Usage:
    # Download scenarios first:
    #   git clone https://github.com/OTRF/Security-Datasets.git
    #   cd Security-Datasets/datasets/small/windows
    #   for f in */host/*.zip; do unzip -o "$f" -d extracted/; done

    python scripts/load_mordor_data.py --data-dir ./mordor_data              # eval
    python scripts/load_mordor_data.py --data-dir ./mordor_data --train      # train + eval
    python scripts/load_mordor_data.py --data-dir ./mordor_data --scenario "covenant_wmi*"
"""

import argparse
import fnmatch
import json
import re
from datetime import timedelta
from pathlib import Path

import pandas as pd

from aisoc.detection.baseline import BaselineStore
from aisoc.detection.evaluate import evaluate, format_report
from aisoc.detection.isolation_forest import AnomalyDetector
from aisoc.features import combined
from aisoc.features.windows import label_windows

MODEL_PATH = Path("models/process_if.joblib")
MORDOR_MODEL_PATH = Path("models/mordor_if.joblib")
LABELS_PATH = Path("simulations/mordor_labels.csv")

# -- Mordor -> Pipeline column mapping ------------------------------------
# Mordor uses native Windows Sysmon field names. Map to what the pipeline
# feature extractors expect (the Wazuh/OpenSearch-style dotted paths).

COL_HOST = "agent.name"
COL_IMAGE = "data.win.eventdata.image"
COL_PARENT = "data.win.eventdata.parentImage"
COL_CMDLINE = "data.win.eventdata.commandLine"
COL_DEST_IP = "data.win.eventdata.destinationIp"
COL_DEST_PORT = "data.win.eventdata.destinationPort"
COL_QUERY = "data.win.eventdata.queryName"
COL_SOURCE = "data.win.eventdata.sourceImage"
COL_TARGET = "data.win.eventdata.targetImage"
COL_GRANTED = "data.win.eventdata.grantedAccess"
COL_REG_TARGET = "data.win.eventdata.targetObject"
COL_IMG_LOADED = "data.win.eventdata.imageLoaded"
COL_SIGNED = "data.win.eventdata.signed"
COL_SIGSTATUS = "data.win.eventdata.signatureStatus"
COL_TIMESTAMP = "timestamp"


def _read_json(path: Path) -> list[dict]:
    """Read a Mordor events file.

    Real OTRF/Security-Datasets files are NEWLINE-DELIMITED JSON (one event
    object per line), not a single JSON array. We try whole-file JSON first
    (for array / {events:[...]} variants) and fall back to line-by-line NDJSON.
    Returns [] on failure so one corrupt file doesn't crash the import.
    """
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read().strip()
    except OSError as exc:
        print(f"  WARNING: skipping {path.name} - {exc}")
        return []
    if not text:
        return []

    # 1) whole-file JSON: array, {events/data/results: [...]}, or a single object
    try:
        data = json.loads(text)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for key in ("events", "data", "results"):
                if key in data:
                    return data[key]
            return []  # recognized JSON but unknown shape — don't guess
    except json.JSONDecodeError:
        pass

    # 2) NDJSON fallback - one JSON object per line (the real Mordor format)
    events: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


def _extract_technique_from_path(path: Path, data_dir: Path) -> str | None:
    """Try to infer a MITRE technique ID from the file path or metadata.

    Mordor organises files as: datasets/.../{tactic}/host/{scenario}.json
    The technique ID is often in the scenario name or parent directory.
    """
    rel = path.relative_to(data_dir)
    parts = str(rel).lower()
    # Common patterns in Mordor filenames: T1059_001, T1059.001, etc.
    match = re.search(r"t(\d{4})[._]?(\d{3})?", parts)
    if match:
        tid = f"T{match.group(1)}"
        if match.group(2):
            tid += f".{match.group(2)}"
        return tid
    return None


# -- Converters ----------------------------------------------------------


def _load_all_events(json_files: list[Path]) -> dict[int, list[dict]]:
    """Parse all JSON files once and dispatch events by Sysmon EventID.

    Avoids triple-parsing (previously each converter re-read every file).
    """
    by_eid: dict[int, list[dict]] = {}
    for path in json_files:
        for event in _read_json(path):
            eid = int(event.get("EventID") or event.get("event_id") or 0)
            if eid not in by_eid:
                by_eid[eid] = []
            by_eid[eid].append(event)
    return by_eid


def _host_for_event(event: dict, _default: str = "mordor-host") -> str:
    """Derive a host identifier from the event.

    Real Mordor Sysmon events carry the host in ``Hostname``; some variants use
    ``Computer``. Fall back to a constant so single-host scenarios still group.
    """
    return str(event.get("Hostname") or event.get("Computer") or event.get("host") or _default)


def _load_process_events(from_eid: dict[int, list[dict]]) -> pd.DataFrame:
    """Extract Sysmon EID 1 (process creation) from pre-parsed events."""
    rows = [
        {
            COL_TIMESTAMP: e.get("UtcTime") or e.get("@timestamp"),
            COL_HOST: _host_for_event(e),
            COL_IMAGE: e.get("Image", ""),
            COL_PARENT: e.get("ParentImage", ""),
            COL_CMDLINE: e.get("CommandLine", ""),
        }
        for e in from_eid.get(1, [])
    ]
    return pd.DataFrame(rows)


def _load_network_events(from_eid: dict[int, list[dict]]) -> pd.DataFrame:
    """Extract Sysmon EID 3 (network connection) from pre-parsed events."""
    rows = [
        {
            COL_TIMESTAMP: e.get("UtcTime") or e.get("@timestamp"),
            COL_HOST: _host_for_event(e),
            COL_DEST_IP: e.get("DestinationIp", ""),
            COL_DEST_PORT: str(e.get("DestinationPort", "")),
        }
        for e in from_eid.get(3, [])
    ]
    return pd.DataFrame(rows)


def _load_dns_events(from_eid: dict[int, list[dict]]) -> pd.DataFrame:
    """Extract Sysmon EID 22 (DNS query) from pre-parsed events."""
    rows = [
        {
            COL_TIMESTAMP: e.get("UtcTime") or e.get("@timestamp"),
            COL_HOST: _host_for_event(e),
            COL_QUERY: e.get("QueryName", ""),
        }
        for e in from_eid.get(22, [])
    ]
    return pd.DataFrame(rows)


def _load_process_access_events(from_eid: dict[int, list[dict]]) -> pd.DataFrame:
    """Extract Sysmon EID 10 (process access) from pre-parsed events.

    This is where credential-access (lsass reads) and injection show up — the
    dominant event type in many attack captures.
    """
    rows = [
        {
            COL_TIMESTAMP: e.get("UtcTime") or e.get("@timestamp"),
            COL_HOST: _host_for_event(e),
            COL_SOURCE: e.get("SourceImage", ""),
            COL_TARGET: e.get("TargetImage", ""),
            COL_GRANTED: e.get("GrantedAccess", ""),
        }
        for e in from_eid.get(10, [])
    ]
    return pd.DataFrame(rows)


def _load_registry_events(from_eid: dict[int, list[dict]]) -> pd.DataFrame:
    """Extract Sysmon EID 12 (key create/delete) + 13 (value set) — persistence."""
    rows = [
        {
            COL_TIMESTAMP: e.get("UtcTime") or e.get("@timestamp"),
            COL_HOST: _host_for_event(e),
            COL_REG_TARGET: e.get("TargetObject", ""),
        }
        for eid in (12, 13)
        for e in from_eid.get(eid, [])
    ]
    return pd.DataFrame(rows)


def _load_image_load_events(from_eid: dict[int, list[dict]]) -> pd.DataFrame:
    """Extract Sysmon EID 7 (image/DLL load) — unsigned-module / hijack signal."""
    rows = [
        {
            COL_TIMESTAMP: e.get("UtcTime") or e.get("@timestamp"),
            COL_HOST: _host_for_event(e),
            COL_IMG_LOADED: e.get("ImageLoaded", ""),
            COL_SIGNED: e.get("Signed", ""),
            COL_SIGSTATUS: e.get("SignatureStatus", ""),
        }
        for e in from_eid.get(7, [])
    ]
    return pd.DataFrame(rows)


def _collect_json_files(data_dir: Path, scenario_filter: str | None) -> list[Path]:
    """Find all .json files in the data directory, optionally filtered."""
    files = sorted(data_dir.rglob("*.json"))
    if scenario_filter:
        files = [f for f in files if fnmatch.fnmatch(str(f).lower(), f"*{scenario_filter.lower()}*")]
    return files


def _build_labels(json_files: list[Path], data_dir: Path) -> pd.DataFrame:
    """Create labels.csv entries from Mordor scenario metadata.

    Each JSON file represents one MITRE technique capture. We span the min/max
    event timestamp and tag the window with the host that produced most of the
    events (the monitored victim). The feature windows are grouped by that same
    Sysmon Hostname, so the label host MUST come from the events too — tagging it
    with the directory name (as an earlier version did) means label_windows never
    matches and every attack silently scores as benign.
    """
    rows = []
    for path in json_files:
        events = _read_json(path)
        if not events:
            continue
        technique = _extract_technique_from_path(path, data_dir)
        timestamps = []
        hosts: list[str] = []
        for e in events:
            ts = e.get("UtcTime") or e.get("@timestamp")
            if not ts:
                continue
            try:
                timestamps.append(pd.to_datetime(ts, utc=True))
            except Exception:
                continue
            hosts.append(_host_for_event(e))
        if not timestamps:
            continue
        host = max(set(hosts), key=hosts.count) if hosts else "mordor-host"
        # Add padding so label_windows catches the full attack window
        rows.append(
            {
                "start_utc": (min(timestamps) - timedelta(seconds=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "end_utc": (max(timestamps) + timedelta(seconds=90)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "host": host,
                "technique_id": technique or "MORDOR",
                "test_number": 0,
                "notes": f"Mordor scenario: {path.stem}",
            }
        )
    return pd.DataFrame(rows)


# -- Main ----------------------------------------------------------------


def run(
    data_dir: Path,
    scenario_filter: str | None,
    train: bool,
    eval_only: bool,
    out_model: Path,
    out_labels: Path,
) -> None:
    json_files = _collect_json_files(data_dir, scenario_filter)
    if not json_files:
        hint = f" matching '{scenario_filter}'" if scenario_filter else ""
        raise SystemExit(
            f"No .json files found{hint} in {data_dir}.\n\n"
            "The Mordor dataset is NOT bundled with this project. Download it first:\n\n"
            "  git clone https://github.com/OTRF/Security-Datasets.git\n"
            "  cd Security-Datasets/datasets/small/windows\n"
            "  mkdir -p ~/mordor_data\n"
            "  for f in */host/*.zip; do unzip -o \"$f\" -d ~/mordor_data/; done\n\n"
            "  Then run: python scripts/load_mordor_data.py --data-dir ~/mordor_data\n\n"
            "Each scenario is a few MB. See https://github.com/OTRF/Security-Datasets"
        )

    print(f"Found {len(json_files)} Mordor JSON files")

    # -- Convert events (single pass) -------------------------------
    by_eid = _load_all_events(json_files)
    proc = _load_process_events(by_eid)
    net = _load_network_events(by_eid)
    dns = _load_dns_events(by_eid)
    pax = _load_process_access_events(by_eid)
    reg = _load_registry_events(by_eid)
    img = _load_image_load_events(by_eid)

    print(f"  {len(proc)} process, {len(net)} network, {len(dns)} DNS, "
          f"{len(pax)} proc-access, {len(reg)} registry, {len(img)} image-load events")

    if all(d.empty for d in (proc, net, pax, reg, img)):
        raise SystemExit("No Sysmon events found in the selected files.")

    # -- Build features ----------------------------------------------
    features = combined.build(
        proc, net, dns,
        process_access_events=pax, registry_events=reg, image_load_events=img,
    )
    print(f"  {len(features)} (host, window) rows x {len(combined.FEATURE_COLUMNS)} features")

    # -- Build labels ------------------------------------------------
    labels = _build_labels(json_files, data_dir)
    if not labels.empty:
        out_labels.parent.mkdir(parents=True, exist_ok=True)
        labels.to_csv(out_labels, index=False)
        print(f"  {len(labels)} attack windows -> {out_labels}")

    if eval_only and not MODEL_PATH.exists() and not out_model.exists():
        raise SystemExit("No model found. Run without --eval-only to train first.")

    # -- Train (optional) --------------------------------------------
    if train:
        clean = features
        if not labels.empty:
            is_attack = label_windows(features, labels)
            n = int(is_attack.sum())
            if n:
                print(f"  excluding {n} attack windows from training")
            clean = features[~is_attack]

        detector = AnomalyDetector().fit(clean[combined.FEATURE_COLUMNS])
        detector.save(out_model)
        print(f"  saved model -> {out_model}")

        baseline = BaselineStore()
        baseline.reset()
        scored = clean.copy()
        scored["score"] = detector.score(scored[combined.FEATURE_COLUMNS])
        for host, grp in scored.groupby("host"):
            baseline.record_many(host, zip(grp["window_start"].astype(str), grp["score"]))
        print(f"  baseline store seeded with {len(scored)} window scores")
    else:
        model = out_model if out_model.exists() else MODEL_PATH
        if not model.exists():
            raise SystemExit(f"No model found at {model}. Use --train to train one.")
        detector = AnomalyDetector.load(model)

    # -- Evaluate ----------------------------------------------------
    if not labels.empty:
        features["score"] = detector.score(features[combined.FEATURE_COLUMNS])
        is_attack = label_windows(features, labels)
        metrics = evaluate(features["score"], is_attack)

        print(f"\n{'-' * 56}")
        print(f"Mordor Evaluation ({len(json_files)} scenarios)")
        print(f"{'-' * 56}")
        print(format_report(metrics))
        if metrics.get("attack_windows", 0) > 0:
            print("\nAttack windows and anomaly scores:")
            hit = features[is_attack].sort_values("window_start")
            for _, r in hit.head(20).iterrows():
                print(f"  {pd.to_datetime(r['window_start']):%H:%M:%S}  score={r['score']:.3f}")
    else:
        print("\nNo attack windows found - check that the Mordor files contain timestamps.")


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Evaluate the anomaly detector on Mordor/OTRF Security-Datasets"
    )
    ap.add_argument("--data-dir", type=Path, required=True,
                    help="directory containing extracted Mordor JSON files")
    ap.add_argument("--scenario", type=str, default=None,
                    help="filter scenarios by name (glob pattern, e.g. 'wmi*')")
    ap.add_argument("--train", action="store_true",
                    help="train a new model before evaluating")
    ap.add_argument("--eval-only", action="store_true",
                    help="skip training, evaluate only (default)")
    ap.add_argument("--out-model", type=Path, default=MORDOR_MODEL_PATH)
    ap.add_argument("--out-labels", type=Path, default=LABELS_PATH)
    args = ap.parse_args()

    if not args.data_dir.is_dir():
        raise SystemExit(
            f"Directory not found: {args.data_dir}\n\n"
            "The Mordor dataset is NOT bundled with this project. Download it first:\n\n"
            "  git clone https://github.com/OTRF/Security-Datasets.git\n"
            "  cd Security-Datasets/datasets/small/windows\n"
            "  mkdir -p ~/mordor_data\n"
            "  for f in */host/*.zip; do unzip -o \"$f\" -d ~/mordor_data/; done\n\n"
            "  Then run: python scripts/load_mordor_data.py --data-dir ~/mordor_data\n\n"
            "Each scenario is a few MB. See https://github.com/OTRF/Security-Datasets"
        )

    run(args.data_dir, args.scenario, args.train, not args.train,
        args.out_model, args.out_labels)


if __name__ == "__main__":
    main()
