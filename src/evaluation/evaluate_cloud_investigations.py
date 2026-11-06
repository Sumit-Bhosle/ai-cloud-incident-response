"""Offline, leakage-safe CloudTrail CASE evaluation (development data only).

Ground truth is read here, never passed to an investigator. This module does not
invoke Ollama or label uninvestigated cases as benign. Standard classification
metrics are computed only over cases receiving a positive/negative decision.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data/lab_evidence/cloudtrail/development"
FORBIDDEN_EVIDENCE_KEYS = {
    "attack_associated", "attack_event_count", "benign_event_count",
    "attack_name", "scenario_names", "should_sample", "ground_truth",
}
POSITIVE = {"suspicious", "malicious", "attack", "likely_malicious"}
NEGATIVE = {"benign", "normal", "likely_benign", "non_suspicious"}
ABSTAIN = {"insufficient_evidence", "inconclusive", "unknown", "uncertain", "needs_review", "undetermined"}


def load_jsonl(path: Path, *, key: str) -> dict:
    if not path.is_file():
        raise FileNotFoundError(path)
    result = {}
    with path.open(encoding="utf-8") as stream:
        for n, line in enumerate(stream, 1):
            if not line.strip():
                continue
            item = json.loads(line)
            if not isinstance(item, dict) or not isinstance(item.get(key), str):
                raise ValueError(f"Invalid {key} in {path.name}:{n}")
            ident = item[key]
            if not ident or ident in result:
                raise ValueError(f"Blank/duplicate {key} in {path.name}:{n}: {ident!r}")
            result[ident] = item
    if not result:
        raise ValueError(f"Empty dataset: {path}")
    return result


def check_evidence(cases: dict, truth: dict) -> None:
    if cases.keys() != truth.keys():
        raise ValueError("Cases and ground truth must contain identical case IDs")
    for case_id, case in cases.items():
        if FORBIDDEN_EVIDENCE_KEYS.intersection(case):
            raise ValueError(f"Ground-truth leakage in case: {case_id}")
        events = case.get("events")
        if not isinstance(events, list) or not events or case.get("event_count") != len(events):
            raise ValueError(f"Bad event count: {case_id}")
        ids = set()
        for event in events:
            if not isinstance(event, dict) or FORBIDDEN_EVIDENCE_KEYS.intersection(event):
                raise ValueError(f"Ground-truth leakage/invalid event in: {case_id}")
            event_id = event.get("event_id")
            if not isinstance(event_id, str) or not event_id or event_id in ids:
                raise ValueError(f"Missing/duplicate internal event ID in: {case_id}")
            ids.add(event_id)
        label = truth[case_id]
        attacks, benign = label.get("attack_event_count"), label.get("benign_event_count")
        if (type(label.get("attack_associated")) is not bool
                or type(attacks) is not int or type(benign) is not int
                or attacks < 0 or benign < 0 or attacks + benign != len(events)
                or label["attack_associated"] != (attacks > 0)):
            raise ValueError(f"Inconsistent case-level ground truth: {case_id}")


def decision(classification: str) -> str:
    if not isinstance(classification, str):
        raise ValueError("Report classification must be a string")
    category = classification.strip().lower().replace(" ", "-").replace("-", "_")
    if category in POSITIVE:
        return "positive"
    if category in NEGATIVE:
        return "negative"
    if category in ABSTAIN:
        return "abstain"
    raise ValueError(f"Unsupported AI classification: {classification!r}; define mapping before evaluation")


def read_reports(directory: Path, cases: dict) -> dict:
    if not directory.is_dir():
        raise FileNotFoundError(directory)
    reports = {}
    for path in sorted(directory.glob("*.json")):
        if path.name.endswith(".verification.json"):
            continue
        artifact = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(artifact, dict) or not isinstance(artifact.get("case_id"), str):
            raise ValueError(f"Unrecognized report JSON: {path}")
        case_id = artifact["case_id"]
        if case_id in reports:
            raise ValueError(f"Duplicate AI report: {case_id}")
        if case_id not in cases:
            raise ValueError(f"AI report references unknown case: {case_id}")
        if not isinstance(artifact.get("report"), dict):
            raise ValueError(f"Missing AI report body: {path}")
        if artifact.get("events_total") != len(cases[case_id]["events"]):
            raise ValueError(f"AI report event count differs: {case_id}")
        presented = artifact.get("events_presented")
        if type(presented) is not int or not 1 <= presented <= len(cases[case_id]["events"]):
            raise ValueError(f"Invalid events_presented: {case_id}")
        decision(artifact["report"].get("classification"))
        time = artifact.get("inference_seconds")
        if type(time) not in (float, int) or time < 0:
            raise ValueError(f"Invalid inference_seconds: {case_id}")
        reports[case_id] = artifact
    return reports


def inspect_report(case: dict, artifact: dict, verifier: dict | None) -> dict:
    report = artifact["report"]
    event_ids = {e["event_id"] for e in case["events"]}
    cited = report.get("evidence_ids", [])
    retrieved = artifact.get("retrieved_knowledge_ids", [])
    knowledge_cited = report.get("knowledge_ids", [])
    valid_event_citations = (isinstance(cited, list) and bool(cited)
                             and all(isinstance(e, str) and e in event_ids for e in cited))
    valid_knowledge_citations = (isinstance(retrieved, list) and isinstance(knowledge_cited, list)
                                 and all(isinstance(k, str) and k in retrieved for k in knowledge_cited))
    if verifier is not None:
        if verifier.get("case_id") != artifact["case_id"]:
            raise ValueError("Verification artifact case ID mismatch")
        if verifier.get("source_case_sha256") != artifact.get("case_sha256"):
            raise ValueError("Verification artifact/report hash mismatch")
        flags = verifier.get("flags", [])
        if not isinstance(flags, list):
            raise ValueError("Verifier flags must be a list")
        verification_status = verifier.get("review_status", "unspecified")
        flag_codes = [flag.get("code", "unknown") for flag in flags if isinstance(flag, dict)]
    else:
        verification_status = "not_run"
        flag_codes = []
    return {
        "decision": decision(report["classification"]),
        "event_citations_valid": valid_event_citations,
        "knowledge_citations_valid": valid_knowledge_citations,
        "verification_status": verification_status,
        "verification_flag_codes": flag_codes,
        "inference_seconds": artifact["inference_seconds"],
        "events_presented": artifact["events_presented"],
        "events_total": artifact["events_total"],
    }


def safe_div(num: int | float, den: int | float):
    return round(num / den, 6) if den else None


def score_rows(rows: list[dict], universe_size: int) -> dict:
    answered = [r for r in rows if r["decision"] != "abstain"]
    tp = sum(r["truth"] and r["decision"] == "positive" for r in answered)
    fp = sum(not r["truth"] and r["decision"] == "positive" for r in answered)
    tn = sum(not r["truth"] and r["decision"] == "negative" for r in answered)
    fn = sum(r["truth"] and r["decision"] == "negative" for r in answered)
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    return {
        "reports": len(rows),
        "case_coverage": safe_div(len(rows), universe_size),
        "answered": len(answered),
        "abstained": len(rows) - len(answered),
        "answered_fraction_of_all_cases": safe_div(len(answered), universe_size),
        "confusion_on_answered_only": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "selective_precision": precision,
        "selective_recall": recall,
        "selective_f1": safe_div(2 * tp, 2 * tp + fp + fn),
        "selective_accuracy": safe_div(tp + tn, len(answered)),
        "citation_membership_passes": sum(r["event_citations_valid"] and r["knowledge_citations_valid"] for r in rows),
        "verified_report_count": sum(r["verification_status"] != "not_run" for r in rows),
        "manual_review_required": sum(r["verification_status"] == "manual_review_required" for r in rows),
        "review_flag_counts": dict(sorted(Counter(code for r in rows for code in r["verification_flag_codes"]).items())),
        "mean_inference_seconds_on_reports": round(sum(r["inference_seconds"] for r in rows) / len(rows), 3) if rows else None,
        "interpretation": "Development sample only; not held-out/generalizable accuracy. Abstentions/missing reports excluded from selective confusion matrix.",
    }


def evaluate(data_dir: Path, methods: dict[str, Path]) -> dict:
    cases_path = data_dir / "cases.jsonl"
    truth_path = data_dir / "case_ground_truth.jsonl"
    cases = load_jsonl(cases_path, key="case_id")
    truth = load_jsonl(truth_path, key="case_id")
    check_evidence(cases, truth)
    rows_by_method = {}
    for method, directory in methods.items():
        reports = read_reports(directory, cases)
        rows = {}
        for case_id, artifact in reports.items():
            verification_path = directory / f"{case_id}.verification.json"
            verifier = json.loads(verification_path.read_text(encoding="utf-8")) if verification_path.exists() else None
            row = inspect_report(cases[case_id], artifact, verifier)
            row["truth"] = truth[case_id]["attack_associated"]
            row["case_id"] = case_id
            rows[case_id] = row
        rows_by_method[method] = rows
    common_ids = set.intersection(*(set(rows) for rows in rows_by_method.values())) if len(rows_by_method) >= 2 else set()
    outcome = {
        "evaluation_scope": "development_only",
        "evaluation_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "data_hashes_sha256": {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in (("cases", cases_path), ("case_ground_truth", truth_path))},
        "total_cases": len(cases),
        "attack_associated_cases": sum(t["attack_associated"] for t in truth.values()),
        "benign_only_cases": sum(not t["attack_associated"] for t in truth.values()),
        "mixed_label_cases": sum(1 for t in truth.values() if t["attack_event_count"] > 0 and t["benign_event_count"] > 0),
        "methods": {method: {**score_rows(list(rows.values()), len(cases)), "missing_reports": len(cases) - len(rows)} for method, rows in rows_by_method.items()},
        "paired_comparison": {
            "available": len(rows_by_method) >= 2,
            "shared_case_count": len(common_ids) if len(rows_by_method) >= 2 else None,
            "shared_cases_only": ({method: score_rows([rows[k] for k in sorted(common_ids)], len(common_ids)) for method, rows in rows_by_method.items()} if len(rows_by_method) >= 2 else {}),
            "note": "Compare methods only on identical case IDs. Case selection is not randomized; no significance claims.",
        },
        "per_case_audit": {method: [rows[k] for k in sorted(rows)] for method, rows in rows_by_method.items()},
        "limitations": [
            "Positive label means any attack-associated event in a heuristic case, not a confirmed independent incident.",
            "Suspicious AI classification is treated as a positive prediction, not confirmed compromise.",
            "Only reported-and-answered cases enter selective precision/recall/F1; coverage and abstention must accompany them.",
            "Citation membership and deterministic verifier flags do not establish claim-level factual correctness.",
            "These are development data. Do not report as final held-out performance.",
        ],
    }
    return outcome


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=DATA)
    parser.add_argument("--method", action="append", metavar="NAME=REPORT_DIR", help="Can repeat for baseline, LLM, RAG")
    parser.add_argument("--output", type=Path, help="Private JSON results file")
    args = parser.parse_args()
    methods = {}
    for spec in args.method or [f"cloud_ai={args.data_dir / 'ai_reports'}"]:
        if "=" not in spec:
            parser.error("--method requires NAME=DIRECTORY")
        name, folder = spec.split("=", 1)
        if not name.strip() or name in methods:
            parser.error("method names must be unique and nonempty")
        methods[name] = Path(folder)
    results = evaluate(args.data_dir, methods)
    output = args.output or args.data_dir / "evaluation/investigation_metrics.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("EVALUATION: DEVELOPMENT DATA ONLY")
    print(f"Cases: {results['total_cases']}; attack-associated: {results['attack_associated_cases']}; mixed: {results['mixed_label_cases']}")
    for name, m in results["methods"].items():
        print(f"{name}: {m['reports']} reports; {m['answered']} answered; {m['abstained']} abstained; {m['missing_reports']} missing")
        print("  Confusion (answered only):", m["confusion_on_answered_only"])
        print("  Selective precision/recall/F1:", m["selective_precision"], m["selective_recall"], m["selective_f1"])
        print("  Citation membership passes:", m["citation_membership_passes"], "Manual review:", m["manual_review_required"])
    print("Shared cases for method comparison:", results["paired_comparison"]["shared_case_count"])
    print("SAVED PRIVATE EVALUATION:", output)
    print("WARNING: One or a few reports are not a representative performance benchmark.")


if __name__ == "__main__":
    main()
