"""Reproducible, non-destructive SOC simulation for the research demonstration.

All event activity is generated as JSON. NO AWS calls, authentication attempts,
network probes, or actual attacks are performed by this module.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "data/lab_evidence/soc_demo"
MODEL = "qwen2.5:1.5b"
OLLAMA = "http://127.0.0.1:11434/api/chat"

# All scenario labels live ONLY in ground_truth.jsonl, never in events.
SCENARIOS = (
    ("benign", "Routine storage inventory", ("ListBuckets", "GetBucketLocation", "GetBucketLogging")),
    ("benign", "Scheduled virtual-machine inventory", ("DescribeInstances", "DescribeVolumes", "DescribeSecurityGroups")),
    ("benign", "Approved identity audit", ("GetCallerIdentity", "ListUsers", "ListRoles")),
    ("benign", "Normal backup verification", ("PutObject", "GetObject", "HeadObject")),
    ("suspicious", "Repeated unsuccessful console logins", ("ConsoleLogin",) * 5),
    ("suspicious", "S3 discovery sequence", ("ListBuckets", "GetBucketPolicy", "GetBucketAcl", "ListObjects")),
    ("suspicious", "Unusual object-read burst", ("GetObject",) * 6),
    ("critical", "Audit logging disruption", ("DescribeTrails", "StopLogging", "DeleteTrail")),
    ("critical", "Administrative permission expansion", ("ListPolicies", "CreateAccessKey", "AttachUserPolicy")),
    ("critical", "Mass object removal", ("ListObjects",) + ("DeleteObject",) * 6),
)

HIGH_RISK = {"StopLogging", "DeleteTrail", "AttachUserPolicy", "CreateAccessKey", "DeleteObject"}
INVESTIGATE = {"ConsoleLogin", "GetBucketPolicy", "GetBucketAcl", "ListObjects", "GetObject"}
AWS_SERVICE = {
    "ConsoleLogin": "signin.amazonaws.com", "GetCallerIdentity": "sts.amazonaws.com",
    "ListUsers": "iam.amazonaws.com", "ListRoles": "iam.amazonaws.com",
    "ListPolicies": "iam.amazonaws.com", "CreateAccessKey": "iam.amazonaws.com",
    "AttachUserPolicy": "iam.amazonaws.com", "StopLogging": "cloudtrail.amazonaws.com",
    "DeleteTrail": "cloudtrail.amazonaws.com", "DescribeTrails": "cloudtrail.amazonaws.com",
    "DescribeInstances": "ec2.amazonaws.com", "DescribeVolumes": "ec2.amazonaws.com",
    "DescribeSecurityGroups": "ec2.amazonaws.com",
}


def canonical(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256(obj):
    return hashlib.sha256(canonical(obj).encode("utf-8")).hexdigest()


def read_jsonl(path):
    with Path(path).open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def write_jsonl(path, rows):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(canonical(row) + "\n")


def make_cases(count=100):
    if count != 100:
        raise ValueError("The research demonstration requires exactly 100 cases")
    cases, truth, wazuh_events = [], [], []
    start = datetime(2026, 11, 8, 19, 0, tzinfo=timezone.utc)
    for index in range(count):
        category, scenario, actions = SCENARIOS[index % len(SCENARIOS)]
        case_id = f"SOCSIM-{index + 1:03d}"
        actor = f"simulated-role-{(index % 9) + 1:02d}"
        ip = f"198.51.100.{(index % 200) + 10}"
        events = []
        for offset, action in enumerate(actions):
            event_id = f"{case_id}-EVT-{offset + 1:02d}"
            service = AWS_SERVICE.get(action, "s3.amazonaws.com")
            failed_login = action == "ConsoleLogin"
            event = {
                "event_id": event_id,
                "source_event_id": event_id,
                "source_type": "soc_demo_synthetic_cloudtrail",
                "timestamp_utc": (start + timedelta(minutes=index * 3, seconds=offset * 10)).isoformat().replace("+00:00", "Z"),
                "action": action,
                "actor": actor,
                "source_ip": ip,
                "event_source": service,
                "aws_region": "ca-central-1",
                "resources": [f"arn:aws:s3:::socdemo-bucket-{index % 12:02d}"],
                "error_code": "FailedAuthentication" if failed_login else None,
                "request_context": {"simulated": True, "test_case": case_id},
            }
            events.append(event)
            # Wazuh receives the very same event ID and fields as Python.
            wazuh_events.append({
                "soc_demo": "research_simulation", "sim_case_id": case_id,
                "sim_event_id": event_id, "action": action,
                "actor": actor, "source_ip": ip, "service": service,
                "resource": event["resources"][0],
                "error_code": event["error_code"] or "none",
                "message": "Synthetic event for approved academic demonstration; no AWS action executed",
            })
        cases.append({"case_id": case_id, "correlation_method": "simulation_case_id", "event_count": len(events), "events": events})
        truth.append({"case_id": case_id, "class_label": category, "scenario": scenario,
                      "should_escalate": category != "benign", "simulated_malicious": category == "critical"})
    return cases, truth, wazuh_events


def assert_isolated(cases):
    forbidden = {"class_label", "scenario", "should_escalate", "simulated_malicious", "ground_truth", "attack_associated", "attack_name"}
    for case in cases:
        if forbidden.intersection(case):
            raise ValueError("Ground truth leaked into model input")
        for event in case["events"]:
            if forbidden.intersection(event):
                raise ValueError("Ground truth leaked into model event")


def prepare(out=DEFAULT_OUT):
    out = Path(out)
    cases, truth, events = make_cases()
    assert_isolated(cases)
    out.mkdir(parents=True, exist_ok=True)
    # Avoid destroying existing recorded evidence on repeated runs.
    paths = [out / name for name in ("cases.jsonl", "ground_truth_PRIVATE.jsonl", "wazuh_events.jsonl")]
    for path, rows in zip(paths, (cases, truth, events)):
        if path.exists():
            if read_jsonl(path) != rows:
                raise ValueError(f"Existing file differs; refusing overwrite: {path}")
        else:
            write_jsonl(path, rows)
    manifest = {"data_origin": "entirely synthetic", "execution_of_attacks": False,
                "case_count": len(cases), "event_count": len(events),
                "class_distribution": dict(sorted(Counter(t["class_label"] for t in truth).items())),
                "case_evidence_sha256": sha256(cases), "ground_truth_sha256": sha256(truth),
                "source": "src/demo/soc_demo.py", "safe_ip_ranges": ["198.51.100.0/24"]}
    mp = out / "manifest.json"
    if mp.exists() and json.loads(mp.read_text()) != manifest:
        raise ValueError("Manifest changed; refusing overwrite")
    mp.write_text(json.dumps(manifest, indent=2) + "\n")
    print("PREPARED", len(cases), "synthetic cases,", len(events), "simulated log events")
    print("DISTRIBUTION", manifest["class_distribution"])
    print("PRIVATE OUTPUT", out)
    return manifest


def baseline(case):
    actions = [e["action"] for e in case["events"]]
    if any(x in HIGH_RISK for x in actions):
        classification = "critical"
        reason = "High-impact administrative or destructive cloud API action observed."
        cites = [e["event_id"] for e in case["events"] if e["action"] in HIGH_RISK]
    elif actions.count("ConsoleLogin") >= 3 and any(e.get("error_code") for e in case["events"]):
        classification = "suspicious"
        reason = "Repeated unsuccessful cloud sign-in attempts observed."
        cites = [e["event_id"] for e in case["events"] if e["action"] == "ConsoleLogin"]
    elif actions.count("GetObject") >= 5 or ({"GetBucketPolicy", "GetBucketAcl"} <= set(actions)):
        classification = "suspicious"
        reason = "Object-read burst or storage-permission reconnaissance pattern observed."
        cites = [e["event_id"] for e in case["events"] if e["action"] in INVESTIGATE]
    else:
        classification = "benign"
        reason = "No specified high-risk pattern matched; this does not prove the activity is safe."
        cites = [case["events"][0]["event_id"]]
    return {"classification": classification, "summary": reason, "reasoning": reason,
            "evidence_ids": cites, "knowledge_ids": [],
            "next_checks": ["Confirm activity with the resource owner", "Review adjacent API activity and IAM permissions"]}


def _flatten_references(obj):
    if isinstance(obj, list):
        for value in obj:
            yield from _flatten_references(value)
    elif isinstance(obj, dict):
        if ("id" in obj or "reference_id" in obj) and any(k in obj for k in ("title", "summary", "description", "text", "content")):
            yield obj
        else:
            for value in obj.values():
                if isinstance(value, (dict, list)):
                    yield from _flatten_references(value)


def references(root=ROOT):
    found = {}
    for filename in ("security_references.json", "cloudtrail_guidance.json"):
        path = Path(root) / "data/knowledge_base" / filename
        if not path.exists():
            continue
        for row in _flatten_references(json.loads(path.read_text(encoding="utf-8"))):
            key = str(row.get("id") or row.get("reference_id"))
            found[key] = {"id": key, "title": str(row.get("title", "")),
                          "summary": str(row.get("summary") or row.get("description") or row.get("text") or row.get("content") or "")[:650],
                          "url": str(row.get("url", ""))}
    return list(found.values())


def pick_refs(refs, case, max_refs=3):
    words = set(re.findall(r"[a-z]{3,}", " ".join(e["action"]+" "+e["event_source"] for e in case["events"]).lower()))
    def score(r):
        text = f'{r["title"]} {r["summary"]}'.lower()
        return sum(word in text for word in words)
    return sorted(refs, key=lambda r: (-score(r), r["id"]))[:max_refs]


def validate_ai(report, case, refs):
    if not isinstance(report, dict):
        raise ValueError("Report must be an object")
    if report.get("classification") not in {"benign", "suspicious", "critical", "insufficient_evidence"}:
        raise ValueError("Unexpected classification")
    valid_events = {e["event_id"] for e in case["events"]}
    valid_refs = {r["id"] for r in refs}
    for key in ("summary", "reasoning"):
        if not isinstance(report.get(key), str) or not report[key].strip():
            raise ValueError(f"Missing {key}")
    for key, allowed in (("evidence_ids", valid_events), ("knowledge_ids", valid_refs)):
        ids = report.get(key)
        if not isinstance(ids, list) or any(not isinstance(x, str) or x not in allowed for x in ids):
            raise ValueError(f"Invalid {key}")
    if not isinstance(report.get("next_checks"), list):
        raise ValueError("Invalid next_checks")
    return report


def call_ollama(case, refs, model=MODEL):
    """Small, fixed SOC task. Labels are excluded by assert_isolated."""
    assert_isolated([case])
    references_text = json.dumps(refs, ensure_ascii=False)
    system = (
        "You are a cautious SOC analyst evaluating SYNTHETIC cloud activity. "
        "Never assert compromise or data loss without evidence. "
        "Provide concise JSON with keys classification, summary, reasoning, evidence_ids, knowledge_ids, next_checks. "
        "classification must be benign, suspicious, critical, or insufficient_evidence. "
        "Cite ONLY supplied event IDs. knowledge_ids must cite ONLY supplied reference IDs; use [] when no refs. "
        "Never invent evidence. An alert is not proof of malicious intent. "
        "Return short explanations for non-technical stakeholders."
    )
    payload = {"model": model, "stream": False, "format": "json",
               "options": {"temperature": 0, "num_predict": 900},
               "messages": [{"role": "system", "content": system},
                            {"role": "user", "content": "Events:\n" + json.dumps(case) +
                             "\nAllowed knowledge references:\n" + references_text}]}
    error = None
    started = time.monotonic()
    for attempt in range(2):
        try:
            request = urllib.request.Request(OLLAMA, data=json.dumps(payload).encode(),
                                             headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(request, timeout=120) as response:
                envelope = json.load(response)
            if envelope.get("done_reason") == "length":
                raise ValueError("Model output truncated by token limit")
            response_json = json.loads(envelope["message"]["content"])
            validate_ai(response_json, case, refs)
            return response_json, round(time.monotonic()-started, 3)
        except (ValueError, KeyError, json.JSONDecodeError, urllib.error.HTTPError, urllib.error.URLError) as exc:
            error = f"{type(exc).__name__}: {exc}"
            if attempt == 0:
                payload["messages"].append({"role": "user", "content": "Prior output failed validation. Return valid short JSON; no invented citation IDs."})
    raise RuntimeError("LLM output failed after retry: " + str(error))


def _select_demo_cases(cases, truth, n=6):
    label_by_id = {t["case_id"]: t["class_label"] for t in truth}
    selected = []
    for label in ("benign", "suspicious", "critical"):
        selected.extend([case for case in cases if label_by_id[case["case_id"]] == label][:n // 3])
    return selected


def _confusion(rows, labels):
    valid = [r for r in rows if r.get("prediction") in {"benign", "suspicious", "critical"}]
    return {"answered": len(valid), "correct": sum(labels[r["case_id"]] == r["prediction"] for r in valid),
            "accuracy_on_answered": round(sum(labels[r["case_id"]] == r["prediction"] for r in valid)/len(valid),4) if valid else None,
            "failures_or_abstentions": len(rows)-len(valid)}


def executive_markdown(cases, predictions, labels):
    counts = Counter(labels.values())
    lines = ["# Simulated SOC — Executive Investigation Report", "",
             "**Research simulation only. No real attack was executed.**", "",
             "## Executive overview", "",
             f"Prepared a controlled sample of 100 scenarios: {counts['benign']} benign, "
             f"{counts['suspicious']} suspicious and {counts['critical']} designated critical simulations.",
             "Classification labels are simulation ground truth, not verified real incidents.", "",
             "## Comparable investigation results", "",
             "| Method | Classified | Correct (among answered) | Review/failure |", "|---|---:|---:|---:|"]
    for method in ("baseline", "llm_only", "rag"):
        rows = predictions[method]
        metric = _confusion(rows, labels)
        lines.append(f"| {method} | {metric['answered']}/{len(rows)} | {metric['correct']}/{metric['answered'] or 1} | {metric['failures_or_abstentions']} |")
    lines.extend(["", "## Same-case comparison", "", "| Case | Rule baseline | LLM only | RAG + LLM | Simulation reference |", "|---|---|---|---|---|"])
    lookup_pred = {m: {r["case_id"]: r.get("prediction") or "error" for r in predictions[m]} for m in predictions}
    for case in cases:
        cid = case["case_id"]
        lines.append(f"| {cid} | {lookup_pred['baseline'][cid]} | {lookup_pred['llm_only'][cid]} | {lookup_pred['rag'][cid]} | {labels[cid]} |")
    lines.extend(["", "Simulation reference is used for scoring ONLY after prediction generation; not an independently verified real attack.", "", "## Example case summaries", ""])
    lookup = {c["case_id"]: c for c in cases}
    for result in predictions["rag"]:
        case_id = result["case_id"]
        assessment = result.get("prediction")
        potential_impact = (
            "Possible administrative compromise or service/data disruption; NOT confirmed by simulated event logs alone."
            if assessment == "critical" else
            "Potential unauthorized access or policy exposure; further review is required."
            if assessment == "suspicious" else
            "No confirmed business impact from the supplied simulated evidence; absence of alerts is not proof of safety."
        )
        lines.extend([f"### {case_id}", "", f"**Observed cloud actions:** {', '.join(e['action'] for e in lookup[case_id]['events'])}.",
                      f"**AI assessment:** {assessment or 'unavailable'} (unverified).",
                      f"**Business summary:** {result.get('summary') or 'Report unavailable; analyst review needed.'}",
                      f"**Potential business impact:** {potential_impact}",
                      f"**Recommended check:** {result.get('next_check') or 'Confirm with SOC and resource owner.'}",
                      f"**Evidence references:** {', '.join(result.get('evidence_ids', [])) or 'Not cited'}.",
                      f"**Knowledge references:** {', '.join(result.get('knowledge_ids', [])) or 'Not cited'}.", ""])
    lines.extend(["## SOC cross-check and limitations", "",
                  "Wazuh detection and ingestion must be independently verified using the exported alert records.",
                  "Wazuh detection is a rule-based observation, not ground truth about actual compromise.",
                  "Ground truth was separated from model input and used only after report generation.",
                  "LLM explanations and citations are not fully fact-verified. Analyst approval is required.",
                  "These six deliberately selected simulated cases are not representative of real-world accuracy.", ""])
    return "\n".join(lines)


def compare(out=DEFAULT_OUT, root=ROOT, model=MODEL):
    out = Path(out)
    cases = read_jsonl(out / "cases.jsonl")
    truth = read_jsonl(out / "ground_truth_PRIVATE.jsonl")
    assert_isolated(cases)
    selected = _select_demo_cases(cases, truth)
    refs = references(root)
    labels = {t["case_id"]: t["class_label"] for t in truth}
    print("Selected", len(selected), "cases; knowledge base entries:", len(refs))
    results = {x: [] for x in ("baseline", "llm_only", "rag")}
    reports_dir = out / "reports"
    reports_dir.mkdir(exist_ok=True)
    existing = [reports_dir / f"{case['case_id']}_{method}.json" for case in selected for method in results]
    already = [path for path in existing if path.exists()]
    if already:
        raise FileExistsError(f"Prior experiment exists; refusing re-run before LLM calls: {already[0]}")
    for case in selected:
        print("CASE", case["case_id"])
        for method in results:
            chosen_refs = pick_refs(refs, case) if method == "rag" else []
            start = time.monotonic()
            try:
                if method == "baseline":
                    report = baseline(case)
                    seconds = round(time.monotonic() - start, 4)
                else:
                    report, seconds = call_ollama(case, chosen_refs, model)
                entry = {"case_id": case["case_id"], "method": method, "prediction": report["classification"],
                         "seconds": seconds, "summary": report["summary"], "reasoning": report["reasoning"],
                         "evidence_ids": report["evidence_ids"], "knowledge_ids": report["knowledge_ids"],
                         "next_check": (report["next_checks"] or [None])[0],
                         "retrieved_knowledge_ids": [r["id"] for r in chosen_refs],
                         "source_sha256": sha256(case), "simulation": True}
            except Exception as exc:
                entry = {"case_id": case["case_id"], "method": method, "prediction": None,
                         "error": f"{type(exc).__name__}: {exc}", "seconds": round(time.monotonic()-start, 2)}
            results[method].append(entry)
            path = reports_dir / f"{case['case_id']}_{method}.json"
            if path.exists():
                raise FileExistsError(f"Prior experiment report exists; use a new --out directory: {path}")
            path.write_text(json.dumps(entry, indent=2) + "\n", encoding="utf-8")
            print(" ",method,entry.get("prediction") or "ERROR",entry["seconds"],"s")
    (out / "executive_report.md").write_text(executive_markdown(selected, results, labels), encoding="utf-8")
    metrics = {"experimental_sample_size": len(selected), "source": "100 synthetic SOC scenarios",
               "comparisons": {method: _confusion(rows, labels) for method, rows in results.items()},
               "limitations": "Not a population accuracy estimate; Wazuh validation separate; simulated cases"}
    (out / "metrics_PRIVATE.json").write_text(json.dumps(metrics, indent=2) + "\n")
    print("SAVED", out / "executive_report.md")
    print("COMPARISON", json.dumps(metrics["comparisons"]))
    return metrics


def crosscheck(out=DEFAULT_OUT, alerts=None):
    out = Path(out)
    cases = read_jsonl(out / "cases.jsonl")
    expected = {ev["event_id"]: case["case_id"] for case in cases for ev in case["events"]}
    seen = set()
    for alert in read_jsonl(alerts):
        data = alert.get("data", {})
        if not isinstance(data, dict) or data.get("soc_demo") != "research_simulation":
            continue
        event_id = data.get("sim_event_id")
        if event_id in expected and data.get("sim_case_id") == expected[event_id]:
            seen.add(event_id)
    result = {"source": str(alerts), "events_generated": len(expected), "wazuh_alerts_matching_event_ids": len(seen),
              "coverage": round(len(seen)/len(expected),4),
              "note": "Alert presence validates log ingestion and rule matches, not attack correctness"}
    (out / "wazuh_crosscheck_PRIVATE.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return result


def main():
    parser = argparse.ArgumentParser(description="Safe synthetic SOC incident demonstration")
    parser.add_argument("command", choices=("prepare", "compare", "crosscheck"))
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--alerts", type=Path, help="Wazuh alerts.json export for crosscheck")
    parser.add_argument("--model", default=MODEL)
    args = parser.parse_args()
    if args.command == "prepare":
        prepare(args.out)
    elif args.command == "compare":
        compare(args.out, model=args.model)
    elif args.command == "crosscheck":
        if not args.alerts:
            parser.error("crosscheck requires --alerts")
        crosscheck(args.out, args.alerts)


if __name__ == "__main__":
    main()
