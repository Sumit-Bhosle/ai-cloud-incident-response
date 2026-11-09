"""Wazuh-to-AI research bridge with source-event verification and analyst safeguards.

Only READS existing Wazuh alerts and local synthetic evidence. Never performs AWS
operations, countermeasures, Wazuh configuration changes, or alert injection.
Ground-truth labels are never read by the model-inference path; evaluation loads
these separately only AFTER cached predictions have been saved.

Example:
    python3 -m src.demo.wazuh_pipeline audit --alerts /path/alerts.json
    python3 -m src.demo.wazuh_pipeline run --alerts /path/alerts.json --case SOCSIM-008
    python3 -m src.demo.wazuh_pipeline run --alerts /path/alerts.json --limit 100
    python3 -m src.demo.wazuh_pipeline evaluate
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import gzip
import json
from pathlib import Path
import re
import statistics
import time

from . import soc_demo as demo
from .grounded_model import grounded_ollama
from .executive_html import render_html

DEFAULT_EVIDENCE = demo.DEFAULT_OUT
DEFAULT_RESULTS = DEFAULT_EVIDENCE / "wazuh_ai_pipeline"
RULE_IDS = {"110100", "110101", "110102"}
SEVERITIES = ("benign", "suspicious", "critical")
HIGH_RISK = demo.HIGH_RISK
MEDIUM_RULE_ACTIONS = {"ConsoleLogin", "GetBucketPolicy", "GetBucketAcl", "GetObject"}
SOURCE_LOCATION = "/var/log/soc_demo_cloud.jsonl"
SOURCE_COMPARE = ("soc_demo", "sim_case_id", "sim_event_id", "action", "actor",
                  "source_ip", "service", "resource", "error_code")


def _alert_files(path):
    """Read a single JSONL file or a directory of Wazuh JSONL/json.gz archives."""
    path = Path(path)
    if path.is_file():
        return [path]
    if not path.exists() or not path.is_dir():
        raise FileNotFoundError(f"Wazuh alert source not found: {path}")
    files = [p for p in path.rglob("*") if p.is_file() and (
        p.name == "alerts.json" or p.name.endswith(".json.gz") or p.name.endswith(".jsonl")
        or p.name.startswith("ossec-alerts-") and p.name.endswith(".json"))]
    if not files:
        raise FileNotFoundError(f"No Wazuh JSON alert files in {path}")
    return sorted(files)


def _iter_alerts(paths):
    for p in paths:
        opener = gzip.open if p.suffix == ".gz" else open
        with opener(p, "rt", encoding="utf-8", errors="replace") as handle:
            for line_number, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    # A concurrently-written trailing record can be incomplete.
                    # Do not treat an invalid alert as valid evidence.
                    continue
                if isinstance(item, dict):
                    yield item


def expected_index(evidence=DEFAULT_EVIDENCE):
    evidence = Path(evidence)
    cases = demo.read_jsonl(evidence / "cases.jsonl")
    expected_rows = demo.read_jsonl(evidence / "wazuh_events.jsonl")
    manifest = json.loads((evidence / "manifest.json").read_text())
    demo.assert_isolated(cases)
    if demo.sha256(cases) != manifest["case_evidence_sha256"]:
        raise ValueError("Synthetic case manifest integrity check failed")
    if len(expected_rows) != manifest["event_count"] or len(cases) != manifest["case_count"]:
        raise ValueError("Synthetic case/event count differs from manifest")
    if any(row.get("soc_demo") != "research_simulation" for row in expected_rows):
        raise ValueError("Unexpected non-simulation source event")
    expected = {row["sim_event_id"]: row for row in expected_rows}
    if len(expected) != len(expected_rows):
        raise ValueError("Duplicate source event IDs in generated dataset")
    case_index = {c["case_id"]: c for c in cases}
    if len(case_index) != len(cases):
        raise ValueError("Duplicate source case IDs in generated dataset")
    return case_index, expected


def load_verified_wazuh(alerts, evidence=DEFAULT_EVIDENCE):
    """Only records with matching alert ID + ALL identifying source fields are trusted.

    Returns verified raw Wazuh alerts keyed by case, and explicit ingestion audit.
    Wazuh rule matches are proof of parsing/detection, NOT proof of a compromise.
    """
    index, expected = expected_index(evidence)
    actual = {}
    mismatches = []
    unknown = set()
    duplicate = 0
    candidate_count = 0
    for alert in _iter_alerts(_alert_files(alerts)):
        data = alert.get("data")
        if not isinstance(data, dict) or data.get("soc_demo") != "research_simulation":
            continue
        candidate_count += 1
        event_id = data.get("sim_event_id")
        reference = expected.get(event_id)
        if reference is None:
            unknown.add(str(event_id))
            continue
        action = reference["action"]
        expected_rule = "110102" if action in HIGH_RISK else "110101" if action in MEDIUM_RULE_ACTIONS else "110100"
        if str(alert.get("rule", {}).get("id")) != expected_rule:
            mismatches.append({"event_id": event_id, "reason": "unexpected_rule_id"})
            continue
        if alert.get("location") != SOURCE_LOCATION:
            mismatches.append({"event_id": event_id, "reason": "unexpected_source_location"})
            continue
        wrong = [field for field in SOURCE_COMPARE if data.get(field) != reference.get(field)]
        if wrong:
            mismatches.append({"event_id": event_id, "reason": "source_field_mismatch", "fields": wrong})
            continue
        old = actual.get(event_id)
        if old is not None:
            duplicate += 1
            # Check the duplicate doesn't claim a different rule/severity.
            if old["rule"]["id"] != alert["rule"]["id"]:
                mismatches.append({"event_id": event_id, "reason": "conflicting_rule_ids"})
                actual.pop(event_id, None)
            continue
        actual[event_id] = alert
    invalid_ids = {x["event_id"] for x in mismatches}
    for event_id in invalid_ids:
        actual.pop(event_id, None)
    by_case = defaultdict(list)
    for event_id, alert in actual.items():
        by_case[expected[event_id]["sim_case_id"]].append(alert)
    for alerts_list in by_case.values():
        alerts_list.sort(key=lambda a: a["data"]["sim_event_id"])
    case_counts = {cid: len(case["events"]) for cid, case in index.items()}
    complete = [cid for cid, records in by_case.items() if len(records) == case_counts[cid]]
    missing_cases = [cid for cid in index if cid not in complete]
    audit = {
        "source": str(alerts), "simulation_only": True,
        "simulated_cases": len(index), "expected_simulated_events": len(expected),
        "candidate_wazuh_alert_records": candidate_count,
        "verified_unique_events": len(actual),
        "verified_coverage": round(len(actual) / len(expected), 4),
        "complete_cases": len(complete), "partial_or_absent_cases": len(missing_cases),
        "partial_or_absent_case_ids": sorted(missing_cases),
        "duplicate_alert_records": duplicate,
        "unknown_simulated_event_ids": sorted(unknown),
        "mismatch_count": len(mismatches), "mismatch_examples": mismatches[:20],
        "rules_seen": dict(sorted(Counter(str(a["rule"]["id"]) for a in actual.values()).items())),
        "warning": "SIEM rule match is not proof that an actual attack occurred. Partial cases must not be scored.",
    }
    return index, by_case, audit


def normalise_wazuh_case(case_id, alerts):
    """Construct the AI input ONLY from verified Wazuh alert fields."""
    events = []
    for alert in sorted(alerts, key=lambda a: a["data"]["sim_event_id"]):
        data = alert["data"]
        events.append({
            "event_id": data["sim_event_id"], "source_event_id": data["sim_event_id"],
            "source_type": "wazuh_verified_synthetic_cloud_alert",
            "timestamp_utc": alert.get("timestamp", "unknown"),
            "action": data["action"], "actor": data["actor"],
            "source_ip": data["source_ip"], "event_source": data["service"],
            "resources": [data["resource"]],
            "error_code": None if data["error_code"] == "none" else data["error_code"],
            "wazuh_alert_id": str(alert.get("id", "")),
            "wazuh_rule_id": str(alert["rule"]["id"]),
            "wazuh_rule_level": int(alert["rule"].get("level", 0)),
            "request_context": {"simulated": True, "log_origin": alert.get("location", "unknown")},
        })
    case = {"case_id": case_id, "correlation_method": "verified_wazuh_sim_case_id",
            "event_count": len(events), "events": events}
    demo.assert_isolated([case])
    return case


def observable_findings(case):
    """Evidence-derived observations; do not assert AWS operations actually succeeded."""
    events = case["events"]
    actions = [x["action"] for x in events]
    findings = []
    def add(title, explanation, impact, next_steps, matching):
        event_ids = [e["event_id"] for e in events if e["action"] in matching]
        if event_ids:
            findings.append({"title": title, "observation": explanation,
                             "business_risk": impact, "recommended_checks": next_steps,
                             "evidence_ids": event_ids})
    if {"StopLogging", "DeleteTrail"} & set(actions):
        add("Cloud audit-log disruption indicators",
            "Wazuh recorded API events named StopLogging or DeleteTrail. Logs do not establish whether those requests succeeded.",
            "If effective, reduced audit visibility could delay detection or investigation.",
            ["Check CloudTrail configuration and service event outcomes", "Preserve remaining audit evidence and contact the cloud security owner"],
            {"StopLogging", "DeleteTrail"})
    if {"CreateAccessKey", "AttachUserPolicy"} & set(actions):
        add("Cloud identity and permission changes",
            "Wazuh recorded credential-creation or policy-attachment API activity; actor authorization and execution results need checking.",
            "If unauthorized and successful, credentials or permissions could be misused.",
            ["Verify IAM approval, caller identity, and actual changes", "Review access keys and policy history with security staff"],
            {"CreateAccessKey", "AttachUserPolicy"})
    if "DeleteObject" in actions:
        add("Cloud object deletion events",
            "Wazuh recorded DeleteObject API events, but this evidence alone does not verify successful deletion.",
            "If successful, files or backups might be unavailable or altered.",
            ["Verify object versioning and actual delete outcomes", "Check backups and recovery options with the resource owner"],
            {"DeleteObject"})
    failed = [e for e in events if e["action"] == "ConsoleLogin" and e.get("error_code")]
    if len(failed) >= 3:
        add("Repeated failed console sign-ins",
            f"Wazuh recorded {len(failed)} failed sign-in events within this simulated case.",
            "Repeated failures may represent an access problem or attempts to guess credentials; account compromise is not confirmed.",
            ["Check identity sign-in history and MFA events", "Ask the identity owner whether the sign-ins were expected"],
            {"ConsoleLogin"})
    if actions.count("GetObject") >= 5:
        add("Unusual object-read volume",
            f"Wazuh recorded {actions.count('GetObject')} GetObject events grouped into one simulated case.",
            "An unexpected object-read burst may expose data if access was unauthorized.",
            ["Confirm the actor's data-access need", "Review related requests, permissions, and successful outcomes"],
            {"GetObject"})
    if {"GetBucketPolicy", "GetBucketAcl"} <= set(actions):
        add("Storage permissions reconnaissance pattern",
            "The event sequence contains both GetBucketPolicy and GetBucketAcl lookups.",
            "These calls can be legitimate, but an unexpected pair warrants permission-review context.",
            ["Check resource-owner approval", "Review adjacent S3 activity and IAM identity"],
            {"GetBucketPolicy", "GetBucketAcl"})
    if not findings:
        findings.append({
            "title": "No targeted escalation pattern in supplied events",
            "observation": f"Wazuh recorded {len(events)} simulated events; this rule set found no designated high-risk sequence.",
            "business_risk": "No compromise or business loss is established by the available records; normal-looking activity is not proof of safety.",
            "recommended_checks": ["Confirm the observed activity with the responsible cloud owner"],
            "evidence_ids": [e["event_id"] for e in events],
        })
    return findings


def check_model_claims(report, case):
    """Conservative automated checks, NOT a general-purpose truth verifier.

    Even when zero issues are found, generated prose remains unverified and is
    never promoted to the factual executive narrative automatically.
    """
    if not report:
        return ["model_unavailable"]
    text = " ".join(str(report.get(x, "")) for x in ("summary", "reasoning")).lower()
    actions = [e["action"] for e in case["events"]]
    issues = []
    if ("s3 bucket" in text or "bucket" in text) and ("delet" in text or "remov" in text) and "DeleteBucket" not in actions:
        issues.append("unsupported_bucket_deletion_claim")
    if "single event" in text and len(actions) > 1:
        issues.append("contradicts_multiple_events")
    if "brute force" in text and not (actions.count("ConsoleLogin") >= 3 and any(e.get("error_code") for e in case["events"])):
        issues.append("unsupported_brute_force_attribution")
    if any(x in text for x in ("the deletion was successful", "successfully deleted", "data was stolen", "definitely compromised", "confirmed compromise")):
        issues.append("unsupported_success_or_compromise_assertion")
    # Valid ID references alone do not verify natural-language claims.
    return issues


def analyst_guardrail(case, raw_reports):
    baseline_report = demo.baseline(case)
    tier = {"benign": 0, "suspicious": 1, "critical": 2}
    recommended = baseline_report["classification"]
    adjudications = {}
    review_required = recommended != "benign"
    for method in ("llm_only", "rag"):
        item = raw_reports.get(method) or {}
        ai = item.get("prediction")
        issues = item.get("claim_issues", [])
        warnings = list(issues)
        if ai is None or ai == "insufficient_evidence":
            warnings.append("missing_or_abstaining_model_assessment")
        elif ai in tier and tier[ai] < tier[recommended]:
            warnings.append("model_underrates_evidence_based_risk")
        if not item.get("evidence_ids"):
            warnings.append("model_did_not_cite_event_ids")
        if method == "rag" and item.get("retrieved_knowledge_ids") and not item.get("knowledge_ids"):
            warnings.append("retrieval_without_knowledge_citations")
        if warnings:
            review_required = True
        adjudications[method] = {"raw_model_verdict": ai or "unavailable", "flags": sorted(set(warnings))}
    return {
        "evidence_based_triage": recommended,
        "evidence_based_reason": baseline_report["reasoning"],
        "analyst_approval_required": True,  # Never auto-authorize response or dismiss an incident.
        "priority_review": review_required,
        "safeguard": "Model assessments cannot downgrade evidence-based risk. This is not a proof of malicious intent.",
        "model_adjudication": adjudications,
        "factual_findings": observable_findings(case),
    }


def _safe_report(case, method, report, elapsed, allowed_refs):
    if report is None:
        return {"method": method, "prediction": None, "seconds": elapsed,
                "evidence_ids": [], "knowledge_ids": [], "claim_issues": ["model_unavailable"]}
    issues = check_model_claims(report, case)
    return {"method": method, "prediction": report["classification"], "seconds": elapsed,
            "evidence_ids": list(report.get("evidence_ids", [])),
            "knowledge_ids": list(report.get("knowledge_ids", [])),
            "retrieved_knowledge_ids": [x["id"] for x in allowed_refs],
            "model_summary_UNVERIFIED": report.get("summary", ""),
            "model_reasoning_UNVERIFIED": report.get("reasoning", ""),
            "model_suggested_checks_UNVERIFIED": report.get("next_checks", []),
            "claim_issues": issues}


def investigate_case(case, model=demo.MODEL, ai_func=None, root=demo.ROOT):
    """No ground-truth access. `ai_func` allows deterministic offline tests."""
    demo.assert_isolated([case])
    ai_func = ai_func or grounded_ollama
    refs = demo.references(root)
    started = time.monotonic()
    base_report = demo.baseline(case)
    result = {"baseline": _safe_report(case, "baseline", base_report, round(time.monotonic()-started, 4), [])}
    for method in ("llm_only", "rag"):
        selected = demo.pick_refs(refs, case) if method == "rag" else []
        start = time.monotonic()
        try:
            candidate, elapsed = ai_func(case, selected, model)
            demo.validate_ai(candidate, case, selected)
            result[method] = _safe_report(case, method, candidate, elapsed, selected)
        except Exception as exc:
            result[method] = _safe_report(case, method, None, round(time.monotonic()-start, 3), selected)
            result[method]["error"] = f"{type(exc).__name__}: {exc}"
    guardrails = analyst_guardrail(case, result)
    ids = {e["event_id"]: {"wazuh_alert_id": e["wazuh_alert_id"],
                            "wazuh_rule_id": e["wazuh_rule_id"],
                            "wazuh_rule_level": e["wazuh_rule_level"]} for e in case["events"]}
    return {
        "case_id": case["case_id"], "origin": "verified_wazuh_synthetic_alert_records",
        "synthetic": True, "source_evidence_sha256": demo.sha256(case),
        "event_count": len(case["events"]), "events_provenance": ids,
        "observed_actions": [e["action"] for e in case["events"]],
        "results": result, "guardrails": guardrails,
        "no_real_aws_actions_performed": True,
        "not_professional_signoff": "Human security analyst must validate actions and approve remediation.",
    }


def _atomic_save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise FileExistsError(f"Refusing overwrite: {path}")
    tmp = path.with_suffix(".tmp")
    try:
        tmp.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        tmp.replace(path)
    finally:
        if tmp.exists():
            tmp.unlink()


def _is_complete(case, records):
    return len(records) == len(case["events"]) and {a["data"]["sim_event_id"] for a in records} == {x["event_id"] for x in case["events"]}


def execute(alerts, evidence=DEFAULT_EVIDENCE, output=DEFAULT_RESULTS, model=demo.MODEL,
            case_id=None, limit=100, ai_func=None, root=demo.ROOT):
    if limit < 1:
        raise ValueError("limit must be >= 1")
    cases, grouped, audit = load_verified_wazuh(alerts, evidence)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    # Audit is informative and may evolve as Wazuh alerts arrive; safe to update.
    (output / "ingestion_audit.json").write_text(json.dumps(audit, indent=2) + "\n")
    if case_id and case_id not in cases:
        raise ValueError(f"Unknown case ID: {case_id}")
    candidates = [case_id] if case_id else sorted(cases)
    completed = 0
    skipped = 0
    cached = 0
    for cid in candidates:
        records = grouped.get(cid, [])
        if not _is_complete(cases[cid], records):
            print(f"SKIP {cid}: incomplete Wazuh evidence ({len(records)}/{len(cases[cid]['events'])})")
            skipped += 1
            continue
        case = normalise_wazuh_case(cid, records)
        fp = output / "cases" / f"{cid}.json"
        if fp.exists():
            old = json.loads(fp.read_text(encoding="utf-8"))
            if old.get("source_evidence_sha256") != demo.sha256(case):
                raise ValueError(f"Cached Wazuh evidence differs for {cid}; refusing to mix runs")
            print(f"CACHED {cid}: already investigated; not overwriting evidence")
            cached += 1
            continue
        print(f"INVESTIGATING {cid} using {len(records)} verified Wazuh alert records", flush=True)
        row = investigate_case(case, model=model, ai_func=ai_func, root=root)
        _atomic_save(fp, row)
        completed += 1
        print(f"  baseline={row['results']['baseline']['prediction']} \
llm_only={row['results']['llm_only']['prediction'] or 'ERROR'} \
rag={row['results']['rag']['prediction'] or 'ERROR'} \
priority_review={row['guardrails']['priority_review']}", flush=True)
        if completed >= limit:
            break
    status = {"newly_investigated": completed, "cached": cached, "incomplete_skipped": skipped,
              "output": str(output), "source_verified_events": audit["verified_unique_events"],
              "complete_wazuh_cases": audit["complete_cases"]}
    print("RUN STATUS", json.dumps(status))
    return status


def _score(results, truth):
    predictions = [r for r in results if r["case_id"] in truth]
    valid = [r for r in predictions if r.get("prediction") in SEVERITIES]
    correct = sum(r["prediction"] == truth[r["case_id"]] for r in valid)
    def f1_for(label):
        tp = sum(x["prediction"] == label and truth[x["case_id"]] == label for x in valid)
        fp = sum(x["prediction"] == label and truth[x["case_id"]] != label for x in valid)
        fn = sum(x.get("prediction") != label and truth[x["case_id"]] == label for x in predictions)
        p = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        return {"precision": round(p, 4), "recall": round(recall, 4),
                "f1": round(2 * p * recall / (p + recall), 4) if p + recall else 0.0}
    labels = {k: f1_for(k) for k in SEVERITIES}
    return {"total": len(predictions), "valid": len(valid), "correct": correct,
            "failures_or_abstentions": len(predictions)-len(valid),
            "accuracy_on_all": round(correct / len(predictions), 4) if predictions else None,
            "accuracy_on_answered": round(correct / len(valid), 4) if valid else None,
            "per_class": labels,
            "macro_f1": round(statistics.mean(v["f1"] for v in labels.values()), 4),
            "mean_elapsed_s": round(statistics.mean(r.get("seconds", 0) for r in predictions), 3) if predictions else None,
            "confusion_by_true": {label: dict(Counter((r.get("prediction") or "ERROR")
                                           for r in predictions if truth[r["case_id"]] == label))
                                  for label in SEVERITIES}}


def score_cached(evidence=DEFAULT_EVIDENCE, output=DEFAULT_RESULTS):
    """Ground truth opened ONLY here, after predictions were persisted."""
    output = Path(output)
    cached = sorted((output / "cases").glob("SOCSIM-*.json"))
    if not cached:
        raise ValueError("No completed Wazuh-linked investigations. Run 'run' first.")
    rows = [json.loads(p.read_text(encoding="utf-8")) for p in cached]
    case_ids = [r["case_id"] for r in rows]
    if len(case_ids) != len(set(case_ids)):
        raise ValueError("Duplicate case IDs in cached investigations")
    cases, _ = expected_index(evidence)
    for r in rows:
        if r["case_id"] not in cases or not r.get("synthetic") or r.get("origin") != "verified_wazuh_synthetic_alert_records":
            raise ValueError("Invalid synthetic evidence provenance in cached results")
    labels = {t["case_id"]:t["class_label"] for t in demo.read_jsonl(Path(evidence) / "ground_truth_PRIVATE.jsonl")}
    methods = {}
    for method in ("baseline", "llm_only", "rag"):
        predictions = [{"case_id": r["case_id"], **r["results"][method]} for r in rows]
        methods[method] = _score(predictions, labels)
    # The safeguarded decision is explicitly a rule-based HYBRID TRIAGE, not an LLM accuracy claim.
    safeguarded = [{"case_id":r["case_id"], "prediction": r["guardrails"]["evidence_based_triage"]} for r in rows]
    methods["guardrailed_triage_rule_enforced"] = _score(safeguarded, labels)
    methods["guardrailed_triage_rule_enforced"]["mean_elapsed_s"] = None
    audit_path = output / "ingestion_audit.json"
    audit = json.loads(audit_path.read_text()) if audit_path.exists() else {}
    quality = {}
    for name in ("llm_only", "rag"):
        outputs = [r["results"][name] for r in rows]
        valid = [o for o in outputs if o.get("prediction") in SEVERITIES]
        cited = sum(bool(o.get("evidence_ids")) for o in valid)
        with_references = [o for o in valid if o.get("retrieved_knowledge_ids")]
        with_knowledge_citations = sum(bool(o.get("knowledge_ids")) for o in with_references)
        flagged = sum(bool(o.get("claim_issues")) for o in outputs)
        undermined = sum("model_underrates_evidence_based_risk" in
                        r["guardrails"]["model_adjudication"][name]["flags"] for r in rows)
        quality[name] = {
            "valid_output_rate": round(len(valid)/len(rows),4),
            "cited_evidence_when_answered": round(cited/len(valid),4) if valid else None,
            "retrieval_with_knowledge_citation_rate": round(with_knowledge_citations/len(with_references),4) if with_references else None,
            "reports_flagged_by_conservative_claim_checker": flagged,
            "cases_with_risk_underrating": undermined,
        }
    quality["analyst_workload_proxy"] = {
        "priority_review_cases": sum(r["guardrails"]["priority_review"] for r in rows),
        "priority_review_fraction": round(sum(r["guardrails"]["priority_review"] for r in rows)/len(rows),4),
        "human_review_time_observed": False,
        "note": "This is a policy-based review proxy, not a measured analyst time saving.",
    }
    meta = {
        "study": "Wazuh-linked synthetic SOC paired comparison",
        "sample_cases": len(rows), "simulated_case_population": 100,
        "model_experiment": "New Wazuh-event prompt; not directly comparable to earlier six-case soc_demo comparison",
        "model_input_notes": "Model receives verified event fields; Wazuh rule severity and simulation truth labels withheld from prompt",
        "source_of_predictions": "Wazuh alerts verified against source events",
        "evaluation_truth_source": "isolated synthetic ground_truth_PRIVATE.jsonl (read only during scoring)",
        "selected_case_ids": sorted(case_ids),
        "ingestion_audit": audit,
        "methods": methods,
        "quality_and_efficiency_proxies": quality,
        "report_truthfulness": "Automated factual summaries use observed actions and policy rules, not unverified LLM text.",
        "limitations": ["Synthetic case patterns repeat 10 templates; no statistical generalization to live cloud compromise.",
                        "Baseline and safeguards share rule patterns with synthetic scenario construction.",
                        "Raw LLM outputs may be wrong or fail; do not present safeguard scores as AI performance.",
                        "Missing Wazuh alerts are excluded rather than fabricated.",
                        "No real attacks, cloud calls, autonomous response, or final human approval occurred."],
    }
    (output / "evaluation_PRIVATE.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    md = render_executive(rows, meta)
    (output / "EXECUTIVE_REPORT_REVIEW_REQUIRED.md").write_text(md, encoding="utf-8")
    (output / "EXECUTIVE_REPORT_REVIEW_REQUIRED.html").write_text(render_html(rows, meta), encoding="utf-8")
    print("SCORED", len(rows), "cases; baseline", methods["baseline"]["accuracy_on_all"],
          "llm", methods["llm_only"]["accuracy_on_all"], "rag", methods["rag"]["accuracy_on_all"])
    print("EXECUTIVE", output / "EXECUTIVE_REPORT_REVIEW_REQUIRED.md")
    print("VISUAL REPORT", output / "EXECUTIVE_REPORT_REVIEW_REQUIRED.html")
    return meta


def render_executive(rows, metrics):
    def clean(text):
        return str(text).replace("|", "/").replace("\n", " ")
    lines = ["# Executive Security Investigation — Wazuh-Linked Research Prototype", "",
             "**ACADEMIC SIMULATION — NO REAL AWS ATTACKS. ANALYST REVIEW REQUIRED.**", "",
             "## Business decision summary", "",
             f"{len(rows)} synthetic cases were investigated using **actual Wazuh alert records** linked to our generated event IDs. "
             "We compared a rule-based baseline, a local unmodified Qwen LLM, and Qwen with retrieved security references. "
             "The AI's own verdicts are displayed separately from evidence-based triage. No automated action was performed.", "",
             "| Method | Correct / cases | Output failures/abstentions | Accuracy (all cases) | Mean runtime |",
             "|---|---:|---:|---:|---:|"]
    for name in ("baseline", "llm_only", "rag", "guardrailed_triage_rule_enforced"):
        m = metrics["methods"][name]
        mean = f"{m['mean_elapsed_s']:.2f}s" if m.get("mean_elapsed_s") is not None else "n/a"
        lines.append(f"| {name} | {m['correct']}/{m['total']} | {m['failures_or_abstentions']} | "
                     f"{m['accuracy_on_all']:.1%} | {mean} |")
    lines.extend(["", "## Explainability, reliability and workload proxies", "",
                  "These values measure output validity, citations and rule-based review demand. They do **not** establish real analyst time savings.", "",
                  "| Indicator | LLM-only | RAG |", "|---|---:|---:|"])
    quality = metrics["quality_and_efficiency_proxies"]
    for field, label in (("valid_output_rate", "Valid classified output"),
                         ("cited_evidence_when_answered", "Evidence citations on valid answers"),
                         ("reports_flagged_by_conservative_claim_checker", "Conservative factual-claim flags"),
                         ("cases_with_risk_underrating", "Cases underrating rule-based risk")):
        def fmt(v):
            return "n/a" if v is None else (f"{v:.1%}" if isinstance(v, float) else str(v))
        lines.append(f"| {label} | {fmt(quality['llm_only'][field])} | {fmt(quality['rag'][field])} |")
    r = quality["rag"]["retrieval_with_knowledge_citation_rate"]
    lines.extend(["", f"RAG retrieved-reference citation rate (when reference retrieval was available): {r:.1%}." if r is not None else "No eligible RAG retrieval citation denominator.",
                  f"Priority analyst review queue: {quality['analyst_workload_proxy']['priority_review_cases']}/{len(rows)} cases. "
                  "No human review time was measured.", "",
                  "**Interpretation:** Rule-enforced triage is a safety control, not evidence that the AI improved. "
                  "This is not a real-world accuracy estimate. The source scenario generator and baseline share design assumptions.", "",
                  "## Same-incident Wazuh-to-AI comparison", "",
                  "| Wazuh case ID | Events | Rule triage | Raw LLM | Raw RAG | Guardrail priority review |",
                  "|---|---:|---|---|---|---|"])
    for r in rows:
        res = r["results"]
        lines.append(f"| {r['case_id']} | {r['event_count']} | {res['baseline']['prediction']} | "
                     f"{res['llm_only'].get('prediction') or 'FAILED'} | {res['rag'].get('prediction') or 'FAILED'} | "
                     f"{'YES' if r['guardrails']['priority_review'] else 'Routine analyst sign-off'} |")
    lines.extend(["", "## Evidence-checked incident briefs", "",
                  "The summaries below describe *observed API event records*; they do not claim an operation succeeded or a genuine compromise occurred. "
                  "Raw LLM explanations are deliberately **not** promoted to trusted factual narrative.", ""])
    for r in rows:
        lines.extend([f"### {r['case_id']} — {r['guardrails']['evidence_based_triage'].upper()} TRIAGE", "",
                      f"**Observed actions:** {', '.join(map(clean, r['observed_actions']))}.",
                      f"**Wazuh source:** {r['event_count']} verified alerts, each with a matching simulated event ID.",
                      f"**Raw LLM / RAG:** {r['results']['llm_only'].get('prediction') or 'FAILED'} / "
                      f"{r['results']['rag'].get('prediction') or 'FAILED'}. "
                      "These assessments may be incorrect.", ""])
        for finding in r["guardrails"]["factual_findings"]:
            ids = ", ".join(finding["evidence_ids"])
            lines.extend([f"**{clean(finding['title'])}** — {clean(finding['observation'])}",
                          f"- Potential business exposure: {clean(finding['business_risk'])}",
                          f"- Evidence IDs: `{ids}`",
                          "- Recommended human checks: " + "; ".join(map(clean, finding["recommended_checks"])), ""])
        flagged = []
        for method in ("llm_only", "rag"):
            details = r["guardrails"]["model_adjudication"][method]
            if details["flags"]:
                flagged.append(method + ": " + ", ".join(details["flags"]))
        lines.extend(["**QA flags:** " + ("; ".join(flagged) if flagged else "No predefined issues detected; natural-language claims are still unverified."),
                      "**Decision:** Analyst review before any remediation or release.", ""])
    lines.extend(["## Provenance and research limitations", "",
                  "- Events were created for simulation. Wazuh ingested the marked synthetic logs; an indexed alert is not independent proof of wrongdoing.",
                  "- Matching the Wazuh event ID to source events is a *consistency* check, not independent attack truth.",
                  "- Real-world cloud attack effectiveness, true compromise outcomes, and response-time improvements were not demonstrated by this dataset.",
                  "- The separately stored synthetic labels were accessed only for post-investigation scoring.",
                  "- A 1.5B-parameter pretrained local Qwen model was used; no fine-tuning was performed.",
                  "- API event names and synthetic resource metadata may simplify or misrepresent real AWS conditions.",
                  "- Human approval is mandatory; no autonomous protective actions or AWS operations were executed.", ""])
    return "\n".join(lines)


def watch(alerts, evidence=DEFAULT_EVIDENCE, output=DEFAULT_RESULTS, case_id=None,
          model=demo.MODEL, interval=5.0, once=False, max_cases=1, ai_func=None, root=demo.ROOT):
    """Simple automatic Wazuh alert poller; never injects or changes events."""
    print("POLLING Wazuh alert records; waiting for complete case evidence; Ctrl+C to stop.", flush=True)
    total = 0
    while True:
        status = execute(alerts, evidence=evidence, output=output, case_id=case_id,
                         model=model, limit=max_cases-total, ai_func=ai_func, root=root)
        total += status["newly_investigated"]
        if once or total >= max_cases:
            return total
        time.sleep(max(1.0, interval))


def main():
    parser = argparse.ArgumentParser(description="Evidence-verified Wazuh -> AI research pipeline (simulation only)")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("audit", "run", "watch", "evaluate"):
        p = sub.add_parser(name)
        p.add_argument("--evidence", type=Path, default=DEFAULT_EVIDENCE)
        p.add_argument("--out", type=Path, default=DEFAULT_RESULTS)
        if name != "evaluate":
            p.add_argument("--alerts", required=True, type=Path,
                           help="Actual Wazuh alerts.json or folder containing Wazuh archived JSON alerts")
        if name in ("run", "watch"):
            p.add_argument("--case", help="One SOCSIM-### case; otherwise all complete cases")
            p.add_argument("--model", default=demo.MODEL)
            p.add_argument("--limit", type=int, default=100 if name == "run" else 1)
        if name == "watch":
            p.add_argument("--interval", type=float, default=5.0)
            p.add_argument("--once", action="store_true", help="Process available matching case(s) once and exit")
    args = parser.parse_args()
    if args.command == "audit":
        _, _, result = load_verified_wazuh(args.alerts, args.evidence)
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "ingestion_audit.json").write_text(json.dumps(result, indent=2)+"\n")
        print(json.dumps(result, indent=2))
    elif args.command == "run":
        execute(args.alerts, args.evidence, args.out, args.model, args.case, args.limit)
    elif args.command == "watch":
        watch(args.alerts, args.evidence, args.out, args.case, args.model, args.interval, args.once, args.limit)
    elif args.command == "evaluate":
        score_cached(args.evidence, args.out)


if __name__ == "__main__":
    main()
