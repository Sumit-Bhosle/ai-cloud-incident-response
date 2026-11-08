"""Three-arm CloudTrail SOC investigation comparison. Python standard library only.

IMPORTANT: Label lookup is restricted to sample selection and post-inference scoring.
All investigator inputs are derived exclusively from cases.jsonl.
"""
from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import random
import statistics
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[2]
DEV = ROOT / "data/lab_evidence/cloudtrail/development"
OUT = DEV / "benchmarks/comparison_03"
OLLAMA_URL = "http://127.0.0.1:11434/api/chat"
MODEL = "qwen2.5:1.5b"
MODES = ("baseline", "llm_only", "rag")
FORBIDDEN = {"attack_associated", "attack_event_count", "benign_event_count", "attack_name", "scenario_names", "should_sample", "ground_truth", "label"}


def read_jsonl(path):
    with Path(path).open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def assert_no_labels(value):
    if isinstance(value, dict):
        leaked = FORBIDDEN.intersection(value)
        if leaked:
            raise ValueError(f"Label leakage in investigator data: {sorted(leaked)}")
        for nested in value.values():
            assert_no_labels(nested)
    elif isinstance(value, list):
        for nested in value:
            assert_no_labels(nested)


def select_cases(cases, truth, seed=42):
    """Select 3 scenario-stratified attack cases and 3 benign controls.

    Labels used solely for experimental sampling, never model inputs.
    """
    ids = {c["case_id"]: c for c in cases}
    if len(ids) != len(cases):
        raise ValueError("Duplicate case IDs")
    if ids.keys() != truth.keys():
        raise ValueError("Case/ground-truth mismatch")
    rng = random.Random(seed)
    scenarios = sorted({s for v in truth.values() for s in v.get("scenario_names", [])})
    selected = []
    covered = set()
    for scenario in scenarios:
        eligible = [c for c in cases if scenario in truth[c["case_id"]].get("scenario_names", []) and c["case_id"] not in covered]
        if not eligible:
            continue
        # Prefer multi-event but reasonably sized cases; large/one-event cases remain eligible.
        rng.shuffle(eligible)
        eligible.sort(key=lambda c: (0 if 2 <= len(c["events"]) <= 20 else 1 if len(c["events"]) == 1 else 2, len(c["events"])))
        chosen = eligible[0]
        selected.append(chosen)
        covered.add(chosen["case_id"])
    if not selected:
        raise ValueError("No attack-associated development cases available")
    benign = [c for c in cases if not truth[c["case_id"]]["attack_associated"]]
    rng.shuffle(benign)
    for group in (lambda n: 2 <= n <= 20, lambda n: n == 1, lambda n: n > 20):
        choices = [c for c in benign if group(len(c["events"])) and c["case_id"] not in covered]
        if choices:
            selected.append(choices[0])
            covered.add(choices[0]["case_id"])
    # Fill remaining benign slots even when a size category is absent.
    remaining = [c for c in benign if c["case_id"] not in covered]
    for c in remaining:
        if sum(not truth[x["case_id"]]["attack_associated"] for x in selected) >= 3:
            break
        selected.append(c)
        covered.add(c["case_id"])
    if len(selected) < 4:
        raise ValueError("Insufficient attack and benign cases for comparison")
    for c in selected:
        assert_no_labels(c)
    return selected


def case_view(case, max_events=10):
    """Same deterministic evidence view for every investigation method."""
    assert_no_labels(case)
    events = case["events"]
    if not events:
        raise ValueError("Empty case")
    # Protect CPU context, retain activity diversity + chronological edges.
    ordered = sorted(events, key=lambda e: (str(e.get("timestamp_utc", "")), str(e.get("event_id", ""))))
    chosen = []
    seen = set()
    for e in ordered:
        action = str(e.get("action", ""))
        if action not in seen and len(chosen) < max_events:
            chosen.append(e)
            seen.add(action)
    if len(chosen) < max_events:
        for e in [ordered[0], ordered[-1], *ordered]:
            if len(chosen) >= max_events:
                break
            if e not in chosen:
                chosen.append(e)
    chosen = sorted(chosen, key=lambda e: (str(e.get("timestamp_utc", "")), str(e.get("event_id", ""))))
    # Reduce large request_context/resources into bounded model-visible snippets.
    bounded = []
    for original in chosen:
        bounded.append({
            key: (json.dumps(original[key], ensure_ascii=False)[:350]
                  if key in ("request_context", "resources") and original.get(key) is not None
                  else original.get(key))
            for key in ("event_id", "timestamp_utc", "action", "actor", "source_ip", "event_source", "aws_region", "error_code", "request_context", "resources")
            if key in original
        })
    summary = {
        "action_counts_all_events": dict(Counter(str(e.get("action", "")) for e in events).most_common(20)),
        "services_all_events": dict(Counter(str(e.get("event_source", "")) for e in events).most_common(10)),
        "distinct_actors": len({str(e.get("actor")) for e in events}),
        "distinct_source_ips": len({str(e.get("source_ip")) for e in events}),
        "events_with_error_code": sum(bool(e.get("error_code")) for e in events),
        "earliest_timestamp": ordered[0].get("timestamp_utc"),
        "latest_timestamp": ordered[-1].get("timestamp_utc"),
    }
    view = {"case_id": case["case_id"], "events_total": len(events), "events_presented": len(chosen),
            "evidence_truncated": len(chosen) < len(events), "summary": summary, "events": bounded}
    assert_no_labels(view)
    return view


def baseline(view):
    """Transparent traditional detection rules, not ML and not proof of compromise."""
    actions = view["summary"]["action_counts_all_events"]
    reasons = []
    get_count = sum(count for action, count in actions.items() if action in {"GetObject", "ListObjects", "ListObjectsV2"})
    delete_count = sum(count for action, count in actions.items() if action in {"DeleteObject", "DeleteBucket"})
    if get_count >= 20:
        reasons.append(f"High-volume S3 reads/listings: {get_count} events")
    if delete_count >= 20:
        reasons.append(f"High-volume S3 deletes: {delete_count} events")
    sensitive = {"CreateAccessKey", "PutUserPolicy", "AttachUserPolicy", "CreateUser", "AssumeRole", "GetFederationToken"}
    hits = sorted(set(actions).intersection(sensitive))
    if hits:
        reasons.append("Sensitive IAM/STS operations: " + ", ".join(hits))
    if any("anonymous" in str(e.get("actor", "")).lower() for e in view["events"]):
        reasons.append("Anonymous identity observed in presented events")
    positive = bool(reasons)
    return {"summary": "Rule triggers: " + "; ".join(reasons) if positive else "No configured baseline detection rule triggered.",
            "classification": "suspicious" if positive else "benign",
            "reasoning": "; ".join(reasons) if reasons else "Negative baseline result means no configured rule matched; it does not prove safety.",
            "evidence_ids": [e["event_id"] for e in view["events"][:3]] if reasons else [],
            "next_checks": ["Confirm actor authorization, affected resources, and surrounding CloudTrail events."],
            "knowledge_ids": []}


def reference_docs(root=ROOT):
    refs = []
    for filename in ("security_references.json", "cloudtrail_guidance.json"):
        p = root / "data/knowledge_base" / filename
        if not p.exists():
            continue
        obj = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(obj, list):
            entries = obj
        elif isinstance(obj, dict):
            entries = next((v for v in obj.values() if isinstance(v, list)), [])
        else:
            entries = []
        for i, item in enumerate(entries):
            if isinstance(item, dict):
                key = str(item.get("id") or item.get("knowledge_id") or item.get("reference_id") or f"{filename}-{i}")
                text = json.dumps(item, ensure_ascii=False)
                refs.append({"id": key, "text": text[:650]})
    return refs


def select_knowledge(view, refs, max_items=3):
    from re import findall
    tokens = set(findall(r"[a-zA-Z]{3,}", json.dumps(view["summary"]).lower()))
    scored = []
    for doc in refs:
        d = set(findall(r"[a-zA-Z]{3,}", doc["text"].lower()))
        scored.append((len(tokens & d), doc["id"], doc))
    scored.sort(key=lambda x: (-x[0], x[1]))
    return [x[2] for x in scored[:max_items] if x[0] > 0] or [x[2] for x in scored[:1]]


REPORT_SCHEMA = {"type": "object", "properties": {
    "summary": {"type": "string", "maxLength": 220},
    "classification": {"type": "string", "enum": ["suspicious", "benign", "insufficient_evidence"]},
    "reasoning": {"type": "string", "maxLength": 350},
    "evidence_ids": {"type": "array", "items": {"type": "string"}, "maxItems": 3},
    "next_checks": {"type": "array", "items": {"type": "string", "maxLength": 140}, "maxItems": 2},
    "knowledge_ids": {"type": "array", "items": {"type": "string"}, "maxItems": 2}},
    "required": ["summary", "classification", "reasoning", "evidence_ids", "next_checks", "knowledge_ids"],
    "additionalProperties": False}


class ModelOutputError(ValueError):
    """The model returned incomplete/invalid structured output. Never score it."""


def _request_qwen(view, refs, mode, model, endpoint, timeout, predict_tokens):
    """One generation request. Keep identical prompts/evidence across LLM/RAG."""
    shared = (
        "You are a cautious SOC analyst examining AWS CloudTrail evidence. "
        "Classify as suspicious, benign, or insufficient_evidence. "
        "Do not equate an absent errorCode with confirmed success. "
        "Never claim an attack solely from repeated management API calls. "
        "Distinguish observed evidence from hypotheses. "
        "Cite ONLY event_id values in events and knowledge IDs in retrieved_references. "
        "If retrieved_references is empty, knowledge_ids MUST be an empty list []. "
        "Do not invent source fields, citations, or incident certainty. "
        "If evidence does not justify a conclusion use insufficient_evidence. "
        "Return ONLY a compact JSON object with all six required fields: "
        "summary, classification, reasoning, evidence_ids, next_checks, knowledge_ids. "
        "Keep summary under 30 words, reasoning under 45 words, at most 3 evidence IDs, "
        "at most 2 knowledge IDs, and at most 2 short next_checks. No markdown."
    )
    context = refs if mode == "rag" else []
    content = json.dumps({"investigation_evidence": view, "retrieved_references": context}, ensure_ascii=False)
    # Strict citation contract reflects ONLY references provided to this method.
    # In LLM-only condition no retrieval occurs: knowledge_ids must be [].
    # Prediction choices/evidence/prompt are unchanged between conditions.
    allowed_knowledge_ids = sorted({str(r["id"]) for r in context})
    schema = deepcopy(REPORT_SCHEMA)
    knowledge_prop = schema["properties"]["knowledge_ids"]
    knowledge_prop["maxItems"] = min(2, len(allowed_knowledge_ids))
    if allowed_knowledge_ids:
        knowledge_prop["items"] = {"type": "string", "enum": allowed_knowledge_ids}
    payload = {"model": model, "stream": False, "format": schema,
               "options": {"temperature": 0, "seed": 42, "num_predict": predict_tokens, "num_ctx": 4096},
               "messages": [{"role": "system", "content": shared}, {"role": "user", "content": content}]}
    request = Request(endpoint, data=json.dumps(payload).encode("utf-8"), headers={"Content-Type": "application/json"})
    with urlopen(request, timeout=timeout) as response:
        outer = json.load(response)
    if not isinstance(outer, dict) or not isinstance(outer.get("message"), dict):
        raise ModelOutputError("Invalid Ollama response envelope")
    response_content = outer["message"].get("content", "")
    done_reason = outer.get("done_reason", "unknown")
    token_count = outer.get("eval_count", "unknown")
    if not isinstance(response_content, str):
        raise ModelOutputError("Model did not return text")
    if done_reason == "length":
        raise ModelOutputError(f"Output token limit reached (done_reason=length, eval_count={token_count}, num_predict={predict_tokens})")
    try:
        result = json.loads(response_content)
    except json.JSONDecodeError as exc:
        raise ModelOutputError(
            f"Invalid model JSON: {exc.msg} at char {exc.pos}; "
            f"done_reason={done_reason}, eval_count={token_count}, num_predict={predict_tokens}"
        ) from exc
    if not isinstance(result, dict) or set(result) != set(REPORT_SCHEMA["required"]):
        raise ModelOutputError("Incomplete model report or unexpected fields")
    if not all(isinstance(result[key], str) for key in ("summary", "classification", "reasoning")):
        raise ModelOutputError("Invalid report text fields")
    if result["classification"] not in ("suspicious", "benign", "insufficient_evidence"):
        raise ModelOutputError("Unsupported classification")
    if not all(isinstance(result[key], list) and all(isinstance(x, str) for x in result[key]) for key in ("evidence_ids", "next_checks", "knowledge_ids")):
        raise ModelOutputError("Invalid report list fields")
    if len(result["evidence_ids"]) > 3 or len(result["knowledge_ids"]) > 2 or len(result["next_checks"]) > 2:
        raise ModelOutputError("Report exceeds requested list limits")
    evidence_ids = {e["event_id"] for e in view["events"]}
    if not set(result["evidence_ids"]).issubset(evidence_ids):
        raise ModelOutputError("Unknown evidence citation")
    knowledge_ids = {r["id"] for r in context}
    if not set(result["knowledge_ids"]).issubset(knowledge_ids):
        raise ModelOutputError("Unknown or unprovided knowledge citation")
    return result


def call_qwen(view, refs, mode, model=MODEL, endpoint=OLLAMA_URL, timeout=240):
    """One retry for incomplete JSON; never invent or silently fix predictions."""
    if mode not in ("llm_only", "rag"):
        raise ValueError(f"Unknown AI comparison mode: {mode}")
    failures = []
    for predict_tokens in (900, 1500):
        try:
            return _request_qwen(view, refs, mode, model, endpoint, timeout, predict_tokens)
        except ModelOutputError as exc:
            failures.append(str(exc))
        except HTTPError as exc:
            # Ollama may occasionally return a transient server error.
            # Never invent a report; retry the same request once.
            if exc.code not in (500, 502, 503, 504):
                raise
            failures.append(f"Ollama HTTP {exc.code}")
            time.sleep(1)
    raise ModelOutputError("Model failed two structured-output attempts; " + " | ".join(failures))


def metrics(rows):
    answered = [r for r in rows if r["prediction"] in ("suspicious", "benign")]
    tp = sum(r["true_attack"] and r["prediction"] == "suspicious" for r in answered)
    fp = sum(not r["true_attack"] and r["prediction"] == "suspicious" for r in answered)
    tn = sum(not r["true_attack"] and r["prediction"] == "benign" for r in answered)
    fn = sum(r["true_attack"] and r["prediction"] == "benign" for r in answered)
    def div(a, b): return round(a / b, 4) if b else None
    precision = div(tp, tp + fp)
    recall = div(tp, tp + fn)
    f1 = div(2 * tp, 2 * tp + fp + fn)
    return {"total_selected": len(rows), "answered": len(answered), "abstained": len(rows) - len(answered),
            "reports_with_evidence_citations": sum(bool(r.get("has_citation")) for r in rows),
            "reports_with_knowledge_citations": sum(bool(r.get("has_knowledge_citation")) for r in rows),
            "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
            "selective_precision": precision, "selective_recall": recall, "selective_f1": f1,
            "mean_inference_seconds": round(statistics.mean(r["seconds"] for r in rows), 2) if rows else None}


def run(cases, truth, output_dir, model=MODEL, max_events=10, only_prepare=False):
    selected = select_cases(cases, truth)
    output_dir.mkdir(parents=True, exist_ok=True)
    write_json(output_dir / "selection_audit_PRIVATE.json", [{"case_id": c["case_id"], "scenario_names": truth[c["case_id"]].get("scenario_names", []), "attack_associated": truth[c["case_id"]]["attack_associated"], "event_count": len(c["events"])} for c in selected])
    write_json(output_dir / "manifest.json", {"model": model, "method_names": MODES,
        "selected_cases": [c["case_id"] for c in selected], "sample_design": "3 scenario-stratified development cases plus up to 3 benign controls; exploratory, not representative", "max_detailed_events": max_events, "generation_settings": {"temperature": 0, "seed": 42, "num_ctx": 4096, "num_predict": 900, "retry_num_predict": 1500, "max_attempts": 2, "knowledge_id_schema": "bounded to retrieved IDs", "transient_http_retry": True}})
    if only_prepare:
        return {"cases": len(selected), "case_ids": [c["case_id"] for c in selected]}
    refs = reference_docs()
    if not refs:
        raise RuntimeError("No knowledge-base entries found: RAG cannot be evaluated without retrieved references")
    print(f"Knowledge-base references available: {len(refs)}", flush=True)
    table = {mode: [] for mode in MODES}
    for i, case in enumerate(selected, 1):
        view = case_view(case, max_events)
        digest = hashlib.sha256(json.dumps(case, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        print(f"\nCASE {i}/{len(selected)}: {case['case_id']} ({view['events_presented']}/{view['events_total']} details)", flush=True)
        for mode in MODES:
            retrieved = select_knowledge(view, refs) if mode == "rag" else []
            start = time.perf_counter()
            try:
                report = baseline(view) if mode == "baseline" else call_qwen(view, retrieved, mode, model=model)
                error = None
            except Exception as ex:
                report = None
                error = f"{type(ex).__name__}: {ex}"
            elapsed = time.perf_counter() - start
            artifact = {"case_id": case["case_id"], "case_sha256": digest, "method": mode, "model": "deterministic-rules" if mode == "baseline" else model,
                        "events_total": view["events_total"], "events_presented": view["events_presented"], "retrieved_knowledge_ids": [x["id"] for x in retrieved],
                        "inference_seconds": round(elapsed, 2), "report": report, "error": error,
                        "validation_scope": "citation ID membership only; claims not fully verified"}
            write_json(output_dir / mode / f"{case['case_id']}.json", artifact)
            # Ground truth is accessed ONLY here, AFTER the prediction has been generated.
            table[mode].append({"case_id": case["case_id"], "true_attack": bool(truth[case["case_id"]]["attack_associated"]),
                "prediction": report["classification"] if report else "error", "seconds": elapsed,
                "has_citation": bool(report and report["evidence_ids"]),
                "has_knowledge_citation": bool(report and report["knowledge_ids"])})
            print(f"  {mode:9} {artifact['report']['classification'] if report else 'ERROR'} {elapsed:.1f}s", flush=True)
    results = {mode: metrics([r for r in rows if r["prediction"] != "error"]) for mode, rows in table.items()}
    for mode, rows in table.items():
        results[mode]["failures"] = sum(r["prediction"] == "error" for r in rows)
        results[mode]["selected_total_including_failures"] = len(rows)
    result = {"status": "development pilot; scenario-stratified, not representative", "comparison_cases": [x["case_id"] for x in selected],
              "methods": results, "per_case_PRIVATE": table,
              "limitations": ["Not a population accuracy estimate", "Case correlation is heuristic", "Some input cases are truncated but full-case action counts are shown", "No human-time savings measured", "Citation membership is not claim verification"]}
    write_json(output_dir / "comparison_metrics_PRIVATE.json", result)
    print("\n===== THREE-METHOD COMPARISON =====")
    for mode, data in results.items():
        print(mode, data)
    print("SAVED:", output_dir)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--prepare-only", action="store_true")
    p.add_argument("--model", default=MODEL)
    p.add_argument("--max-events", type=int, default=10)
    args = p.parse_args()
    if not 1 <= args.max_events <= 100:
        p.error("--max-events must be 1..100")
    cases = read_jsonl(DEV / "cases.jsonl")
    truth_rows = read_jsonl(DEV / "case_ground_truth.jsonl")
    truth = {r["case_id"]: r for r in truth_rows}
    if len(truth) != len(truth_rows):
        raise ValueError("Duplicate truth IDs")
    result = run(cases, truth, OUT, model=args.model, max_events=args.max_events, only_prepare=args.prepare_only)
    print(json.dumps(result if args.prepare_only else {"completed": True, "output": str(OUT)}, indent=2))


if __name__ == "__main__":
    main()
