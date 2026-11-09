"""Small-model prompting for Wazuh-sourced evidence; no labels or real AWS calls.

This is a new prompt configuration for the Wazuh-linked experiment. Results are
not directly comparable with earlier soc_demo.compare() runs because the input
source and prompt differ. No finetuning of the local pretrained model occurs.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from . import soc_demo as demo


JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "classification": {"type": "string", "enum": ["benign", "suspicious", "critical", "insufficient_evidence"]},
        "summary": {"type": "string"},
        "reasoning": {"type": "string"},
        "evidence_ids": {"type": "array", "items": {"type": "string"}},
        "knowledge_ids": {"type": "array", "items": {"type": "string"}},
        "next_checks": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["classification", "summary", "reasoning", "evidence_ids", "knowledge_ids", "next_checks"],
}


def _compact_evidence(case):
    return [{
        "id": e["event_id"], "action": e["action"], "service": e["event_source"],
        "error": e.get("error_code") or "not_reported",
        "actor": e["actor"], "ip": e["source_ip"],
        "resource": e["resources"][0] if e.get("resources") else "not_reported",
    } for e in case["events"]]


def _prompt(case, refs):
    allowed = [e["event_id"] for e in case["events"]]
    reference_ids = [x["id"] for x in refs]
    system = (
        "You are a cloud SOC analyst. Interpret a SYNTHETIC security log, not an active attack. "
        "Describe only recorded API actions. An API event and Wazuh rule match DO NOT prove successful execution, intent, breach, or data loss. "
        "Interpret action semantics correctly: StopLogging and DeleteTrail affect CloudTrail audit trails, NOT S3 buckets. "
        "FailedAuthentication on ConsoleLogin means login FAILED. Repeated failed logins are worth investigating. "
        "Privilege/key changes and disabling audit logs are high-impact; routine resource lookups may be benign. "
        "Classify urgency as benign, suspicious, critical, or insufficient_evidence. "
        "Use critical for high-impact operations that require urgent investigation, even when success is unverified. "
        "Write concise, nontechnical English. Do not call anything a confirmed attack. "
        "Return only JSON with exactly these keys: classification, summary, reasoning, evidence_ids, knowledge_ids, next_checks. "
        "Evidence IDs and knowledge IDs MUST be copied exactly from allowed lists, not invented. "
        "If no references are available, knowledge_ids must be []. Keep summary and reasoning under 35 words each, next_checks 1-2 short actions."
    )
    message = {
        "task": "Triage these Wazuh-decoded synthetic cloud API events without seeing Wazuh rule severity or the simulation truth labels; provide an evidence-grounded explanation.",
        "events": _compact_evidence(case),
        "allowed_event_ids": allowed,
        "retrieved_knowledge": [{"id": r["id"], "title": r.get("title", ""),
                                 "summary": r.get("summary", "")[:400]} for r in refs],
        "allowed_knowledge_ids": reference_ids,
        "important": "Do not use an unattested outcome as fact; do not conflate AWS services.",
    }
    return system, json.dumps(message, separators=(",", ":"), ensure_ascii=False)


def grounded_ollama(case, refs, model=demo.MODEL, endpoint=demo.OLLAMA):
    demo.assert_isolated([case])
    system, user = _prompt(case, refs)
    started = time.monotonic()
    last_error = None
    for attempt in range(2):
        # Some Ollama versions support schema mode; fallback to JSON mode.
        format_spec = JSON_SCHEMA if attempt == 0 else "json"
        prompt = user if attempt == 0 else user + "\nOutput short, complete JSON only. Use only the exact evidence IDs."
        body = {
            "model": model, "stream": False, "format": format_spec,
            "options": {"temperature": 0, "num_predict": 750},
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": prompt}],
        }
        try:
            req = urllib.request.Request(endpoint, data=json.dumps(body).encode("utf-8"),
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=75) as resp:
                envelope = json.load(resp)
            if envelope.get("done_reason") == "length":
                raise ValueError("Model answer truncated")
            content = envelope["message"]["content"].strip()
            if content.startswith("```"):
                content = content.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
            report = json.loads(content)
            demo.validate_ai(report, case, refs)
            return report, round(time.monotonic()-started, 3)
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError,
                ValueError, TypeError, KeyError) as exc:
            last_error = f"{type(exc).__name__}: {exc}"
    raise RuntimeError(f"Model produced no validated report after 2 attempts: {last_error}")
