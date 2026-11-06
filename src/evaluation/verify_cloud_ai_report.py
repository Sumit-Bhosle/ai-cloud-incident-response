"""Phase 100: conservative, deterministic review of a saved CloudTrail AI report.

Checks provenance, format, citation membership, a few objectively checkable
statements, and builds an independently derived evidence-fact ledger. This is
NOT a general natural-language factual verifier or a detection-accuracy test.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
from collections import Counter

from jsonschema import Draft202012Validator

from src.investigation.cloud_case_investigator import (
    CASES, KNOWLEDGE, REPORTS, ROOT, SCHEMA, make_payload, no_labels,
    select_references,
)

CASE_ID_PATTERN = re.compile(r"CLOUD-DEV-CASE-[0-9a-f]{16}\Z")

# A limited, explicitly documented ruleset. Do not treat a rule-free report
# as fully fact-checked: most free-text statements require human examination.
MISSING_ERROR_SUCCESS = [
    re.compile(
        r"\b(?:absence|lack|missing|no|without)\b[^.]{0,130}"
        r"\b(?:error\s*code|errorcode|errors?)\b[^.]{0,130}"
        r"\b(?:success(?:ful(?:ly)?)?|succeed(?:ed)?|completed)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:success(?:ful(?:ly)?)?|succeed(?:ed)?)\b[^.]{0,130}"
        r"\b(?:without|no|lack|absence|missing)\b[^.]{0,90}"
        r"\b(?:error\s*code|errorcode|errors?)\b",
        re.IGNORECASE,
    ),
]

IP_ABSENCE = re.compile(
    r"\b(?:source\s*ip|ip\s*address)\b.{0,170}"
    r"\b(?:not\s+(?:provided|available|recorded|present)|missing|unknown)\b",
    re.IGNORECASE,
)

CONFIRMED_COMPROMISE = re.compile(
    r"\b(?:confirmed\s+(?:compromise|attack|intrusion|exfiltration)|"
    r"proves?\s+(?:an?\s+)?(?:attack|compromise|exfiltration))\b",
    re.IGNORECASE,
)


def load_case(case_id, path=CASES):
    """Look up exactly one existing case, never a ground-truth file."""
    if not CASE_ID_PATTERN.fullmatch(case_id):
        raise ValueError("Invalid development case ID")
    matches = []
    with path.open(encoding="utf-8") as source:
        for line in source:
            if line.strip():
                case = json.loads(line)
                if case.get("case_id") == case_id:
                    matches.append(case)
    if len(matches) != 1:
        raise ValueError("Expected exactly one matching development case")
    no_labels(matches[0])
    return matches[0]


def evidence_ledger(case, payload):
    """Facts recomputed from case evidence, not written by the LLM."""
    source_events = case["events"]
    shown = payload["evidence_events"]
    by_action = {}
    for event in source_events:
        by_action.setdefault(event["action"], []).append(event["event_id"])

    return {
        "scope": "normalized CloudTrail development evidence; not attack ground truth",
        "case_event_count": len(source_events),
        "events_presented_to_model": len(shown),
        "model_evidence_truncated": payload["evidence_is_truncated"],
        "action_counts_from_full_case": [
            {
                "action": action,
                "count": len(ids),
                "example_evidence_ids": ids[:12],
                "example_ids_truncated": len(ids) > 12,
            }
            for action, ids in sorted(by_action.items())
        ],
        "observed_event_fields": [
            {
                "evidence_id": e["event_id"],
                "action": e.get("action"),
                "actor": e.get("actor"),
                "source_ip": e.get("source_ip"),
                "error_code": e.get("error_code"),
                "timestamp_utc": e.get("timestamp_utc"),
            }
            for e in shown
        ],
    }


def screen_language(report, payload):
    """Flag narrowly defined mistakes for analyst review; no general NLP claim."""
    narrative = " ".join(
        str(report.get(field, "")) for field in ("summary", "reasoning")
    )
    flags = []

    def add(code, severity, reason):
        flags.append({"code": code, "severity": severity, "reason": reason})

    if any(rx.search(narrative) for rx in MISSING_ERROR_SUCCESS):
        add(
            "ERROR_ABSENCE_USED_AS_SUCCESS_PROOF", "high",
            "Missing errorCode alone does not prove a successful API operation.",
        )

    shown = payload["evidence_events"]
    if (shown and all(e.get("source_ip") not in (None, "", "unknown") for e in shown)
            and IP_ABSENCE.search(narrative)):
        add(
            "SOURCE_IP_REPORTED_UNAVAILABLE", "high",
            "The model-visible normalized events contain source_ip values; review the statement.",
        )

    if CONFIRMED_COMPROMISE.search(narrative):
        add(
            "UNPROVEN_CONFIRMED_ATTACK_LANGUAGE", "high",
            "Strong attribution/attack claims require additional corroboration.",
        )

    if payload["evidence_is_truncated"]:
        add(
            "INCOMPLETE_MODEL_VIEW", "medium",
            "The model saw only part of this case; review the excluded events.",
        )

    if report["classification"] in {"suspicious", "malicious", "attack"}:
        add(
            "POSITIVE_CLASSIFICATION_REQUIRES_CORROBORATION", "medium",
            "An AI security classification is a hypothesis, not verified attack ground truth.",
        )

    if not report["evidence_ids"]:
        add(
            "NO_EVENT_CITATIONS", "medium",
            "The model did not cite any of its presented evidence events.",
        )

    return flags


def review_artifact(artifact, case, documents):
    """Independently verify run provenance and apply limited evidence checks."""
    no_labels(case)
    no_labels(artifact)
    case_id = case["case_id"]
    if not CASE_ID_PATTERN.fullmatch(case_id):
        raise ValueError("Invalid development case ID")
    if artifact.get("case_id") != case_id:
        raise ValueError("Report references a different case ID")
    digest = hashlib.sha256(
        json.dumps(case, sort_keys=True).encode("utf-8")
    ).hexdigest()
    if artifact.get("case_sha256") != digest:
        raise ValueError("Case evidence hash mismatch; cannot safely review report")

    references = select_references(case["events"], documents)
    payload = make_payload(case, references)
    if artifact.get("events_total") != payload["total_events"]:
        raise ValueError("Saved total event count does not match source case")
    if artifact.get("events_presented") != payload["events_presented"]:
        raise ValueError("Saved presented event count does not match source case")
    if artifact.get("retrieved_knowledge_ids") != [r["id"] for r in references]:
        raise ValueError("Saved knowledge IDs differ from currently selected references")

    report = artifact.get("report")
    Draft202012Validator(SCHEMA).validate(report)
    visible_ids = [e["event_id"] for e in payload["evidence_events"]]
    if len(visible_ids) != len(set(visible_ids)):
        raise ValueError("Duplicate presented evidence IDs")
    if not set(report["evidence_ids"]).issubset(visible_ids):
        raise ValueError("AI cites unknown or unpresented evidence IDs")
    reference_ids = {r["id"] for r in references}
    if not set(report["knowledge_ids"]).issubset(reference_ids):
        raise ValueError("AI cites unknown or unretrieved knowledge IDs")

    flags = screen_language(report, payload)
    return {
        "case_id": case_id,
        "model": artifact.get("model"),
        "source_case_sha256": digest,
        "verification_method": "deterministic provenance, citation-ID and targeted-language checks",
        "citations_exist": True,
        "citations_are_claim_level_verified": False,
        "evidence_ledger": evidence_ledger(case, payload),
        "flags": flags,
        "review_status": (
            "manual_review_required" if flags else "limited_automatic_checks_passed"
        ),
        "limitations": [
            "Does not verify every natural-language sentence against source evidence.",
            "Cited event membership does not establish that a particular claim is true.",
            "Does not use attack ground truth or measure detection accuracy.",
            "A missing flag must not be interpreted as an accurate report.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case-id", required=True)
    args = parser.parse_args()
    case_id = args.case_id
    case = load_case(case_id)
    artifact_path = REPORTS / (case_id + ".json")
    output = REPORTS / (case_id + ".verification.json")
    if not artifact_path.is_file():
        raise FileNotFoundError(f"AI report not found: {artifact_path}")
    # Refuse to clobber an earlier review or follow symlinks to it.
    if output.exists() or output.is_symlink():
        raise FileExistsError(f"Verification report already exists: {output}")
    relative = output.relative_to(ROOT).as_posix()
    if subprocess.run(
        ["git", "check-ignore", "-q", relative], cwd=ROOT, check=False
    ).returncode != 0:
        raise ValueError("Verification output is not Git-ignored")
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    references = json.loads(KNOWLEDGE.read_text(encoding="utf-8"))
    review = review_artifact(artifact, case, references)
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(output, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(review, stream, indent=2)
        stream.write("\n")
    print("CASE:", case_id)
    print("CITATION MEMBERSHIP: PASSED")
    print("DETERMINISTIC FLAGS:", len(review["flags"]))
    for flag in review["flags"]:
        print(f" - {flag['code']}: {flag['reason']}")
    print("REVIEW STATUS:", review["review_status"])
    print("SAVED PRIVATELY:", relative)
    print("LIMITATION: Not all free-text claims are automatically verified.")


if __name__ == "__main__":
    main()
