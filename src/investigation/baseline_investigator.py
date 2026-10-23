
"""Deterministic baseline investigator for synthetic cloud audit events.

This pilot implementation uses predefined rules, not an AI model.
It reads raw events only; ground-truth labels are used separately for evaluation.
"""

import json
from collections import defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
EVENTS_FILE = PROJECT_ROOT / "data" / "raw" / "cloud_audit_events.jsonl"
OUTPUT_FILE = PROJECT_ROOT / "results" / "baseline_findings.json"


def load_events(path):
    """Load JSONL events and validate basic structure."""
    events = []

    required_fields = {
        "event_id",
        "timestamp",
        "scenario_id",
        "event_type",
        "action",
        "status",
    }

    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON on line {line_number}: {exc}"
                ) from exc

            missing = required_fields - event.keys()
            if missing:
                raise ValueError(
                    f"Line {line_number} missing fields: {sorted(missing)}"
                )

            events.append(event)

    event_ids = [event["event_id"] for event in events]
    if len(event_ids) != len(set(event_ids)):
        raise ValueError("Duplicate event IDs detected.")

    return events


def investigate_scenario(scenario_id, events):
    """Apply predefined rules to one scenario's events."""
    event_ids = [event["event_id"] for event in events]

    successful_events = [
        event for event in events if event["status"] == "Success"
    ]

    successful_types = {event["event_type"] for event in successful_events}

    # Rule 1: suspicious access pattern.
    no_mfa_login = any(
        event["event_type"] == "ConsoleLogin"
        and event["status"] == "Success"
        and event.get("mfa_used") is False
        for event in events
    )

    key_created = any(
        event["event_type"] == "CreateAccessKey"
        and event["status"] == "Success"
        for event in events
    )

    admin_policy_attached = any(
        event["event_type"] == "AttachAdminPolicy"
        and event["status"] == "Success"
        for event in events
    )

    if no_mfa_login and key_created and admin_policy_attached:
        return {
            "scenario_id": scenario_id,
            "classification": "suspicious",
            "severity": "high",
            "matched_rule": "BASELINE-RULE-001",
            "supporting_event_ids": event_ids,
            "reasons": [
                "Successful console login without MFA.",
                "Successful access-key creation.",
                "Successful administrative policy attachment.",
            ],
            "limitations": [
                "The pattern indicates suspicious activity but does not "
                "prove malicious intent or attribution."
            ],
        }

    # Rule 2: known benign pilot pattern.
    normal_read_only = (
        any(
            event["event_type"] == "ConsoleLogin"
            and event["status"] == "Success"
            and event.get("mfa_used") is True
            for event in events
        )
        and any(
            event["event_type"] == "ListResources"
            and event["status"] == "Success"
            for event in events
        )
        and not (
            {"CreateAccessKey", "AttachAdminPolicy"} & successful_types
        )
    )

    if normal_read_only:
        return {
            "scenario_id": scenario_id,
            "classification": "benign",
            "severity": "low",
            "matched_rule": "BASELINE-RULE-002",
            "supporting_event_ids": event_ids,
            "reasons": [
                "Successful login with MFA.",
                "Successful read-only resource listing.",
                "No successful access-key creation or administrative "
                "policy attachment in this scenario."
            ],
            "limitations": [
                "This narrow rule does not establish that all activity "
                "in the scenario is safe."
            ],
        }

    # Rule 3: known benign backup pilot pattern.
    approved_backup_pattern = (
        any(
            event["event_type"] == "AssumeRole"
            and event["status"] == "Success"
            and event.get("mfa_used") is True
            and event.get("resource") == "backup-role"
            for event in events
        )
        and any(
            event["event_type"] == "BackupStart"
            and event["status"] == "Success"
            and event.get("resource") == "backup-vault"
            for event in events
        )
    )

    if approved_backup_pattern:
        return {
            "scenario_id": scenario_id,
            "classification": "benign",
            "severity": "low",
            "matched_rule": "BASELINE-RULE-003",
            "supporting_event_ids": event_ids,
            "reasons": [
                "MFA-protected assumption of the backup role.",
                "Successful backup activity in the backup vault."
            ],
            "limitations": [
                "The synthetic events do not independently verify a real "
                "change ticket or business approval."
            ],
        }

    return {
        "scenario_id": scenario_id,
        "classification": "inconclusive",
        "severity": "undetermined",
        "matched_rule": None,
        "supporting_event_ids": event_ids,
        "reasons": [
            "No predefined baseline rule matched this scenario."
        ],
        "limitations": [
            "Inconclusive does not mean benign; analyst review is required."
        ],
    }


def main():
    events = load_events(EVENTS_FILE)

    grouped = defaultdict(list)
    for event in events:
        grouped[event["scenario_id"]].append(event)

    findings = [
        investigate_scenario(scenario_id, scenario_events)
        for scenario_id, scenario_events in sorted(grouped.items())
    ]

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(findings, file, indent=2)
        file.write("\n")

    print(f"Input events: {len(events)}")
    print(f"Scenarios investigated: {len(findings)}")
    print(f"Findings written to: {OUTPUT_FILE}")

    for finding in findings:
        print(
            f"{finding['scenario_id']}: "
            f"{finding['classification']} "
            f"(rule: {finding['matched_rule'] or 'none'})"
        )


if __name__ == "__main__":
    main()
