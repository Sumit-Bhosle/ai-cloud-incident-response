"""Read Wazuh alert evidence for laboratory normalization."""

import json
from pathlib import Path


def load_wazuh_alerts(source_path):
    """Load and check Wazuh JSONL alert records."""

    source = Path(source_path)
    alerts = []
    seen_ids = set()

    with source.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue

            try:
                alert = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(
                    f"Invalid JSON at line {line_number}"
                ) from error

            if not isinstance(alert, dict):
                raise ValueError(
                    f"Alert at line {line_number} must be an object."
                )

            alert_id = alert.get("id")

            if not isinstance(alert_id, str) or not alert_id:
                raise ValueError(
                    f"Missing alert ID at line {line_number}"
                )

            if alert_id in seen_ids:
                raise ValueError(
                    f"Duplicate Wazuh alert ID at line {line_number}"
                )

            seen_ids.add(alert_id)
            alerts.append(alert)

    if not alerts:
        raise ValueError("No Wazuh alerts found.")

    return alerts


def normalize_wazuh_alert(alert, index, source_path):
    """Convert a Wazuh authentication alert into research evidence."""
    import re
    from datetime import datetime, timezone

    rule = alert.get("rule", {})
    if not isinstance(rule, dict):
        raise ValueError("Invalid Wazuh rule")

    rule_id = str(rule.get("id", ""))
    level = rule.get("level")
    description = rule.get("description")
    full_log = alert.get("full_log", "")
    alert_id = alert.get("id")
    timestamp = alert.get("timestamp")

    if not isinstance(level, int) or isinstance(level, bool):
        raise ValueError("Invalid rule severity")

    if not isinstance(description, str) or not description:
        raise ValueError("Missing rule description")

    if not isinstance(full_log, str):
        raise ValueError("Invalid original log")

    if not isinstance(alert_id, str) or not alert_id:
        raise ValueError("Missing Wazuh alert ID")

    if not isinstance(timestamp, str):
        raise ValueError("Missing alert timestamp")

    dt = datetime.fromisoformat(
        timestamp.replace("Z", "+00:00")
    )

    if dt.tzinfo is None:
        raise ValueError("Alert timestamp must include timezone")

    timestamp_utc = (
        dt.astimezone(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )

    if rule_id == "5503":
        if "pam_unix(su-l:auth): authentication failure" not in full_log:
            raise ValueError("Unexpected rule 5503 log pattern")

        event_type = "authentication_failure"

        data = alert.get("data") or {}
        if not isinstance(data, dict):
            raise ValueError("Invalid decoded data")

        actor = data.get("srcuser")
        target = data.get("dstuser")

        if not actor:
            match = re.search(r"\bruser=(\S+)", full_log)
            actor = match.group(1) if match else None

        if not target:
            match = re.search(r"\buser=(\S+)", full_log)
            target = match.group(1) if match else None

    elif rule_id == "5301":
        match = re.search(
            r"FAILED SU \(to ([^)]+)\) (\S+) on (\S+)",
            full_log,
        )

        if not match:
            raise ValueError("Unexpected rule 5301 log pattern")

        target, actor, _terminal = match.groups()
        event_type = "user_switch_failure"

    else:
        raise ValueError(f"Unsupported Wazuh rule: {rule_id}")

    return {
        "event_id": f"PFL-001-RUN-002-EVT-{index:03d}",
        "run_id": "PFL-001-RUN-002",
        "scenario_id": "PFL-001",
        "timestamp_utc": timestamp_utc,
        "source_type": "wazuh_alert",
        "raw_evidence_path": source_path,
        "raw_record_locator": f"wazuh_alert_id:{alert_id}",
        "source_event_id": alert_id,
        "event_type": event_type,
        "action": "switch_user",
        "actor": actor,
        "target": target,
        "observed_outcome": "failed",
        "wazuh_rule_id": rule_id,
        "wazuh_rule_level": level,
        "wazuh_rule_description": description,
        "normalization_notes": (
            "Derived from a Wazuh detection alert. "
            "Timestamp is Wazuh alert time, not necessarily "
            "the original journal event time. "
            "Authorized local authentication preflight; "
            "not a cloud incident."
        ),
    }


def main():
    import hashlib
    import subprocess
    from jsonschema import Draft202012Validator
    from src.evaluation.validate_lab_record import build_format_checker

    root = Path(__file__).resolve().parents[2]

    relative_source = (
        "data/lab_evidence/preflight/run_002/wazuh_alerts.jsonl"
    )
    relative_output = (
        "data/lab_evidence/preflight/run_002/normalized_events.jsonl"
    )

    source = root / relative_source
    output = root / relative_output
    schema_path = root / "schemas/normalized_event.schema.json"

    ignored = subprocess.run(
        ["git", "check-ignore", "-q", relative_output],
        cwd=root,
        check=False,
    )
    if ignored.returncode != 0:
        raise ValueError("Output is not Git-ignored")

    expected_hash = (
        "14ee3541c06da1f18214d192b8dde7eaebd81921bfd89d99bf195de44d6465b1"
    )

    actual_hash = hashlib.sha256(source.read_bytes()).hexdigest()

    if actual_hash != expected_hash:
        raise ValueError("Original Wazuh evidence SHA-256 mismatch")

    alerts = load_wazuh_alerts(source)

    events = [
        normalize_wazuh_alert(alert, index, relative_source)
        for index, alert in enumerate(alerts, start=1)
    ]

    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = Draft202012Validator(
        schema,
        format_checker=build_format_checker(),
    )

    for event in events:
        validator.validate(event)

    content = "".join(
        json.dumps(event) + "\n" for event in events
    ).encode("utf-8")

    if output.is_symlink():
        raise ValueError("Refusing symbolic-link output")

    if output.exists():
        if output.read_bytes() != content:
            raise ValueError("Existing output differs")
        print("Existing normalized output matches.")
    else:
        with output.open("xb") as file:
            file.write(content)
        output.chmod(0o600)
        print("Normalized Wazuh events saved.")

    print("\n===== WAZUH NORMALIZATION =====")
    print("Source SHA-256: VERIFIED")
    print("JSON Schema: PASSED")
    print("Events normalized:", len(events))

    for event in events:
        print(
            event["event_id"],
            "| Rule", event["wazuh_rule_id"],
            "|", event["event_type"],
        )

    print("Output:", relative_output)
    print("WAZUH NORMALIZATION PASSED")


if __name__ == "__main__":
    main()
