"""Normalize verified Ubuntu journal evidence for preflight PFL-001."""

import hashlib
import io
import json
import re
import struct
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src/evaluation"))

from validate_lab_record import build_format_checker

SOURCE = ROOT / (
    "data/lab_evidence/preflight/"
    "su_failed_2026-11-03.journal-export"
)
METADATA = SOURCE.parent / "collection_metadata.json"
OUTPUT = SOURCE.parent / "normalized_events.jsonl"
SCHEMA = ROOT / "schemas/normalized_event.schema.json"

RUN_ID = "PFL-001-RUN-001"
SCENARIO_ID = "PFL-001"

NEEDED_FIELDS = {
    "__CURSOR",
    "__REALTIME_TIMESTAMP",
    "_PID",
    "SYSLOG_IDENTIFIER",
    "MESSAGE",
}


def parse_journal_export(raw):
    """Read systemd export entries, including binary-safe fields."""
    stream = io.BytesIO(raw)
    records = []
    current = {}

    while True:
        line = stream.readline()

        if not line:
            if current:
                records.append(current)
            break

        if line == b"\n":
            if current:
                records.append(current)
                current = {}
            continue

        if not line.endswith(b"\n"):
            raise ValueError("Incomplete journal field.")

        line = line[:-1]

        if b"=" in line:
            key, value = line.split(b"=", 1)
        else:
            key = line
            length_bytes = stream.read(8)

            if len(length_bytes) != 8:
                raise ValueError("Incomplete binary field length.")

            length = struct.unpack("<Q", length_bytes)[0]

            if length > len(raw):
                raise ValueError("Invalid binary field length.")

            value = stream.read(length)

            if len(value) != length or stream.read(1) != b"\n":
                raise ValueError("Incomplete binary journal field.")

        key = key.decode("ascii")

        if key in NEEDED_FIELDS:
            if key in current:
                raise ValueError(f"Duplicate field: {key}")

            current[key] = value.decode("utf-8")

    return records


def normalize_record(record, index, source_path, expected_pid):
    """Convert one observed journal record to our event schema."""
    for key in NEEDED_FIELDS:
        if key not in record:
            raise ValueError(f"Missing journal field: {key}")

    if record["_PID"] != str(expected_pid):
        raise ValueError("Unexpected source process ID.")

    if record["SYSLOG_IDENTIFIER"] != "su":
        raise ValueError("Unexpected journal source.")

    message = record["MESSAGE"]

    if "pam_unix(su-l:auth): authentication failure" in message:
        event_type = "authentication_failure"

        actor_match = re.search(r"\bruser=(\S+)", message)
        target_match = re.search(r"\buser=(\S+)", message)

        actor = actor_match.group(1) if actor_match else None
        target = target_match.group(1) if target_match else None

    elif message.startswith("FAILED SU (to "):
        event_type = "user_switch_failure"

        match = re.match(
            r"^FAILED SU \(to ([^)]+)\) (\S+) on (\S+)$",
            message,
        )

        if not match:
            raise ValueError("Unrecognized failed SU message.")

        target, actor, _terminal = match.groups()

    else:
        raise ValueError("Unrecognized journal event; review manually.")

    microseconds = int(record["__REALTIME_TIMESTAMP"])

    event_time = (
        datetime(1970, 1, 1, tzinfo=timezone.utc)
        + timedelta(microseconds=microseconds)
    ).isoformat().replace("+00:00", "Z")

    return {
        "event_id": f"{RUN_ID}-EVT-{index:03d}",
        "run_id": RUN_ID,
        "scenario_id": SCENARIO_ID,
        "timestamp_utc": event_time,
        "source_type": "linux_journal",
        "raw_evidence_path": source_path,
        "raw_record_locator": (
            "journal_cursor:" + record["__CURSOR"]
        ),
        "source_event_id": record["__CURSOR"],
        "event_type": event_type,
        "action": "switch_user",
        "actor": actor,
        "target": target,
        "observed_outcome": "failed",
        "normalization_notes": (
            "Derived from original systemd journal evidence. "
            "Authorized local authentication preflight; "
            "not a cloud incident."
        ),
    }


def main():
    relative_source = SOURCE.relative_to(ROOT).as_posix()
    relative_output = OUTPUT.relative_to(ROOT).as_posix()

    ignored = subprocess.run(
        ["git", "check-ignore", "-q", relative_output],
        cwd=ROOT,
        check=False,
    )

    if ignored.returncode != 0:
        raise ValueError("Output is not Git-ignored. Refusing to write.")

    raw = SOURCE.read_bytes()
    metadata = json.loads(METADATA.read_text(encoding="utf-8"))

    actual_hash = hashlib.sha256(raw).hexdigest()

    if actual_hash != metadata["sha256"]:
        raise ValueError("Original evidence SHA-256 mismatch.")

    records = parse_journal_export(raw)

    if len(records) != metadata["journal_record_count"]:
        raise ValueError("Journal record count mismatch.")

    events = [
        normalize_record(
            record,
            index,
            relative_source,
            metadata["source_process_id"],
        )
        for index, record in enumerate(records, start=1)
    ]

    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))

    validator = Draft202012Validator(
        schema,
        format_checker=build_format_checker(),
    )

    for event in events:
        validator.validate(event)

    output_bytes = (
        "".join(json.dumps(event) + "\n" for event in events)
    ).encode("utf-8")

    if OUTPUT.exists():
        if OUTPUT.read_bytes() != output_bytes:
            raise ValueError(
                "Existing normalized output differs. "
                "Refusing to overwrite it."
            )
        print("Existing normalized output matches.")
    else:
        with OUTPUT.open("xb") as file:
            file.write(output_bytes)
        OUTPUT.chmod(0o600)

    print("NORMALIZATION PASSED")
    print("Original evidence SHA-256: VERIFIED")
    print("Schema validation: PASSED")
    print("Normalized events:", len(events))

    for event in events:
        print(
            event["event_id"],
            "|", event["timestamp_utc"],
            "|", event["event_type"],
        )

    print("Output:", relative_output)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError) as error:
        print("NORMALIZATION FAILED:", error)
        sys.exit(1)
