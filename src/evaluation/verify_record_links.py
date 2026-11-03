"""Verify links between execution, events, and ground truth."""

import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

from validate_lab_record import build_format_checker


ROOT = Path(__file__).resolve().parents[2]


SCHEMAS = {
    "execution": ROOT / "schemas/lab_execution.schema.json",
    "event": ROOT / "schemas/normalized_event.schema.json",
    "ground_truth": ROOT / "schemas/ground_truth.schema.json",
}


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def validate_structure(record, record_type):
    """Verify a record against its existing JSON Schema."""

    schema = read_json(SCHEMAS[record_type])

    validator = Draft202012Validator(
        schema,
        format_checker=build_format_checker(),
    )

    errors = list(validator.iter_errors(record))

    if errors:
        raise ValueError(
            f"Invalid {record_type} record: {errors[0].message}"
        )


def load_events(path):
    """Load and structurally validate normalized JSONL events."""

    events = []

    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        if not line.strip():
            continue

        event = json.loads(line)

        validate_structure(event, "event")
        events.append(event)

    if not events:
        raise ValueError("No normalized events found.")

    return events


def verify_links(manifest_path, events_path, annotation_path):
    """Check cross-record consistency for one laboratory run."""

    manifest = read_json(manifest_path)
    annotation = read_json(annotation_path)

    validate_structure(manifest, "execution")
    validate_structure(annotation, "ground_truth")

    events = load_events(events_path)

    run_id = manifest["run_id"]
    scenario_id = manifest["scenario_id"]

    if annotation["run_id"] != run_id:
        raise ValueError("Ground-truth run ID mismatch.")

    if annotation["scenario_id"] != scenario_id:
        raise ValueError("Ground-truth scenario ID mismatch.")

    known_paths = {
        artifact["file_path"]
        for artifact in manifest["evidence_artifacts"]
    }

    event_ids = set()

    for event in events:
        event_id = event["event_id"]

        if event_id in event_ids:
            raise ValueError(f"Duplicate event ID: {event_id}")

        event_ids.add(event_id)

        if event["run_id"] != run_id:
            raise ValueError(f"Run ID mismatch: {event_id}")

        if event["scenario_id"] != scenario_id:
            raise ValueError(f"Scenario ID mismatch: {event_id}")

        if not event_id.startswith(f"{run_id}-EVT-"):
            raise ValueError(
                f"Event ID does not belong to run: {event_id}"
            )

        if event["raw_evidence_path"] not in known_paths:
            raise ValueError(
                f"Undeclared raw evidence path: {event_id}"
            )

    supporting_ids = set(annotation["supporting_event_ids"])

    missing_ids = supporting_ids - event_ids

    if missing_ids:
        raise ValueError(
            f"Missing supporting event IDs: {sorted(missing_ids)}"
        )

    print("CROSS-RECORD VERIFICATION PASSED")
    print("Run:", run_id)
    print("Scenario:", scenario_id)
    print("Normalized events:", len(events))
    print("Verified evidence references:", len(supporting_ids))

    return 0


def main():
    if len(sys.argv) != 4:
        print(
            "Usage: python3 verify_record_links.py "
            "<manifest.json> <events.jsonl> <ground_truth.json>"
        )
        return 2

    try:
        return verify_links(
            Path(sys.argv[1]),
            Path(sys.argv[2]),
            Path(sys.argv[3]),
        )

    except (OSError, ValueError, TypeError, KeyError) as error:
        print(f"CROSS-RECORD VERIFICATION FAILED: {error}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
