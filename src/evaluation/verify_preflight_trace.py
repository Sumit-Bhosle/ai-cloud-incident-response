"""Verify the original PFL-001 Linux evidence end to end."""

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

sys.path.insert(0, str(ROOT / "src/ingestion"))

from normalize_linux_journal import (
    normalize_record,
    parse_journal_export,
)

from verify_record_links import verify_links


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def verify(folder, root=ROOT):
    """Verify evidence, source records, and annotations."""

    root = Path(root).resolve()
    folder = Path(folder).resolve()
    allowed = (root / "data/lab_evidence").resolve()

    if not folder.is_relative_to(allowed):
        raise ValueError("Experiment folder is outside lab evidence.")

    manifest_path = folder / "manifest.json"
    events_path = folder / "normalized_events.jsonl"
    truth_path = folder / "ground_truth.json"
    metadata_path = folder / "collection_metadata.json"

    manifest = read_json(manifest_path)
    metadata = read_json(metadata_path)
    ground_truth = read_json(truth_path)

    # Check structural validity and cross-record relationships.
    verify_links(manifest_path, events_path, truth_path)

    if manifest["run_id"] != "PFL-001-RUN-001":
        raise ValueError("Unexpected preflight run.")

    if manifest["scenario_id"] != "PFL-001":
        raise ValueError("Unexpected preflight scenario.")

    artifacts = manifest["evidence_artifacts"]

    if len(artifacts) != 1:
        raise ValueError("Expected exactly one source artifact.")

    artifact = artifacts[0]

    if artifact["source_type"] != "linux_journal":
        raise ValueError("Unexpected evidence source type.")

    source = Path(artifact["file_path"])

    if source.is_absolute() or ".." in source.parts:
        raise ValueError("Unsafe evidence path.")

    evidence_path = (root / source).resolve()

    if not evidence_path.is_relative_to(allowed):
        raise ValueError("Evidence escapes protected directory.")

    if metadata["evidence_file"] != artifact["file_path"]:
        raise ValueError("Metadata evidence path mismatch.")

    raw = evidence_path.read_bytes()
    actual_hash = hashlib.sha256(raw).hexdigest()

    if actual_hash != artifact["sha256"]:
        raise ValueError("Manifest SHA-256 mismatch.")

    if actual_hash != metadata["sha256"]:
        raise ValueError("Collection metadata SHA-256 mismatch.")

    print("ORIGINAL EVIDENCE INTEGRITY: PASSED")

    records = parse_journal_export(raw)

    if len(records) != metadata["journal_record_count"]:
        raise ValueError("Original journal count mismatch.")

    events = [
        json.loads(line)
        for line in events_path.read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip()
    ]

    if len(events) != len(records):
        raise ValueError("Normalized event count mismatch.")

    cursors = [record["__CURSOR"] for record in records]

    if len(cursors) != len(set(cursors)):
        raise ValueError("Duplicate source journal cursor.")

    for index, (record, event) in enumerate(
        zip(records, events), start=1
    ):
        expected = normalize_record(
            record,
            index,
            artifact["file_path"],
            metadata["source_process_id"],
        )

        if event != expected:
            raise ValueError(
                f"Event {index} differs from original evidence."
            )

        print(
            "SOURCE VERIFIED:",
            event["event_id"],
            event["event_type"],
        )

    event_ids = {event["event_id"] for event in events}
    supporting_ids = set(ground_truth["supporting_event_ids"])

    if event_ids != supporting_ids:
        raise ValueError("Ground-truth evidence references mismatch.")

    print("GROUND-TRUTH REFERENCES: VERIFIED")
    print("GROUND-TRUTH STATUS:", ground_truth["review_status"])
    print("END-TO-END PREFLIGHT TRACE: PASSED")


def main():
    folder = ROOT / "data/lab_evidence/preflight"

    try:
        verify(folder)
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
    ) as error:
        print("END-TO-END PREFLIGHT TRACE: FAILED")
        print("Reason:", error)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
