"""Offline end-to-end evidence tests using synthetic fixtures only."""

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(ROOT / "src/evaluation"))
sys.path.insert(0, str(ROOT / "src/ingestion"))

from verify_preflight_trace import verify
from normalize_linux_journal import (
    parse_journal_export,
    normalize_record,
)


class PreflightTraceTests(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

        self.root = Path(self.temp.name)
        self.folder = (
            self.root / "data/lab_evidence/preflight"
        )
        self.folder.mkdir(parents=True)

        self.source_path = (
            "data/lab_evidence/preflight/example.journal-export"
        )
        self.source = self.root / self.source_path

        messages = [
            (
                "pam_unix(su-l:auth): authentication failure; "
                "logname=demo uid=1000 euid=0 "
                "tty=/dev/pts/0 ruser=demo rhost=  user=root"
            ),
            "FAILED SU (to root) demo on pts/0",
        ]

        blocks = []

        for index, message in enumerate(messages, start=1):
            block = (
                f"__CURSOR=synthetic-cursor-{index}\n"
                f"__REALTIME_TIMESTAMP="
                f"{1700000000000000 + (index-1)*1000000}\n"
                "_PID=4927\n"
                "SYSLOG_IDENTIFIER=su\n"
                f"MESSAGE={message}\n\n"
            )
            blocks.append(block)

        raw = "".join(blocks).encode("utf-8")
        self.source.write_bytes(raw)

        digest = hashlib.sha256(raw).hexdigest()

        records = parse_journal_export(raw)

        self.events = [
            normalize_record(
                record, index, self.source_path, 4927
            )
            for index, record in enumerate(records, start=1)
        ]

        self.manifest = {
            "run_id": "PFL-001-RUN-001",
            "scenario_id": "PFL-001",
            "environment_type": "local_endpoint_preflight",
            "started_at_utc": self.events[0]["timestamp_utc"],
            "actions": [],
            "evidence_artifacts": [
                {
                    "source_type": "linux_journal",
                    "file_path": self.source_path,
                    "sha256": digest,
                }
            ],
        }

        self.ground_truth = {
            "run_id": "PFL-001-RUN-001",
            "scenario_id": "PFL-001",
            "annotation_version": 1,
            "expected_classification": "benign",
            "classification_rationale": (
                "Synthetic fixture for validation tests."
            ),
            "supporting_event_ids": [
                e["event_id"] for e in self.events
            ],
            "missing_evidence": [],
            "expected_response": ["Document test event"],
            "review_status": "draft",
        }

        self.metadata = {
            "evidence_file": self.source_path,
            "sha256": digest,
            "journal_record_count": 2,
            "source_process_id": 4927,
        }

        self.save_records()

    def write_json(self, name, content):
        (self.folder / name).write_text(
            json.dumps(content, indent=2) + "\n",
            encoding="utf-8",
        )

    def save_records(self):
        self.write_json("manifest.json", self.manifest)
        self.write_json("ground_truth.json", self.ground_truth)
        self.write_json("collection_metadata.json", self.metadata)

        (self.folder / "normalized_events.jsonl").write_text(
            "".join(json.dumps(e) + "\n" for e in self.events),
            encoding="utf-8",
        )

    def run_check(self):
        return verify(self.folder, root=self.root)

    def test_valid_complete_trace(self):
        self.run_check()

    def test_modified_original_evidence_rejected(self):
        with self.source.open("ab") as file:
            file.write(b"tampered\n")

        with self.assertRaisesRegex(
            ValueError, "Manifest SHA-256 mismatch"
        ):
            self.run_check()

    def test_modified_normalized_event_rejected(self):
        self.events[0]["event_type"] = "user_switch_failure"
        self.save_records()

        with self.assertRaisesRegex(
            ValueError, "differs from original evidence"
        ):
            self.run_check()

    def test_missing_ground_truth_reference_rejected(self):
        self.ground_truth["supporting_event_ids"] = [
            "PFL-001-RUN-001-EVT-999"
        ]
        self.save_records()

        with self.assertRaisesRegex(
            ValueError, "Missing supporting event IDs"
        ):
            self.run_check()

    def test_unsafe_source_path_rejected(self):
        unsafe = "../outside.journal-export"

        self.manifest["evidence_artifacts"][0][
            "file_path"
        ] = unsafe

        for event in self.events:
            event["raw_evidence_path"] = unsafe

        self.save_records()

        with self.assertRaisesRegex(
            ValueError, "Unsafe evidence path"
        ):
            self.run_check()

    def test_wrong_source_process_rejected(self):
        self.metadata["source_process_id"] = 9999
        self.save_records()

        with self.assertRaisesRegex(
            ValueError, "Unexpected source process ID"
        ):
            self.run_check()


if __name__ == "__main__":
    unittest.main()
