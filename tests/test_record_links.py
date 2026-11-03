"""Automated tests for cross-record evidence consistency."""

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "src/evaluation/verify_record_links.py"


class RecordLinkTests(unittest.TestCase):

    def setUp(self):
        self.manifest = {
            "run_id": "LAB-001-RUN-001",
            "scenario_id": "LAB-001",
            "environment_type": "isolated_endpoint_lab",
            "started_at_utc": "2026-11-02T12:00:00Z",
            "actions": [],
            "evidence_artifacts": [
                {
                    "source_type": "linux_audit_log",
                    "file_path": "data/lab_evidence/demo_auth.log",
                    "sha256": "a" * 64
                }
            ]
        }

        self.event = {
            "event_id": "LAB-001-RUN-001-EVT-001",
            "run_id": "LAB-001-RUN-001",
            "scenario_id": "LAB-001",
            "timestamp_utc": "2026-11-02T12:00:00Z",
            "source_type": "linux_audit_log",
            "raw_evidence_path": "data/lab_evidence/demo_auth.log",
            "raw_record_locator": "line:1",
            "event_type": "authentication",
            "observed_outcome": "failed"
        }

        self.ground_truth = {
            "run_id": "LAB-001-RUN-001",
            "scenario_id": "LAB-001",
            "annotation_version": 1,
            "expected_classification": "inconclusive",
            "classification_rationale": "Test fixture only.",
            "supporting_event_ids": [
                "LAB-001-RUN-001-EVT-001"
            ],
            "missing_evidence": [],
            "expected_response": ["Review the incident"],
            "review_status": "draft"
        }

    def run_verifier(self, manifest=None, events=None,
                     ground_truth=None):

        manifest = (
            copy.deepcopy(self.manifest)
            if manifest is None else manifest
        )

        events = (
            [copy.deepcopy(self.event)]
            if events is None else events
        )

        ground_truth = (
            copy.deepcopy(self.ground_truth)
            if ground_truth is None else ground_truth
        )

        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)

            manifest_path = folder / "manifest.json"
            events_path = folder / "events.jsonl"
            ground_truth_path = folder / "ground_truth.json"

            manifest_path.write_text(
                json.dumps(manifest), encoding="utf-8"
            )

            events_path.write_text(
                "".join(json.dumps(e) + "\n" for e in events),
                encoding="utf-8"
            )

            ground_truth_path.write_text(
                json.dumps(ground_truth), encoding="utf-8"
            )

            return subprocess.run(
                [
                    sys.executable,
                    str(VERIFIER),
                    str(manifest_path),
                    str(events_path),
                    str(ground_truth_path)
                ],
                capture_output=True,
                text=True,
                check=False
            )

    def test_valid_links(self):
        result = self.run_verifier()

        self.assertEqual(
            result.returncode, 0,
            result.stdout + result.stderr
        )
        self.assertIn(
            "CROSS-RECORD VERIFICATION PASSED",
            result.stdout
        )

    def test_missing_supporting_event(self):
        annotation = copy.deepcopy(self.ground_truth)
        annotation["supporting_event_ids"] = [
            "LAB-001-RUN-001-EVT-999"
        ]

        result = self.run_verifier(
            ground_truth=annotation
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "Missing supporting event IDs",
            result.stdout
        )

    def test_wrong_ground_truth_scenario(self):
        annotation = copy.deepcopy(self.ground_truth)
        annotation["scenario_id"] = "LAB-002"

        result = self.run_verifier(
            ground_truth=annotation
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "Ground-truth scenario ID mismatch",
            result.stdout
        )

    def test_duplicate_event_ids(self):
        events = [
            copy.deepcopy(self.event),
            copy.deepcopy(self.event)
        ]

        result = self.run_verifier(events=events)

        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "Duplicate event ID",
            result.stdout
        )

    def test_undeclared_evidence_path(self):
        event = copy.deepcopy(self.event)
        event["raw_evidence_path"] = (
            "data/lab_evidence/unknown.log"
        )

        result = self.run_verifier(events=[event])

        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "Undeclared raw evidence path",
            result.stdout
        )

    def test_wrong_event_run_id(self):
        event = copy.deepcopy(self.event)
        event["run_id"] = "LAB-002-RUN-001"

        result = self.run_verifier(events=[event])

        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "Run ID mismatch",
            result.stdout
        )


if __name__ == "__main__":
    unittest.main()
