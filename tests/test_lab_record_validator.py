"""Reproducible tests for laboratory JSON Schema validation."""

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "src/evaluation/validate_lab_record.py"


class LabRecordValidatorTests(unittest.TestCase):

    def setUp(self):
        self.execution = {
            "run_id": "LAB-001-RUN-001",
            "scenario_id": "LAB-001",
            "environment_type": "isolated_endpoint_lab",
            "started_at_utc": "2026-11-02T12:00:00Z",
            "actions": [],
            "evidence_artifacts": [],
        }

        self.ground_truth = {
            "run_id": "LAB-001-RUN-001",
            "scenario_id": "LAB-001",
            "annotation_version": 1,
            "expected_classification": "inconclusive",
            "classification_rationale": "Test fixture only.",
            "supporting_event_ids": [],
            "missing_evidence": ["No evidence collected"],
            "expected_response": ["Review available evidence"],
            "review_status": "draft",
        }

    def run_validator(self, kind, record):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "record.json"
            path.write_text(json.dumps(record), encoding="utf-8")

            return subprocess.run(
                [sys.executable, str(VALIDATOR), kind, str(path)],
                capture_output=True,
                text=True,
                check=False,
            )

    def test_valid_execution(self):
        result = self.run_validator("execution", self.execution)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("VALIDATION PASSED", result.stdout)

    def test_missing_scenario_id(self):
        record = copy.deepcopy(self.execution)
        del record["scenario_id"]

        result = self.run_validator("execution", record)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("VALIDATION FAILED", result.stdout)

    def test_valid_ground_truth(self):
        result = self.run_validator("ground_truth", self.ground_truth)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("VALIDATION PASSED", result.stdout)

    def test_invalid_classification(self):
        record = copy.deepcopy(self.ground_truth)
        record["expected_classification"] = "definitely_hacked"

        result = self.run_validator("ground_truth", record)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("expected_classification", result.stdout)

    def test_invalid_timestamp(self):
        record = copy.deepcopy(self.execution)
        record["started_at_utc"] = "not-a-date"

        result = self.run_validator("execution", record)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_invalid_checksum(self):
        record = copy.deepcopy(self.execution)
        record["evidence_artifacts"] = [{
            "source_type": "linux_audit_log",
            "file_path": "sample.log",
            "sha256": "invalid-hash",
        }]

        result = self.run_validator("execution", record)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
