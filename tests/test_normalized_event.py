"""Automated tests for normalized laboratory security events."""

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "src/evaluation/validate_lab_record.py"


class NormalizedEventTests(unittest.TestCase):

    def setUp(self):
        self.event = {
            "event_id": "LAB-001-RUN-001-EVT-001",
            "run_id": "LAB-001-RUN-001",
            "scenario_id": "LAB-001",
            "timestamp_utc": "2026-11-02T12:00:00Z",
            "source_type": "linux_audit_log",
            "raw_evidence_path": "data/lab_evidence/example.log",
            "raw_record_locator": "line:1",
            "event_type": "authentication",
            "observed_outcome": "failed"
        }

    def validate(self, event):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "event.json"

            path.write_text(
                json.dumps(event),
                encoding="utf-8"
            )

            return subprocess.run(
                [
                    sys.executable,
                    str(VALIDATOR),
                    "event",
                    str(path)
                ],
                capture_output=True,
                text=True,
                check=False
            )

    def test_valid_normalized_event(self):
        result = self.validate(self.event)

        self.assertEqual(
            result.returncode,
            0,
            result.stdout + result.stderr
        )

        self.assertIn("VALIDATION PASSED", result.stdout)

    def test_invalid_event_timestamp(self):
        event = copy.deepcopy(self.event)
        event["timestamp_utc"] = "not-a-date"

        result = self.validate(event)

        self.assertEqual(result.returncode, 1)
        self.assertIn("timestamp_utc", result.stdout)

    def test_invalid_event_id(self):
        event = copy.deepcopy(self.event)
        event["event_id"] = "INVALID-ID"

        result = self.validate(event)

        self.assertEqual(result.returncode, 1)
        self.assertIn("event_id", result.stdout)


if __name__ == "__main__":
    unittest.main()
