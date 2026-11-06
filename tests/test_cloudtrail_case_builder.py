"""Tests for CloudTrail normalization and case construction."""

import contextlib
import io
import json
import subprocess
import tempfile
import unittest
import zipfile

from pathlib import Path
from unittest.mock import patch

from src.ingestion import build_cloudtrail_cases as builder


def make_record(event_id, timestamp, attack=False,
                actor="user-A", ip="10.0.0.1"):
    return {
        "eventID": event_id,
        "eventTime": timestamp,
        "eventSource": "s3.amazonaws.com",
        "eventName": "GetObject",
        "userIdentity": {"principalId": actor},
        "sourceIPAddress": ip,
        "awsRegion": "ca-central-1",
        "requestParameters": {"bucketName": "test-bucket"},
        "should_sample": attack,
        "attack_name": "TestScenario" if attack else None,
    }


class CloudTrailCaseBuilderTests(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

        self.root = Path(self.temp.name)
        subprocess.run(
            ["git", "init", "-q", str(self.root)],
            check=True,
            capture_output=True,
        )

        (self.root / ".gitignore").write_text(
            "/data/lab_evidence/\n", encoding="utf-8"
        )

        self.source = self.root / (
            "data/lab_evidence/cloudtrail/train_labeled_a.zip"
        )
        self.dest = self.root / (
            "data/lab_evidence/cloudtrail/development"
        )
        self.source.parent.mkdir(parents=True)

    def write_dataset(self, records):
        with zipfile.ZipFile(self.source, "w") as archive:
            archive.writestr(
                "training.json",
                json.dumps({"Records": records}),
            )

    def run_builder(self):
        with patch.multiple(
            builder,
            ROOT=self.root,
            SOURCE=self.source,
            DEST=self.dest,
        ):
            with contextlib.redirect_stdout(io.StringIO()):
                builder.main()

    def sample_records(self):
        return [
            make_record(
                "duplicate-ID", "2026-11-04T02:01:00Z",
                attack=True,
            ),
            make_record(
                "duplicate-ID", "2026-11-04T02:02:00Z",
                attack=False,
            ),
            make_record(
                "event-003", "2026-11-04T02:03:00Z",
                actor="user-B",
            ),
            make_record(
                "event-004", "2026-11-04T02:40:00Z",
                attack=True,
            ),
        ]

    def read_jsonl(self, name):
        return [
            json.loads(line)
            for line in (self.dest / name).read_text(
                encoding="utf-8"
            ).splitlines()
            if line.strip()
        ]

    def test_utc_conversion_and_identity(self):
        record = make_record(
            "source-123",
            "2026-11-04T02:05:00+02:00",
        )
        event, _ = builder.normalize(record, 1)

        self.assertEqual(
            event["timestamp_utc"],
            "2026-11-04T00:05:00Z",
        )
        self.assertEqual(event["source_event_id"], "source-123")
        self.assertEqual(event["actor"], "user-A")
        self.assertNotIn("should_sample", event)

    def test_missing_required_field_rejected(self):
        record = make_record("123", "2026-11-04T02:05:00Z")
        del record["eventName"]

        with self.assertRaises(ValueError):
            builder.normalize(record, 1)

    def test_missing_timezone_rejected(self):
        record = make_record("123", "2026-11-04T02:05:00")

        with self.assertRaises(ValueError):
            builder.normalize(record, 1)

    def test_case_correlation_and_label_separation(self):
        self.write_dataset(self.sample_records())
        self.run_builder()

        cases = self.read_jsonl("cases.jsonl")
        truth = self.read_jsonl("case_ground_truth.jsonl")
        event_truth = self.read_jsonl("event_ground_truth.jsonl")

        events = [
            event for case in cases for event in case["events"]
        ]

        self.assertEqual(len(events), 4)
        self.assertEqual(len(cases), 3)
        self.assertEqual(len(event_truth), 4)

        self.assertEqual(
            len({event["event_id"] for event in events}), 4
        )
        self.assertEqual(
            sum(
                event["source_event_id"] == "duplicate-ID"
                for event in events
            ),
            2,
        )

        self.assertEqual(
            sum(
                case["attack_event_count"] > 0
                and case["benign_event_count"] > 0
                for case in truth
            ),
            1,
        )

        evidence_text = json.dumps(cases)
        self.assertNotIn('"should_sample"', evidence_text)
        self.assertNotIn('"attack_name"', evidence_text)
        self.assertNotIn('"attack_associated"', evidence_text)

    def test_repeated_build_is_idempotent(self):
        self.write_dataset(self.sample_records())
        self.run_builder()

        original = (self.dest / "cases.jsonl").read_bytes()
        self.run_builder()

        self.assertEqual(
            original,
            (self.dest / "cases.jsonl").read_bytes(),
        )

    def test_modified_output_is_rejected(self):
        self.write_dataset(self.sample_records())
        self.run_builder()

        (self.dest / "cases.jsonl").write_text(
            "tampered\n", encoding="utf-8"
        )

        with self.assertRaisesRegex(ValueError, "differs"):
            self.run_builder()

    def test_invalid_ground_truth_type_rejected(self):
        record = make_record("123", "2026-11-04T02:05:00Z")
        record["should_sample"] = "true"
        self.write_dataset([record])

        with self.assertRaises(ValueError):
            self.run_builder()

    def test_gitignore_protection_required(self):
        self.write_dataset(self.sample_records())
        (self.root / ".gitignore").unlink()

        with self.assertRaisesRegex(ValueError, "Git-ignored"):
            self.run_builder()


if __name__ == "__main__":
    unittest.main()
