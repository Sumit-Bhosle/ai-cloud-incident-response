"""Tests for Linux journal parsing and normalization.

These fixtures are synthetic and contain no private logs.
"""

import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "ingestion"))

from normalize_linux_journal import (
    parse_journal_export,
    normalize_record,
)


class LinuxJournalNormalizerTests(unittest.TestCase):

    def make_record(self, message, pid="4927"):
        return {
            "__CURSOR": "synthetic-test-cursor-001",
            "__REALTIME_TIMESTAMP": "1700000000000000",
            "_PID": pid,
            "SYSLOG_IDENTIFIER": "su",
            "MESSAGE": message,
        }

    def test_parse_two_text_records(self):
        raw = (
            b"__CURSOR=synthetic-1\n"
            b"MESSAGE=first\n\n"
            b"__CURSOR=synthetic-2\n"
            b"MESSAGE=second\n\n"
        )

        records = parse_journal_export(raw)

        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["MESSAGE"], "first")
        self.assertEqual(records[1]["MESSAGE"], "second")

    def test_parse_binary_journal_field(self):
        message = b"synthetic\nmultiline message"

        raw = (
            b"__CURSOR=synthetic-1\n"
            b"MESSAGE\n"
            + struct.pack("<Q", len(message))
            + message
            + b"\n\n"
        )

        records = parse_journal_export(raw)

        self.assertEqual(len(records), 1)
        self.assertEqual(
            records[0]["MESSAGE"],
            "synthetic\nmultiline message",
        )

    def test_authentication_failure_normalization(self):
        record = self.make_record(
            "pam_unix(su-l:auth): authentication failure; "
            "logname=demo uid=1000 euid=0 "
            "tty=/dev/pts/0 ruser=demo rhost=  user=root"
        )

        event = normalize_record(
            record,
            1,
            "data/lab_evidence/example.journal-export",
            4927,
        )

        self.assertEqual(
            event["event_type"],
            "authentication_failure",
        )
        self.assertEqual(event["actor"], "demo")
        self.assertEqual(event["target"], "root")
        self.assertEqual(event["observed_outcome"], "failed")
        self.assertEqual(
            event["timestamp_utc"],
            "2023-11-14T22:13:20Z",
        )
        self.assertEqual(
            event["event_id"],
            "PFL-001-RUN-001-EVT-001",
        )

    def test_failed_user_switch_normalization(self):
        record = self.make_record(
            "FAILED SU (to root) demo on pts/0"
        )

        event = normalize_record(
            record,
            2,
            "data/lab_evidence/example.journal-export",
            4927,
        )

        self.assertEqual(
            event["event_type"],
            "user_switch_failure",
        )
        self.assertEqual(event["actor"], "demo")
        self.assertEqual(event["target"], "root")
        self.assertEqual(
            event["event_id"],
            "PFL-001-RUN-001-EVT-002",
        )

    def test_wrong_process_id_rejected(self):
        record = self.make_record(
            "FAILED SU (to root) demo on pts/0",
            pid="9999",
        )

        with self.assertRaisesRegex(
            ValueError, "Unexpected source process ID"
        ):
            normalize_record(record, 1, "example.log", 4927)

    def test_missing_journal_cursor_rejected(self):
        record = self.make_record(
            "FAILED SU (to root) demo on pts/0"
        )

        del record["__CURSOR"]

        with self.assertRaisesRegex(
            ValueError, "Missing journal field"
        ):
            normalize_record(record, 1, "example.log", 4927)

    def test_unknown_event_rejected(self):
        record = self.make_record(
            "A completely unrelated synthetic message"
        )

        with self.assertRaisesRegex(
            ValueError, "Unrecognized journal event"
        ):
            normalize_record(record, 1, "example.log", 4927)


if __name__ == "__main__":
    unittest.main()
