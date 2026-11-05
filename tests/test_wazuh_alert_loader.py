"""Unit tests for the Wazuh JSONL alert loader."""

import json
import tempfile
import unittest
from pathlib import Path

from src.ingestion.normalize_wazuh_alerts import load_wazuh_alerts


class WazuhAlertLoaderTests(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.source = Path(self.temp.name) / "alerts.jsonl"

    def tearDown(self):
        self.temp.cleanup()

    def write_records(self, records):
        self.source.write_text(
            "\n".join(records) + "\n",
            encoding="utf-8",
        )

    def test_two_valid_alerts(self):
        self.write_records([
            json.dumps({"id": "alert-001"}),
            json.dumps({"id": "alert-002"}),
        ])

        alerts = load_wazuh_alerts(self.source)

        self.assertEqual(len(alerts), 2)
        self.assertEqual(alerts[0]["id"], "alert-001")

    def test_malformed_json_rejected(self):
        self.write_records(['{"id": "broken"'])

        with self.assertRaises(ValueError):
            load_wazuh_alerts(self.source)

    def test_duplicate_alert_ids_rejected(self):
        self.write_records([
            json.dumps({"id": "same-id"}),
            json.dumps({"id": "same-id"}),
        ])

        with self.assertRaisesRegex(ValueError, "Duplicate"):
            load_wazuh_alerts(self.source)

    def test_missing_alert_id_rejected(self):
        self.write_records([
            json.dumps({"rule": {"id": "5503"}}),
        ])

        with self.assertRaisesRegex(ValueError, "Missing alert ID"):
            load_wazuh_alerts(self.source)

    def test_non_object_record_rejected(self):
        self.write_records([
            json.dumps(["not", "an", "object"]),
        ])

        with self.assertRaises(ValueError):
            load_wazuh_alerts(self.source)

    def test_empty_file_rejected(self):
        self.source.write_text("", encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "No Wazuh alerts"):
            load_wazuh_alerts(self.source)

    def test_blank_lines_ignored(self):
        self.source.write_text(
            '\n{"id": "alert-001"}\n\n',
            encoding="utf-8",
        )

        alerts = load_wazuh_alerts(self.source)

        self.assertEqual(len(alerts), 1)


if __name__ == "__main__":
    unittest.main()
