"""Isolated leakage / coverage / scoring tests: no real datasets needed."""
import json
import tempfile
import unittest
from pathlib import Path

from src.evaluation import evaluate_cloud_investigations as ev


class CloudInvestigationEvaluationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.reports = self.root / "ai_reports"
        self.reports.mkdir()
        self.cases = []
        self.truth = []
        for ident, attack in (("A", True), ("B", False), ("C", True), ("D", False)):
            self.cases.append({"case_id": ident, "event_count": 1, "events": [{"event_id": f"EV-{ident}", "action": "GetObject"}]})
            self.truth.append({"case_id": ident, "attack_associated": attack,
                               "attack_event_count": int(attack), "benign_event_count": int(not attack), "scenario_names": []})
        self.save_data()

    def save_data(self):
        for filename, records in (("cases.jsonl", self.cases), ("case_ground_truth.jsonl", self.truth)):
            (self.root / filename).write_text("\n".join(json.dumps(x) for x in records) + "\n")

    def add_report(self, ident, classification, directory=None, evidence_ids=None):
        directory = directory or self.reports
        directory.mkdir(exist_ok=True)
        artifact = {
            "case_id": ident, "case_sha256": "abc123", "events_total": 1,
            "events_presented": 1, "inference_seconds": 1.25,
            "retrieved_knowledge_ids": ["AWS-CLOUDTRAIL"],
            "report": {"classification": classification,
                       "evidence_ids": evidence_ids if evidence_ids is not None else [f"EV-{ident}"],
                       "knowledge_ids": ["AWS-CLOUDTRAIL"], "summary": "test"},
        }
        (directory / f"{ident}.json").write_text(json.dumps(artifact))

    def test_sample_coverage_not_global_accuracy(self):
        self.add_report("A", "suspicious")
        self.add_report("B", "suspicious")
        self.add_report("C", "insufficient_evidence")
        result = ev.evaluate(self.root, {"llm": self.reports})["methods"]["llm"]
        self.assertEqual((result["reports"], result["answered"], result["abstained"], result["missing_reports"]), (3, 2, 1, 1))
        self.assertEqual(result["confusion_on_answered_only"], {"tp": 1, "fp": 1, "tn": 0, "fn": 0})
        self.assertEqual(result["selective_precision"], 0.5)
        self.assertEqual(result["case_coverage"], 0.75)

    def test_missing_report_not_counted_as_benign(self):
        self.add_report("A", "benign")
        m = ev.evaluate(self.root, {"llm": self.reports})["methods"]["llm"]
        self.assertEqual(m["confusion_on_answered_only"]["fn"], 1)
        self.assertEqual(m["confusion_on_answered_only"]["tn"], 0)
        self.assertEqual(m["missing_reports"], 3)

    def test_duplicate_case_ids_rejected(self):
        self.cases.append(self.cases[0])
        self.save_data()
        with self.assertRaisesRegex(ValueError, "duplicate"):
            ev.evaluate(self.root, {"llm": self.reports})

    def test_label_leakage_rejected(self):
        self.cases[0]["events"][0]["attack_associated"] = True
        self.save_data()
        with self.assertRaisesRegex(ValueError, "leakage"):
            ev.evaluate(self.root, {"llm": self.reports})

    def test_mixed_case_supported(self):
        self.cases[0]["event_count"] = 2
        self.cases[0]["events"].append({"event_id": "EV-A-2"})
        self.truth[0]["benign_event_count"] = 1
        self.save_data()
        self.assertEqual(ev.evaluate(self.root, {"llm": self.reports})["mixed_label_cases"], 1)


    def test_mixed_case_count_not_event_count(self):
        self.cases[0]["event_count"] = 6
        self.cases[0]["events"].extend(
            {"event_id": f"EV-A-{n}"} for n in range(2, 7)
        )
        self.truth[0]["benign_event_count"] = 5
        self.save_data()
        result = ev.evaluate(self.root, {"llm": self.reports})
        self.assertEqual(result["mixed_label_cases"], 1)

    def test_no_paired_comparison_for_one_method(self):
        self.add_report("A", "suspicious")
        paired = ev.evaluate(
            self.root, {"llm": self.reports}
        )["paired_comparison"]
        self.assertFalse(paired["available"])
        self.assertIsNone(paired["shared_case_count"])
        self.assertEqual(paired["shared_cases_only"], {})

    def test_inconsistent_labels_rejected(self):
        self.truth[0]["attack_associated"] = False
        self.save_data()
        with self.assertRaisesRegex(ValueError, "Inconsistent"):
            ev.evaluate(self.root, {"llm": self.reports})

    def test_bad_citation_counted_not_silently_discarded(self):
        self.add_report("A", "suspicious", evidence_ids=["NOT-IN-CASE"])
        m = ev.evaluate(self.root, {"llm": self.reports})["methods"]["llm"]
        self.assertEqual(m["citation_membership_passes"], 0)
        self.assertEqual(m["confusion_on_answered_only"]["tp"], 1)

    def test_verification_hash_mismatch_rejected(self):
        self.add_report("A", "suspicious")
        (self.reports / "A.verification.json").write_text(json.dumps({"case_id": "A", "source_case_sha256": "wrong", "flags": []}))
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            ev.evaluate(self.root, {"llm": self.reports})

    def test_verification_review_flags(self):
        self.add_report("A", "suspicious")
        (self.reports / "A.verification.json").write_text(json.dumps({
            "case_id": "A", "source_case_sha256": "abc123", "review_status": "manual_review_required", "flags": [{"code": "ERROR_ABSENCE_USED_AS_SUCCESS_PROOF"}]}))
        m = ev.evaluate(self.root, {"llm": self.reports})["methods"]["llm"]
        self.assertEqual(m["manual_review_required"], 1)
        self.assertEqual(m["review_flag_counts"]["ERROR_ABSENCE_USED_AS_SUCCESS_PROOF"], 1)

    def test_paired_comparison_only_common_cases(self):
        second = self.root / "rag"
        self.add_report("A", "suspicious")
        self.add_report("B", "benign")
        self.add_report("A", "benign", directory=second)
        r = ev.evaluate(self.root, {"llm": self.reports, "rag": second})
        self.assertEqual(r["paired_comparison"]["shared_case_count"], 1)
        self.assertEqual(r["paired_comparison"]["shared_cases_only"]["rag"]["confusion_on_answered_only"]["fn"], 1)

    def test_empty_reports_do_not_generate_fake_metrics(self):
        m = ev.evaluate(self.root, {"llm": self.reports})["methods"]["llm"]
        self.assertEqual(m["reports"], 0)
        self.assertIsNone(m["selective_accuracy"])
        self.assertEqual(m["missing_reports"], 4)

    def test_unknown_classification_rejected(self):
        self.add_report("A", "maybe_attack???")
        with self.assertRaisesRegex(ValueError, "Unsupported"):
            ev.evaluate(self.root, {"llm": self.reports})


if __name__ == "__main__":
    unittest.main()
