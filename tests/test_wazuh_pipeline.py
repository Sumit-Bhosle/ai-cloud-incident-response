"""Offline tests: no Wazuh manager or Ollama required."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from src.demo import soc_demo as d
from src.demo import wazuh_pipeline as p


class TestWazuhLinkedPipeline(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.evidence = self.root / "evidence"
        self.out = self.root / "result"
        d.prepare(self.evidence)
        self.cases = d.read_jsonl(self.evidence / "cases.jsonl")
        self.wazuh = d.read_jsonl(self.evidence / "wazuh_events.jsonl")
        self.alerts = self.root / "alerts.json"
        self.make_alerts(self.wazuh)

    def make_alerts(self, records):
        alerts = []
        for i, record in enumerate(records):
            action = record["action"]
            tier = "110102" if action in d.HIGH_RISK else "110101" if action in {"ConsoleLogin", "GetBucketPolicy", "GetBucketAcl", "GetObject"} else "110100"
            level = 12 if tier == "110102" else 8 if tier == "110101" else 3
            alerts.append({"id": f"alert-{i}", "timestamp": "2026-11-09T02:02:02.000-0500",
                           "data": record, "rule": {"id": tier, "level": level}, "location": "/var/log/soc_demo_cloud.jsonl"})
        d.write_jsonl(self.alerts, alerts)

    def test_verified_400_and_100_complete(self):
        cases, grouped, audit = p.load_verified_wazuh(self.alerts, self.evidence)
        self.assertEqual(len(cases), 100)
        self.assertEqual(len(grouped), 100)
        self.assertEqual(audit["verified_unique_events"], 400)
        self.assertEqual(audit["complete_cases"], 100)
        self.assertEqual(audit["mismatch_count"], 0)

    def test_missing_3_skips_first_case(self):
        self.make_alerts(self.wazuh[3:])
        _, grouped, audit = p.load_verified_wazuh(self.alerts, self.evidence)
        self.assertEqual(audit["verified_unique_events"], 397)
        self.assertEqual(audit["complete_cases"], 99)
        self.assertIn("SOCSIM-001", audit["partial_or_absent_case_ids"])
        self.assertNotIn("SOCSIM-001", grouped)

    def test_tampering_blocked(self):
        corrupt = dict(self.wazuh[0])
        corrupt["actor"] = "not-the-source-actor"
        self.make_alerts([corrupt])
        _, _, audit = p.load_verified_wazuh(self.alerts, self.evidence)
        self.assertEqual(audit["verified_unique_events"], 0)
        self.assertEqual(audit["mismatch_count"], 1)

    def test_unexpected_rule_not_trusted(self):
        self.make_alerts([self.wazuh[0]])
        rows = d.read_jsonl(self.alerts)
        rows[0]["rule"]["id"] = "999"
        d.write_jsonl(self.alerts, rows)
        _, _, audit = p.load_verified_wazuh(self.alerts, self.evidence)
        self.assertEqual(audit["verified_unique_events"], 0)
        self.assertEqual(audit["mismatch_count"], 1)

    def test_duplicate_alerts_counted_once(self):
        self.make_alerts([self.wazuh[0], self.wazuh[0]])
        _, _, audit = p.load_verified_wazuh(self.alerts, self.evidence)
        self.assertEqual(audit["verified_unique_events"], 1)
        self.assertEqual(audit["duplicate_alert_records"], 1)

    def test_model_case_is_from_alerts_no_truth(self):
        _, grouped, _ = p.load_verified_wazuh(self.alerts, self.evidence)
        case = p.normalise_wazuh_case("SOCSIM-008", grouped["SOCSIM-008"])
        self.assertEqual(case["correlation_method"], "verified_wazuh_sim_case_id")
        self.assertEqual({e["event_id"] for e in case["events"]},
                         {"SOCSIM-008-EVT-01", "SOCSIM-008-EVT-02", "SOCSIM-008-EVT-03"})
        self.assertNotIn("critical", json.dumps(case))
        self.assertNotIn("class_label", json.dumps(case))
        self.assertIn("wazuh_rule_id", case["events"][0])

    def test_cloudtrail_delete_is_not_s3_delete(self):
        _, grouped, _ = p.load_verified_wazuh(self.alerts, self.evidence)
        case = p.normalise_wazuh_case("SOCSIM-008", grouped["SOCSIM-008"])
        findings = p.observable_findings(case)
        self.assertTrue(any("Cloud audit-log" in x["title"] for x in findings))
        self.assertNotIn("S3 bucket deletion", json.dumps(findings))
        issues = p.check_model_claims({"summary": "This shows deletion of an S3 bucket", "reasoning": ""}, case)
        self.assertIn("unsupported_bucket_deletion_claim", issues)

    def test_signins_and_bruteforce_unverified(self):
        _, grouped, _ = p.load_verified_wazuh(self.alerts, self.evidence)
        case = p.normalise_wazuh_case("SOCSIM-005", grouped["SOCSIM-005"])
        notes = p.observable_findings(case)
        self.assertTrue(any("failed console" in x["title"].lower() for x in notes))
        self.assertIn("not confirmed", json.dumps(notes))

    def test_underrating_critical_is_blocked(self):
        _, grouped, _ = p.load_verified_wazuh(self.alerts, self.evidence)
        case = p.normalise_wazuh_case("SOCSIM-008", grouped["SOCSIM-008"])
        raw = {"llm_only": {"prediction": "benign", "evidence_ids": [case["events"][0]["event_id"]]},
               "rag": {"prediction": "suspicious", "evidence_ids": [case["events"][0]["event_id"]]}}
        safe = p.analyst_guardrail(case, raw)
        self.assertEqual(safe["evidence_based_triage"], "critical")
        self.assertTrue(safe["priority_review"])
        self.assertIn("model_underrates_evidence_based_risk", safe["model_adjudication"]["llm_only"]["flags"])

    def fake_ai(self, case, refs, model):
        self.assertNotIn("class_label", json.dumps(case))
        self.assertEqual(case["correlation_method"], "verified_wazuh_sim_case_id")
        # Deliberately incorrect simulated model output; guardrail must catch.
        item = {"classification": "benign", "summary": "A routine event", "reasoning": "No issue", "evidence_ids":
                [case["events"][0]["event_id"]], "knowledge_ids": [], "next_checks": ["Review account"]}
        return item, 0.01

    def test_case_run_resume_truth_scored_only_after(self):
        result = p.execute(self.alerts, self.evidence, self.out, case_id="SOCSIM-008", ai_func=self.fake_ai, root=self.root)
        self.assertEqual(result["newly_investigated"], 1)
        report = json.loads((self.out / "cases/SOCSIM-008.json").read_text())
        self.assertEqual(report["origin"], "verified_wazuh_synthetic_alert_records")
        self.assertEqual(report["results"]["llm_only"]["prediction"], "benign")
        self.assertEqual(report["guardrails"]["evidence_based_triage"], "critical")
        self.assertNotIn("class_label", json.dumps(report))
        # Cached reports are never overwritten or secretly re-evaluated.
        again = p.execute(self.alerts, self.evidence, self.out, case_id="SOCSIM-008", ai_func=self.fake_ai, root=self.root)
        self.assertEqual(again["cached"], 1)
        self.assertEqual(again["newly_investigated"], 0)
        scores = p.score_cached(self.evidence, self.out)
        self.assertEqual(scores["sample_cases"], 1)
        self.assertEqual(scores["methods"]["llm_only"]["correct"], 0)
        self.assertEqual(scores["methods"]["baseline"]["correct"], 1)
        md = (self.out / "EXECUTIVE_REPORT_REVIEW_REQUIRED.md").read_text()
        self.assertIn("Wazuh-Linked", md)
        self.assertIn("SOCSIM-008", md)
        self.assertIn("Cloud audit-log disruption indicators", md)

    def test_model_failure_fails_open_to_human_review_not_benign(self):
        def failing(case, refs, model):
            raise RuntimeError("model endpoint offline")
        p.execute(self.alerts, self.evidence, self.out, case_id="SOCSIM-008", ai_func=failing, root=self.root)
        row = json.loads((self.out / "cases/SOCSIM-008.json").read_text())
        self.assertIsNone(row["results"]["rag"]["prediction"])
        self.assertTrue(row["guardrails"]["priority_review"])
        self.assertEqual(row["guardrails"]["evidence_based_triage"], "critical")

    def test_watch_once_automatic(self):
        processed = p.watch(self.alerts, self.evidence, self.out, case_id="SOCSIM-009", once=True,
                            ai_func=self.fake_ai, root=self.root)
        self.assertEqual(processed, 1)
        self.assertTrue((self.out / "cases/SOCSIM-009.json").exists())

    def test_incomplete_case_never_scored(self):
        self.make_alerts(self.wazuh[1:])
        status = p.execute(self.alerts, self.evidence, self.out, case_id="SOCSIM-001", ai_func=self.fake_ai)
        self.assertEqual(status["newly_investigated"], 0)
        self.assertFalse((self.out / "cases/SOCSIM-001.json").exists())


if __name__ == "__main__":
    unittest.main()

class PublishSafetyTests(unittest.TestCase):
    def test_publisher_refuses_unverified_results(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "publisher", Path(__file__).resolve().parents[1] / "tools/publish_wazuh_milestone.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            with self.assertRaises(FileNotFoundError):
                module.publish(root / "missing.json", root)
            fake = root / "fake.json"
            fake.write_text(json.dumps({"sample_cases": 0}))
            with self.assertRaises(ValueError):
                module.publish(fake, root)
