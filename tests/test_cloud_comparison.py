"""Regression tests for the three-arm comparison. No Ollama required."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from src.evaluation import run_cloud_comparison as m


def ev(i, action="GetObject", actor="someone"):
    return {"event_id": str(i), "action": action, "actor": actor, "event_source": "s3.amazonaws.com",
            "timestamp_utc": f"2026-11-01T12:00:{int(i)%60:02d}Z", "source_ip": "127.0.0.1", "error_code": None}


def case(i, count=1, action="GetObject"):
    return {"case_id": str(i), "events": [ev(i * 100 + k, action) for k in range(count)], "event_count": count, "correlation_method": "test"}


class ComparisonTests(unittest.TestCase):
    def setUp(self):
        self.cases = [case(1, 1), case(2, 3), case(3, 8), case(4, 2), case(5, 1), case(6, 7)]
        self.truth = {str(i): {"attack_associated": i <= 3, "scenario_names": [f"Scenario{i}"] if i <= 3 else [],
                  "attack_event_count": 1 if i <= 3 else 0, "benign_event_count": 0 if i <= 3 else 1} for i in range(1, 7)}

    def test_sample_has_known_attack_variety_and_benign(self):
        got = m.select_cases(self.cases, self.truth)
        self.assertEqual(len(got), 6)
        self.assertEqual({x["case_id"] for x in got}, {str(x) for x in range(1, 7)})

    def test_sample_reproducible(self):
        a = m.select_cases(self.cases, self.truth)
        b = m.select_cases(self.cases, self.truth)
        self.assertEqual([x["case_id"] for x in a], [x["case_id"] for x in b])

    def test_reject_label_leak(self):
        c = case(7)
        c["events"][0]["attack_associated"] = True
        with self.assertRaises(ValueError):
            m.case_view(c)

    def test_preserve_full_case_statistics_after_truncation(self):
        v = m.case_view(case(7, 30), max_events=5)
        self.assertTrue(v["evidence_truncated"])
        self.assertEqual(v["summary"]["action_counts_all_events"]["GetObject"], 30)
        self.assertEqual(len(v["events"]), 5)

    def test_baseline_high_volume(self):
        v = m.case_view(case(7, 30))
        self.assertEqual(m.baseline(v)["classification"], "suspicious")

    def test_baseline_no_rule_is_not_proof(self):
        v = m.case_view(case(7, 1))
        self.assertEqual(m.baseline(v)["classification"], "benign")
        self.assertIn("does not prove safety", m.baseline(v)["reasoning"])

    def test_evaluation_scores_and_abstention(self):
        z = m.metrics([{"prediction": "suspicious", "true_attack": True, "seconds": 2},
                       {"prediction": "suspicious", "true_attack": False, "seconds": 1},
                       {"prediction": "insufficient_evidence", "true_attack": True, "seconds": 3}])
        self.assertEqual(z["confusion"], {"tp": 1, "fp": 1, "tn": 0, "fn": 0})
        self.assertEqual(z["abstained"], 1)
        self.assertEqual(z["selective_precision"], 0.5)

    def test_retrieval_is_conditional_in_model_payload(self):
        v = m.case_view(case(7))
        generated = []
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): pass
        def fake_open(request, timeout):
            generated.append(json.loads(request.data))
            class Resp(Response):
                pass
            out = Resp()
            out.message = None
            return out
        # Simulate urlopen with one function that returns a readable JSON stream
        import io
        def open_req(req, timeout):
            generated.append(json.loads(req.data))
            return io.BytesIO(json.dumps({"message": {"content": json.dumps({"summary":"a", "classification":"benign", "reasoning":"b", "evidence_ids":[], "knowledge_ids":[], "next_checks":[]})}}).encode())
        with patch.object(m, "urlopen", side_effect=open_req):
            m.call_qwen(v, [{"id":"K1", "text":"S3 guidance"}], "llm_only")
            m.call_qwen(v, [{"id":"K1", "text":"S3 guidance"}], "rag")
        a = json.loads(generated[0]["messages"][1]["content"])
        b = json.loads(generated[1]["messages"][1]["content"])
        self.assertEqual(a["investigation_evidence"], b["investigation_evidence"])
        self.assertEqual(a["retrieved_references"], [])
        self.assertEqual(len(b["retrieved_references"]), 1)
        self.assertEqual(generated[0]["messages"][0], generated[1]["messages"][0])

    def test_invalid_citation_fails(self):
        import io
        bad = {"summary":"", "classification":"benign", "reasoning":"", "evidence_ids":["fake"], "knowledge_ids":[], "next_checks":[]}
        def open_req(*args, **kwargs):
            return io.BytesIO(json.dumps({"message": {"content": json.dumps(bad)}}).encode())
        with patch.object(m, "urlopen", side_effect=open_req):
            with self.assertRaisesRegex(ValueError, "citation"):
                m.call_qwen(m.case_view(case(7)), [], "llm_only")

    def test_json_failure_retries_with_larger_token_budget(self):
        import io
        generated = []
        good = {"summary":"Short result", "classification":"benign", "reasoning":"No rule indicated an incident", "evidence_ids":[], "knowledge_ids":[], "next_checks":[]}
        responses = [
            {"done_reason":"length", "eval_count":900, "message":{"content":"{\"summary\": \"unfinished"}},
            {"done_reason":"stop", "eval_count":180, "message":{"content":json.dumps(good)}},
        ]
        def open_req(req, timeout):
            generated.append(json.loads(req.data))
            return io.BytesIO(json.dumps(responses[len(generated)-1]).encode())
        with patch.object(m, "urlopen", side_effect=open_req):
            result = m.call_qwen(m.case_view(case(7)), [], "llm_only")
        self.assertEqual(result["classification"], "benign")
        self.assertEqual([x["options"]["num_predict"] for x in generated], [900, 1500])

    def test_malformed_json_retries_even_without_length_flag(self):
        import io
        generated = []
        good = {"summary":"OK", "classification":"insufficient_evidence", "reasoning":"Unknown", "evidence_ids":[], "knowledge_ids":[], "next_checks":[]}
        responses = [
            {"done_reason":"stop", "message":{"content":"{not valid json"}},
            {"done_reason":"stop", "message":{"content":json.dumps(good)}}
        ]
        def open_req(req, timeout):
            generated.append(json.loads(req.data))
            return io.BytesIO(json.dumps(responses[len(generated)-1]).encode())
        with patch.object(m, "urlopen", side_effect=open_req):
            report = m.call_qwen(m.case_view(case(7)), [], "llm_only")
        self.assertEqual(report["classification"], "insufficient_evidence")
        self.assertEqual(len(generated), 2)

    def test_two_bad_outputs_fail_closed(self):
        import io
        broken = {"done_reason":"length", "eval_count":900, "message":{"content":"{\"summary\":\"x"}}
        def open_req(req, timeout):
            return io.BytesIO(json.dumps(broken).encode())
        with patch.object(m, "urlopen", side_effect=open_req):
            with self.assertRaisesRegex(m.ModelOutputError, "two structured-output attempts"):
                m.call_qwen(m.case_view(case(7)), [], "rag")

    def test_invalid_citation_still_fails_without_fake_fallback(self):
        import io
        bad = {"summary":"x", "classification":"benign", "reasoning":"x", "evidence_ids":["invented"], "knowledge_ids":[], "next_checks":[]}
        def open_req(req, timeout):
            return io.BytesIO(json.dumps({"done_reason":"stop", "message":{"content":json.dumps(bad)}}).encode())
        with patch.object(m, "urlopen", side_effect=open_req):
            with self.assertRaisesRegex(m.ModelOutputError, "citation"):
                m.call_qwen(m.case_view(case(7)), [], "llm_only")


    def test_llm_only_schema_disallows_unprovided_knowledge_ids(self):
        import io
        captured = []
        good = {"summary":"x", "classification":"benign", "reasoning":"x", "evidence_ids":[], "knowledge_ids":[], "next_checks":[]}
        def fake_open(req, timeout):
            captured.append(json.loads(req.data))
            return io.BytesIO(json.dumps({"message":{"content":json.dumps(good)}}).encode())
        with patch.object(m, "urlopen", side_effect=fake_open):
            m.call_qwen(m.case_view(case(7)), [{"id":"REF-1", "text":"Knowledge"}], "llm_only")
        schema = captured[0]["format"]["properties"]["knowledge_ids"]
        self.assertEqual(schema["maxItems"], 0)
        self.assertEqual(json.loads(captured[0]["messages"][1]["content"])["retrieved_references"], [])
        self.assertIn("knowledge_ids MUST be an empty list", captured[0]["messages"][0]["content"])

    def test_rag_schema_only_allows_retrieved_reference_ids(self):
        import io
        captured = []
        good = {"summary":"x", "classification":"benign", "reasoning":"x", "evidence_ids":[], "knowledge_ids":["REF-1"], "next_checks":[]}
        def fake_open(req, timeout):
            captured.append(json.loads(req.data))
            return io.BytesIO(json.dumps({"message":{"content":json.dumps(good)}}).encode())
        with patch.object(m, "urlopen", side_effect=fake_open):
            m.call_qwen(m.case_view(case(7)), [{"id":"REF-1", "text":"Knowledge"}], "rag")
        schema = captured[0]["format"]["properties"]["knowledge_ids"]
        self.assertEqual(schema["items"]["enum"], ["REF-1"])
        self.assertEqual(schema["maxItems"], 1)

    def test_unprovided_knowledge_id_remains_rejected(self):
        import io
        bad = {"summary":"x", "classification":"benign", "reasoning":"x", "evidence_ids":[], "knowledge_ids":["HALLUCINATED"], "next_checks":[]}
        def fake_open(req, timeout):
            return io.BytesIO(json.dumps({"message":{"content":json.dumps(bad)}}).encode())
        with patch.object(m, "urlopen", side_effect=fake_open):
            with self.assertRaisesRegex(m.ModelOutputError, "Unknown or unprovided knowledge citation"):
                m.call_qwen(m.case_view(case(7)), [], "llm_only")

    def test_http_500_retried_then_valid_result(self):
        import io
        from urllib.error import HTTPError
        captured = []
        good = {"summary":"x", "classification":"benign", "reasoning":"x", "evidence_ids":[], "knowledge_ids":[], "next_checks":[]}
        def fake_open(req, timeout):
            captured.append(json.loads(req.data))
            if len(captured) == 1:
                raise HTTPError("http://127.0.0.1:11434/api/chat", 500, "Internal Server Error", {}, None)
            return io.BytesIO(json.dumps({"message":{"content":json.dumps(good)}}).encode())
        with patch.object(m, "urlopen", side_effect=fake_open), patch.object(m.time, "sleep"):
            result = m.call_qwen(m.case_view(case(7)), [], "llm_only")
        self.assertEqual(result["classification"], "benign")
        self.assertEqual(len(captured), 2)

    def test_http_400_not_retried(self):
        from urllib.error import HTTPError
        with patch.object(m, "urlopen", side_effect=HTTPError("http://local/api/chat", 400, "Bad Request", {}, None)) as mock:
            with self.assertRaises(HTTPError):
                m.call_qwen(m.case_view(case(7)), [], "llm_only")
        self.assertEqual(mock.call_count, 1)

    def test_prepare_only_makes_no_model_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(m, "call_qwen", side_effect=AssertionError("no model in preparation")):
                result = m.run(self.cases, self.truth, Path(tmp), only_prepare=True)
            self.assertEqual(result["cases"], 6)
            self.assertTrue((Path(tmp) / "manifest.json").exists())
            self.assertFalse((Path(tmp) / "comparison_metrics_PRIVATE.json").exists())


if __name__ == "__main__":
    unittest.main()
