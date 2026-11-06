"""Phase 100 deterministic review tests; no AI inference or private data."""
import copy
import hashlib
import json
import unittest

from src.evaluation.verify_cloud_ai_report import (
    evidence_ledger, review_artifact, screen_language,
)
from src.investigation.cloud_case_investigator import make_payload


def sample_case():
    return {
        "case_id": "CLOUD-DEV-CASE-" + "a" * 16,
        "event_count": 3,
        "events": [
            {
                "event_id": f"CLOUD-DEV-EVT-{n:06d}",
                "timestamp_utc": f"2026-11-04T02:0{n}:00Z",
                "event_source": "ssm.amazonaws.com",
                "action": action,
                "actor": "test-role",
                "source_ip": "192.0.2.10",
                "aws_region": "us-east-1",
                "error_code": None,
                "resources": [],
            }
            for n, action in enumerate(
                ["UpdateInstanceInformation", "ListInstanceAssociations", "UpdateInstanceInformation"], 1
            )
        ],
    }


def fixture():
    case = sample_case()
    documents = [{"id": "AWS-CLOUDTRAIL", "title": "CloudTrail", "summary": "API log", "url": "https://example.org", "services": ["all"]}]
    payload = make_payload(case, documents)
    artifact = {
        "case_id": case["case_id"],
        "case_sha256": hashlib.sha256(json.dumps(case, sort_keys=True).encode()).hexdigest(),
        "events_total": 3,
        "events_presented": 3,
        "retrieved_knowledge_ids": ["AWS-CLOUDTRAIL"],
        "model": "qwen2.5:1.5b",
        "report": {
            "summary": "Three SSM API records are present.",
            "classification": "insufficient_evidence",
            "reasoning": "No conclusion can be established from these records alone.",
            "evidence_ids": ["CLOUD-DEV-EVT-000001", "CLOUD-DEV-EVT-000003"],
            "knowledge_ids": ["AWS-CLOUDTRAIL"],
            "next_checks": ["Check actor authorization"],
        },
    }
    return case, documents, payload, artifact


class CloudAIReportVerifierTests(unittest.TestCase):
    def test_valid_artifact_has_limited_verification(self):
        case, docs, _, artifact = fixture()
        review = review_artifact(artifact, case, docs)
        self.assertEqual(review["review_status"], "limited_automatic_checks_passed")
        self.assertFalse(review["citations_are_claim_level_verified"])

    def test_evidence_ledger_has_independent_action_counts(self):
        case, _, payload, _ = fixture()
        ledger = evidence_ledger(case, payload)
        counts = {row["action"]: row["count"] for row in ledger["action_counts_from_full_case"]}
        self.assertEqual(counts["UpdateInstanceInformation"], 2)
        self.assertEqual(counts["ListInstanceAssociations"], 1)

    def test_case_hash_mismatch_rejected(self):
        case, docs, _, artifact = fixture()
        artifact["case_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            review_artifact(artifact, case, docs)

    def test_unknown_event_citation_rejected(self):
        case, docs, _, artifact = fixture()
        artifact["report"]["evidence_ids"] = ["FAKE-EVENT"]
        with self.assertRaisesRegex(ValueError, "unknown or unpresented"):
            review_artifact(artifact, case, docs)

    def test_unretrieved_knowledge_citation_rejected(self):
        case, docs, _, artifact = fixture()
        artifact["report"]["knowledge_ids"] = ["NOT-RETRIEVED"]
        with self.assertRaisesRegex(ValueError, "unretrieved"):
            review_artifact(artifact, case, docs)

    def test_missing_error_does_not_prove_success(self):
        _, _, payload, artifact = fixture()
        artifact["report"]["reasoning"] = (
            "The absence of an error code in these events suggests that operations were successful."
        )
        codes = {r["code"] for r in screen_language(artifact["report"], payload)}
        self.assertIn("ERROR_ABSENCE_USED_AS_SUCCESS_PROOF", codes)

    def test_false_claim_that_source_ip_is_unavailable(self):
        _, _, payload, artifact = fixture()
        artifact["report"]["summary"] = (
            "The source IP address is 192.0.2.10, which is not provided with the event IDs."
        )
        codes = {r["code"] for r in screen_language(artifact["report"], payload)}
        self.assertIn("SOURCE_IP_REPORTED_UNAVAILABLE", codes)

    def test_suspicious_result_requires_review(self):
        case, docs, _, artifact = fixture()
        artifact["report"]["classification"] = "suspicious"
        review = review_artifact(artifact, case, docs)
        self.assertEqual(review["review_status"], "manual_review_required")
        self.assertIn("POSITIVE_CLASSIFICATION_REQUIRES_CORROBORATION", [f["code"] for f in review["flags"]])

    def test_truncated_view_requires_review(self):
        case, docs, _, artifact = fixture()
        extra = []
        for i in range(4, 30):
            e = copy.deepcopy(case["events"][0])
            e["event_id"] = f"CLOUD-DEV-EVT-{i:06d}"
            e["timestamp_utc"] = f"2026-11-04T03:{i:02d}:00Z"
            extra.append(e)
        case["events"].extend(extra)
        case["event_count"] = len(case["events"])
        payload = make_payload(case, docs)
        codes = {r["code"] for r in screen_language(artifact["report"], payload)}
        self.assertIn("INCOMPLETE_MODEL_VIEW", codes)

    def test_ground_truth_fields_rejected(self):
        case, docs, _, artifact = fixture()
        case["events"][0]["attack_name"] = "PrivateLabel"
        with self.assertRaisesRegex(ValueError, "Ground-truth"):
            review_artifact(artifact, case, docs)

    def test_mismatched_retrieval_rejected(self):
        case, docs, _, artifact = fixture()
        artifact["retrieved_knowledge_ids"] = ["OTHER"]
        with self.assertRaisesRegex(ValueError, "knowledge IDs differ"):
            review_artifact(artifact, case, docs)


if __name__ == "__main__":
    unittest.main()
