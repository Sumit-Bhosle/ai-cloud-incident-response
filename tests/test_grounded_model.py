"""Unit tests of guarded prompt contracts and printable business reporting."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from src.demo import soc_demo as d
from src.demo import grounded_model as g
from src.demo import executive_html as h
from src.demo import wazuh_pipeline as p


class GroundedPromptTests(unittest.TestCase):
    def test_model_never_sees_truth_or_rule_severity(self):
        cases, _, _ = d.make_cases()
        case = {**cases[7], "correlation_method": "verified_wazuh_sim_case_id"}
        for row in case["events"]:
            row["wazuh_rule_level"] = 12
        system, prompt = g._prompt(case, [])
        self.assertNotIn("class_label", prompt)
        self.assertNotIn("wazuh_level", prompt)
        self.assertNotIn('"wazuh_rule_level"', prompt)
        self.assertIn("StopLogging", prompt)
        self.assertIn("DeleteTrail", prompt)
        self.assertEqual(json.loads(prompt)["allowed_knowledge_ids"], [])

    def test_html_escapes_untrusted_case_text(self):
        case = {"case_id": "SOCSIM-<script>", "guardrails": {"evidence_based_triage": "critical",
                "priority_review": True, "model_adjudication": {"llm_only": {"flags": []}, "rag": {"flags": []}},
                "factual_findings": [{"title": "Not <script>", "observation": "No compromise established",
                                      "business_risk": "Potential impact", "recommended_checks": ["Human check"],
                                      "evidence_ids": ["ID-01"]}]}, "observed_actions": ["StopLogging"],
                "event_count": 1, "results": {"llm_only": {"prediction": "benign"},
                                              "rag": {"prediction": "suspicious"}}}
        scores = {name: {"correct": 0, "failures_or_abstentions": 0} for name in
                  ("baseline", "llm_only", "rag")}
        html = h.render_html([case], {"methods": scores, "ingestion_audit": {"verified_unique_events": 1}})
        self.assertIn("SOCSIM-&lt;script&gt;", html)
        self.assertNotIn("SOCSIM-<script>", html)
        self.assertIn("Human check", html)

    def test_grounded_model_rejects_hallucinated_ids(self):
        cases, _, _ = d.make_cases()
        case = cases[0]
        invalid = {"classification": "benign", "summary": "routine", "reasoning": "routine",
                   "evidence_ids": ["FABRICATED"], "knowledge_ids": [], "next_checks": []}
        # Contract does not accept nonexistent evidence references, independent of the model.
        with self.assertRaises(ValueError):
            d.validate_ai(invalid, case, [])


if __name__ == "__main__":
    unittest.main()
