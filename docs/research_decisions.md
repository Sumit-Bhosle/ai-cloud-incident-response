# Research and Technical Decision Log

## Research Topic

Evaluating AI-Assisted Cloud Security Incident Response

## Purpose

Record important research and implementation decisions, their rationale,
alternatives considered, limitations, and current status.

Decisions may change as the literature review, compatibility checks, and
experimental evidence develop. Changes must be documented rather than hidden.

---

## RD-001 — Evaluate AI Assistance Rather Than Only Build a Copilot

**Status:** Adopted

**Decision:** Evaluate AI-assisted incident investigation against a
non-AI baseline.

**Rationale:** Building an AI tool alone would not establish whether it
improves investigation outcomes. A baseline allows measurable comparison.

**Planned evaluation dimensions:**
- Investigation classification accuracy.
- Reliability and unsupported claims.
- Evidence grounding and explainability.
- Investigation efficiency.

**Limitation:** Final metrics and scoring rules still need to be specified
before formal experiments.

---

## RD-002 — Start With Synthetic Data

**Status:** Adopted for the initial pilot

**Decision:** Begin with manually authored synthetic cloud-audit-style events.

**Rationale:** Synthetic data allows local development without paid cloud
services or exposure of production security logs.

**Trade-off:** Synthetic events are simplified and may not represent real
cloud telemetry, realistic incident diversity, or operational noise.

**Follow-up:** Expand scenario coverage and assess ground-truth quality before
drawing research conclusions.

---

## RD-003 — Separate Ground Truth From Event Records

**Status:** Adopted

**Decision:** Store expected scenario labels separately from raw synthetic
events.

**Rationale:** This supports reproducible evaluation and makes the expected
answers explicit.

**Limitation:** Current labels were manually authored and have not undergone
independent expert review.

---

## RD-004 — Establish a Non-AI Baseline Before AI Integration

**Status:** Adopted; implementation pending

**Decision:** Implement a deterministic Python investigation workflow before
integrating a local language model.

**Rationale:** A transparent baseline provides a comparison point and helps
separate the effects of explicit rules from AI-generated findings.

**Planned output:** Structured classifications, supporting event IDs, and
evaluation results.

**Limitation:** Rule-based performance has not yet been measured.

---

## RD-005 — Keep the Research Environment Local and Cost-Conscious

**Status:** Adopted

**Decision:** Prioritize free local tools and avoid requiring paid cloud
subscriptions for the initial experiments.

**Rationale:** The Research Topic should remain accessible and reproducible within
the available computing environment.

**Constraints:** The current Ubuntu VM has approximately 7.2 GiB of reported
RAM. Wazuh and local language-model requirements must be checked before
installation or integration.

**Alternatives:** A simulated cloud-audit dataset can support early research
without provisioning a real cloud account.

---

## RD-006 — Retain Human Responsibility for Decisions

**Status:** Adopted

**Decision:** Treat AI outputs as recommendations requiring verification,
not as authoritative conclusions or automatic remediation instructions.

**Rationale:** Security investigation findings must be traceable to evidence,
and unsupported AI claims must be identified.

**Planned evaluation:** Record evidence supporting each finding and identify
unsupported or contradicted claims.

---

## RD-007 — Maintain Versioned and Reproducible Research Records

**Status:** Adopted

**Decision:** Use Git and GitHub to version source code, dataset documentation,
development history, experiment records, and research decisions.

**Rationale:** Version history helps trace implementation changes and connect
experimental results to the code and data used.

**Current evidence:**
- Initial Research Topic commit: 62cdf54
- Development log commit: 50795dd

**Follow-up:** Record relevant commit IDs and configurations for each
meaningful experiment.

---

## RD-008 — Treat Wazuh and Local LLM Integration as Pending

**Status:** Pending compatibility and resource assessment

**Decision:** Do not assume Wazuh or a local language model is installed or
working until installation and functional tests confirm it.

**Rationale:** The Research Topic should prioritize a working, testable research
pipeline and avoid unsupported compatibility assumptions.

**Next action:** Build and validate the Python baseline first, then reassess
integration requirements.

---

## Change History

When a decision changes, record the date, previous decision, new decision,
reason for change, and any effect on completed experiments or conclusions.

---

## RD-009 — Preserve Frozen Holdout Results and Version Future Improvements

**Date:** October 30, 2026
**Status:** Adopted

**Decision:** Preserve the first-run Experiment 005 results, the frozen holdout dataset, and the existing deterministic V1/V2 investigators.

**Rationale:** The observed mismatches are legitimate research findings. Modifying the investigators or test cases after observing results would undermine the interpretation of the original comparison.

**Evidence:**
- Frozen dataset commit: `d2f1535`.
- V1 matched 7/10 provisional labels.
- V2 matched 9/10 provisional labels.
- V2 did not recognize the longer benign sequence in HLD-008.

**Future development:** Any improved deterministic investigator must use a separate version and evaluation record. Reusing the existing holdout after inspecting its results must be identified as retrospective testing, not a new independent holdout.

**Research boundary:** No AI-assisted system has been implemented or evaluated yet. The current results describe deterministic baseline behavior only.

<!-- DECISION-2026-11-04-AI-CLOUD -->

## Research design decision — 2026-11-04 | AI-first incident investigation, not SIEM-only

**Decision:** Wazuh remains a verified monitoring/detection input; the Research Topic's evaluated research contribution is the **evidence-grounded AI investigation** workflow, not a new SIEM implementation.

**Dataset design:** Use controlled Linux/Wazuh evidence to demonstrate live ingestion and use labeled AWS CloudTrail records for cloud-security evaluation. Use the provided development split for architecture iteration and hold the designated test split for final evaluation. Disclose that test-set summary statistics were inspected during development.

**Unit of analysis:** Track event-level input and case-level investigation separately. Do not call 2,585 attack-labeled log records 2,585 independent compromises. First correlation heuristic is `actor + source IP + 30-minute window`; validate its splits/merges before claiming incident grouping quality.

**Study conditions:** Preserve deterministic rule baselines, run LLM-only and RAG-assisted methods under controlled comparable settings, and use independent human review where available. Ground truth is held separately from LLM/RAG prompts.

**Trust boundary:** Model responses are recommendations requiring review; no automated destructive remediation. A valid schema, matching event IDs, or retrieved MITRE ID is not sufficient proof of a supported conclusion. Add claim-level validation and abstention assessment.

**Professor reproducibility:** Build a sanitized portable dataset, documented installation requirements, one-command demo, source-code walkthrough, and video/PPT showing exactly which functions cause each stage. Existing dev scripts still depend on private evidence and Ollama; this deliverable is pending.

---

<!-- SOC-MILESTONE-2026-11-09-VERIFIED:START -->

## Design decision — 2026-11-09 | Treat the SOC simulation as a functional demonstration

**Decision:** Publish reviewed methodology, selected aggregate metrics, and authentic Wazuh screenshots, but keep labeled cases and generated AI reports private. Preserve the chronological record and avoid merging experiments.

- **Synthetic Wazuh demonstration:** 100 engineered scenarios/400 events; six three-class cases for LLM comparison. These are not real incident-response accuracy estimates.
- **Public CloudTrail development comparison:** different evidence population and a **binary** attack-associated classification metric. Its precision/recall/F1 cannot be compared numerically against the synthetic three-class outcomes.
- **Grounding boundary:** Known citation IDs, retrieved reference documents and valid JSON alone don't establish correctness of claims. The audited executive brief is written independently from visible event actions and explicitly states uncertainties.
- **Operational safety:** Wazuh rule severity must not be equated with verified compromise; analyst approval stays mandatory. No automated remediation in this demo.
- **Unresolved:** 400 UI hits vs 397 matches in the inspected local file, and misleading model explanations. These are tracked rather than quietly normalized or discarded.

Full justification and evidence: [SOC results](soc_results_2026-11-09.md).

<!-- SOC-MILESTONE-2026-11-09-VERIFIED:END -->

<!-- FINAL-RESEARCH-2026-11-09-APPEND -->

## Final interpretation decisions — 9 Nov 2026

1. **Source of truth:** Do not equate SIEM rule matches with proven attacks. Trust only Wazuh event records whose source fields and `sim_event_id` agree with the independent generated source manifest; keep simulation labels out of model inputs.
2. **Fair comparison:** Baseline, local LLM and RAG consume identical complete case evidence; errors and abstentions remain in all-case accuracy. Do not present the rule-enforced review gate as AI accuracy.
3. **Method boundaries:** This is **polling-based Wazuh-file integration**, not a Wazuh click-through UI or autonomous response. RAG uses local curated security notes, not a comprehensive or up-to-date knowledge service.
4. **Negative findings are valid:** 100% baseline, 53% LLM, 30% RAG on in-distribution synthetic cases. Preserve unfavorable AI results without relabeling outcomes.
5. **Claim safety:** Executive summaries are anchored in actual event names and verified IDs; unsupported model text is flagged, not silently trusted. Review is mandatory before release.
6. **Privacy and cleanup:** Keep raw model output, labels and Wazuh alert exports Git-ignored. Remove only demonstrably empty, nonstructural artifacts; retain empty Python package markers and historical negative experiments.
