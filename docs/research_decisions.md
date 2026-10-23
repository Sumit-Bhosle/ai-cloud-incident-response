# Research and Technical Decision Log

## Project

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

**Rationale:** The project should remain accessible and reproducible within
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
- Initial project commit: 62cdf54
- Development log commit: 50795dd

**Follow-up:** Record relevant commit IDs and configurations for each
meaningful experiment.

---

## RD-008 — Treat Wazuh and Local LLM Integration as Pending

**Status:** Pending compatibility and resource assessment

**Decision:** Do not assume Wazuh or a local language model is installed or
working until installation and functional tests confirm it.

**Rationale:** The project should prioritize a working, testable research
pipeline and avoid unsupported compatibility assumptions.

**Next action:** Build and validate the Python baseline first, then reassess
integration requirements.

---

## Change History

When a decision changes, record the date, previous decision, new decision,
reason for change, and any effect on completed experiments or conclusions.
