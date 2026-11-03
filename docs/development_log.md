# Project Development Log

## Project Information

- Title: Evaluating AI-Assisted Cloud Security Incident Response
- Focus: Accuracy, Reliability, Explainability, and Analyst Efficiency
- Repository: https://github.com/Sumit-Bhosle/ai-cloud-incident-response
- Current branch: main
- Log purpose: Record implementation progress, verification, decisions,
  failures, limitations, and evidence for research reporting.

## Entry 001 — Research Scope and Environment Preparation

**Status:** Initial setup completed.

**Objective:** Establish a local development environment for a reproducible
cloud-security incident-response research project without requiring paid
cloud services.

**Environment and actions confirmed:**
- Ubuntu 26.04.1 LTS virtual machine.
- Four virtual CPU cores.
- Approximately 7.2 GiB RAM reported by Ubuntu.
- Virtual disk expanded to approximately 80 GB.
- Python 3.14.4 and Git 2.53.0.
- Project directory: `~/Projects/ai-cloud-incident-response`.
- GitHub remote configured for the project repository.

**Compatibility limitation:** Wazuh installation and local LLM inference have
not been confirmed. Compatibility and resource requirements must be evaluated
before these components are adopted.

## Entry 002 — Repository Initialization

**Date:** 2026-10-23

**Objective:** Establish the initial version-controlled project structure.

**Files created and committed:**
- `.gitignore`
- `README.md`
- `src/ingestion/generate_dataset.py`
- `data/raw/cloud_audit_events.jsonl`
- `data/ground_truth/incident_labels.json`
- `docs/dataset_card.md`

**Verification:**
- Initial Git commit created successfully.
- Commit: `62cdf54`
- Commit message: `Initialize AI-assisted cloud incident response research`
- Git status showed a clean working tree after the commit.
- GitHub push completed; a subsequent push reported `Everything up-to-date`.
- GitHub CLI authentication was verified.

**Evidence:** Git commit `62cdf54` and terminal outputs recorded in the
project development conversation.

## Entry 003 — Synthetic Pilot Dataset

**Date:** 2026-10-23

**Objective:** Create a small reproducible dataset to test event ingestion
and future investigation and evaluation code.

**Implementation:**
- Added a Python generator at `src/ingestion/generate_dataset.py`.
- Generated `data/raw/cloud_audit_events.jsonl`.
- Generated `data/ground_truth/incident_labels.json`.
- Documented the dataset in `docs/dataset_card.md`.

**Pilot scenarios:**
- SCN-001: MFA-protected login and read-only activity.
- SCN-002: Login without MFA, access-key creation, administrative policy
  attachment, and a denied secret-access attempt.
- SCN-003: Approved backup activity.

**Verification results:**
- Generator reported 8 synthetic events and 3 scenario labels.
- Ground-truth JSON parsed successfully.
- JSONL validation reported 8 event records.
- All 8 event IDs were unique.
- Scenario IDs were SCN-001, SCN-002, and SCN-003.
- Dataset validation passed.

**Limitations:**
- All records are synthetic, manually authored examples.
- Event fields are cloud-audit-style fields, not verified provider-native logs.
- Ground-truth labels are provisional and have not undergone independent review.
- The pilot is too small to support generalizable research conclusions.
- No AI performance, analyst performance, or efficiency results have been measured.

## Current State

**Completed:** Initial repository, synthetic pilot data, dataset generator,
dataset card, initial commit, and GitHub synchronization.

**Not yet completed:** Baseline investigation workflow, formal scoring rules,
expanded dataset, independent label review, AI-assisted investigation,
comparative experiments, and final analysis.

No experimental improvement or performance claim is made at this stage.

## Logging Protocol

For each subsequent milestone, record:
1. Date and objective.
2. Implementation and files changed.
3. Environment or configuration changes.
4. Commands and tests executed.
5. Actual results and errors encountered.
6. Decisions and rationale.
7. Limitations and threats to validity.
8. Related Git commit and next step.

Only record results that were actually observed. Mark proposed work as planned,
and distinguish debugging evidence from experimental evidence.

### Entry 004 — Rule-Based Baseline Investigation and Evaluation

**Status:** Implemented and locally validated; committed and pushed.

**Implementation**
- Added `src/investigation/baseline_investigator.py` to validate and group synthetic cloud-audit events, apply transparent scenario rules, and produce structured findings.
- Added `src/evaluation/evaluate_baseline.py` to compare predicted classifications against the separately stored ground-truth labels.
- Recorded scenario-level accuracy and per-class precision, recall, and F1.
- Updated `docs/experiment_log.md` with the baseline experiment and its limitations.

**Observed pilot results**
- Input: 8 synthetic audit events across 3 scenarios.
- Correct classifications: 3 of 3.
- Observed accuracy: 100%.
- Benign scenarios: 2; suspicious scenarios: 1.
- Both scripts executed successfully, and the generated findings were validated as JSON.

**Limitations**
The rules were designed around the current pilot scenarios. Ground-truth labels have not been independently reviewed, and there is no held-out evaluation set. These results are preliminary and do not establish performance on unseen incidents. AI-assisted evaluation and human analyst-efficiency measurements have not yet been conducted.

**Reproducibility**
- Investigator: `python3 src/investigation/baseline_investigator.py`
- Evaluator: `python3 src/evaluation/evaluate_baseline.py`
- Git commit: `1f6e7e3` — `Implement baseline investigation and evaluation`
- Repository: https://github.com/Sumit-Bhosle/ai-cloud-incident-response

### Entry 005 — Synthetic Robustness Diagnostic

- Added an eight-scenario diagnostic dataset containing 15 synthetic events.
- Added a reusable robustness evaluator at `src/evaluation/evaluate_robustness.py`.
- Verified unique event IDs and consistent scenario/ground-truth coverage.
- Observed 8/8 classification matches with the original baseline rules unchanged.
- Corrected the evaluator to capture rule identifiers from the `matched_rule` field.
- Documented the synthetic-data limitations and reproduction command in `docs/experiment_log.md`.
- No real cloud logs, AI-assisted investigation, or real-world detection performance were evaluated in this milestone.


### Entry 006 — Baseline Failure-Mode Diagnostic

- Created a separate five-scenario, 13-event synthetic failure-mode dataset.
- Added provisional expected labels in `data/failure_modes/ground_truth.json`.
- Implemented the reusable evaluator `src/evaluation/evaluate_failure_modes.py`.
- Reproduced 2/5 classification matches (40% scenario-level agreement) without modifying the original baseline rules.
- Identified observed limitations involving cross-identity event aggregation and detection coverage for successful administrative-policy changes.
- Recorded the results and methodological limitations in `docs/experiment_log.md`.
- No real cloud telemetry or AI-assisted investigation was evaluated in this milestone.

### Entry 007 — Identity-Aware Deterministic Baseline V2

**Date:** October 29, 2026
**Status:** Implemented, locally tested, and committed; GitHub synchronization pending.

**Objective:** Address limitations identified in Experiment 003 while preserving the original V1 implementation for reproducible comparison.

**Implementation**
- Added `src/investigation/baseline_v2.py`.
- Implemented chronological event ordering using timestamps.
- Added explicit actor-based correlation for ordered login, access-key creation, and administrative-policy attachment.
- Added detection of successful administrative-policy attachments.
- Added narrow benign-pattern recognition for the original synthetic pilot.
- Added IP-associated pattern detection for records without explicit actor identities.
- Preserved the distinction between IP association and verified actor identity.

**Observed development tests**
- FM-001: Correlated three-action pattern detected for user-alpha.
- FM-002: Three separate actors identified; unrelated actions were not combined into one correlated sequence.
- FM-003 and FM-005: Successful administrative-policy changes detected.
- FM-004: Remained inconclusive.
- Original pilot: 3/3 classifications matched provisional labels.
- Failure-mode dataset: 5/5 classifications matched provisional labels.
- Python compilation completed successfully.

**Development observations**
- Initial V2 implementation did not classify the original pilot correctly.
- Narrow benign-pattern recognition and IP-associated correlation were subsequently added.
- Final observed development-set agreement was 8/8 scenarios.

**Limitations**
- All scenarios are synthetic and manually authored.
- V2 was developed using these same scenarios; the results are not independent validation.
- A shared source IP does not establish actor identity.
- Session continuity, authorization, and malicious intent remain unverified.
- No AI-assisted investigation or human analyst-efficiency experiment has been conducted.

**Version control**
- Local Git commit: f109406
- Commit message: Implement identity-aware deterministic baseline V2

**Next steps**
- Conduct independent synthetic holdout testing.
- Implement reproducible V1/V2 comparison reporting.
- Develop and evaluate the AI-assisted investigation workflow.
- Prepare installation documentation and presentation demonstrations.

### Entry 008 — Frozen Holdout Evaluation and Failure Analysis

**Date:** October 30, 2026
**Status:** Implemented and locally verified; final documentation commit pending.

**Objective**
Evaluate the unchanged deterministic V1 and V2 investigators on a separate synthetic holdout dataset.

**Implementation**
- Created `docs/holdout_test_plan.md` with 10 predefined investigation scenarios.
- Added `src/ingestion/generate_holdout.py` to generate synthetic security events.
- Generated 24 events in `data/holdout/events.jsonl`.
- Created provisional classifications in `data/holdout/ground_truth.json`.
- Validated event IDs, scenario coverage, and expected classifications.
- Froze the dataset and labels in Git commit `d2f1535`.
- Implemented `src/evaluation/evaluate_holdout.py`.
- Preserved the original V1 and V2 investigation implementations.

**Observed results**
- V1: 7/10 matches (70%).
- V2: 9/10 matches (90%).
- V1 mismatches: HLD-003, HLD-005, HLD-010.
- V2 mismatch: HLD-008.
- Verified that the evaluation report is valid JSON.
- Verified that the frozen dataset remained unchanged.

**Development findings**
- V2 avoided incorrect cross-actor correlations observed in V1.
- V2 recognized a privilege-change scenario missed by V1.
- V2 failed to recognize a longer benign read-only sequence.
- V2 returned no supporting event IDs for its HLD-008 inconclusive finding.

**Limitations**
- Synthetic scenarios and provisional labels.
- Small, researcher-designed test set.
- No external independent benchmark.
- No AI-assisted investigator or human analyst-efficiency evaluation yet.

**Reproducibility**
- Dataset freeze commit: `d2f1535`
- Evaluator: `src/evaluation/evaluate_holdout.py`
- Command: `python3 src/evaluation/evaluate_holdout.py`
- Full findings: `docs/experiment_log.md`, Experiment 005.

**Next steps**
- Preserve V1/V2 and the recorded holdout results.
- Develop a separate AI-assisted investigation workflow.
- Evaluate evidence grounding, unsupported claims, reliability, and efficiency.

### Entry 009 — Evidence Integrity Verification

**Date:** November 2, 2026
**Status:** Implemented and locally tested; Git commit pending.

**Objective**
Verify that collected laboratory evidence files have not
changed relative to their recorded SHA-256 checksums.

**Implementation**
- Created `src/evaluation/verify_evidence.py`.
- Implemented streaming SHA-256 file hashing.
- Restricted evidence references to `data/lab_evidence/`.
- Added detection of missing files, modified files,
  unsafe paths, and empty evidence manifests.
- Created five reproducible tests in
  `tests/test_evidence_integrity.py`.

**Observed results**
- Evidence integrity tests: 5/5 passed.
- Existing schema validation tests: 6/6 passed.
- Total automated test suite: 11/11 passed.
- Temporary demonstration evidence was removed
  after testing.

**Limitations**
- Checksums detect differences from recorded file hashes.
- They do not establish original evidence authenticity.
- The verifier is not yet a complete cross-record validator.
- Genuine laboratory security evidence has not yet
  been collected or evaluated.

**Reproduction**
python3 -m unittest discover -s tests -p "test_*.py" -v

**Next steps**
- Document evidence-verification usage.
- Implement cross-record evidence ID checks.
- Prepare isolated laboratory collection.
- Collect and verify genuine security telemetry.

### Entry 010 — Normalized Security Event Schema

**Date:** November 2, 2026
**Status:** Implemented and locally tested.

**Objective**
Create a common event structure for future Windows,
Linux, Wazuh, and cloud security telemetry.

**Implementation**
- Created schemas/normalized_event.schema.json.
- Added event validation to validate_lab_record.py.
- Preserved original source-log references.
- Added three permanent normalized-event tests.

**Observed results**
- Valid event accepted.
- Invalid UTC timestamp rejected.
- Invalid event identifier rejected.
- Complete automated test suite: 14/14 passed.

**Limitations**
- Only structural validation has been tested.
- Cross-record references are not yet verified.
- Genuine laboratory security logs have not yet been collected.
- No AI-assisted investigator has been evaluated.

**Next steps**
- Implement cross-record evidence verification.
- Configure the isolated security laboratory.
- Collect genuine controlled security telemetry.
