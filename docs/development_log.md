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
