# Experiment Log

## Project

Evaluating AI-Assisted Cloud Security Incident Response

## Logging Rules

- Record actual observations, not expected or invented results.
- Identify the dataset and code version used in each run.
- Record configurations, evaluation criteria, and errors.
- Keep ground-truth labels separate from investigator outputs.
- Do not modify labels merely to improve scores.
- Mark incomplete experiments clearly.

## Experiment 000 — Dataset Generator Validation

**Status:** Completed initial validation  
**Date:** 2026-10-23

### Objective
Verify that the synthetic pilot dataset can be generated and parsed.

### Dataset
- Source: `src/ingestion/generate_dataset.py`
- Events: `data/raw/cloud_audit_events.jsonl`
- Ground truth: `data/ground_truth/incident_labels.json`

### Procedure
1. Run the dataset generator.
2. Parse the ground-truth JSON.
3. Parse every non-empty JSONL event line.
4. Check the event count, unique event IDs, and scenario IDs.

### Observed Results
- Generator reported 8 synthetic events.
- Generator reported 3 ground-truth scenario labels.
- Ground-truth JSON parsed successfully.
- 8 event records were parsed.
- 8 unique event IDs were found.
- Scenario IDs were SCN-001, SCN-002, and SCN-003.
- Dataset validation passed.

### Limitations
This is a small synthetic pilot dataset. These checks establish basic
structural validity, not realism, label correctness, investigator accuracy,
or generalizability.

### Evidence
- Initial project commit: `62cdf54`
- Development documentation commit: `50795dd`

## Experiment 001 — Baseline Investigator

**Status:** Planned; not yet run

### Objective
Implement and test a deterministic, non-AI investigator against the pilot
dataset and its separately stored ground-truth labels.

### Planned Procedure
1. Validate required event fields.
2. Group events by scenario.
3. Apply documented investigation rules.
4. Produce findings with supporting event IDs.
5. Compare classifications with ground truth.
6. Record errors and calculate appropriate pilot metrics.

### Results
Not yet available.

### Limitations
No baseline investigation results have been measured yet.
