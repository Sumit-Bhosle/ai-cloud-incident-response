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

## Experiment 001 — Deterministic Baseline Evaluation

**Status:** Completed on the initial synthetic pilot
**Date:** 2026-10-23

### Objective
Evaluate the deterministic baseline investigator against the separately
stored ground-truth classifications.

### Implementation
- Investigator: `src/investigation/baseline_investigator.py`
- Evaluator: `src/evaluation/evaluate_baseline.py`
- Input events: `data/raw/cloud_audit_events.jsonl`
- Ground truth: `data/ground_truth/incident_labels.json`
- Investigator output: `results/baseline_findings.json`

### Procedure
1. Load and validate the synthetic event records.
2. Group events by scenario ID.
3. Apply predefined investigation rules.
4. Produce classifications, reasons, supporting event IDs, and limitations.
5. Compare predictions against ground-truth labels.
6. Calculate scenario-level accuracy and per-class precision, recall, and F1.

### Observed Investigator Results
- Events processed: 8.
- Scenarios investigated: 3.
- SCN-001 classified as benign by BASELINE-RULE-002.
- SCN-002 classified as suspicious by BASELINE-RULE-001.
- SCN-003 classified as benign by BASELINE-RULE-003.
- Findings were written to `results/baseline_findings.json`.
- Findings included supporting event IDs, reasons, and limitations.
- The denied secret-access event was not described as a successful retrieval.

### Observed Evaluation Results
- Scenarios evaluated: 3.
- Correct classifications: 3 out of 3.
- Accuracy: 1.000 (100.0%).
- Benign class: precision 1.000, recall 1.000, F1 1.000, support 2.
- Suspicious class: precision 1.000, recall 1.000, F1 1.000, support 1.
- All three scenario comparisons were reported as MATCH.

### Interpretation
The baseline matched all three labels in this pilot run. The rules were
designed around these scenarios, so this result is a functional smoke test,
not evidence of generalization to unseen incidents.

### Limitations and Threats to Validity
- Only three scenarios were evaluated.
- The synthetic scenarios are simplified and manually authored.
- Ground-truth labels have not undergone independent expert review.
- The rules were designed around the pilot scenarios, creating a risk of
  optimistic results.
- No held-out test set has been evaluated.
- Classification metrics do not measure evidence quality, unsupported
  claims, human analyst efficiency, or real-world operational performance.
- No AI-assisted comparison has been conducted.

### Evidence and Reproducibility
- Run the investigator with:
  `python3 src/investigation/baseline_investigator.py`
- Run the evaluator with:
  `python3 src/evaluation/evaluate_baseline.py`
- Record the Git commit containing the finalized scripts and this log update
  after it is created.

### Next Actions
- Add tests for malformed data, missing fields, duplicate IDs, and unknown
  scenario patterns.
- Expand scenario diversity before making broader claims.
- Define evaluation procedures for evidence grounding and unsupported claims.
- Preserve this pilot result rather than silently replacing it when rules
  or data change.


### Experiment 002 — Synthetic Robustness Diagnostic

**Objective:** Check whether the existing rule-based baseline handles additional synthetic scenarios consistently with their predefined ground-truth labels.

**Inputs:**
- `data/robustness/events.jsonl`
- `data/robustness/additional_events.jsonl`
- `data/robustness/ground_truth.json`

**Observed dataset:** 15 synthetic events across 8 scenarios. Ground-truth validation passed, with unique event IDs and matching scenario and label sets.

**Method:** Applied the existing `investigate_scenario` function without modifying the baseline rules. Compared each predicted classification with its predefined expected classification. Corrected the evaluator to read the investigator's `matched_rule` field.

**Observed results:**
- Scenarios evaluated: 8
- Classification matches: 8/8
- Scenario-level agreement: 1.000 (100%)
- ROB-001–ROB-005: all classified as `inconclusive`, matching their expected labels.
- ROB-006: `benign`, matched by `BASELINE-RULE-002`.
- ROB-007: `suspicious`, matched by `BASELINE-RULE-001`.
- ROB-008: `benign`, matched by `BASELINE-RULE-003`.

**Interpretation:** The baseline behaved as expected on these constructed diagnostic cases. Five cases assessed conservative handling of insufficient evidence; three reused patterns represented by the existing rules. This experiment does not establish generalization to unseen incidents or real cloud telemetry.

**Limitations:** All events are synthetic and manually constructed. The additional recognized patterns are not an independent benchmark of unseen behavior. Scenario-level agreement does not measure evidence quality, analyst efficiency, response correctness, or AI-versus-baseline performance.

**Reproduction command:**
```bash
python3 src/evaluation/evaluate_robustness.py
```

**Output:** `results/robustness/robustness_findings.json` (generated local artifact; not necessarily tracked by Git).

### Experiment 003 — Synthetic Baseline Failure-Mode Diagnostic

**Objective:** Investigate limitations of the original deterministic baseline using five synthetic scenarios designed to challenge its classification logic.

**Inputs:**
- `data/failure_modes/events.jsonl`
- `data/failure_modes/ground_truth.json`

**Implementation:** Added `src/evaluation/evaluate_failure_modes.py` to validate the test inputs, run the existing `investigate_scenario` function, compare predicted classifications with provisional expected labels, and save a JSON report. The original baseline rules were not modified.

**Observed results:**
- Events: 13
- Scenarios: 5
- Matches: 2/5
- Mismatches: 3
- Scenario-level agreement: 0.400 (40%)

**Scenario findings:**
- FM-001: Correctly classified as suspicious despite reverse chronological record order.
- FM-002: Classified as suspicious even though the relevant successful actions belong to three different identities.
- FM-003: Returned inconclusive despite a successful administrative-policy attachment.
- FM-004: Correctly returned inconclusive for a successful login without MFA alone.
- FM-005: Returned inconclusive despite a successful administrative-policy attachment alongside MFA-protected read-only activity.

**Interpretation:** The diagnostic exposed limitations in identity correlation and detection coverage for privilege changes. The baseline uses scenario-level event presence checks rather than robust actor/session correlation and broader investigation logic.

**Limitations:** All events are synthetic, manually constructed, and evaluated against provisional expected labels. The five scenarios are too small and intentionally targeted to support general performance claims. The 40% agreement is specific to this diagnostic set, not a real-world accuracy estimate.

**Reproduction command:**
```bash
python3 src/evaluation/evaluate_failure_modes.py
```

**Output:** `results/failure_modes/failure_mode_findings.json`.

### Experiment 004 — Baseline V1 versus V2 Development-Set Comparison

**Date:** October 29, 2026

**Objective:** Compare the original deterministic investigator with an identity-aware V2 candidate on existing synthetic development scenarios.

**Inputs**
- `data/raw/cloud_audit_events.jsonl`
- `data/ground_truth/incident_labels.json`
- `data/failure_modes/events.jsonl`
- `data/failure_modes/ground_truth.json`

**Method**
- Preserved the original V1 implementation.
- Developed V2 to address observed identity-correlation and privilege-change detection limitations.
- Executed V2 against the original pilot and failure-mode datasets.
- Compared observed scenario classifications with provisional labels.
- Reviewed V1 results previously recorded for the same datasets.

**Observed results**

| Dataset | V1 matches | V2 matches |
|---|---:|---:|
| Original pilot | 3/3 | 3/3 |
| Failure modes | 2/5 | 5/5 |
| Combined | 5/8 | 8/8 |

Combined development-set agreement:
- V1: 62.5%
- V2: 100%

**Key findings**
- FM-001: V2 identified a chronologically ordered, same-actor suspicious pattern.
- FM-002: V2 returned inconclusive rather than combining three distinct actors into a single correlated incident.
- FM-003 and FM-005: V2 identified successful administrative-policy changes associated with other activity by the same actor.
- FM-004: V2 correctly retained an inconclusive classification.
- SCN-002: V2 detected an IP-associated suspicious pattern while explicitly reporting that actor identity was not verified.
- SCN-001 and SCN-003: V2 recognized the narrowly defined benign pilot patterns.

**Interpretation**
V2 matched more provisional development labels than V1 on these constructed scenarios. The changes address specific weaknesses exposed during development.

**Limitations and threats to validity**
- V2 was designed and revised using these same scenarios.
- The observed 100% agreement is development-set fit, not an independent accuracy estimate.
- Ground-truth labels are provisional and not independently reviewed.
- The sample contains only eight scenarios across two datasets.
- Classification agreement alone does not establish evidence quality, reliability, operational effectiveness, or analyst efficiency.
- No AI-assisted model was evaluated.
- Independent holdout testing remains necessary.

**Reproducibility**
- V1 implementation: `src/investigation/baseline_investigator.py`
- V2 implementation: `src/investigation/baseline_v2.py`
- V2 implementation commit: `f109406`
- A dedicated automated comparison runner is planned but not yet implemented.

### Experiment 005 — Frozen Synthetic Holdout Comparison

**Date:** October 30, 2026

**Objective:** Compare the unchanged deterministic Baseline V1 and identity-aware Baseline V2 on a separate, frozen synthetic dataset and examine classification failures and evidence quality.

**Inputs**
- `data/holdout/events.jsonl`
- `data/holdout/ground_truth.json`
- `docs/holdout_test_plan.md`

**Dataset**
- 24 synthetic cloud-security events.
- 10 scenarios.
- Provisional expected labels: 3 benign, 5 inconclusive, 2 suspicious.
- Dataset, labels, generator, and test plan frozen in Git commit `d2f1535` before the first holdout evaluation.

**Method**
- Preserved both investigator implementations without modification.
- Used `src/evaluation/evaluate_holdout.py` to evaluate the same scenarios with V1 and V2.
- Compared scenario classifications against the frozen provisional labels.
- Inspected mismatches, matched rules, supporting event IDs, explanations, and limitations.
- Verified that the frozen dataset files were unchanged after evaluation.

**Observed results**

| Investigator | Matches | Mismatches | Agreement |
|---|---:|---:|---:|
| Baseline V1 | 7/10 | 3 | 70% |
| Baseline V2 | 9/10 | 1 | 90% |

V2 achieved two additional classification matches, a 20-percentage-point difference on this dataset.

**Failure analysis**
- HLD-003: V1 incorrectly classified activity from three different actors as a correlated suspicious pattern. V2 returned inconclusive.
- HLD-005: V1 missed a successful administrative-policy change associated with MFA-protected activity by the same actor. V2 classified it as suspicious.
- HLD-008: V2 returned inconclusive for a longer benign read-only sequence. Its narrow benign-pattern rule did not recognize the sequence, and the returned finding contained no supporting event IDs. V1 classified it as benign.
- HLD-010: V1 incorrectly combined activity from different actors sharing a source IP. V2 returned inconclusive.

**Interpretation**
The identity-aware V2 matched more provisional labels and avoided two cross-actor aggregation errors observed in V1. However, V2's narrow benign-pattern recognition caused it to withhold a benign classification on HLD-008. This was an inconclusive result, not a suspicious classification.

**Limitations and threats to validity**
- The dataset contains only 10 manually authored synthetic scenarios.
- Expected classifications are provisional and have not been independently reviewed.
- The study team designed the holdout scenarios with knowledge of the baseline rules.
- Freezing the dataset before execution prevents silent post-result changes but does not establish external independence.
- Scenario-level classification agreement is not equivalent to real-world detection accuracy.
- Evidence quality, explanation quality, response correctness, and analyst efficiency require separate evaluation.
- No AI-assisted investigator was evaluated in this experiment.

**Reproducibility**
- Frozen dataset commit: `d2f1535`
- V1: `src/investigation/baseline_investigator.py`
- V2: `src/investigation/baseline_v2.py`
- Evaluator: `src/evaluation/evaluate_holdout.py`
- Command: `python3 src/evaluation/evaluate_holdout.py`
- Generated report: `results/holdout/holdout_findings.json` (local artifact excluded from Git tracking).

**Follow-up**
Preserve the observed HLD-008 failure in the Experiment 005 record. Any subsequent changes to benign-pattern recognition must be versioned and evaluated separately rather than treated as an improvement to this frozen first-run result.
