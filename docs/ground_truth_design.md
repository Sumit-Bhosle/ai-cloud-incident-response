# Ground-Truth Dataset and Evidence Design

## Research Topic

Evaluating AI-Assisted Cloud Security Incident Response

COMP 5112 - Research Methodology

## 1. Purpose

Define how controlled laboratory incidents, observed
security telemetry, verified evidence, and expected
investigation outcomes will be recorded.

Reference: Group 13 Presentation 2, Slides 18-21.

This design is prospective. No genuine laboratory
incident dataset has yet been collected.

## 2. Dataset Categories

LAB-001: IAM compromise
LAB-002: Suspicious API activity
LAB-003: Privilege escalation
LAB-004: Unauthorized resource access
LAB-005: Data-access anomaly

Each category should include controlled suspicious
activity and relevant benign controls.

## 3. Evidence Provenance

Every scenario execution must have a unique run ID.

Record:
- Scenario ID and run ID
- Execution date and environment
- Operating system and software versions
- Test account and monitored target
- Authorized action performed
- Execution timestamp and time zone
- Whether the action succeeded or failed
- Log source and collection method
- Original event identifiers
- Original evidence file paths
- Collection errors or missing evidence

Preserve UTC timestamps wherever possible.

Record clock offsets when systems are not synchronized.

## 4. Evidence Source Types

Possible sources:
- Windows Security Event Logs
- Linux authentication and audit logs
- Wazuh alerts and indexed event records
- Genuine cloud audit logs, if available
- Explicitly identified cloud-style simulations

An endpoint authentication event must not be
misrepresented as a genuine cloud IAM event.

Wazuh alerts are derived observations, not
independently verified ground truth.

## 5. Ground-Truth Labels

Supported provisional classifications:

- benign
- suspicious
- inconclusive

Classification describes the available evidence,
not automatically the attacker's intent.

For each scenario run, record:
- Expected classification
- Expected relevant event IDs
- Actual confirmed action outcome
- Expected response or analyst next step
- Evidence supporting the conclusion
- Evidence that is missing or uncertain
- Annotation rationale
- Reviewer and review status

Do not label an action successful merely because
the test script attempted it.

## 6. Proposed Record Structure

One execution record should contain:

run_id
scenario_id
scenario_category
environment_type
source_type
started_at_utc
ended_at_utc
authorized_actions
observed_action_outcomes
raw_evidence_files
evidence_event_ids
expected_classification
expected_response
ground_truth_rationale
limitations
review_status
reviewer
reviewed_at_utc

These are design fields, not populated results.

## 7. Evidence Verification

For every completed experiment:

1. Document the authorized test procedure.
2. Execute it in an isolated laboratory.
3. Record actual success or failure.
4. Export original security evidence.
5. Verify timestamps and source identity.
6. Link observations to the scenario run.
7. Record missing or contradictory evidence.
8. Review and lock ground-truth annotations.
9. Preserve evidence file checksums.
10. Record the dataset version in Git.

An attempted attack and a confirmed compromise
are different outcomes.

## 8. Data Separation

Keep separate:
- Raw evidence
- Execution and scenario manifests
- Verified ground truth
- MITRE/NIST/cloud knowledge documents
- Deterministic baseline outputs
- AI investigation outputs
- Human analyst evaluation records

Do not provide hidden ground-truth labels directly
to an AI investigator during blind evaluation.

Do not present synthetic development data as
genuine laboratory-collected telemetry.

## 9. Dataset Split and Evaluation Integrity

Separate development, validation, and final
evaluation scenarios where feasible.

Avoid placing near-duplicate runs of the same
incident sequence across development and test sets.

Freeze evaluation labels before scoring.

Changes to a previously evaluated dataset must
be versioned and disclosed.

Existing synthetic Experiment 005 results remain
unchanged and separate from future lab experiments.

## 10. Safety and Publication

Use only authorized, isolated test systems.

Use test accounts and non-sensitive sample files.

Avoid destructive activity or real-world targets.

Do not publish:
- Passwords, tokens, or private keys
- Real personal information
- Unnecessary host or network identifiers
- Sensitive security configurations

Publish sanitized evidence and reproducible
instructions where appropriate.

## 11. Current Status

Design: In progress

Controlled incident execution: Not started

Genuine laboratory logs: Not yet collected

Ground-truth verification: Pending

Knowledge-base construction: Pending

AI-assisted evaluation: Pending

## 12. Next Steps

1. Implement machine-readable record schemas.
2. Define laboratory network isolation.
3. Verify auditing and log export procedures.
4. Execute a small benign control experiment.
5. Validate real collected event provenance.
6. Proceed with controlled incident scenarios.
