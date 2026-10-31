# Experiment 005 — Fresh Synthetic Holdout Test Plan

Date: October 29, 2026
Status: Scenario specifications prepared before holdout execution

## Objective

Evaluate the unchanged Baseline V1 and Baseline V2
investigators using newly authored synthetic scenarios.

## Scenario Specifications

| ID | Expected | Description |
|---|---|---|
| HLD-001 | benign | MFA login followed by successful read-only resource access. |
| HLD-002 | suspicious | Same actor completes no-MFA login, access-key creation, and admin-policy attachment. Input records are deliberately out of timestamp order. |
| HLD-003 | inconclusive | Login, key creation, and admin-policy attachment belong to distinct actors without evidence of coordination. |
| HLD-004 | inconclusive | MFA login followed by a denied admin-policy attachment; no successful privilege change is established. |
| HLD-005 | suspicious | Same actor performs MFA login, resource listing, and successful admin-policy attachment. |
| HLD-006 | inconclusive | No-MFA login alone, with insufficient surrounding evidence. |
| HLD-007 | benign | MFA-protected backup-role assumption followed by expected backup activity. |
| HLD-008 | benign | MFA login followed by multiple successful read-only activities without privilege changes. |
| HLD-009 | inconclusive | Successful administrative-policy attachment without surrounding activity sufficient to establish malicious intent. Requires review. |
| HLD-010 | inconclusive | Same source IP appears across multiple explicitly different actors; shared IP is not proof of shared identity. |

## Evaluation Protocol

1. Create synthetic events consistent with this plan.
2. Create separately stored provisional labels.
3. Freeze the test inputs and labels before executing either baseline.
4. Run existing V1 and V2 without changing their rules.
5. Record classifications, matches, mismatches, and evidence.
6. Preserve unexpected results and document possible causes.
7. Do not modify the test cases or investigator rules to improve the reported holdout score.

## Limitations

- The dataset is synthetic and manually authored.
- Labels are provisional and not independently reviewed.
- The study team designs the scenarios, so this is not an externally independent benchmark.
- A correct classification is not proof of real-world attack-detection capability.
- Suspicious indicates investigation priority, not confirmed malicious intent.
- AI-assisted performance is not part of this experiment.
