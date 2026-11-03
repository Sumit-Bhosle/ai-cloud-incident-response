# Problems Faced in Incident Response Project

## Purpose

Track genuine engineering and research challenges
encountered while developing the AI-Assisted Cloud
Security Incident Response research project.

Use these notes for future technical and behavioral
interview preparation.

Keyword: problems faced in incident response project

## Confirmed Development Challenges

### INT-001 — JSON Schema Timestamp Validation

Problem:
The jsonschema library accepted invalid date-time
values because its optional RFC 3339 validation
support was unavailable.

Investigation:
Checked registered format validators and tested
valid and invalid timestamps directly.

Solution:
Implemented a custom UTC timestamp checker using
Python datetime parsing and a regular expression.

Result:
Invalid timestamps were rejected.

Lesson:
A schema keyword does not guarantee runtime
enforcement without appropriate validation support.

Interview topics:
Python, dependency management, defensive programming,
data integrity, debugging.

### INT-002 — Regression During Regex Correction

Problem:
The first timestamp validation correction rejected
a legitimate UTC timestamp because the generated
regular expression contained incorrect escaping.

Solution:
Corrected the regex and tested valid and invalid
UTC timestamps.

Result:
All six automated validator tests passed.

Lesson:
Test both positive and negative cases.
A bug fix can introduce another bug.

Interview topics:
Unit testing, regression testing, problem solving.

### INT-003 — Incorrect Cross-Actor Correlation

Problem:
Baseline V1 combined security events belonging to
different actors into a suspicious activity pattern.

Solution:
Developed a separate identity-aware Baseline V2.

Observed result:
V2 avoided the cross-actor classification errors
observed in HLD-003 and HLD-010.

Lesson:
Shared scenario context or an IP address does not
prove that events belong to the same identity.

Interview topics:
Cybersecurity, SIEM, incident correlation.

### INT-004 — Missed Privilege Changes

Problem:
Baseline V1 missed some successful privilege changes
when its predefined suspicious pattern was absent.

Solution:
V2 added broader privilege-change investigation
logic while retaining cautious classifications.

Lesson:
Narrow detection rules can miss relevant activity.

Interview topics:
Detection engineering, security monitoring.

### INT-005 — Overly Narrow Benign Recognition

Problem:
Baseline V2 returned inconclusive for the longer
benign read-only sequence HLD-008.

Status:
Limitation documented and preserved.
No corrective V2 modification made.

Lesson:
More restrictive rules are not always better.
Recognizing benign behavior also matters.

Interview topics:
Edge cases, reliability, evaluation design.

### INT-006 — Synthetic Dataset Limitations

Problem:
Early tests used manually constructed synthetic
events and provisional ground-truth labels.

Decision:
Design an isolated laboratory to collect actual
security logs and verify scenario outcomes.

Status:
Laboratory design underway; real evidence collection
has not yet been completed.

Lesson:
Development-set agreement cannot be presented
as real-world detection accuracy.

Interview topics:
Research integrity, AI evaluation, reproducibility.

### INT-007 — Hardware Resource Constraints

Problem:
The Windows laptop has approximately 16 GB RAM,
while the proposed research stack includes
multiple virtual machines, SIEM, RAG, and an LLM.

Approach:
Plan sequential laboratory sessions and preserve
evidence for offline investigation.

Status:
Architecture planned, not yet deployed or validated.

Lesson:
Architecture must account for actual hardware
constraints and operating-system compatibility.

Interview topics:
Systems engineering, virtualization, tradeoffs.

## Future Entry Format

For each new challenge, record:

- Problem and symptoms
- Root cause and investigation
- Solution attempted
- Tests and observed result
- Lessons learned
- Relevant technical skills
- STAR interview explanation
- Git commit or experiment reference

## Interview Preparation

Prepare detailed STAR answers after implementation
and before relevant job interviews.

Do not invent results, responsibilities, or
technical accomplishments.
