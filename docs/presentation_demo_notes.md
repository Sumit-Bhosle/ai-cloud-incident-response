# Research Presentation and Demonstration Notes

Project: Evaluating AI-Assisted Cloud Security
Incident Response

## Demo 01 — Laboratory Record Validation

WHAT:
JSON Schemas define the expected structure of
laboratory execution and ground-truth records.

WHY:
Inconsistent or incomplete research records could
undermine incident investigation and evaluation.

HOW:
Python's jsonschema library checks required fields,
data types, permitted values, and timestamp formats.

WHAT IT PRODUCES:
Validation results and field-specific error messages.

VERIFICATION:
Six automated tests, including deliberately invalid
records and the corrected UTC timestamp checker.

LIMITATION:
Valid JSON records are not automatically truthful.

## Demo 02 — SHA-256 Evidence Integrity

WHAT:
A mechanism for verifying whether recorded evidence
files match their stored SHA-256 fingerprints.

WHY:
Changes to incident logs could alter the conclusions
of baseline and AI-assisted investigations.

HOW:
Python hashes the evidence file and compares the
calculated value with the manifest's recorded hash.

WHAT IT PRODUCES:
Pass/fail results identifying matching or modified files.

VERIFICATION:
Five automated tests covering valid evidence,
modified evidence, missing files, unsafe paths,
and empty evidence manifests.

LIMITATION:
A matching fingerprint does not prove that the
original log was genuine or correctly collected.

## Connection to the Research Question

These components establish more reliable experiment
inputs and support reproducible evaluation.

They do not directly demonstrate AI superiority or
measure incident-detection accuracy.

## Professor Demonstration Plan

1. Show an example laboratory record.
2. Run schema validation.
3. Show rejection of an invalid timestamp.
4. Show an original evidence file and checksum.
5. Modify a temporary demonstration file.
6. Run the integrity verifier.
7. Explain the detected mismatch.
8. Discuss provenance and remaining limitations.

Keep demonstrations separate from actual lab results.

## Demo 03 — Normalized Security Event Records

WHAT:
A common JSON structure representing security
events from different logging systems.

WHY:
Windows, Linux, Wazuh, and cloud audit systems
produce different event formats.

HOW:
Normalize important fields such as event ID,
run ID, timestamp, actor, action, outcome,
and original evidence location.

WHAT IT PRODUCES:
Consistent machine-readable security events
that retain references to original logs.

VERIFICATION:
Three normalized-event tests passed.
Complete project test suite: 14/14 passed.

RESEARCH BENEFIT:
Supports event correlation, evidence traceability,
explainability, and comparable investigations.

LIMITATION:
A structurally valid event may still reference
missing evidence or contain an incorrect interpretation.

DEMO:
Show a valid normalized event, reject an invalid
timestamp, and trace an event to its original
evidence once real laboratory logs are available.

## Demo 04 — Cross-Record Evidence Verification

WHAT:
A Python program that checks consistency between
execution records, normalized events, and ground truth.

WHY:
Investigation findings must not cite nonexistent
events or mix evidence from different experiments.

HOW:
Compare run IDs, scenario IDs, unique event IDs,
and declared raw-evidence references.

WHAT IT PRODUCES:
Pass/fail results identifying broken references.

VERIFICATION:
Six dedicated tests passed.
Complete project test suite: 20/20 passed.

RESEARCH BENEFIT:
Supports evidence traceability and reproducibility.

LIMITATION:
A valid reference does not automatically mean the
evidence supports the investigator's conclusion.

DEMONSTRATION:
Run a valid example, then reference an event that
does not exist and show the verification failure.

## Demo 05 — First Genuine Security-Log Collection

SCENARIO:
A controlled failed authentication attempt on Ubuntu.

WHAT WE DID:
Attempted to switch to root using an incorrect password.

OBSERVED:
Ubuntu recorded two authentication-related journal
entries associated with the test process.

COLLECTION:
Exported the journal records in their original
journal-export format.

INTEGRITY:
Calculated and reverified the SHA-256 fingerprint.

RESEARCH PURPOSE:
Demonstrates evidence collection and provenance
before using collected logs for investigation.

IMPORTANT LIMITATION:
An authorized local authentication test is not
equivalent to a real cloud attack.

NEXT DEMO:
Normalize the collected records and verify their
relationships to the experiment documentation.
