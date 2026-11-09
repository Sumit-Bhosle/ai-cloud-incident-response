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

## Demo 06 — Real Linux Log Normalization

WHAT:
A Python normalizer for genuine systemd journal records.

WHY:
Raw security logs must become structured,
machine-readable events before automated investigation.

HOW:
Read original journal-export evidence, verify SHA-256,
extract timestamps and authentication details,
preserve journal cursors, and validate JSON records.

ACTUAL OBSERVED OUTPUT:
- PFL-001-RUN-001-EVT-001: authentication_failure
- PFL-001-RUN-001-EVT-002: user_switch_failure

VERIFICATION:
- Two genuine records normalized.
- JSON Schema validation passed.
- Repeat execution reproduced identical output.
- Full automated suite: 29/29 passed.

DEMO COMMAND:
python3 src/ingestion/normalize_linux_journal.py

LIMITATIONS:
Preflight-specific implementation.
Not yet a general-purpose SIEM ingestion pipeline.
Not evidence of an actual cyberattack.

PRESENTATION VISUAL:
Original log -> Normalizer -> Structured JSON
-> Schema Validation -> Investigation Dataset

## Demo 07 — Complete Security Evidence Verification

SCENARIO:
Controlled failed root authentication on Ubuntu.

WORKING PIPELINE:
Authentication attempt
-> Original Linux journal
-> SHA-256 verification
-> Python event normalization
-> Execution manifest
-> Draft ground truth
-> Cross-record verification
-> Source-record reconstruction

LIVE DEMONSTRATION COMMAND:
python3 src/evaluation/verify_preflight_trace.py

TEST COMMAND:
python3 -m unittest discover -s tests -p "test_*.py" -v

ACTUAL RESULTS:
- Two genuine journal records.
- Two normalized security events.
- 2/2 supporting event references verified.
- End-to-end evidence trace passed.
- 35/35 automated tests passed.

PRESENTATION EXPLANATION:
The system verifies that normalized investigation
records can be reconstructed from preserved security
logs and consistently linked to experiment annotations.

RESEARCH LIMITATIONS:
This is a local authorized preflight experiment.
It is not cloud attack detection or AI evaluation.
Ground truth is still draft.

VIDEO PLAN:
Show the original evidence, JSON events, manifest,
ground truth, and verification output.
Use sanitized records for external sharing.

<!-- DEMO-2026-11-04-AI-CLOUD -->

## Demo 08 — Source-code walkthrough: Wazuh → LLM/RAG → CloudTrail cases (prototype)

**Opening explanation:** "Wazuh detects observed security activity. Python structures and verifies the event data. A local Ollama language model generates a draft investigation. Our retrieval module supplies curated security guidance, while validation checks the JSON structure and whether cited IDs exist. The research then evaluates when these drafts are correct, unsupported or misleading."

| Stage | Show this code | Demonstration / professor's likely question |
| :-- | :-- | :-- |
| Wazuh loader and normalizer | `src/ingestion/normalize_wazuh_alerts.py` | How are alerts loaded and mapped to a common schema? |
| Local AI investigator | `src/investigation/ai_investigator.py` | Which model, prompt, fields, parameters and local API are used? |
| RAG retrieval | `src/investigation/rag_investigator.py` | How do token overlap and top-k selection choose MITRE guidance? |
| Model input/output comparison | `src/evaluation/compare_rag_conditions.py` | How do we hold the prompt/model fixed and change retrieval context? |
| CloudTrail case builder | `src/ingestion/build_cloudtrail_cases.py` | How do we keep labels separate and group related events? |
| Regression suite | `tests/` | Which 42 historical tests pass, and which new-module tests are still required? |

**Rehearsal commands (only in configured local lab):**

```bash
python3 -m src.ingestion.normalize_wazuh_alerts
python3 -m src.investigation.ai_investigator
python3 -m src.investigation.rag_investigator
python3 -m src.ingestion.build_cloudtrail_cases
python3 -m unittest discover -s tests
```

**Avoid during live demonstration:** The controlled comparison script refuses to overwrite an existing private output. It is not a repeatable one-command demo until output management is improved. Don't delete research outputs merely to re-run it.

**Evidence clips/screenshots:** Reuse the six genuine images in `docs/assets/screenshots/` and the original PNG/SVG in `docs/assets/diagrams/`. Show actual on-screen source and output; never imply the currently planned cloud-case-to-LLM connection or claim-level verifier is already implemented.

**Professor-run deliverable remaining:** Sanitized portable input, supported Python version/dependencies, Ollama model availability/fallback clarity, concise start script, executable test suite, user guide, video, PPT and final report.

## November 5, 2026 — Professor Code Demonstration

Show `src/ingestion/build_cloudtrail_cases.py` and explain:

- Dataset ingestion and normalization
- Actor/IP/time-window correlation
- Separate ground-truth storage
- Protected evidence outputs
- Automated tests in `tests/test_cloudtrail_case_builder.py`

Run: `python3 -m unittest discover -s tests`

Verified result: 50 tests passed. The portable standalone AI demo remains pending.

---

<!-- SOC-MILESTONE-2026-11-09-VERIFIED:START -->

## Professor demonstration — verified SOC pilot (9 November 2026)

**Show in this order (approximately 3–4 minutes, using existing saved outputs):**

1. **Set scope:** "These are 100 simulated cloud-security cases, generating 400 synthetic log events. We performed no real attacks." Show [dataset distribution](assets/soc-2026-11-09/01-simulation-distribution.png).
2. **Real SIEM / simulated input:** Open Wazuh **Threat Hunting → Events**, filter `rule.groups = soc_demo`, and show **400 hits** across severity rules 110100/3, 110101/8, 110102/12; [verified screenshot](assets/soc-2026-11-09/wazuh-filtered-400-events.png). Do **not** call 100 high alerts 100 real critical incidents.
3. **Same source IDs, separate execution paths:** Point out `sim_event_id` appears in generated case and Wazuh fields. Local file cross-check: **397/400**; acknowledge three-record unresolved difference.
4. **Three-method comparison:** Show [six-case stacked outcome chart](assets/soc-2026-11-09/02-six-case-outcomes.png) and [case-level matrix](assets/soc-2026-11-09/03-same-case-decisions.png): baseline 6/6 correct, LLM-only 2/6 correct with 2 errors, RAG 2/6 correct with 1 error. This **small engineered sample does not prove general superiority**.
5. **Critical analysis:** Open the [reviewed SOCSIM-008 executive brief](soc_results_2026-11-09.md#reviewed-sample-executive-brief--socsim-008-simulation-only). Explain that `StopLogging`/`DeleteTrail` would justify investigation in a live AWS account, but the model mistakenly called it S3-bucket deletion. An evidence-grounded report needs review.
6. **Close:** "A working research demonstration now joins SOC visibility to AI comparison on shared simulated evidence; future steps are automated alert-to-AI intake, external ground-truth evaluation, claim-level checking and analyst efficiency measurement." No live AI runs or log reinjection required to demonstrate the recorded results.

**If asked about deployment errors:** Show experiment log: first custom rule `<field name="action">` failed with Wazuh static-field error, roll-back restored service, two conditions were changed to `<action type="pcre2">`, all three rules were then verified. **Do not erase the debugging history.**

<!-- SOC-MILESTONE-2026-11-09-VERIFIED:END -->
