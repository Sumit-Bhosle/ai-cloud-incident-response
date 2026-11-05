# Research Development Checkpoint — November 4, 2026

## Project
Evaluating AI-Assisted Cloud Security Incident Response
COMP 5112, Lakehead University — Group 13

## Verified achievements
- Wazuh 4.14.9 monitoring with genuine Linux authentication alerts.
- Detection rules 5503 and 5301 verified in the SOC dashboard.
- Private Wazuh evidence exported, normalized and SHA-256 verified.
- Local Ollama / Qwen2.5 1.5B inference executed.
- Python AI investigator produced a schema-valid JSON report.
- Keyword-based RAG retrieved MITRE ATT&CK references.
- Exploratory LLM-only versus RAG comparison executed.
- CloudTrail test dataset audited: 24,087 records, 2,585 attack-labeled,
  21,502 benign, ten attack scenarios.
- Eight repeated eventID occurrences identified in the test dataset.

## Verification performed at checkpoint
- Python compilation: PASSED
- Automated regression tests: PASSED
- CloudTrail development case builder: VERIFIED
- Case builder details: 4216 records, 1742 cases; labels separated
- Private CloudTrail evidence Git-ignored: YES

## Research observations
- Both LLM-only and RAG-assisted conditions classified the authorized
  authentication preflight as suspicious.
- The RAG comparison produced no knowledge citations despite retrieving documents.
- Format and citation-ID validation do not prove factual correctness.
- Two Wazuh alerts resulted from one controlled authentication attempt.
- Both attack and benign CloudTrail records contain common S3 API actions.

## Implementation status
- Wazuh and journal normalization: functioning, verified with real lab data.
- Local LLM inference and RAG: functional research prototypes.
- CloudTrail case builder: VERIFIED.
- Cloud case-level AI investigation and large-scale benchmark: pending.
- Full citation support verification: pending.
- Clean-machine standalone professor demonstration: pending.
- Final report, presentation and video: pending.

## Architecture and demo risks to resolve
1. The current Wazuh normalizer has hard-coded experiment paths and a hash.
2. The AI scripts depend on local Ollama and private evidence files.
3. Keyword retrieval can return relevant sources without supported claims.
4. The initial actor/IP/30-minute correlation is a heuristic, not a
   validated incident-grouping algorithm.
5. Dedicated automated tests are still required for the new AI, RAG,
   CloudTrail ingestion and case-correlation modules.
6. Final evaluation must keep ground truth separate from AI input and
   report case-level as well as event-level results.
7. Build a sanitized, portable demo with explicit setup commands.

## Next development session
1. Resolve any CloudTrail case-builder verification failures.
2. Add CloudTrail normalization and correlation tests.
3. Build case-level AI investigation and evidence verification.
4. Benchmark on development cases before running the held-out test set.
5. Package a professor-runnable demo, code walkthrough and SOC report.

## Research integrity
Results are preliminary. No claim is made that RAG improves accuracy,
that 2,585 attack-labeled events represent 2,585 independent attacks,
or that the current prototype is production-ready.
