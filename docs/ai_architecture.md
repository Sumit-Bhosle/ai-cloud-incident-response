<!-- AI-ARCH-2026-11-04 -->
# Evidence-Grounded AI Investigation Architecture

*Research prototype reference — updated November 4, 2026*

> This document separates **verified functionality**, **experimental prototypes**, and **planned research work**. The project evaluates AI-assisted incident response; Wazuh is a telemetry source, not the AI.

## Architecture overview

```mermaid
flowchart LR
  W[Wazuh security alerts] --> N[Wazuh normalizer]
  C[AWS CloudTrail ZIP] --> P[CloudTrail normalization + time-window cases]
  N --> X[Evidence and provenance records]
  P --> X
  X --> L[Local Ollama / Qwen LLM prototype]
  R[Keyword MITRE / NIST reference retrieval] --> L
  L --> J[JSON investigation + citation IDs]
  J --> V[Existing: schema and ID checks]
  V --> H[Human review]
  G[(Private case/event labels)] --> E[Evaluation - under development]
  H --> E
  V -.-> F[Planned: claim-level support checking]
```

**Important:** `build_cloudtrail_cases.py` does not yet feed its case outputs to the LLM. The graph is an intended system architecture assembled from separately verified components, not a demonstrated autonomous end-to-end deployment.

## Code responsibilities

| Python module | Core responsibility | Input → output | Status |
| :-- | :-- | :-- | :-- |
| `src/ingestion/normalize_linux_journal.py` | Parse original `su` journal export, validate and normalize | Linux journal → JSONL events | Verified with real preflight |
| `src/ingestion/normalize_wazuh_alerts.py` | Read archived Wazuh alerts, verify known-run hash, normalize | Wazuh JSONL → JSONL events | Verified on run 002; currently run-specific |
| `src/investigation/ai_investigator.py` | Build prompt, run Ollama API, schema/ID-check response | Wazuh events → JSON report | Prototype executed |
| `src/investigation/rag_investigator.py` | Tokenize, retrieve notes, invoke LLM with references | Events + notes → JSON report | Keyword RAG prototype executed |
| `src/evaluation/compare_rag_conditions.py` | Compare same-prompt runs with/without retrieved docs | One Wazuh case → private comparison | Executed once; non-blind |
| `src/ingestion/build_cloudtrail_cases.py` | Normalize event fields and group actor/IP/time bins, separate labels | Training ZIP → private case and truth JSONL | Executed on 4,216 records |

## Explaination

**`normalize(record, index)` (CloudTrail):** Extracts timestamps, actor identifiers, source IP, AWS service/action and limited context, then returns an event and a grouping key. It intentionally does not copy source `should_sample`/`attack_name` labels into AI evidence.

**`retrieve_references(events, documents, top_k)` (RAG):** Tokenizes event-action descriptions and document summaries; ranks by lexical overlap. This is deterministic retrieval, not embedding-based semantic search; a matching document is background knowledge, not proof of attack.

**`investigate(events)` or `investigate_with_rag(...)` (AI):** Selects event fields, constructs a system/user prompt, sends a JSON request to local Ollama, parses a model-generated report, validates schema and known citation IDs. This proves interface execution, *not* factual trustworthiness or a trained custom model. Qwen2.5 1.5B is a downloaded pretrained model used for inference, not a model trained by this project.

**`main()` (case builder):** Reads the training ZIP, normalizes every record, groups by `(actor, source_ip, 30-minute bin)`, writes the separate private label files, and checks for a direct label leak. Case grouping is a heuristic and can combine unrelated events.

## Measurable research limitations

- The authorized `su` preflight has been repeatedly labeled `suspicious` by LLM variants. This remains a preserved error case.
- The controlled RAG investigation returned no knowledge IDs despite retrieval. Citation membership is not citation *support*.
- Evaluation must keep case-level and event-level metrics distinct; no comprehensive score has been computed yet.
- Existing 42 regression tests cover earlier pipeline functionality; these new AI/CloudTrail modules need dedicated unit/integration tests.
- Source datasets and private results remain Git-ignored; the public repo does not currently include a clean-machine standalone demo.

## Local developer execution (requires configured lab)

```bash
python3 -m unittest discover -s tests
python3 -m src.ingestion.build_cloudtrail_cases
python3 -m src.investigation.ai_investigator
python3 -m src.investigation.rag_investigator
```

**Next architecture gates:** robust correlation; provenance-aware citation validation; guarded abstention; controlled cloud case evaluation; sanitized reproducible demo; documented exact dependency/model versions and latency measurements.

## Phase 99 — CloudTrail integration

Source: `src/investigation/cloud_case_investigator.py`

1. Read correlated development cases.
2. Select a small case without using ground truth.
3. Choose service-relevant AWS/MITRE references.
4. Cap detailed events and flag truncated evidence.
5. Send evidence and references to local Qwen.
6. Validate JSON schema and known citation IDs.
7. Save a protected private report.

Current limitations: keyword/service-based retrieval,
heuristic case grouping, no claim-level factual verifier,
and no independently established AI classification accuracy.

## Phase 100 — Independent Evidence Verification

CloudTrail case → AI/RAG report → deterministic verifier
→ verification artifact → analyst review.

Implementation: `src/evaluation/verify_cloud_ai_report.py`

The original AI response remains unchanged. The verifier
checks evidence hashes, citation identifiers and selected
factual claims without consulting attack ground truth.

Full claim-level semantic verification remains future work.

## Investigation evaluation framework

CloudTrail cases + saved investigation reports feed the
independent evaluation module.

Ground-truth labels are joined only during evaluation,
not supplied as AI investigation inputs.

Metrics include report coverage, confusion counts,
selective classification metrics, citation membership,
verification flags and inference time.

Cross-method comparison requires reports for common case IDs.

---

<!-- SOC-MILESTONE-2026-11-09-VERIFIED:START -->

## Implemented simulated SOC integration — verified 2026-11-09

The [actual execution diagram, Wazuh screenshots, and evaluation results](soc_results_2026-11-09.md) supersede any impression that the SOC-to-LLM step is automatically triggered. The simulator emits two views of **the same synthetic events**: a monitored JSON log for Wazuh and grouped case JSONL for the Python investigators. Wazuh rules 110100–110102 produce detection alerts; Python independently runs baseline, Qwen2.5 LLM-only, and keyword-retrieval RAG. A separate ID-matching routine compares Wazuh alert IDs against source event IDs; the AI does **not** presently ingest the Wazuh dashboard or its indexed alerts directly.

The pilot showed 400 dashboard hits, 397 local alert-ID matches and a six-case comparison. **Retrieval is not source-grounded fact verification** and the generated report contains identified hallucinations. No fine-tuning, autonomous incident response, or analyst-efficiency improvement is established.

<!-- SOC-MILESTONE-2026-11-09-VERIFIED:END -->

<!-- FINAL-RESEARCH-2026-11-09-APPEND -->

## Completed 2026-11-09 implementation: verified Wazuh polling bridge

`src/demo/wazuh_pipeline.py` reads the actual Wazuh manager alert JSON or its JSON/GZ archive directory, filters simulation-tagged records, and verifies case ID, event ID, actor, IP, action, service, resource, error code, Wazuh rule and log source against generated evidence. Incomplete cases are not scored. A `watch` mode polls for new complete cases. The identical verified case goes to rule baseline, Ollama/Qwen model and reference-assisted model; truth labels and Wazuh severity are excluded from prompts. `grounded_model.py` enforces constrained output formats and citations; `executive_html.py` renders an evidence-based report with human review gating. The review gate does not alter the recorded raw model classification for evaluation.

Full setup: [SETUP_FROM_SCRATCH.md](SETUP_FROM_SCRATCH.md). Final results: [wazuh_ai_final_results.md](wazuh_ai_final_results.md).
