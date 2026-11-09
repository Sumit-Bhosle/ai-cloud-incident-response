# Three-Method Cloud Security Investigation Comparison

## Research question
Do pretrained LLMs and retrieval-augmented LLMs improve security incident classification and evidence-supported explanations relative to conventional rules?

## Fixed methods
1. **Baseline:** transparent deterministic rules on action counts, identity hints, and sensitive operations.
2. **LLM-only:** local Qwen2.5 1.5B via Ollama, no retrieved security context.
3. **RAG + LLM:** same model/prompt/evidence/seed, plus locally retrieved AWS/MITRE/NIST notes.

## Experimental dataset and control
- Development CloudTrail cases from `data/lab_evidence/cloudtrail/development/cases.jsonl`.
- Three attack-scenario-stratified cases plus up to three benign controls are selected deterministically. Ground truth is **used only for sampling and post-prediction evaluation**, never supplied to an investigator.
- Each arm receives **the same event subset and full-case action-count overview**. Details are capped at 10 events by default to fit a small CPU model. This may conceal relevant attack details, especially in large mixed cases.
- Raw archives and private outputs are Git-ignored. Do not delete originals or the initial pilot.

## Outputs
`data/lab_evidence/cloudtrail/development/benchmarks/comparison_02/`
- `manifest.json`: selected IDs, model and configuration.
- `selection_audit_PRIVATE.json`: selected development case labels (not model-visible).
- `baseline/*.json`, `llm_only/*.json`, `rag/*.json`: full per-case results.
- `comparison_metrics_PRIVATE.json`: per-case predictions, confusion counts, abstentions and inference time.

## Commands
```bash
python3 -m unittest discover -s tests -q
python3 -m src.evaluation.run_cloud_comparison --prepare-only
python3 -m src.evaluation.run_cloud_comparison
```

## Important limitations
- Scenario-stratified six-case sample is a **functional demonstration**, not a representative accuracy estimate. The dataset has three known development scenarios; unseen scenarios are in the reserved test split.
- Heuristic event correlation does not establish independent incidents.
- Precision/recall/F1 are computed **only on cases classified benign or suspicious**, with abstentions and failures explicitly reported.
- Baseline `benign` means no configured rule fired, not a guarantee of safety.
- Valid citation IDs do **not** independently prove free-text claims. Existing `verify_cloud_ai_report.py` supplies targeted additional checks, but it does not verify all claims.
- Inference time is not the same as measured human analyst time; analyst efficiency claims are not demonstrated.

## Structured-output failure and correction (November 8, 2026)
The original experiment in `comparison_01/` returned 11 Qwen JSON errors across 12 AI calls. The baseline completed all six cases, LLM-only completed one, and RAG completed none. The 400-token generation cap was a plausible contributor; no raw model finish-reason diagnostics were captured, so truncation could not be conclusively established. See [failure analysis](llm_output_failure_analysis.md).

The revised `comparison_02/` keeps the same cases, model, evidence, ground truth, and three methods. It requests concise structured output, raises the output limit (900 tokens, one retry at 1500), and records Ollama finish-reason details in errors. No malformed JSON is silently repaired or counted as correct.

## November 8: second live failure, isolated correction
`comparison_02/` produced six valid RAG reports but zero valid LLM-only reports. Five LLM-only reports invented knowledge citations in a condition with no retrieval, and one returned Ollama HTTP 500. The validator correctly rejected these. The updated source constrains `knowledge_ids` to an empty list for LLM-only and to retrieved IDs for RAG, while retaining the same cases, evidence, Qwen model, temperature, seed and evaluation. It retries transient Ollama server errors once. New outputs go only into `comparison_03/`. See [documented failures](llm_output_failure_analysis.md). No reported metrics should be replaced with guessed values.

## Verified three-method experiment — comparison_03

Dataset: AWS CloudTrail development split.
Sample: 6 selected cases, 3 attack-associated and 3 benign.
Methods: Traditional baseline, Qwen LLM-only, Qwen with RAG.
Model: Qwen2.5 1.5B through local Ollama.

| Metric | Baseline | LLM-only | RAG + LLM |
|---|---:|---:|---:|
| Successful reports | 6/6 | 6/6 | 6/6 |
| Precision | 1.0000 | 0.5000 | 0.5000 |
| Recall | 0.3333 | 1.0000 | 0.3333 |
| F1 | 0.5000 | 0.6667 | 0.4000 |
| False positives | 0 | 3 | 1 |
| False negatives | 2 | 0 | 2 |
| Mean reported inference time (s) | 0.0 | 19.31 | 12.53 |
| Reports with evidence citations | 1 | 6 | 2 |
| Reports with knowledge citations | 0 | 0 | 0 |

### Engineering failures and corrections

- Comparison 01: 11 of 12 AI runs failed with malformed JSON.
- Comparison 02: RAG succeeded 6/6, but LLM-only failed 6/6.
- Identified invented knowledge citations in LLM-only mode and
  one Ollama HTTP 500 error.
- Corrected structured-output handling, citation constraints,
  and transient failure handling.
- Comparison 03: all 18 investigation reports generated successfully.
- Complete automated suite: 109 tests passed.

### Research limitations

This is a small, balanced development-only experiment, not
a representative estimate of production detection accuracy.

Some large cases were truncated to ten detailed events.
RAG retrieved references for all cases but produced zero
knowledge citations and evidence citations in only two reports.

The existing deterministic verification checks do not validate
all free-text claims. Results do not establish RAG superiority.

Ground-truth labels were used for scoring, not investigator input.
All three experiment directories remain preserved privately.

## Original debugging notes

# Three-Method SOC Comparison: First Failure and Correction

**Research date:** November 8, 2026  
**Component:** `src/evaluation/run_cloud_comparison.py`  
**Dataset:** CloudTrail development cases; six identical selected case IDs for the three methods  
**First run archived privately:** `data/lab_evidence/cloudtrail/development/benchmarks/comparison_01/`

## What failed (actual experiment)

| Method | Valid reports | Failed runs | Observed classification evidence |
|---|---:|---:|---|
| Deterministic baseline | 6/6 | 0 | TP=1, FP=0, TN=3, FN=2; F1=0.50 on this pilot only |
| Local Qwen LLM-only | 1/6 | 5 | One valid benign classification; no meaningful performance estimate |
| Qwen with RAG | 0/6 | 6 | No usable classification metrics |

All eleven failed AI outputs raised `JSONDecodeError`: primarily `Unterminated string`, with one `Expecting property name enclosed in double quotes` error. The runner recorded each failure as an error, not as a benign prediction; the original reports remain preserved privately. The full automated suite had **100 passing tests**, yet live model generation failed. This shows why mocked unit tests cannot substitute for real model integration tests.

## Likely cause, without overstating it

The original run allowed **400 output tokens** per generation (`num_predict=400`) for six-field structured JSON. It is plausible that some responses were cut off; however, the original runner did not record Ollama `done_reason` or `eval_count`, so we cannot conclusively attribute every error to token exhaustion. Model-generated malformed JSON is another possible contributor.

## Correction

- Kept the **same original cases, model (`qwen2.5:1.5b`), deterministic seed, evidence view and ground-truth separation**.
- Requested concise report fields with a bounded JSON schema and increased the initial output budget to **900 tokens**.
- Added **one bounded retry at 1500 tokens** if the response is incomplete, malformed or fails report validation. There is **no silent JSON repair** and no fabricated classification.
- Added informative failure diagnostics including Ollama `done_reason`, token count (`eval_count`, if returned) and token budget.
- Kept the original run at `comparison_01/`; all rerun outputs are isolated under `comparison_02/`.
- Added four regression tests for truncated JSON, invalid JSON, repeated failure and citation validation.

## Rerun and scientific limitations

Run `python3 -m unittest discover -s tests -q` first, then `python3 -m src.evaluation.run_cloud_comparison`. **Expected test count after fix: 104.** Interpret real results only after checking successful report counts per method. Never fill in missing results, treat abstentions as correct predictions, or claim general accuracy from this six-case pilot.

The benchmark still uses heuristic correlation and some **truncated event details** (e.g. 10/258). It is a demonstration of the proposed comparison, **not a comprehensive incident-detection accuracy claim**. Citation-ID membership is not full claim-level verification; measured model inference time is not analyst time saved.

**Research lesson:** valid data pipelines and passing tests are necessary but insufficient; empirical LLM outputs require format checks, failure accounting and preserved negative results.

## Second experiment: comparison_02 (actual observed results)

The structured JSON correction allowed **RAG 6/6** and baseline **6/6** to generate usable reports, while **LLM-only 0/6** failed. The failure records identify the next cause precisely:

- **Five LLM-only cases:** Qwen cited knowledge references that were **not supplied** in LLM-only mode. The validator correctly rejected these reports rather than accepting hallucinated citations, including after the bounded retry.
- **One LLM-only case:** Ollama returned HTTP **500**, a separate transient or service-side error whose underlying cause has not been established.
- **RAG 6/6 valid reports:** TP=2, FP=3, TN=0, FN=1, F1=0.50 in this six-case development experiment. Baseline: TP=1, FP=0, TN=3, FN=2, F1=0.50. In this tiny case set RAG increased recall but also false positives; it did not improve F1.

The failures demonstrate a limitation of a small pretrained LLM under structured output constraints. They must be kept as negative findings, not discarded. **The initial comparison_02 files remain unchanged.**

## Third correction: mode-dependent citation constraints

The corrected experiment in `comparison_03/` does **not** change case selection, evidence, Qwen model, deterministic seed or ground-truth handling. It enforces the *only* allowed citations at generation time:

- **LLM-only:** `retrieved_references=[]`; JSON schema requires `knowledge_ids` to contain **zero** items. Prompt explicitly instructs empty `knowledge_ids` whenever no references are supplied.
- **RAG:** schema permits only the IDs of references that were actually retrieved. Existing post-generation citation membership verification remains active.
- **Ollama HTTP 500/502/503/504:** allow one bounded repeat of the generation request; HTTP 400 and other nontransient errors still fail immediately. A repeated service error is recorded, not hidden.

Five further regression tests check these conditions. A real Qwen smoke test and complete comparison are required to establish whether this change works on the Ubuntu VM; mock tests alone cannot prove it.

---

<!-- SOC-MILESTONE-2026-11-09-VERIFIED:START -->

## Separate Nov 9 synthetic SOC experiment — do not merge with CloudTrail pilot

A later **100-case synthetic Wazuh simulation** ran a distinct **six-case three-class** comparison. On the same selected cases, the rule baseline was **6/6 correct**, Qwen LLM-only **2/6 correct with 2 output errors**, and Qwen RAG **2/6 correct with 1 error**. Class labels were deliberately generated; this is a demonstration, not external attack-detection accuracy. The prior CloudTrail development benchmark in this document measures a **different binary attack-associated target**, so its F1 scores cannot be combined with these synthetic three-class results. See the [synthetic SOC evaluation with screenshots, outcome charts and factual-error audit](soc_results_2026-11-09.md).

<!-- SOC-MILESTONE-2026-11-09-VERIFIED:END -->
