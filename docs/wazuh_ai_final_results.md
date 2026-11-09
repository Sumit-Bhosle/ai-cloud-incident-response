# Wazuh-linked AI investigation — observed results

**Research simulation, not real AWS attack observations.**

Fully investigated matched Wazuh cases: **100** (from up to 100 generated synthetic cases).

## Verified Wazuh source coverage

- Expected simulated events: **400**
- Verified unique events: **400**
- Verified coverage: **1.0**
- Complete cases: **100**
- Partial or absent cases: **0**
- Mismatch count: **0**

The alert-file count may differ from indexed Wazuh dashboard search hits due to their different storage windows; do not interpret that difference as evidence of a malicious event.

## Paired comparison of the same cases

| Method | Correct / evaluated | Model errors or abstentions | Accuracy on all | Macro F1 | Mean runtime (seconds) |
|---|---:|---:|---:|---:|---:|
| `baseline` | 100/100 | 0 | 100.0% | 1.000 | 0.0 |
| `llm_only` | 53/100 | 0 | 53.0% | 0.419 | 13.466 |
| `rag` | 30/100 | 0 | 30.0% | 0.154 | 13.944 |
| `guardrailed_triage_rule_enforced` | 100/100 | 0 | 100.0% | 1.000 | not applicable |

**Accuracy note:** All-case accuracy counts errors/abstentions as failures. The guardrailed rule-enforced row is a safety feature built from existing rules, not a fourth independent AI model. Model prompts exclude Wazuh rule severity and private simulation reference labels.

**Prompt/version note:** This Wazuh-linked experiment uses a separate structured prompt and directly read Wazuh records; its results are not directly comparable to the earlier six-case synthetic `soc_demo.compare()` or CloudTrail development experiments.

## Research limitations

- Synthetic case patterns repeat 10 templates; no statistical generalization to live cloud compromise.
- Baseline and safeguards share rule patterns with synthetic scenario construction.
- Raw LLM outputs may be wrong or fail; do not present safeguard scores as AI performance.
- Missing Wazuh alerts are excluded rather than fabricated.
- No real attacks, cloud calls, autonomous response, or final human approval occurred.

**Supporting evidence:** `docs/assets/soc-2026-11-09/wazuh-filtered-400-events.png`, `docs/soc_results_2026-11-09.md`, and local private matched-alert investigation reports. The private source logs and raw model responses remain Git-ignored.
