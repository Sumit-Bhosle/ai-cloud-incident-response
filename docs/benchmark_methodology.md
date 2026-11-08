# Cloud Investigation Benchmark Methodology

## First pilot: reproducible development cohort

`python3 -m src.evaluation.prepare_cloud_benchmark`

- Inputs are **development** split CloudTrail cases and separately stored case truth.
- A fixed random seed selects four pure attack-associated cases and four pure benign cases, each with at most 20 events.
- Attack samples preferentially cover different named scenarios; benign samples preferentially span different case-size groups.
- Mixed-label cases are excluded **from this initial pilot only**; future benchmarking must explicitly include them.
- A label-free `cases.jsonl` and `manifest.json` provide inputs to all methods.
- `selection_audit_PRIVATE.json` contains evaluation labels and must **never** be sent to any investigator or LLM.
- Benchmark outputs remain Git-ignored under `data/lab_evidence/cloudtrail/development/benchmarks/pilot_01/`.
- File SHA-256 metadata and refusal to overwrite modified outputs improve repeatability.

## Scientific caveats

The 4:4 sample is **case-control-balanced**, not representative of the dataset's attack prevalence. Do not report its accuracy as a population estimate. This is a *pipeline pilot*, not a final benchmark. Do not tune prompts or detection thresholds against held-out test cases. No CloudTrail test-split data are read by this script.

## Follow-up work

1. Make the rule-based baseline accept the same `cases.jsonl` case objects as the AI and RAG investigators.
2. Fix model version, prompt and generation parameters; preserve the same event evidence and token budget for AI-only vs RAG.
3. Save all outputs with case ID, source hash, model settings, inference time and verification results.
4. Evaluate only matched cases, report abstention and coverage separately, and conduct a larger/more representative development study before final test evaluation.
