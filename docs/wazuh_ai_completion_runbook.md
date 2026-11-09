<!-- FINAL-RESEARCH-2026-11-09-HISTORICAL -->

> **Historical snapshot notice (updated 9 Nov 2026):** This page preserves an earlier experiment state; for the completed 100-case Wazuh-sourced results, see [final measurements](wazuh_ai_final_results.md) and [research journey](RESEARCH_JOURNEY_AND_LIMITATIONS.md). The earlier 397/400 current-log discrepancy was resolved by reading Wazuh archives (400/400 verified IDs, 100 complete cases, zero mismatches).

---

# One-day research completion gate — Wazuh → AI → executive review

**Project:** Evaluating AI-Assisted Cloud Security Incident Response (COMP 5112).  
**Purpose:** Complete the actual Wazuh-to-AI evidence flow **without inventing attacks, assuming model correctness, or overwriting prior experiments**.  
**Local model:** pretrained `qwen2.5:1.5b` through Ollama; **not fine-tuned**.

## Completion criteria (all P0 mandatory)

- [x] **P0. Wazuh source verified:** import the manager's real JSON alert records. For every used event, verify its source event ID, case ID, actor, IP, action, resource, service, error code, rule ID and monitored log source. Report missing or conflicting events. No inferred incidents.
- [x] **P0. End-to-end:** run one named critical case **from Wazuh alerts**, obtaining baseline, raw LLM and raw RAG assessments plus a guarded triage decision. Each report must expose matched Wazuh alert IDs and simulated event IDs.
- [x] **P0. Fact safety:** do not publish unverifiable claims about confirmed data loss, successful AWS operations, S3 deletion when only CloudTrail deletion occurred, or credential attacks without evidence. Human approval is always required.
- [x] **P0. Model errors:** show abstentions/errors, claim checks, contradictory severity and missing citations. On failure the case stays in analyst review; it never defaults silently to benign.
- [x] **P0. Executive output:** reviewed readable HTML **and** Markdown with what Wazuh recorded, possible impact, exact matching IDs, concrete actions for the client and risk qualification.
- [x] **P1. Reproducible evaluation:** run across all eligible complete Wazuh cases (up to 100), with cached checkpoints, same cases for all methods, true/false classifications and failures scored against truth **after** models run.
- [x] **P1. Documentation:** publish only the observed data and limitations, do not merge six-case earlier CloudTrail development outcomes with the new 100-case synthetic experiment.

**Important scope boundary:** An automated **polling bridge** reads Wazuh's alert file and investigates a complete case when it is available. This is not a production deployment, a Wazuh dashboard action/webhook, an AWS API integration, a real attack, or autonomous incident remediation. Our generated labels are a designed reference, not real attack ground truth.

## 0. One-time installation

From Ubuntu project root, extract the update ZIP:

```bash
cd ~/Projects/ai-cloud-incident-response
unzip -n ~/Downloads/wazuh_ai_research_completion.zip -d .
python3 -m unittest discover -s tests -q
```

**Does not replace** your existing `src/demo/soc_demo.py`, Wazuh rules, README, synthetic datasets, or previous experiments.

## 1. Get the real manager alerts to a private, user-owned export

This exports only simulation-tagged Wazuh alert records and keeps the file outside Git; never expose credentials or unrelated Linux audit records.

```bash
cd ~/Projects/ai-cloud-incident-response
umask 077
sudo grep '"soc_demo":"research_simulation"' /var/ossec/logs/alerts/alerts.json > data/lab_evidence/soc_demo/wazuh_alerts_export_PRIVATE.jsonl
python3 -m src.demo.wazuh_pipeline audit --alerts data/lab_evidence/soc_demo/wazuh_alerts_export_PRIVATE.jsonl
```

Expected for the current lab: **at least 397 verified IDs out of 400**. In a prior Wazuh dashboard screenshot, the indexer showed 400 hits, whereas the current manager alert file matched 397 event IDs. Do not silently equate these counts. If exactly 397, up to **99 of 100 cases** may be complete. You can also investigate archived JSON Wazuh logs by running `sudo python3 -m src.demo.wazuh_pipeline audit --alerts /var/ossec/logs/alerts` (read-only; writes the audit as root). Be careful of root-owned output files after sudo; keep the normal-user export for routine runs. If archived logs yield all 400, export the verified records to a user-owned private file before the batch run.

If the manager log is rotating while recording, repeat the export to a *new* private file and run it as a new experiment, rather than mutating an already-saved report's evidence fingerprint.

## 2. End-to-end acceptance test on a HIGH-impact case

```bash
python3 -m src.demo.wazuh_pipeline run \
  --alerts data/lab_evidence/soc_demo/wazuh_alerts_export_PRIVATE.jsonl \
  --case SOCSIM-008
```

This case includes recorded `DescribeTrails`, `StopLogging` and `DeleteTrail` cloud audit events. The correct evidence-based concern is **possible CloudTrail audit disruption**, **not S3 bucket deletion**, and success of those API calls remains unverified.

Wait for the baseline, LLM and RAG results. A failed model remains a recorded failure and **requires human review**. Output is incrementally saved under `data/lab_evidence/soc_demo/wazuh_ai_pipeline/cases/SOCSIM-008.json`.

```bash
python3 -m src.demo.wazuh_pipeline evaluate
```

Open the generated stakeholder report in Ubuntu or Windows:

`data/lab_evidence/soc_demo/wazuh_ai_pipeline/EXECUTIVE_REPORT_REVIEW_REQUIRED.html`

Also inspect `EXECUTIVE_REPORT_REVIEW_REQUIRED.md` and `evaluation_PRIVATE.json`.

## 3. Full reproducible same-case evaluation

**Once the single-case live test passes**, run the remaining complete cases (resumable). The new prompt is applied to both LLM and RAG modes. Each completed case is cached; rerunning the command won't repeat successful/corrupted responses or overwrite prior results.

```bash
python3 -m src.demo.wazuh_pipeline run \
  --alerts data/lab_evidence/soc_demo/wazuh_alerts_export_PRIVATE.jsonl \
  --limit 100
python3 -m src.demo.wazuh_pipeline evaluate
```

Depending on CPU resources and response retries, ~200 local model invocations may take significant time. If interrupted, rerun the identical `run` command. **Do not** run a second parallel batch. Record actual durations and errors rather than assuming an exact time or result. If Wazuh lacks a complete set of source events, the case is skipped and not scored.

The experiment computes 3-class precision/recall/F1, macro-F1, all-case accuracy (including errors), answer-only accuracy, failure counts, confusion by true label, model runtime and individual evidence references. The `guardrailed_triage_rule_enforced` row is a deterministic safety gate and **must not** be represented as improved AI accuracy.

## 4. Optional automatic Wazuh alert polling (single-case recording demonstration)

You can demonstrate that the system directly polls Wazuh alert JSON records, groups matching case IDs, and launches AI investigation automatically. Using an **existing** simulated case is sufficient; no new attack or log injection is required.

```bash
sudo python3 -m src.demo.wazuh_pipeline watch \
  --alerts /var/ossec/logs/alerts/alerts.json \
  --case SOCSIM-009 \
  --once \
  --out /tmp/wazuh_ai_live_demo
```

This runs with sudo only because Wazuh's alert file is protected. The `/tmp` demo reports may be root-owned. It reads Wazuh and writes a new investigation; **it does not restart Wazuh, inject an event, delete anything, or call AWS**.

For continuous file polling omit `--once` and use `--limit 100`; press **Ctrl+C** to stop. For clean presentation, start with the existing case and show alert IDs mapping into the investigation JSON. A complete production event-streaming/webhook integration is **out of scope** and should not be claimed.

## 5. Publish the final verified findings (only AFTER actual model runs)

```bash
python3 tools/publish_wazuh_milestone.py
python3 -m unittest discover -s tests -q
git diff --check
git status --short
```

The publisher reads actual aggregate scores from `data/lab_evidence/` and writes a public, aggregate-only `docs/wazuh_ai_final_results.md`; it updates the README link idempotently. Do **not** commit `data/lab_evidence/`, the full local Wazuh alerts, or private per-case model reports.

Commit only the source/test/docs from this completion patch and the generated aggregate report, **after confirming the local run**. Suggested truthful commit: `feat: connect Wazuh alerts to guarded AI investigation and evaluation`.

## Demonstration narrative (4–6 minutes)

1. **Wazuh dashboard:** filter `rule.groups: soc_demo`; show 400 indexed **synthetic** alerts, 3 rule levels, and a specific case/event ID (`SOCSIM-008`). Wazuh runs on the real installed SIEM but the CloudTrail-like content is simulated.
2. **Evidence bridge:** show the `audit` output. Explain 400 indexed vs 397 in the local current alert-file snapshot if unresolved; never claim perfect coverage without evidence.
3. **Automated investigation:** `watch --once --case SOCSIM-009` or `run --case SOCSIM-008` reads Wazuh alerts and launches baseline / LLM / RAG on the corresponding evidence. Ground-truth labels stay out of prompts.
4. **Stakeholder report:** open the generated HTML, show cloud audit risk, Wazuh event citations, potential business impact and actionable human checks.
5. **Critical research finding:** some raw model verdicts are wrong or unavailable; the guardrail prevents silent downgrade. Explain baseline/LLM/RAG scores, error rates, latency and limitations from observed results.
6. **Claim boundaries:** no real AWS incident, no fine-tuning, no autonomous remediation, no proven real-world AI performance improvement.

## Documentation references

See the project's existing `docs/soc_demo.md`, `docs/soc_results_2026-11-09.md`, `docs/three_method_comparison.md`, and `docs/experiment_log.md`. Keep their earlier results unchanged. Wazuh stored-alert source: https://documentation.wazuh.com/current/user-manual/manager/alert-management.html
