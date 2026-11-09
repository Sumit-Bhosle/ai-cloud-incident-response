# Research journey, engineering decisions and measured limitations

**Project:** Evaluating AI-Assisted Cloud Security Incident Response · Lakehead University COMP 5112 · Study consolidation, November 9, 2026.

This document is the **final status narrative**; earlier dated logs and pilot reports retain their historical snapshots, including errors. It does not rewrite or erase experiments that failed.

## 1. Motivation and research question

We evaluated whether AI could support a conventional security operations workflow: detect cloud-like security events, correlate the same incident evidence, produce a grounded investigation, communicate findings in nontechnical language, and measure the behavior of a rules baseline versus LLM-only and retrieved-reference-assisted LLM variants.

The original design intentionally separated **facts observed in logs** from **model interpretation** and from **simulator-defined labels**. Actual response quality, rather than the presence of an AI model, was the deciding measurement.

## 2. Chronological development

| Stage | What was built or tested | Verification and learning |
|---|---|---|
| Research design | Architecture and evidence/schema contracts | Defined labels separately from investigation evidence; source-event integrity and citation membership checks |
| Local feasibility | Windows host, VMware Ubuntu guest, Python and locally served Ollama/Qwen2.5 1.5B | CPU-only model works, but is slow and may truncate/misformat outputs; pretrained **not fine-tuned** |
| Linux monitoring | Wazuh Manager, Indexer, Dashboard; controlled Linux authentication signals | Real Linux PAM/sudo logs were observed but are **not** the same evidence as the synthetic cloud demo |
| CloudTrail development track | Public Ariel Cyber training archive (4,216 events), normalized into 1,742 heuristic cases | Case boundaries, mixed labels and attack-associated labels made evaluation difficult; external 24,087-event archive was acquired but **not** used as a final external benchmark |
| AI prototype | Rule baselines, local Qwen investigator, retrieved security reference notes | Some responses lacked citations or confused actions with confirmed outcomes |
| Paired six-case CloudTrail pilot | Baseline vs LLM-only vs RAG on the same small set of labeled development cases | Baseline F1=0.50, LLM-only F1≈0.667, RAG F1=0.40; not a robust population-level estimate and a different **binary task** from final SOC study |
| Structured output debugging | Adjusted JSON response constraints, capped prompts and validation/retries | Earlier runs failed formatting, invented IDs or returned Ollama errors; full format success later obtained in the pilot |
| Controlled SOC generator | Ten simulated scenario templates × ten = 100 cases, 400 CloudTrail-like JSON log events | Labels: 40 benign, 30 suspicious, 30 critical; all actions are **simulated** |
| Wazuh demo rules | Rule IDs 110100 (level 3), 110101 (level 8), 110102 (level 12) | First manager restart failed: rule `110101` incorrectly addressed `action` as a static `<field>`; changed to `<action type="pcre2">` and validated; Wazuh recovered safely |
| Dashboard evidence | Ingested 400 records; captured Wazuh Threat Hunting screenshot | The real Wazuh instance showed 400 academic simulation hits, not 400 real attacks |
| First SOC six-case test | Baseline 6/6, LLM 2/6, RAG 2/6 correct with output failures | Early generated client-facing prose hallucinated bucket deletion and wrongly dismissed repeated logins; not safe as-is |
| Evidence-verification bridge | Python reads **actual Wazuh alert records**, checks every source field, groups cases and polls for complete evidence | Verified `SOCSIM-009` through direct `watch --once` to source event IDs; no Wazuh UI button or AWS API action |
| Full 100-case study | 140 regression tests; 100-case score from same Wazuh-linked evidence | Baseline **100/100**, LLM-only **53/100**, RAG **30/100**; model errors and factual-quality flags saved |
| Archived alert reconciliation | Read current and rotated Wazuh JSON alert files | Found **797 candidate** records, **397 duplicates**, **400 unique matching IDs**, **100/100 complete cases**, **0 mismatches**; resolves the earlier 397/400 current-file discrepancy |
| Guarded executive reporting | Human-review-required Markdown and HTML with verified actions, event IDs, potential exposure and analyst checks | AI explanatory text is kept separate; not client-approved without human review |
| Public publication | Code, tests, aggregate-only results, screenshots and research logs committed to GitHub | Verified source commit `0661ce8` on `main` and clean working tree after the final pipeline commit |

The development and experiment logs remain primary records of troubleshooting. This synopsis is a navigational bridge, not a replacement.

## 3. The final 100-case experiment

### Data design and integrity

- **100 designed synthetic cases**, **400 generated event records**, **10 scenario templates repeated 10×**, 3-class severity labels: 40 benign / 30 suspicious / 30 designated critical.
- **Actual SIEM**: Wazuh Manager and dashboard; **synthetic input**: controlled CloudTrail-like JSON, not actual AWS service activity.
- Custom rule distribution among unique verified events: 160 level-3, 140 level-8 and 100 level-12 events.
- Wazuh alert integrity audit: **400/400** unique simulation IDs matched generated source fields, **zero mismatches**; 397 duplicate alert documents from current/rotated sources counted separately.
- Model inputs use **verified Wazuh alert fields**, excluding simulation truth labels and Wazuh rule severity. Truth was read only in the scoring step after saving model outputs.

### Quantitative findings

| Investigation method | Cases scored | Correct | All-case accuracy |
|---|---:|---:|---:|
| Deterministic rules baseline | 100 | 100 | 100% |
| Pretrained Qwen2.5 1.5B (LLM-only) | 100 | 53 | 53% |
| Qwen2.5 1.5B + curated reference-note retrieval (RAG) | 100 | 30 | 30% |

**Do not infer real-world superiority of the baseline.** The generated scenarios and baseline were engineered around aligned features. **Do not infer RAG improved classification:** in this experiment it generally predicted `suspicious` regardless of whether the scenario was benign or critical. Model-specific claims and citations can still be wrong even when structured output is valid.

### Realistic interpretation example: `SOCSIM-009`

The Wazuh alert records contain `ListPolicies`, `CreateAccessKey`, `AttachUserPolicy`, identified by `SOCSIM-009-EVT-01` through `EVT-03`. Rule-based triage categorized the pattern as critical; observed LLM-only and RAG decisions under-rated it as suspicious in the live Wazuh-linked run. The conservative reporting layer preserved human priority review and recommended verifying IAM authorization, key history and policy attachments. This is **not evidence that real AWS permissions changed** or that any account was compromised.

## 4. Engineering failures and what they taught

| Failure / discrepancy | Root cause or verified diagnosis | Remedy / research relevance |
|---|---|---|
| CLI setup script said Wazuh config was missing | Non-root user could not access `/var/ossec/etc/ossec.conf` | Re-run protected inspection and helper with `sudo`, not reinstall Wazuh |
| Wazuh service restart failed | Invalid custom XML condition for `action`: static-field error | Rule `<action type="pcre2">`; rule-test and analysisd validation before restart; rollback worked |
| Model returned invalid JSON / HTTP errors | Local model constraints and output format inconsistent, including truncated answers | JSON schema/format validation, retry, explicit failure/abstention; never default error to benign |
| Wrong model explanations | LLM conflated `DeleteTrail` with S3 bucket deletion and made unsupported brute-force statements | Use deterministic evidence-checked narrative for executive report; separately show model claim flags |
| Dashboard 400 vs current alert file 397 | The current file did not include 3 events also available in archives | Scan Wazuh rotated JSON/GZ archives; dedupe and compare exact event IDs and fields; 400/400 recovered |
| Early 6-case and final 100-case metrics appeared inconsistent | **Different samples, classifiers/prompts, tasks and data origins** | Keep CloudTrail binary pilot, six-case SOC functional demonstration and final three-class SOC study in distinct records |
| Printed `ResourceWarning: HTTPError` during tests | Certain tests deliberately cover HTTP-error conditions | Regression suite still passed; minor warning remains a cleanup candidate, not functional failure |

## 5. What was *not* demonstrated

- Production-grade incident detection, confirmed AWS action outcomes or an actual cloud security breach.
- Generalization to a truly independent, unseen, multi-organization real incident sample. The 100 cases represent only ten repeating scenario designs.
- A full external CloudTrail test-set final comparison. The external archive was downloaded but not a completed held-out research benchmark.
- Demonstrated human analyst time savings. Reported review demand is a **policy-based proxy** only.
- More reliable AI classification than rules, full factual truth checking, or exhaustive MITRE/NIST source coverage. RAG retrieval can occur without the model using the references correctly.
- Automatic containment, self-remediation, incident response inside a cloud account, or an interactive Wazuh dashboard action. The pipeline polls local Wazuh alert files.
- Fine-tuning of Qwen: the model is **pretrained and unchanged**.

## 6. Scientific conclusion

The completed research contributed an end-to-end, reproducible **Wazuh-sourced evidence correlation** and **human-supervised reporting** prototype, with 100 same-evidence synthetic evaluations and an explicit, measured negative result for local LLM severity classification. The credible recommendation is to use LLM assistance as a *reviewable hypothesis and communication aid*, retaining independent evidence checks and human authority, rather than allowing the language model to override verified security observations.

## 7. Source files, reproduction and ethics

Start with [README](../README.md) and [the complete VM-to-report setup](SETUP_FROM_SCRATCH.md). Then inspect [final aggregate results](wazuh_ai_final_results.md), [experiment log](experiment_log.md), [development log](development_log.md), [design decisions](research_decisions.md), [dataset card](dataset_card.md), and [CloudTrail pilot](three_method_comparison.md).

All model outputs, Wazuh alert exports, simulation ground-truth labels and local HTML reports remain **private / Git-ignored**. The Markdown docs and screenshots reproduce **aggregate research observations**, not real attack artifacts. Respect MITRE, NIST, AWS and original dataset provenance when extending the work.
