#!/usr/bin/env python3
"""Add the verified 2026-11-09 SOC milestone to existing Markdown documentation.

- Run from the project root after extracting the SOC documentation ZIP.
- Never deletes/replaces existing documentation, except a prior version of its
  own clearly marked section. Preserves all historical milestones.
- Does not modify source code, research evidence, Wazuh, Git, or network state.
"""
from pathlib import Path
import re
import sys

ROOT = Path.cwd().resolve()
NEEDED = [
    ROOT / 'README.md',
    ROOT / 'src/demo/soc_demo.py',
    ROOT / 'docs/soc_results_2026-11-09.md',
    ROOT / 'docs/assets/soc-2026-11-09/wazuh-filtered-400-events.png',
    ROOT / 'docs/assets/soc-2026-11-09/02-six-case-outcomes.png',
]
missing = [p.relative_to(ROOT).as_posix() for p in NEEDED if not p.is_file()]
if missing:
    sys.exit('STOP: Run from project root after unzip. Missing:\n' + '\n'.join(missing))

README = r'''## Latest verified milestone · SOC simulation and AI investigation (9 Nov 2026)

> **Research prototype / academic simulation:** 100 generated test cases and 400 simulated cloud API records were ingested by a real Wazuh deployment. **No real cloud attacks were executed.** The LLM is pretrained Qwen2.5 1.5B via Ollama, not project-fine-tuned.

![Wazuh Threat Hunting screenshot: 400 filtered synthetic alert hits](docs/assets/soc-2026-11-09/wazuh-filtered-400-events.png)

*Observed visual evidence: Wazuh Threat Hunting → Events, `rule.groups: soc_demo`, **400 hits** with detection levels **3, 8 and 12** (rule IDs `110100`–`110102`). These are generated log entries, **not 400 actual security incidents**.*

| Controlled research measurement | Verified observation |
|---|---:|
| Prepared simulated cases | **100**: 40 benign, 30 suspicious, 30 designated critical |
| Simulated log entries / Wazuh filtered UI hits | **400 / 400** |
| Local `alerts.json` event-ID cross-check | **397 / 400 (99.25%)** — 3-record discrepancy unresolved |
| Evaluated cases (identical evidence in all methods) | **6** |
| Correct predictions out of 6 attempts | **Rule baseline 6** · **LLM-only 2** · **RAG 2** |
| Unsuccessful/invalid model answers | **LLM-only 2 / 6** · **RAG 1 / 6** |

![Six-case outcome comparison: correct, incorrect and failed outputs](docs/assets/soc-2026-11-09/02-six-case-outcomes.png)

**Important research finding:** On this deliberately engineered six-case **synthetic** sample, adding a small local LLM or retrieval did **not** improve classification. Several AI explanations contain unsupported claims, including confusing AWS CloudTrail trail deletion with S3 bucket deletion. The generated executive narrative is **not client-approved**. The software runs a human-supervised research workflow, **not autonomous incident remediation**.

**Explore the evidence:** [Full SOC results, charts, case matrix, corrected executive brief and deployment log](docs/soc_results_2026-11-09.md) · [SOC demo instructions](docs/soc_demo.md) · [Experiment log](docs/experiment_log.md) · [Separate CloudTrail development comparison](docs/three_method_comparison.md)

> **Boundary:** The demo Python investigator and Wazuh monitor the **same generated evidence with matching IDs**. Python does not yet automatically consume Wazuh alerts. Public CloudTrail pilot findings and three-class synthetic SOC metrics are separate experiments; do not mix their scores.
'''

entries = {
    'README.md': README,
    'docs/soc_demo.md': r'''## Executed Wazuh + AI demo — verified 9 November 2026

**The first integration and six-case model comparison have now run.** See the complete [visual evidence, quality audit and executive case study](soc_results_2026-11-09.md).

![Filtered simulated Wazuh alerts](assets/soc-2026-11-09/wazuh-filtered-400-events.png)

- Generated **100** academic cases (**40 benign / 30 suspicious / 30 designated critical**) and **400** distinct synthetic log entries. Wazuh's filtered Events view showed **400 hits**.
- Confirmed rule `110100`/level 3 (general), `110101`/level 8 (`GetObject`), and `110102`/level 12 (`StopLogging`). **Custom rule match ≠ confirmed attack.**
- `crosscheck --alerts /var/ossec/logs/alerts/alerts.json`: **397 of 400** generated event IDs matched; dashboard/file reconciliation remains open.
- On the **same six selected cases**, rule baseline classified 6/6 correctly; LLM-only 2/6 with 2 errors; RAG 2/6 with 1 error. These are *simulation-specific*, not deployment performance estimates.
- Private source reports: `data/lab_evidence/soc_demo/`; their free-text narrative is **not fully evidence-verified**, and the reviewed executive case study in the results document corrects specific model mistakes.
- Deployment incident: original conditions referring to `<field name="action" ...>` caused Wazuh to reject rule 110101; changed **two** conditions to `<action type="pcre2">`, validated and reapplied. Initial installer rollback restored manager availability. This is an **observed integration fix**, not a model result.
- **Do not rerun** the log injection command on the present VM: the 400 demo records were already observed in the dashboard. Duplicate injection changes experiment counts. Use the existing saved reports and dashboard for presentations.

![Pairwise demo comparison](assets/soc-2026-11-09/02-six-case-outcomes.png)
''',
    'docs/experiment_log.md': r'''## Experiment milestone — 2026-11-09 | Wazuh synthetic SOC and six-case AI evaluation

**Evidence:** [Run notes, charts, dashboard screenshots and model-output audit](soc_results_2026-11-09.md). The 100 cases were deliberately simulated; the separate public CloudTrail development comparison is **not** pooled with these figures.

| Check / trial | Actual observation | Limitation / follow-up |
|---|---|---|
| Input generation | 100 cases; **40 benign / 30 suspicious / 30 designated critical**; 400 synthetic event IDs | Labels are engineered and not field-verified attack ground truth |
| Wazuh rule unit testing | General `110100`/3; `GetObject` → `110101`/8; `StopLogging` → `110102`/12 | Rule validation confirms detection patterns, not malicious intent |
| SOC visual ingestion | Threat Hunting filtered `rule.groups: soc_demo` → **400 indexed hits** | Wazuh contains other live Linux alerts; filtered screenshot isolates simulated test subset |
| Local alert cross-check | `397 / 400` matched (`0.9925`) | **Open issue**: three event IDs missing from inspected local-file results; reason unknown |
| Deterministic baseline | **6 answered; 6 correct; 0 failures** | Six scenarios are small and engineered; not representative |
| Local Qwen2.5 1.5B (LLM-only) | **4 answered; 2 correct; 2 errors**; mean **20.01 s/case** including failures | Wrongly labeled suspicious login and a critical case benign |
| Qwen + retrieved reference notes (RAG) | **5 answered; 2 correct; 1 error**; mean **22.65 s/case** including failures | Designated-critical cases downgraded to suspicious |
| Generated executive report | Saved to private `data/lab_evidence/soc_demo/executive_report.md` | **Unsafe to quote verbatim as facts**: wrong descriptions of CloudTrail/S3 and IAM/brute-force evidence |

**Debugging history:** (1) Unprivileged install preview couldn't read `/var/ossec/etc/ossec.conf`; `sudo` resolved access. (2) First Wazuh restart failed despite preliminary analysisd validation; manager recovered on configuration rollback. Log showed `Field 'action' is static` for custom rule `110101`. (3) Corrected **two** XML action conditions to `<action type="pcre2">`; `wazuh-analysisd -t` and `wazuh-logcollector -t` passed and Wazuh Manager ran again. (4) Verified detections using `wazuh-logtest`, dashboard and a per-event-ID cross-check. Both the fault and correction are preserved as an engineering record.

**Research finding (scoped):** LLM/RAG did not outperform the simple baseline on this one six-case three-class simulation. Generated prose frequently exceeded its evidence. No independent analyst-time efficiency, generalization, production safety or automatic Wazuh-to-LLM trigger was demonstrated.
''',
    'docs/development_log.md': r'''## Development checkpoint — 2026-11-09 | Completed SOC demo ingestion + first executive report

Added/ran `src/demo/soc_demo.py` and optional `deploy/wazuh` integration. Confirmed Wazuh Manager stable following a reversible custom-rule startup error; the repair changed two `action` conditions to valid Wazuh action tags. Prepared 100 simulated cases/400 log events; mapped the **same `sim_event_id`** into case evidence and Wazuh alert records; observed 400 filtered indexed hits and 397 matching IDs in one local alert file. Compared rule baseline / Ollama Qwen LLM-only / RAG on six deliberately selected three-class cases and produced a private executive report. Found several nontrivial unsupported claims in that report. Full [results and screenshots](soc_results_2026-11-09.md).

**Architecture status:** Real Wazuh receives the test logs. The investigator reads its own generated case JSONL rather than fetching Wazuh alerts. Human review and claim-level grounding are still needed. The older public CloudTrail development study remains separate.
''',
    'docs/research_decisions.md': r'''## Design decision — 2026-11-09 | Treat the SOC simulation as a functional demonstration

**Decision:** Publish reviewed methodology, selected aggregate metrics, and authentic Wazuh screenshots, but keep labeled cases and generated AI reports private. Preserve the chronological record and avoid merging experiments.

- **Synthetic Wazuh demonstration:** 100 engineered scenarios/400 events; six three-class cases for LLM comparison. These are not real incident-response accuracy estimates.
- **Public CloudTrail development comparison:** different evidence population and a **binary** attack-associated classification metric. Its precision/recall/F1 cannot be compared numerically against the synthetic three-class outcomes.
- **Grounding boundary:** Known citation IDs, retrieved reference documents and valid JSON alone don't establish correctness of claims. The audited executive brief is written independently from visible event actions and explicitly states uncertainties.
- **Operational safety:** Wazuh rule severity must not be equated with verified compromise; analyst approval stays mandatory. No automated remediation in this demo.
- **Unresolved:** 400 UI hits vs 397 matches in the inspected local file, and misleading model explanations. These are tracked rather than quietly normalized or discarded.

Full justification and evidence: [SOC results](soc_results_2026-11-09.md).
''',
    'docs/dataset_card.md': r'''## Distinct dataset — 100-case academic SOC simulation (2026-11-09)

This is **not** a new split of the Ariel Cyber CloudTrail dataset. `python3 -m src.demo.soc_demo prepare` generates 100 controlled cloud-like cases (40 benign, 30 suspicious, 30 *designated critical*) with **400** events and synthetic identifiers (`SOCSIM-...`). Several scenario templates repeat with different test details. Evidence uses reserved documentation IP ranges; **no real AWS API call or attack was performed**.

- Generated model-visible cases: `data/lab_evidence/soc_demo/cases.jsonl`; simulated Wazuh log entries: `wazuh_events.jsonl`; separate labels: `ground_truth_PRIVATE.jsonl`; SHA-256 manifest: `manifest.json`.
- 400 generated log entries appeared as 400 hits under the Wazuh demo rule-group filter, while the local `alerts.json` cross-check found **397/400** matching event IDs. Full reconciliation remains open.
- Six **stratified functional demonstration cases** (2 per designed class) were compared across baseline, Qwen LLM-only and Qwen + retrieval. Not representative or independent ground truth for actual incidents.
- **Do not combine** the synthetic demo accuracy with the separate controlled-public-CloudTrail binary benchmark's F1 scores.

See [complete SOC demo methodology and charts](soc_results_2026-11-09.md).
''',
    'docs/ai_architecture.md': r'''## Implemented simulated SOC integration — verified 2026-11-09

The [actual execution diagram, Wazuh screenshots, and evaluation results](soc_results_2026-11-09.md) supersede any impression that the SOC-to-LLM step is automatically triggered. The simulator emits two views of **the same synthetic events**: a monitored JSON log for Wazuh and grouped case JSONL for the Python investigators. Wazuh rules 110100–110102 produce detection alerts; Python independently runs baseline, Qwen2.5 LLM-only, and keyword-retrieval RAG. A separate ID-matching routine compares Wazuh alert IDs against source event IDs; the AI does **not** presently ingest the Wazuh dashboard or its indexed alerts directly.

The pilot showed 400 dashboard hits, 397 local alert-ID matches and a six-case comparison. **Retrieval is not source-grounded fact verification** and the generated report contains identified hallucinations. No fine-tuning, autonomous incident response, or analyst-efficiency improvement is established.
''',
    'docs/experimental_lab_architecture.md': r'''## Architecture update — 2026-11-09 | Executed synthetic SOC pipeline

The controlled 100-case simulator now emits **400 synthetic cloud-like event records** to a JSON file monitored by a real Wazuh 4.14.9 Manager. Rules `110100`/level 3, `110101`/level 8 and `110102`/level 12 were validated and observed; Threat Hunting displayed 400 hits under `rule.groups = soc_demo`. A local `alerts.json` cross-check matched **397/400** generated event IDs, leaving three not yet reconciled. Independently, `src/demo/soc_demo.py` investigates cases built from the **same generated evidence IDs** using deterministic baseline, Qwen2.5 LLM-only, and RAG. **No automatic Wazuh-to-LLM ingestion exists in this milestone.** See the [executed pipeline diagram, visual proof and failure analysis](soc_results_2026-11-09.md). Synthetic scenario labels are stored separately from prompt inputs and are not independent field truth.
''',
    'docs/presentation_demo_notes.md': r'''## Professor demonstration — verified SOC pilot (9 November 2026)

**Show in this order (approximately 3–4 minutes, using existing saved outputs):**

1. **Set scope:** "These are 100 simulated cloud-security cases, generating 400 synthetic log events. We performed no real attacks." Show [dataset distribution](assets/soc-2026-11-09/01-simulation-distribution.png).
2. **Real SIEM / simulated input:** Open Wazuh **Threat Hunting → Events**, filter `rule.groups = soc_demo`, and show **400 hits** across severity rules 110100/3, 110101/8, 110102/12; [verified screenshot](assets/soc-2026-11-09/wazuh-filtered-400-events.png). Do **not** call 100 high alerts 100 real critical incidents.
3. **Same source IDs, separate execution paths:** Point out `sim_event_id` appears in generated case and Wazuh fields. Local file cross-check: **397/400**; acknowledge three-record unresolved difference.
4. **Three-method comparison:** Show [six-case stacked outcome chart](assets/soc-2026-11-09/02-six-case-outcomes.png) and [case-level matrix](assets/soc-2026-11-09/03-same-case-decisions.png): baseline 6/6 correct, LLM-only 2/6 correct with 2 errors, RAG 2/6 correct with 1 error. This **small engineered sample does not prove general superiority**.
5. **Critical analysis:** Open the [reviewed SOCSIM-008 executive brief](soc_results_2026-11-09.md#reviewed-sample-executive-brief--socsim-008-simulation-only). Explain that `StopLogging`/`DeleteTrail` would justify investigation in a live AWS account, but the model mistakenly called it S3-bucket deletion. An evidence-grounded report needs review.
6. **Close:** "A working research demonstration now joins SOC visibility to AI comparison on shared simulated evidence; future steps are automated alert-to-AI intake, external ground-truth evaluation, claim-level checking and analyst efficiency measurement." No live AI runs or log reinjection required to demonstrate the recorded results.

**If asked about deployment errors:** Show experiment log: first custom rule `<field name="action">` failed with Wazuh static-field error, roll-back restored service, two conditions were changed to `<action type="pcre2">`, all three rules were then verified. **Do not erase the debugging history.**
''',
    'docs/three_method_comparison.md': r'''## Separate Nov 9 synthetic SOC experiment — do not merge with CloudTrail pilot

A later **100-case synthetic Wazuh simulation** ran a distinct **six-case three-class** comparison. On the same selected cases, the rule baseline was **6/6 correct**, Qwen LLM-only **2/6 correct with 2 output errors**, and Qwen RAG **2/6 correct with 1 error**. Class labels were deliberately generated; this is a demonstration, not external attack-detection accuracy. The prior CloudTrail development benchmark in this document measures a **different binary attack-associated target**, so its F1 scores cannot be combined with these synthetic three-class results. See the [synthetic SOC evaluation with screenshots, outcome charts and factual-error audit](soc_results_2026-11-09.md).
''',
    'docs/assets/README.md': r'''## Wazuh SOC research evidence added 9 November 2026

Source: actual user-provided captures of the Wazuh Dashboard / Threat Hunting running on the local Ubuntu VM. No UI screenshot was fabricated or synthesized. New folder: [`soc-2026-11-09/`](soc-2026-11-09/).

- `wazuh-filtered-400-events.png`: Threat Hunting Events filtered to `rule.groups: soc_demo` with **400 indexed hits**, displayed rule IDs/levels.
- `wazuh-threat-hunting-overview.png`: combined 24-hour view; **638 total** including non-simulation events.
- `wazuh-dashboard-summary.png`: overview summary; **100 level-12-to-14 alerts**, **225 level-7-to-11 alerts**, **313 level-0-to-6 alerts** in the selected window; these are *not* 100 distinct real attack incidents.
- `01-simulation-distribution.png` through `04-model-latency.png`: original charts generated from the precise user-shared command output, with method failures explicitly retained.

Source-data transcription and limitations: [complete SOC milestone](../soc_results_2026-11-09.md).
'''
}

# Optional inventory is sometimes under docs/ and sometimes in repository root.
inv_candidates = ['docs/project_inventory.md', 'project_inventory.md']
inv = next((p for p in inv_candidates if (ROOT/p).is_file()), None)
if inv:
    prefix = '' if inv.startswith('docs/') else 'docs/'
    entries[inv] = f'''## Inventory update — 2026-11-09 | Executed simulated SOC workflow

The opening inventory snapshot above remains a historical checkpoint. The newer implemented files are `src/demo/soc_demo.py`, `deploy/wazuh/soc_demo_rules.xml`, `deploy/wazuh/enable_demo.py`, `tests/test_soc_demo.py` and `docs/soc_demo.md`. Research-simulation evidence and model reports live privately under `data/lab_evidence/soc_demo/` and are excluded from Git. Wazuh confirmed **400 filtered demo event hits**, with **397 matching generated IDs** in the inspected local `alerts.json`. The six-case synthetic classification resulted in **6/6 correct for the baseline, 2/6 for LLM-only, 2/6 for RAG**; the existing separate public CloudTrail six-case pilot is a different measurement. Charts, screenshots, corrected executive case study, known model errors, and next work are documented in [{prefix}soc_results_2026-11-09.md]({prefix}soc_results_2026-11-09.md).
'''

KEY = 'SOC-MILESTONE-2026-11-09-VERIFIED'
updated, skipped, unchanged = [], [], []
for rel, section in entries.items():
    path=ROOT / rel
    if not path.is_file():
        skipped.append(rel)
        continue
    start=f'<!-- {KEY}:START -->'
    end=f'<!-- {KEY}:END -->'
    block=f'{start}\n\n{section.strip()}\n\n{end}'
    old=path.read_text(encoding='utf-8')
    if start in old:
        pattern=re.compile(re.escape(start)+r'.*?'+re.escape(end),re.DOTALL)
        new,count=pattern.subn(lambda _:block,old,count=1)
        if count != 1:
            raise RuntimeError(f'Incorrect milestone markers in {rel}')
    elif rel == 'README.md':
        h1=re.search(r'^# .+\n',old,re.MULTILINE)
        if h1:
            idx=h1.end();new=old[:idx]+'\n'+block+'\n\n'+old[idx:]
        else:
            new=block+'\n\n'+old
    else:
        new=old.rstrip()+'\n\n---\n\n'+block+'\n'
    if new!=old:
        path.write_text(new,encoding='utf-8')
        updated.append(rel)
    else:
        unchanged.append(rel)

print('SOC documentation update complete.')
print('Updated:',len(updated), ', '.join(updated) if updated else '(none)')
print('Already current:',len(unchanged), ', '.join(unchanged) if unchanged else '(none)')
print('Missing optional docs:',len(skipped), ', '.join(skipped) if skipped else '(none)')
print('Added standalone milestone and seven visual evidence files via ZIP extraction.')
print('Review with: git status --short && git diff --stat && git diff --check')
print('Script is idempotent: rerunning will not duplicate its sections.')
