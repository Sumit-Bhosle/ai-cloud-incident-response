# Dataset Card: Synthetic Cloud Audit Events

## Purpose
This dataset is a small synthetic pilot for evaluating AI-assisted cloud security incident investigation.

## Data Origin
All records are manually authored synthetic examples. They are not collected from AWS, Azure, or any production environment. The event fields are cloud-audit-style examples, not verified provider-native logs.

## Dataset Contents
- `data/raw/cloud_audit_events.jsonl`: event records, one JSON object per line.
- `data/ground_truth/incident_labels.json`: expected classifications, severity levels, event IDs, and rationale.
- `src/ingestion/generate_dataset.py`: script that generates both files.

The pilot contains eight events across three scenarios.

## Scenarios
- SCN-001: MFA-protected login followed by read-only activity.
- SCN-002: Login without MFA, access-key creation, administrative policy attachment, and a denied secret-access attempt.
- SCN-003: Approved backup role followed by scheduled backup activity.

These simplified scenarios do not represent the full diversity of real cloud incidents.

## Ground Truth
Expected classifications are stored separately from the raw events. Labels were manually authored and have not undergone independent expert review; they should be treated as provisional.

## Intended Uses
- Test event ingestion and JSON parsing.
- Develop baseline and AI-assisted investigation workflows.
- Test evaluation scripts against pilot labels.
- Identify dataset weaknesses before expansion.

## Limitations
- Only eight events and three scenarios.
- Simplified, manually authored records.
- Limited representation of real-world noise, ambiguity, and scale.
- No human-analyst or AI-model performance has yet been measured.
- The pilot cannot support generalizable research conclusions.

## Safety and Privacy
The records use documentation-reserved IP address ranges. No real credentials, customer data, or production logs are intended to be included.

## Reproducibility
Run from the repository root:

    python3 src/ingestion/generate_dataset.py

This regenerates the synthetic event and ground-truth files.

## Planned Improvements
- Expand scenario diversity, including benign, suspicious, and ambiguous cases.
- Define scoring rules for accuracy, evidence grounding, unsupported claims, and investigation time.
- Independently review ground-truth labels before formal experiments.
- Record dataset and experiment versions for reproducibility.

<!-- DATASETCARD-2026-11-04-CLOUDTRAIL -->

## Added dataset profile — AWS CloudTrail labeled research events (2026-11-04 audit)

**Upstream:** [Ariel Cyber — cloud_log_sampling](https://github.com/ArielCyber/cloud_log_sampling) (AWS-generated CloudTrail activity from a controlled research environment). Raw ZIPs are stored privately under `data/lab_evidence/cloudtrail/`; review upstream license and dataset description before redistribution.

| Split | Total records | Attack-labeled | Benign | Usage |
| :-- | --: | --: | --: | :-- |
| Development (`TrainOn/train_labeled_a.zip`) | **4,216** | Not separately recorded in current checkpoint | Not separately recorded | Case correlation and architecture iteration |
| Test (`TestOn/labeled_cloudtrail_a.zip`) | **24,087** | **2,585** | **21,502** | Audited, reserved for later held-out evaluation |

Test ZIP SHA-256: `d5dce3dbdb61ffb935e16cb4728aaca933daa42201a672dfad7387fd168f6eb0`.

**Test distribution:** 10 attack scenario categories, dominated by bulk S3 Put/Get/Delete activity. Eight repeated `eventID` occurrences were detected; these must not be silently deduplicated. Some API actions occur in both benign and attack-labeled records.

**Development output:** `4,216` source records → `1,742` actor/IP/time-bin cases; `64` cases contain ≥1 attack-labeled record; `4` cases combine benign and attack-labeled events. `cases.jsonl` has no explicit `should_sample`/`attack_name` labels. Separate `case_ground_truth.jsonl` and `event_ground_truth.jsonl` remain private.

**Limitations:** Attack *records* are not independent attacks; development correlation may merge or split actual sequences. Future evaluation must audit unintended label leakage, identity stability, timestamp leakage, case contamination and the impact of class imbalance. Do not claim cloud-incident accuracy without held-out, case-level scoring.

---

<!-- SOC-MILESTONE-2026-11-09-VERIFIED:START -->

## Distinct dataset — 100-case academic SOC simulation (2026-11-09)

This is **not** a new split of the Ariel Cyber CloudTrail dataset. `python3 -m src.demo.soc_demo prepare` generates 100 controlled cloud-like cases (40 benign, 30 suspicious, 30 *designated critical*) with **400** events and synthetic identifiers (`SOCSIM-...`). Several scenario templates repeat with different test details. Evidence uses reserved documentation IP ranges; **no real AWS API call or attack was performed**.

- Generated model-visible cases: `data/lab_evidence/soc_demo/cases.jsonl`; simulated Wazuh log entries: `wazuh_events.jsonl`; separate labels: `ground_truth_PRIVATE.jsonl`; SHA-256 manifest: `manifest.json`.
- 400 generated log entries appeared as 400 hits under the Wazuh demo rule-group filter, while the local `alerts.json` cross-check found **397/400** matching event IDs. Full reconciliation remains open.
- Six **stratified functional demonstration cases** (2 per designed class) were compared across baseline, Qwen LLM-only and Qwen + retrieval. Not representative or independent ground truth for actual incidents.
- **Do not combine** the synthetic demo accuracy with the separate controlled-public-CloudTrail binary benchmark's F1 scores.

See [complete SOC demo methodology and charts](soc_results_2026-11-09.md).

<!-- SOC-MILESTONE-2026-11-09-VERIFIED:END -->
