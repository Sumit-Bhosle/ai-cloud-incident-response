# Experimental Laboratory Architecture

## Research Topic
Evaluating AI-Assisted Cloud Security Incident Response

COMP 5112 — Research Methodology

## 1. Research Objective

Evaluate how AI assistance affects accuracy, reliability,
explainability, and analyst efficiency in controlled
cloud-security incident investigation and response.

Architecture reference:
Group 13 Research Presentation 2, Slides 17–21.

## 2. Available Hardware

Host:
- Windows 11 Pro
- Intel Core i5-1145G7
- 4 physical cores / 8 logical processors
- 15.41 GB RAM
- Approximately 315 GB free storage

Existing research VM:
- Ubuntu 26.04.1 LTS
- Approximately 7.2 GiB RAM
- 4 virtual CPUs
- Python 3.14.4

Virtualization:
- VMware Workstation 25.0.0

## 3. Proposed Laboratory Components

### Attack generation
- Isolated Kali Linux VM, subject to resource testing
- Controlled, authorized, non-destructive test activity
- No testing against university or third-party systems

### Monitored targets
- Dedicated disposable Linux and/or Windows test VMs
- Test users and synthetic files
- Auditing and event collection enabled

### Cloud security scenarios
- Actual cloud audit telemetry where feasible and authorized
- Local cloud-style simulation otherwise
- Explicit provenance distinguishing the two sources

### SIEM and evidence collection
- Wazuh candidate on a compatible supported environment
- Collection of relevant endpoint and security events
- Raw evidence retained separately from generated alerts

### Ground truth
- Versioned scenario manifests
- Actions performed and observed outcomes
- Timestamps, identities, targets, and expected evidence
- Expected classification and justified response
- Independent evidence review where feasible

### Knowledge base
- MITRE ATT&CK
- NIST incident-response guidance
- Official cloud-security documentation
- Source URLs, versions, and retrieval dates

### AI investigation
- Locally hosted language model, to be selected
- Retrieval-augmented generation (RAG)
- Vector storage if required by the retrieval approach
- Evidence citations and explicit uncertainty reporting

### Evaluation
- Deterministic Baseline V1 and V2
- AI-assisted investigation workflow
- Human/manual investigation condition
- Python-based comparison and reporting

## 4. Experiment Categories

- LAB-001: IAM compromise
- LAB-002: Suspicious API activity
- LAB-003: Privilege escalation
- LAB-004: Unauthorized resource access
- LAB-005: Data-access anomaly

Each experiment should include benign controls,
documented actions, raw logs, and expected outcomes.

## 5. Evidence and Dataset Integrity

Maintain separate records for:
1. Raw collected security telemetry
2. Scenario execution records
3. Verified ground-truth labels
4. Security knowledge documents
5. Baseline and AI investigation results

Preserve source provenance and evidence identifiers.

Do not treat generated alerts as independently verified
ground truth.

Exclude secrets, credentials, and sensitive personal
information from public research datasets.

## 6. Resource Management

The host has approximately 16 GB installed RAM.

Heavy services should run in separate sessions where
possible.

Live security monitoring may require concurrent
operation of the monitored target and log collector.

Resource allocation and Wazuh compatibility must be
verified before deployment.

The existing V1/V2 implementations and frozen holdout
results must remain unchanged.

## 7. Current Implementation Status

Completed:
- Deterministic Baseline V1
- Deterministic Baseline V2
- Synthetic diagnostic and holdout experiments
- Local hardware assessment

Pending:
- Final lab topology and VM allocation
- Isolated network configuration
- SIEM installation and validation
- Controlled incident execution
- Genuine telemetry collection
- Ground-truth evidence verification
- Knowledge-base construction
- RAG and LLM integration
- Human and AI-assisted comparative evaluation

## 8. Next Engineering Decision

Determine an achievable allocation for the attacker,
monitored target, and evidence collector before
creating or configuring additional virtual machines.

<!-- LABARCH-2026-11-04-AI-CLOUD -->

## AI architecture extension — 2026-11-04

**Verified lab:** VMware Ubuntu VM → systemd journal → Wazuh Manager/Indexer/Dashboard → exported JSON Wazuh alerts → `normalize_wazuh_alerts.py`. Ollama/Qwen2.5 runs locally (CPU-only) and has generated JSON investigations from normalized Wazuh evidence.

**Current research software:** A keyword-overlap retriever selects up to three curated MITRE/NIST notes for LLM context. JSON Schema checks report structure and membership checks confirm cited evidence/reference IDs only; it does not check whether natural-language conclusions are supported.

**Development cloud workflow:** Separate AWS CloudTrail training ZIP → `build_cloudtrail_cases.py` → private `cases.jsonl` + segregated ground truth. Initial grouping by actor, source IP and 30-minute bin is provisional, and the case builder does not yet call the LLM. Public documentation must not expose the actual raw evidence.

**Target next integration:** Case evidence → improved correlation and retrieval → local LLM analysis → fact/citation-support checks → analyst-reviewable SOC report → fair event/case-level evaluation. CloudTrail and live Wazuh are different data sources; do not imply our local Wazuh experiment is itself a cloud attack.

See [AI architecture and source-code walkthrough](ai_architecture.md).

---

<!-- SOC-MILESTONE-2026-11-09-VERIFIED:START -->

## Architecture update — 2026-11-09 | Executed synthetic SOC pipeline

The controlled 100-case simulator now emits **400 synthetic cloud-like event records** to a JSON file monitored by a real Wazuh 4.14.9 Manager. Rules `110100`/level 3, `110101`/level 8 and `110102`/level 12 were validated and observed; Threat Hunting displayed 400 hits under `rule.groups = soc_demo`. A local `alerts.json` cross-check matched **397/400** generated event IDs, leaving three not yet reconciled. Independently, `src/demo/soc_demo.py` investigates cases built from the **same generated evidence IDs** using deterministic baseline, Qwen2.5 LLM-only, and RAG. **No automatic Wazuh-to-LLM ingestion exists in this milestone.** See the [executed pipeline diagram, visual proof and failure analysis](soc_results_2026-11-09.md). Synthetic scenario labels are stored separately from prompt inputs and are not independent field truth.

<!-- SOC-MILESTONE-2026-11-09-VERIFIED:END -->
