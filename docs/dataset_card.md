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
