# Evaluating AI-Assisted Cloud Security Incident Response

**Subtitle:** Accuracy, Reliability, Explainability, and Analyst Efficiency

## Overview

This research project investigates how AI assistance affects cloud security
incident investigation compared with a baseline investigation workflow.

The project focuses on evidence-based investigation, transparent AI outputs,
human verification, and reproducible experiments.

## Research Objectives

- Evaluate investigation accuracy.
- Measure reliability and unsupported claims.
- Assess evidence grounding and explainability.
- Compare investigation time between baseline and AI-assisted workflows.
- Keep the human analyst responsible for final decisions.

## Proposed Architecture

1. Generate clearly labelled synthetic cloud audit events.
2. Collect security telemetry using Wazuh where compatible.
3. Process events and prepare evidence with Python.
4. Investigate incidents using a baseline workflow and a local AI-assisted workflow.
5. Compare results against independently defined ground truth.
6. Report findings using reproducible evaluation scripts and visualizations.

## Technology Direction

- Ubuntu Linux
- Python
- Git and GitHub
- Wazuh, subject to installation compatibility
- Local AI inference, subject to available hardware resources
- Grafana, as an optional visualization layer

The project prioritizes free, local tools and avoids requiring paid cloud services.

## Repository Structure

```text
data/
  raw/
  processed/
  ground_truth/
src/
  ingestion/
  investigation/
  evaluation/
experiments/
results/
docs/
```

## Dataset Notice

Initial datasets will contain synthetic events for research and testing.
They must not be represented as real cloud-provider logs.

## Research Integrity and Safety

- Preserve event evidence and record the source of each finding.
- Distinguish observed facts from hypotheses.
- Do not treat AI-generated conclusions as authoritative.
- Do not perform destructive remediation automatically.
- Never commit credentials, tokens, or sensitive real-world logs.

## Project Status

Initial repository and research dataset preparation.

The architecture and methodology may evolve as the literature review,
compatibility checks, and pilot experiments are completed.
