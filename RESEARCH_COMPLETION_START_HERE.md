# Wazuh → AI completion patch (one-day research priority)

This **additive** update contains a Wazuh alert reader, actual-event identity verification,
paired baseline/LLM/RAG investigation, human-review safeguards, a printable stakeholder
report, resumable evaluation, publication helper and regression tests.

**No changes to your existing `src/demo/soc_demo.py`, Wazuh rules, manager config,
existing README, model, reports or ground-truth files.** It performs no simulated or
real attacks, no AWS actions and no automatic remediation. The Wazuh-linked model
prompt is new, and results should be labeled as a separate experiment from the
previous six-case prototype.

**Quick start (in the Ubuntu project directory):**

```bash
unzip -n ~/Downloads/wazuh_ai_research_completion.zip -d .
python3 -m unittest discover -s tests -q
umask 077
sudo grep '"soc_demo":"research_simulation"' /var/ossec/logs/alerts/alerts.json > data/lab_evidence/soc_demo/wazuh_alerts_export_PRIVATE.jsonl
python3 -m src.demo.wazuh_pipeline audit --alerts data/lab_evidence/soc_demo/wazuh_alerts_export_PRIVATE.jsonl
python3 -m src.demo.wazuh_pipeline run --alerts data/lab_evidence/soc_demo/wazuh_alerts_export_PRIVATE.jsonl --case SOCSIM-008
python3 -m src.demo.wazuh_pipeline evaluate
```

Once you verify the live first-case results:

```bash
python3 -m src.demo.wazuh_pipeline run --alerts data/lab_evidence/soc_demo/wazuh_alerts_export_PRIVATE.jsonl --limit 100
python3 -m src.demo.wazuh_pipeline evaluate
python3 tools/publish_wazuh_milestone.py
```

**Full safety/acceptance checklist, recording steps and evidence boundaries:**
`docs/wazuh_ai_completion_runbook.md`.

**Local verification of this patch:** 31 isolated unit tests passed, plus a 397/400
integration simulation with mock LLM outputs. Real Ollama/Wazuh behavior cannot be
validated outside your installed Ubuntu VM; do not present mock results as research
results. The live tests above are the final acceptance gate.
