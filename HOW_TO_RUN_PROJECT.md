# AI-Assisted Cloud Security Incident Response
**Source Code and Reproduction Instructions**

**Repository:** https://github.com/Sumit-Bhosle/ai-cloud-incident-response

### Project Overview

This research project compares three cloud-security incident investigation approaches:

1. Traditional rule-based investigation
2. Local LLM investigation using Qwen2.5
3. Retrieval-Augmented Generation (RAG) using curated security knowledge

The project integrates Wazuh SIEM for security monitoring, Python for investigation and evaluation, and Ollama for locally hosted LLM inference.

The evaluation uses 100 synthetic security cases and 400 simulated cloud API events. No real cloud attacks were executed.

### System Requirements

- Ubuntu Linux, preferably running in VMware
- Python 3
- Wazuh Manager, Indexer and Dashboard
- Ollama with the `qwen2.5:1.5b` model
- Git

### 1. Download the project

```bash
git clone https://github.com/Sumit-Bhosle/ai-cloud-incident-response.git
cd ai-cloud-incident-response
```

### 2. Configure the environment

Follow the complete installation and configuration instructions in:

`docs/SETUP_FROM_SCRATCH.md`

This explains the VM environment, Wazuh configuration, local AI setup and research workflow.

Install the required local model:

```bash
ollama pull qwen2.5:1.5b
```

### 3. Prepare the research dataset

Extract the supplied dataset ZIP into the repository root, retaining its directory structure.

Alternatively, generate the synthetic dataset using:

```bash
python3 -m src.demo.soc_demo prepare
```

### 4. Run automated tests

```bash
python3 -m unittest discover -s tests -q
```

The final development environment passed 140 automated tests.

### 5. Run the Wazuh-to-AI investigation

After configuring Wazuh and ingesting the simulated events, run:

```bash
sudo python3 -m src.demo.wazuh_pipeline audit \
  --alerts /var/ossec/logs/alerts
```

To investigate one simulated critical incident:

```bash
sudo python3 -m src.demo.wazuh_pipeline watch \
  --alerts /var/ossec/logs/alerts \
  --case SOCSIM-009 \
  --once \
  --out /tmp/soc-review
```

### 6. Generate the executive report

```bash
sudo python3 -m src.demo.wazuh_pipeline evaluate \
  --out /tmp/soc-review
```

The program generates Markdown and HTML reports containing observed activity, potential business impact, evidence references, investigation results and analyst-review requirements.

### Research Results

The completed 100-case controlled evaluation produced:

| Method | Classification Accuracy |
|---|---:|
| Rule-based baseline | 100% |
| LLM-only | 53% |
| RAG-assisted LLM | 30% |

These results apply to the synthetic experimental scenarios and should not be interpreted as real-world incident-detection performance.

### Additional Documentation

- `README.md` — Complete research overview
- `docs/SETUP_FROM_SCRATCH.md` — Full installation guide
- `docs/wazuh_ai_final_results.md` — Final evaluation results
- `docs/RESEARCH_JOURNEY_AND_LIMITATIONS.md` — Implementation history and research limitations

**Note:** Wazuh requires a functioning local installation, and the included dataset is a synthetic research dataset. The project is intended for academic evaluation and human-supervised security investigation, not autonomous production incident response.

For complete VM installation, Wazuh configuration, and
reproducibility instructions, see
[Setup From Scratch](docs/SETUP_FROM_SCRATCH.md).
