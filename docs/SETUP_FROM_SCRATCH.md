# Reproduce the study from scratch — Windows / VMware / Ubuntu / Wazuh / Ollama

**Goal:** Rebuild a non-destructive, isolated academic lab and reproduce the controlled **Wazuh → verified alerts → baseline / Qwen / RAG → evidence-checked executive report → metrics** workflow.

> **Safety first:** The generator writes synthetic JSON log records. It does **not** perform AWS operations or launch attacks. All data used in the main 100-case SOC study is simulated. Use a private VM; do **not** install or inject these rules/logs into an employer's production SIEM. Preserve original logs and never commit secrets.

This is a **clean-install guide**, not an exact VM image or lockfile. Model outputs, response times, passwords, VM IP addresses and Wazuh version may differ. The author completed the study with Wazuh **4.14.9** and a CPU-only Qwen2.5 1.5B local model in a VMware Ubuntu VM.

## 0. Prerequisites and software versions

| Component | Recommended clean lab | Notes |
|---|---|---|
| Host | Windows 10/11 with VMware Workstation | Virtualization enabled in BIOS/UEFI |
| Guest OS | **Ubuntu Server/Desktop 24.04 LTS, 64-bit** | Wazuh's published recommended Ubuntu releases include 24.04; the original author's Ubuntu 26.04 lab worked but is outside that published support list as of 9 Nov 2026 |
| Virtual machine | **4 vCPU, 8 GB RAM, ≥50 GB disk** | Wazuh all-in-one quickstart recommendation for small lab; 8 GB can be constrained when Ollama runs concurrently |
| Networking | VMware NAT (or bridged if managed) | Host browser must be able to reach guest IP; do not expose port 443 to public networks |
| SIEM | Wazuh 4.14 series, all-in-one | Manager, Indexer and Dashboard on guest VM |
| Python | Python 3 from Ubuntu | Core project demonstration uses Python standard library |
| Local model | Ollama + `qwen2.5:1.5b` | Pretrained model; **no fine-tuning**, no cloud API key |
| Git | Git | Checkout source and record versions |

References: [Wazuh all-in-one quickstart](https://documentation.wazuh.com/current/quickstart.html) · [Wazuh dashboard OS requirements](https://documentation.wazuh.com/current/installation-guide/wazuh-dashboard/index.html) · [Ollama Linux install](https://docs.ollama.com/linux). These are authoritative vendor pages; if a newer installer changes, follow the vendor instructions rather than guessing a package version.

## 1. Create Ubuntu VM

1. Download an official 64-bit Ubuntu 24.04 LTS ISO from [ubuntu.com/download](https://ubuntu.com/download).
2. In VMware Workstation, create a new VM using the Ubuntu ISO; allocate **4 CPU cores**, **8 GB RAM** (or more if the host can spare it), and a **50–80 GB** virtual disk.
3. Use a **NAT** network adapter unless you understand bridged networking and firewall exposure. NAT should normally allow the Windows host to reach the guest's VMware virtual network IP.
4. Install Ubuntu and create a normal non-root account. Apply updates and reboot.
5. Optionally take a VMware snapshot named `ubuntu-clean-before-wazuh` before installing security components.

Inside the VM:

```bash
sudo apt update
sudo apt upgrade -y
sudo apt install -y git curl ca-certificates unzip python3 python3-pip python3-venv
python3 --version
hostname -I
```

If Windows cannot open your future dashboard, check whether the VM IP changed via `hostname -I`, VMware adapter settings, whether guest firewall rules block inbound HTTPS, and whether Wazuh's dashboard service is running. **Do not hardcode the original author's `192.168.163.128` address.**

## 2. Install Wazuh all-in-one

**Skip this section on a VM that already has a healthy Wazuh installation.** Rerunning the installer can replace settings and passwords.

The vendor's Wazuh 4.14 assisted quickstart command is:

```bash
mkdir -p ~/wazuh-setup
cd ~/wazuh-setup
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

This installs the **server, indexer and dashboard** on one VM. Store the generated administrator password securely; it should not be placed in the project, screenshots, logs or GitHub. Keep the generated `wazuh-install-files.tar` file private.

Verify services:

```bash
for service in wazuh-manager wazuh-indexer wazuh-dashboard; do
  echo "$service: $(systemctl is-active "$service")"
done
```

All should print `active`. Open `https://GUEST_VM_IP` in your Windows browser using the IP from `hostname -I`. Log in with Wazuh's generated credentials. The local lab may use a self-signed certificate; verify it is your own VM before accepting the browser warning. The dashboard can show *no registered agents* because this project monitors a **local manager JSON log file**; a separate endpoint agent is not required for the SOC simulation.

Useful checks:

```bash
sudo systemctl status wazuh-manager --no-pager
sudo /var/ossec/bin/wazuh-analysisd -t
sudo /var/ossec/bin/wazuh-logcollector -t
```

## 3. Install and verify Ollama

Use the [official Linux instructions](https://docs.ollama.com/linux):

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5:1.5b
ollama list
```

If the installer registered an Ollama service:

```bash
sudo systemctl start ollama
sudo systemctl is-active ollama
```

In installations without a service, run `ollama serve` in a separate terminal, then pull the model from another terminal. The project calls Ollama at **`http://127.0.0.1:11434/api/chat`**; keep it bound locally. CPU inference may be slow, particularly with Wazuh Indexer consuming memory.

## 4. Clone the research repository and run tests

```bash
cd ~
mkdir -p Projects
cd Projects
git clone https://github.com/Sumit-Bhosle/ai-cloud-incident-response.git
cd ai-cloud-incident-response
python3 -m unittest discover -s tests -q
```

The author's verified final run showed **140 tests passing**. Future additions may change the test count. Some test cases deliberately exercise HTTP errors and may print Python `ResourceWarning`; `OK` and no test failures is the check. If a fresh clone is missing Python dependencies for *older optional* project experiments, inspect their module requirements independently. The **main SOC workflow** uses standard-library Python plus the external Wazuh and Ollama services.

**Do not place evidence files or private labels in Git.** Review `.gitignore` before generating anything.

## 5. Generate the controlled synthetic dataset

```bash
python3 -m src.demo.soc_demo prepare
```

Expected summary:

```text
PREPARED 100 synthetic cases, 400 simulated log events
DISTRIBUTION {'benign': 40, 'critical': 30, 'suspicious': 30}
```

Files are placed in the **ignored** `data/lab_evidence/soc_demo/` directory:

- `cases.jsonl` — model-visible scenario evidence, no truth labels
- `wazuh_events.jsonl` — the corresponding Wazuh JSON log records
- `ground_truth_PRIVATE.jsonl` — separate labels for **evaluation only**
- `manifest.json` — case count and integrity hash

The generator repeats **ten designed scenario templates ten times**. The outputs are demonstrations, not independent samples of real AWS attacks.

## 6. Enable the SOC demonstration rules in Wazuh

First back up your existing manager configuration and validate the committed source rule file:

```bash
sudo cp -p /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.before-academic-soc
sudo python3 deploy/wazuh/enable_demo.py
sudo /var/ossec/bin/wazuh-analysisd -t
```

The dry run should show the proposed monitor (`/var/log/soc_demo_cloud.jsonl`) and indicate **no changes made**. It may require `sudo` because Wazuh config is permission-protected. The repo's `deploy/wazuh/soc_demo_rules.xml` must be the **corrected version** using `<action type="pcre2">` in custom rules 110101 and 110102; the original early research version failed Wazuh startup because it used an invalid static field. If a validator reports an error, **do not apply or restart**, and inspect `docs/experiment_log.md`.

Apply only after dry-run validation:

```bash
sudo python3 deploy/wazuh/enable_demo.py --apply
sudo systemctl is-active wazuh-manager
sudo /var/ossec/bin/wazuh-analysisd -t
sudo /var/ossec/bin/wazuh-logcollector -t
```

The helper backs up the existing Wazuh configuration and rolls back on startup failure. It adds a dedicated JSON-log monitor and custom detection rules. **No simulation events are injected by this step.**

Test one JSON event with the Wazuh rule-testing tool:

```bash
head -n 1 data/lab_evidence/soc_demo/wazuh_events.jsonl | sudo /var/ossec/bin/wazuh-logtest
```

Look for Phase 3 with `id: '110100'` and `level: '3'`. Also select a `GetObject` or `StopLogging` event to confirm rule levels `8` and `12`.

## 7. Inject the 400 log records ONCE (no actual attacks)

The next command **appends** generated JSON records into the local monitored file. Run it **once** on a fresh demo VM; repeated injections can create duplicate alerts and distort dashboard counts.

```bash
wc -l data/lab_evidence/soc_demo/wazuh_events.jsonl
sudo wc -l /var/log/soc_demo_cloud.jsonl
```

If the destination file already contains any lines, **do not run the append command again** until you confirm which event IDs are present. On a new empty installation:

```bash
sudo tee -a /var/log/soc_demo_cloud.jsonl \
  < data/lab_evidence/soc_demo/wazuh_events.jsonl > /dev/null
```

Open **Wazuh → Threat Hunting → Events**, filter `rule.groups: soc_demo`, and adjust the date range to the current injection time. You should see events from all three rule levels. In the author's completed run: rule 110100 = 160, rule 110101 = 140, rule 110102 = 100. Fresh environments and indexing windows may behave differently; inspect the actual counts.

Wazuh dashboard data is not itself evidence of malicious intent. The simulation never executes the named AWS actions.

## 8. Export private Wazuh alert records and verify event IDs

Read Wazuh current **and archived** alerts using the small project helper. It selects only `soc_demo: research_simulation` events and preserves duplicate records for the downstream consistency checker. On a new VM, choose a private output path:

```bash
umask 077
sudo python3 tools/export_wazuh_demo_alerts.py \
  --source /var/ossec/logs/alerts \
  --out data/lab_evidence/soc_demo/wazuh_alerts_export_PRIVATE.jsonl
sudo chown "$(id -u):$(id -g)" \
  data/lab_evidence/soc_demo/wazuh_alerts_export_PRIVATE.jsonl
```

Then, as your normal Ubuntu user:

```bash
python3 -m src.demo.wazuh_pipeline audit \
  --alerts data/lab_evidence/soc_demo/wazuh_alerts_export_PRIVATE.jsonl
```

Expected in the author's archived experiment: **400 unique verified event IDs, 100 complete cases and no field mismatches**. Duplicate records from rotation are counted separately, not mistaken for additional incidents. If fewer complete cases are present, inspect the log collector and archive windows; the pipeline **does not score incomplete cases**.

## 9. Run exactly the same Wazuh evidence through three investigators

Start with one critical IAM case:

```bash
python3 -m src.demo.wazuh_pipeline run \
  --alerts data/lab_evidence/soc_demo/wazuh_alerts_export_PRIVATE.jsonl \
  --case SOCSIM-009
python3 -m src.demo.wazuh_pipeline evaluate
```

This creates the project-private JSON investigation record and the **`EXECUTIVE_REPORT_REVIEW_REQUIRED.md`** and **`.html`** outputs in `data/lab_evidence/soc_demo/wazuh_ai_pipeline/`. Verify the report's source IDs for `SOCSIM-009` and confirm that it does **not** claim the observed AWS operations succeeded or that a real breach occurred.

For the complete paired study, run each case exactly once (cached/resumable):

```bash
python3 -m src.demo.wazuh_pipeline run \
  --alerts data/lab_evidence/soc_demo/wazuh_alerts_export_PRIVATE.jsonl \
  --limit 100
python3 -m src.demo.wazuh_pipeline evaluate
```

The batch invokes the local model twice per case and may consume substantial CPU time. Keep the same evidence export and model across this experiment. Do not change prompts, ground truth, or model mid-run and then report the mixture as one controlled condition.

On the author's final 100 cases, the baseline was **100/100**, LLM-only **53/100**, and RAG **30/100**. **Another machine is not guaranteed to produce identical model outputs.** Full report accuracy belongs to *that machine's actual evaluation*, not copied benchmark numbers.

## 10. Open executive report and compare results

```bash
xdg-open data/lab_evidence/soc_demo/wazuh_ai_pipeline/EXECUTIVE_REPORT_REVIEW_REQUIRED.html
```

If the desktop browser raises Ubuntu Snap/GTK mount warnings, open the generated HTML manually in the browser via **Ctrl+O**. The warnings alone do not imply the report failed.

The HTML report includes case-by-case summaries, original action names, matching Wazuh event IDs, business-risk possibilities, analyst checklists and model QA flags. It intentionally excludes unsupported LLM prose from trusted findings. You must **review and approve** any executive narrative before external sharing.

Use `python3 tools/publish_wazuh_milestone.py` to publish aggregate-only findings from your own completed run. The publisher may refuse to overwrite a previous result with different scores; preserve previous results and compare runs rather than silently replacing published findings.

### Optional automatic polling demonstration

```bash
sudo python3 -m src.demo.wazuh_pipeline watch \
  --alerts /var/ossec/logs/alerts \
  --case SOCSIM-009 --once \
  --out /tmp/soc_recording_fresh_01
```

The `watch` command polls Wazuh alert records and starts a case investigation automatically when complete evidence exists. It is **not** a web dashboard button, AWS integration or autonomous remediation.

## 11. Troubleshooting checklist

| Symptom | Check / correction |
|---|---|
| `Wazuh manager config missing` in setup helper | Re-run dry run with `sudo`; `/var/ossec/etc/ossec.conf` is protected |
| Wazuh restart fails after custom-rule installation | Inspect `/var/ossec/logs/ossec.log`; validate `<action>` rule conditions, not `<field name="action">`; restore backup if needed |
| Rule tests pass but dashboard shows no alerts | Verify manager service, `/var/log/soc_demo_cloud.jsonl`, logcollector test, indexer and dashboard services, filter and time range |
| Dashboard count 400 but current `alerts.json` only 397 | Read `/var/ossec/logs/alerts/` **including rotated JSON/JSON.GZ archives**; deduplicate by source event ID and verify fields |
| `watch` prints `CACHED` | Choose a new, unused `--out` directory; cached results are intentionally preserved |
| `sudo` outputs root-owned results | `sudo chown -R "$(id -u):$(id -g)" <your-demo-output-folder>` for only the folder you own |
| Ollama connection refused / model missing | Check `systemctl is-active ollama`, `ollama list`, and `ollama pull qwen2.5:1.5b`; model server listens locally on port 11434 |
| Model emits malformed JSON / incorrect narrative | Guarded model validation and retry; log failures honestly, leave case for analyst review |
| Tests show `ResourceWarning: HTTPError` | Test intentionally covers malformed HTTP responses; check `Ran ... tests` and final `OK` status |
| Git thinks all evidence is modified | Generated outputs belong under Git-ignored `data/lab_evidence/`; never commit them |

## 12. Academic integrity, limitations and publication checklist

Before claiming successful reproduction, verify: Wazuh service active; matching IDs; complete cases; all investigators receive identical case evidence; truth labels excluded from prompts; errors counted; executive report flagged review-required; user approvals preserved; test suite passes.

This demonstration **does not** validate real attack execution, success of AWS API operations, production SOC performance, human time saved, model fine-tuning, or a statistically independent sample of 100 real attacks. The rule baseline shares design assumptions with the simulator, making its 100% score an expected in-distribution result. RAG here uses curated reference-note retrieval, not a proven exhaustive threat-intelligence search.

**Useful reading:** [README](../README.md) · [full study chronology](RESEARCH_JOURNEY_AND_LIMITATIONS.md) · [final measured results](wazuh_ai_final_results.md) · [Wazuh experiment runbook](wazuh_ai_completion_runbook.md) · [Wazuh quickstart](https://documentation.wazuh.com/current/quickstart.html) · [Ollama Linux documentation](https://docs.ollama.com/linux).
