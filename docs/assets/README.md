# SOC Laboratory Visual Evidence

Screenshots are original user-supplied images of their Wazuh 4.14.9 / Ubuntu VMware laboratory. These images are **documentation**, not independently verified forensic originals and not evidence of an actual malicious attack. Review host/account names for privacy before public publishing.

| File | What it demonstrates |
|---|---|
| `01-wazuh-login-page.png` | HTTPS Wazuh login interface reachable on the lab network. |
| `02-wazuh-dashboard-overview.png` | Dashboard operational, alert counters visible, zero registered external agents at capture. |
| `03-ubuntu-controlled-authentication.png` | Authorized `su - root` failure and matching system-journal messages. |
| `04-wazuh-raw-alert-query.png` | Locally queried alert records for rules 5503 and 5301. |
| `05-threat-hunting-rule-5503.png` | Wazuh Threat Hunting graphical evidence, failed PAM login. |
| `06-threat-hunting-rule-5301.png` | Wazuh Threat Hunting graphical evidence, failed user switch. |

`docs/assets/diagrams/soc-evidence-pipeline.svg` is an editable vector flowchart. `soc-evidence-pipeline.png` is the raster version useful for PowerPoint.

**Research status:** 35 automated Python tests passed at the last reported check. Separate preflight PFL-001-RUN-001 was verified end-to-end. Wazuh monitored test PFL-001-RUN-002 generated both alerts and dashboard matches; its full dataset integration and ground-truth verification remain pending. No AI-assisted evaluation has been performed yet.
