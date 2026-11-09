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

---

<!-- SOC-MILESTONE-2026-11-09-VERIFIED:START -->

## Wazuh SOC research evidence added 9 November 2026

Source: actual user-provided captures of the Wazuh Dashboard / Threat Hunting running on the local Ubuntu VM. No UI screenshot was fabricated or synthesized. New folder: [`soc-2026-11-09/`](soc-2026-11-09/).

- `wazuh-filtered-400-events.png`: Threat Hunting Events filtered to `rule.groups: soc_demo` with **400 indexed hits**, displayed rule IDs/levels.
- `wazuh-threat-hunting-overview.png`: combined 24-hour view; **638 total** including non-simulation events.
- `wazuh-dashboard-summary.png`: overview summary; **100 level-12-to-14 alerts**, **225 level-7-to-11 alerts**, **313 level-0-to-6 alerts** in the selected window; these are *not* 100 distinct real attack incidents.
- `01-simulation-distribution.png` through `04-model-latency.png`: original charts generated from the precise user-shared command output, with method failures explicitly retained.

Source-data transcription and limitations: [complete SOC milestone](../soc_results_2026-11-09.md).

<!-- SOC-MILESTONE-2026-11-09-VERIFIED:END -->
