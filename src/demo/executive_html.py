"""Printable, no-dependency stakeholder dashboard; generated only from verified case reports."""
from __future__ import annotations
from collections import Counter
from html import escape


def e(x):
    return escape(str(x), quote=True)


def render_html(rows, metrics):
    audit = metrics.get("ingestion_audit", {})
    m = metrics["methods"]
    count = len(rows)
    priority = sum(bool(r["guardrails"]["priority_review"]) for r in rows)
    classes = Counter(r["guardrails"]["evidence_based_triage"] for r in rows)
    bars = []
    for name, label in (("baseline", "Conventional rules"), ("llm_only", "Local LLM"),
                        ("rag", "LLM + references")):
        r = m[name]
        percent = round(100 * r["correct"] / count) if count else 0
        bars.append(f'<div class="barrow"><span>{e(label)}</span><div class="track"><div class="bar" style="width:{percent}%"></div></div>'
                    f'<strong>{r["correct"]}/{count}</strong></div>')
    cases_html = []
    for r in rows:
        case_id = e(r["case_id"])
        triage = r["guardrails"]["evidence_based_triage"]
        flags = []
        for method in ("llm_only", "rag"):
            issues = r["guardrails"]["model_adjudication"][method]["flags"]
            if issues:
                flags.append(f'<li><b>{e(method)}:</b> {e(", ".join(issues))}</li>')
        findings = []
        for finding in r["guardrails"]["factual_findings"]:
            refs = " ".join(f'<code>{e(i)}</code>' for i in finding["evidence_ids"])
            checks = "; ".join(finding["recommended_checks"])
            findings.append(f'<div class="finding"><strong>{e(finding["title"])}</strong>'
                            f'<p>{e(finding["observation"])}</p>'
                            f'<p><b>Potential exposure:</b> {e(finding["business_risk"])}</p>'
                            f'<p><b>Human checks:</b> {e(checks)}</p>'
                            f'<div class="refs">Wazuh-matched event IDs: {refs}</div></div>')
        results = r["results"]
        summary = (f'{case_id} · {e(triage.upper())} triage · {r["event_count"]} Wazuh events · '
                   f'LLM: {e(results["llm_only"].get("prediction") or "FAILED")} · '
                   f'RAG: {e(results["rag"].get("prediction") or "FAILED")}')
        cases_html.append(f'<details class="incident"><summary>{summary}</summary>'
                          f'<div class="incident-body"><p><b>Observed API actions:</b> {e(", ".join(r["observed_actions"]))}</p>'
                          f'{"".join(findings)}<div><b>Model QA flags:</b></div><ul>{"".join(flags) or "<li>None of the predefined claim checks fired; prose still unverified.</li>"}</ul>'
                          '<p class="disclaimer">No automatic remediation; analyst approval required. Reported actions are simulated log records, not confirmed execution.</p>'
                          '</div></details>')
    html = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Wazuh-Linked SOC Investigation | Academic Research</title>
<style>
:root{{--ink:#152034;--muted:#5d6980;--line:#e4e9f2;--bg:#f3f6fb;--blue:#2455bd;--amber:#a66312;--red:#ae3446;--green:#207e6e}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,Segoe UI,sans-serif}}main{{max-width:1060px;margin:auto;padding:38px 24px 70px}}
.kicker{{text-transform:uppercase;letter-spacing:.17em;font-weight:700;color:var(--blue);font-size:11px}}h1{{font-size:36px;line-height:1.13;margin:10px 0 14px;letter-spacing:-.045em}}h2{{font-size:20px;margin:38px 0 14px;letter-spacing:-.02em}}p{{margin:8px 0 14px}}.lead{{font-size:17px;color:var(--muted);max-width:830px}}
.card{{background:white;border:1px solid var(--line);border-radius:13px;padding:22px;box-shadow:0 2px 8px #162d5409}}.warning{{border-left:4px solid var(--amber);background:#fffaf2;padding:15px 18px;border-radius:7px;font-weight:600}}
.stats{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:24px 0}}.stat-value{{display:block;font-size:28px;font-weight:750;letter-spacing:-.04em}}.stat-label{{display:block;color:var(--muted);font-size:12px}}
.twocol{{display:grid;grid-template-columns:1fr 1fr;gap:16px}}.barrow{{display:flex;align-items:center;gap:12px;margin:12px 0}}.barrow>span{{width:145px;font-size:13px}}.track{{flex:1;background:#e7eefb;height:12px;border-radius:8px;overflow:hidden}}.bar{{height:100%;background:var(--blue);border-radius:8px}}.barrow>strong{{width:44px;text-align:right;font-variant-numeric:tabular-nums}}
.meta{{color:var(--muted);font-size:12px}}.legend{{display:grid;gap:13px}}.legend strong{{display:block}}.incident{{background:white;border:1px solid var(--line);border-radius:9px;margin:10px 0;overflow:hidden}}.incident>summary{{cursor:pointer;padding:17px 18px;font-weight:700;list-style-position:inside}}.incident[open]>summary{{background:#f8faff;border-bottom:1px solid var(--line)}}.incident-body{{padding:16px 20px}}.finding{{border-left:3px solid #b5c8ed;padding:8px 14px;margin:12px 0;background:#f8faff}}.refs{{font-size:12px;color:var(--muted)}}code{{font-size:12px;background:#e9effc;border-radius:3px;padding:2px 5px;margin:2px;display:inline-block}}
.disclaimer{{color:var(--red);font-weight:600}}footer{{font-size:12px;color:var(--muted);border-top:1px solid var(--line);padding-top:20px;margin-top:40px}}
@media(max-width:720px){{.stats{{grid-template-columns:1fr 1fr}}.twocol{{grid-template-columns:1fr}}h1{{font-size:29px}}}}
@media print{{body{{background:white}}main{{padding:0}}.card{{box-shadow:none}}details:not([open]){{display:none}}}}
</style></head><body><main>
<div class="kicker">Lakehead University · COMP 5112 · Controlled research simulation</div>
<h1>AI-Assisted Cloud Security<br>Incident Investigation</h1>
<p class="lead">Stakeholder overview of Wazuh-linked alert ingestion, rule-based triage, local LLM analysis, and reference-assisted AI analysis.</p>
<div class="warning">Academic simulation only. No actual AWS attacks, confirmed compromises, or automatic protective actions. Human review is required.</div>
<section class="stats"><div class="card"><span class="stat-value">{count}</span><span class="stat-label">Cases fully investigated</span></div>
<div class="card"><span class="stat-value">{audit.get("verified_unique_events", "—")}/{audit.get("expected_simulated_events", 400)}</span><span class="stat-label">Source-linked Wazuh events</span></div>
<div class="card"><span class="stat-value">{priority}</span><span class="stat-label">Cases needing priority analyst review</span></div>
<div class="card"><span class="stat-value">{m["rag"]["failures_or_abstentions"]}</span><span class="stat-label">RAG failures or abstentions</span></div></section>
<h2>What the experiment actually shows</h2><div class="twocol"><div class="card"><strong>Correct classifications on evaluated cases</strong>{''.join(bars)}
<p class="meta">Errors and abstentions count as incorrect. This simulation repeats scenario templates; numbers do not predict production accuracy.</p></div>
<div class="card legend"><div><strong>Evidence-based response</strong>Risk based on Wazuh-decoded actions, never a verified breach.</div>
<div><strong>LLM / RAG findings</strong>Raw model verdicts retained for comparison, but unsupported text is excluded from trusted summaries.</div>
<div><strong>Analyst gate</strong>AI cannot silently downgrade high-risk evidence. No autonomous account or cloud changes.</div></div></div>
<h2>Incident classification summary</h2><p>Evidence-based triage (not ground-truth proof): <b>{classes.get("benign",0)}</b> benign pattern(s), <b>{classes.get("suspicious",0)}</b> suspicious pattern(s), <b>{classes.get("critical",0)}</b> critical-review pattern(s).</p>
<h2>Case-by-case stakeholder briefs</h2><p class="meta">Expand a case for observed actions, evidence IDs, potential business exposure, and recommended human checks.</p>{''.join(cases_html)}
<footer>Research method: Wazuh JSON alerts validated against known generated event fields; AI prompts exclude Wazuh rule severity and simulation ground-truth labels. Model outputs are separately scored against isolated simulation labels. Wazuh is a real SIEM in this experiment, but all cloud API events shown here are synthetic. No claim of improved AI accuracy or live incident response is supported by this experiment.</footer>
</main></body></html>'''
    return html
