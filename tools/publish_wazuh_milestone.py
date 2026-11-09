"""Publish only reproducible aggregate results after live evaluation is complete."""
from pathlib import Path
import argparse
import json

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPORT = ROOT / "data/lab_evidence/soc_demo/wazuh_ai_pipeline/evaluation_PRIVATE.json"


def render(metrics):
    count = metrics["sample_cases"]
    lines = ["# Wazuh-linked AI investigation — observed results", "",
             "**Research simulation, not real AWS attack observations.**", "",
             f"Fully investigated matched Wazuh cases: **{count}** (from up to 100 generated synthetic cases).", "",
             "## Verified Wazuh source coverage", ""]
    audit = metrics.get("ingestion_audit", {})
    for field in ("expected_simulated_events", "verified_unique_events", "verified_coverage", "complete_cases", "partial_or_absent_cases", "mismatch_count"):
        lines.append(f"- {field.replace('_', ' ').capitalize()}: **{audit.get(field, 'not verified')}**")
    lines.extend(["", "The alert-file count may differ from indexed Wazuh dashboard search hits due to their different storage windows; do not interpret that difference as evidence of a malicious event.", "",
                  "## Paired comparison of the same cases", "",
                  "| Method | Correct / evaluated | Model errors or abstentions | Accuracy on all | Macro F1 | Mean runtime (seconds) |",
                  "|---|---:|---:|---:|---:|---:|"])
    for method, r in metrics["methods"].items():
        speed = str(r["mean_elapsed_s"]) if r.get("mean_elapsed_s") is not None else "not applicable"
        acc = f"{r['accuracy_on_all']:.1%}" if r.get("accuracy_on_all") is not None else "n/a"
        lines.append(f"| `{method}` | {r['correct']}/{r['total']} | {r['failures_or_abstentions']} | {acc} | {r['macro_f1']:.3f} | {speed} |")
    lines.extend(["", "**Accuracy note:** All-case accuracy counts errors/abstentions as failures. The guardrailed rule-enforced row is a safety feature built from existing rules, not a fourth independent AI model. Model prompts exclude Wazuh rule severity and private simulation reference labels.", "",
                  "**Prompt/version note:** This Wazuh-linked experiment uses a separate structured prompt and directly read Wazuh records; its results are not directly comparable to the earlier six-case synthetic `soc_demo.compare()` or CloudTrail development experiments.", "",
                  "## Research limitations", ""])
    lines.extend(f"- {item}" for item in metrics.get("limitations", []))
    lines.extend(["", "**Supporting evidence:** `docs/assets/soc-2026-11-09/wazuh-filtered-400-events.png`, "
                  "`docs/soc_results_2026-11-09.md`, and local private matched-alert investigation reports. "
                  "The private source logs and raw model responses remain Git-ignored.", ""])
    return "\n".join(lines)


def publish(input_path=DEFAULT_REPORT, root=ROOT):
    path = Path(input_path)
    if not path.exists():
        raise FileNotFoundError("No verified evaluation yet; run Wazuh-linked cases and evaluate first: " + str(path))
    metrics = json.loads(path.read_text(encoding="utf-8"))
    if not metrics.get("sample_cases") or metrics.get("source_of_predictions") != "Wazuh alerts verified against source events":
        raise ValueError("No valid Wazuh-linked evaluation found")
    doc = Path(root) / "docs/wazuh_ai_final_results.md"
    doc.parent.mkdir(parents=True, exist_ok=True)
    text = render(metrics)
    if doc.exists() and doc.read_text(encoding="utf-8") != text:
        raise ValueError("A published results file already exists with different metrics; manual review required")
    doc.write_text(text, encoding="utf-8")
    readme = Path(root) / "README.md"
    if readme.exists():
        original = readme.read_text(encoding="utf-8")
        marker = "## Wazuh-to-AI: verified end-to-end research milestone"
        if marker not in original:
            addition = ("\n\n" + marker + "\n\n" +
                        "The tested Wazuh alert ingestion → baseline / local LLM / RAG → evidence-based human-review gate "
                        "→ stakeholder report workflow is documented in "
                        "[the runbook](docs/wazuh_ai_completion_runbook.md). "
                        "For actual sample sizes, error rates, model scores and limitations, "
                        "see [the observed results](docs/wazuh_ai_final_results.md). "
                        "The cloud events were **synthetically generated**; model assessments are not independently verified compromises.\n")
            readme.write_text(original.rstrip() + addition + "\n", encoding="utf-8")
    print("PUBLISHED", doc)
    print("READ ME LINK", readme)
    return doc


if __name__ == "__main__":
    cli = argparse.ArgumentParser()
    cli.add_argument("--metrics", type=Path, default=DEFAULT_REPORT)
    args = cli.parse_args()
    publish(args.metrics)
