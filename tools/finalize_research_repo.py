#!/usr/bin/env python3
"""Safely inspect and refresh the actual local research git checkout.

Usage:
  python3 tools/finalize_research_repo.py --audit
  python3 tools/finalize_research_repo.py --apply
  python3 tools/finalize_research_repo.py --apply --prune-safe-empty

IMPORTANT: no git commit/push, network operation or destructive mass deletion.
The README is replaced *only* on --apply and backed up under .git/repo_refresh_backups/.
Empty __init__.py and other code files are deliberately retained.
"""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
from datetime import datetime
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "repo_refresh_templates"
MARKER = "FINAL-RESEARCH-2026-11-09"
SNAPSHOT_NOTE = ("**Historical snapshot notice (updated 9 Nov 2026):** This page preserves an earlier "
                 "experiment state; for the completed 100-case Wazuh-sourced results, see "
                 "[final measurements](wazuh_ai_final_results.md) and "
                 "[research journey](RESEARCH_JOURNEY_AND_LIMITATIONS.md). "
                 "The earlier 397/400 current-log discrepancy was resolved by reading Wazuh archives "
                 "(400/400 verified IDs, 100 complete cases, zero mismatches).")

APPENDS = {
  "docs/development_log.md": """## Final integration and repository publication — 9 Nov 2026

- Recovered the full 100-case academic SOC simulation after Wazuh rule and manager recovery testing. The custom action rules (`110101`, `110102`) now validate, and the dashboard displayed 400 clearly tagged synthetic alerts.
- Implemented `src/demo/wazuh_pipeline.py` and `src/demo/grounded_model.py` for direct Wazuh alert-reading, same-case source-field verification, three-method investigations, analyst review, and private cached results. Added HTML reporting in `src/demo/executive_html.py`.
- A direct `watch --once --case SOCSIM-009` run read three verified Wazuh records and completed baseline / LLM-only / RAG processing. Output: baseline critical, LLM-only suspicious, RAG suspicious, `priority_review=True` (one observed run; model results may vary).
- Initial current-file audit found 397/400 IDs and 99 complete cases; a later current-plus-archive audit found 797 candidate records, 397 duplicates, **400 unique matching IDs**, all 100 cases and no mismatches.
- Completed the final paired 100-case evaluation and generated review-required stakeholder HTML/Markdown outputs. Commit `0661ce8` published the pipeline, tests and aggregate results on `main`, with a clean worktree after push.
- Verified `python3 -m unittest discover -s tests -q` completed **140 tests: OK**. The HTTPError ResourceWarning is retained as a minor test-cleanliness issue, not a failed test.
- Consolidated README, full reproduction guide, final research narrative and repository audit without erasing historical snapshots. Repository cleanup is intentionally evidence-preserving.

""",
  "docs/experiment_log.md": """## Final Wazuh-sourced 100-case comparison — 9 Nov 2026

**Dataset:** ten deliberately designed templates repeated ten times; 100 simulator-labeled cases (40 benign / 30 suspicious / 30 critical), 400 synthetic CloudTrail-like JSON events. **No AWS attacks or remediation** executed.

**Evidence provenance:** actual Wazuh Manager `alerts.json` plus archived JSON/JSON.GZ records. Full read: 797 candidate records, 397 duplicates, **400/400 distinct source IDs matched**, 0 source-field mismatches, 100 complete cases. Three rule groups: `110100=160`, `110101=140`, `110102=100`. Original 397/400 result came from the current alert file alone and is **resolved**, not discarded.

**Paired classification:** all three investigators processed the same complete Wazuh-linked cases. Baseline **100/100 (100%)**, LLM-only **53/100 (53%)**, RAG-assisted **30/100 (30%)**. Do not confuse this *three-class severity* experiment with the earlier six-case *binary CloudTrail* pilot or six-case SOC functional demo. Predictions and truth labels were separated until scoring. The matched baseline is expected to benefit from the simulator's pattern design.

**Quality and interpretation:** the pretrained `qwen2.5:1.5b` model sometimes under-rated high-risk IAM or audit-log sequences and produced unsupported claims (including wrong service/resource attribution). The final executive reporter uses verified observed actions, exact event IDs and conservative deterministic summaries; its generated outputs are **review required**, not fact-certified client deliverables. RAG did not improve accuracy. Analyst review demand was calculated as a proxy; **human time saved was not measured**.

**Integration faults preserved:** initial Wazuh static `action` rule mismatch caused manager restart failure; rollback and `<action type=\"pcre2\">` corrected it. Earlier LLM JSON-format/HTTP errors required validation and retry. No model fine-tuning or actual cloud response occurred.

**Reproduction references:** [from-scratch setup](SETUP_FROM_SCRATCH.md), [full experiment journey](RESEARCH_JOURNEY_AND_LIMITATIONS.md), [published aggregate metrics](wazuh_ai_final_results.md). Offline suite: **140 passed**.

""",
  "docs/research_decisions.md": """## Final interpretation decisions — 9 Nov 2026

1. **Source of truth:** Do not equate SIEM rule matches with proven attacks. Trust only Wazuh event records whose source fields and `sim_event_id` agree with the independent generated source manifest; keep simulation labels out of model inputs.
2. **Fair comparison:** Baseline, local LLM and RAG consume identical complete case evidence; errors and abstentions remain in all-case accuracy. Do not present the rule-enforced review gate as AI accuracy.
3. **Method boundaries:** This is **polling-based Wazuh-file integration**, not a Wazuh click-through UI or autonomous response. RAG uses local curated security notes, not a comprehensive or up-to-date knowledge service.
4. **Negative findings are valid:** 100% baseline, 53% LLM, 30% RAG on in-distribution synthetic cases. Preserve unfavorable AI results without relabeling outcomes.
5. **Claim safety:** Executive summaries are anchored in actual event names and verified IDs; unsupported model text is flagged, not silently trusted. Review is mandatory before release.
6. **Privacy and cleanup:** Keep raw model output, labels and Wazuh alert exports Git-ignored. Remove only demonstrably empty, nonstructural artifacts; retain empty Python package markers and historical negative experiments.

""",
  "docs/dataset_card.md": """## Final Wazuh-linked synthetic SOC dataset (separate from Ariel Cyber CloudTrail) — 9 Nov 2026

| Property | Verified design / observation |
|---|---|
| Source and scope | Local deterministic generator in `src/demo/soc_demo.py`; no AWS requests made |
| Case and event counts | 100 designed cases and 400 simulated API records |
| Label distribution | 40 benign, 30 suspicious, 30 designated critical |
| Scenario diversity | Ten hand-designed templates each repeated ten times; **not independent real-world cases** |
| Event-to-alert integrity | 400 matching distinct Wazuh identifiers, zero mismatches after scanning current and archived manager alerts |
| Alert severity | Rule `110100` level 3: 160; `110101` level 8: 140; `110102` level 12: 100 |
| Truth leakage defense | `ground_truth_PRIVATE.jsonl` isolated and accessed only by evaluation code after saved model predictions |
| Storage and confidentiality | `data/lab_evidence/soc_demo/` is Git-ignored; don't commit Wazuh exports, generated labels or raw LLM reports |
| Known biases | Templates repeated; baseline intentionally aligned to patterns; no real attacker behaviors, unauthorized outcomes or human time measurements |

**Do not combine** this final 100-case three-class experiment with the earlier 6-case binary CloudTrail pilot; the public Ariel Cyber datasets are a separate provenance track. See [the full methodology](RESEARCH_JOURNEY_AND_LIMITATIONS.md).

""",
  "docs/ai_architecture.md": """## Completed 2026-11-09 implementation: verified Wazuh polling bridge

`src/demo/wazuh_pipeline.py` reads the actual Wazuh manager alert JSON or its JSON/GZ archive directory, filters simulation-tagged records, and verifies case ID, event ID, actor, IP, action, service, resource, error code, Wazuh rule and log source against generated evidence. Incomplete cases are not scored. A `watch` mode polls for new complete cases. The identical verified case goes to rule baseline, Ollama/Qwen model and reference-assisted model; truth labels and Wazuh severity are excluded from prompts. `grounded_model.py` enforces constrained output formats and citations; `executive_html.py` renders an evidence-based report with human review gating. The review gate does not alter the recorded raw model classification for evaluation.

Full setup: [SETUP_FROM_SCRATCH.md](SETUP_FROM_SCRATCH.md). Final results: [wazuh_ai_final_results.md](wazuh_ai_final_results.md).

""",
  "docs/presentation_demo_notes.md": """## Final verified 6–7-minute demonstration flow — 9 Nov 2026

1. **Intro (45 s):** show README problem, method and architecture; no real attacks or fine-tuning.
2. **Wazuh (75 s):** Threat Hunting → Events → `rule.groups: soc_demo`; use historical Nov 8–9 date window. Show alert rules 110100/110101/110102 and 400 events. Filter `data.sim_case_id: SOCSIM-009` for three IAM-action records.
3. **Investigation (80 s):** in Ubuntu use a **fresh** `--out` path:

   ```bash
   sudo python3 -m src.demo.wazuh_pipeline watch --alerts /var/ossec/logs/alerts --case SOCSIM-009 --once --out /tmp/soc-recording-fresh
   sudo python3 -m src.demo.wazuh_pipeline evaluate --out /tmp/soc-recording-fresh
   ```

4. **Report (90 s):** open `EXECUTIVE_REPORT_REVIEW_REQUIRED.html`; explain verified actions, `SOCSIM-009-EVT-01`–`EVT-03`, IAM business concern, QA flags and manual checks.
5. **Results (80 s):** show 100-case final chart: baseline 100%, LLM-only 53%, RAG 30%; explain baseline-template alignment and negative AI reliability result.

**Rehearse without recording** and warm `sudo -v` first. The last published 100-case outputs remain untouched; this is one *new* case replay. Model predictions may vary. No action in the demo makes AWS API calls or remediates an account.

""",
}

PREPEND_TO_HISTORICAL = (
    "docs/soc_results_2026-11-09.md", "docs/soc_demo.md",
    "docs/project_inventory.md", "docs/wazuh_ai_completion_runbook.md",
)


def git_files():
    cmd = ["git", "ls-files", "-z", "--cached"]
    result = subprocess.run(cmd, cwd=ROOT, capture_output=True, check=True)
    return sorted((ROOT / p.decode("utf-8", "replace")) for p in result.stdout.split(b"\0") if p)


def all_relevant_files():
    # Include untracked non-ignored files to report the current working tree comprehensively.
    result = subprocess.run(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                            cwd=ROOT, capture_output=True, check=True)
    return sorted(set(ROOT / p.decode("utf-8", "replace") for p in result.stdout.split(b"\0") if p))


def backup(path, backup_root):
    if path.exists():
        dest = backup_root / path.relative_to(ROOT)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, dest)


def append_once(path, content, backup_root):
    if not path.is_file():
        return False
    original = path.read_text(encoding="utf-8")
    tag = f"<!-- {MARKER}-APPEND -->"
    if tag in original:
        return False
    backup(path, backup_root)
    updated = original.rstrip() + "\n\n" + tag + "\n\n" + content.strip() + "\n"
    path.write_text(updated, encoding="utf-8")
    return True


def prepend_once(path, backup_root):
    if not path.is_file():
        return False
    original = path.read_text(encoding="utf-8")
    tag = f"<!-- {MARKER}-HISTORICAL -->"
    if tag in original:
        return False
    backup(path, backup_root)
    path.write_text(tag + "\n\n> " + SNAPSHOT_NOTE + "\n\n---\n\n" + original, encoding="utf-8")
    return True


def local_md_references(root):
    refs = Counter()
    broken = []
    for doc in sorted(root.rglob("*.md")):
        if any(part.startswith(".git") or part.startswith(".") for part in doc.relative_to(root).parts):
            continue
        if doc.is_symlink() or "data/lab_evidence" in str(doc):
            continue
        try:
            content = doc.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        # Markdown images + markdown links; `url` can include a title or fragment.
        for match in re.finditer(r'!?(?:\[[^\]]*\])\(([^)]+)\)', content):
            raw = match.group(1).strip().strip("<>").split(' "', 1)[0].strip()
            if not raw or raw.startswith(("https://", "http://", "mailto:", "#", "data:", "javascript:")):
                continue
            path_part = unquote(raw.split("#", 1)[0].split("?", 1)[0])
            if not path_part or path_part.startswith("/"):
                continue
            target = (doc.parent / path_part).resolve()
            if not target.is_relative_to(root.resolve()):
                continue
            refs[target] += 1
            if not target.exists():
                broken.append((doc.relative_to(root).as_posix(), raw))
    return refs, sorted(set(broken))


def safe_empty_candidates(files, refs):
    # Treat placeholders referenced in code/configuration as potentially structural.
    text_paths = (p for p in files if p.is_file() and p.suffix.lower() in
                  (".py", ".sh", ".toml", ".cfg", ".ini", ".yaml", ".yml", ".md"))
    text_bodies = []
    for p in text_paths:
        try:
            if p.stat().st_size < 2_000_000:
                text_bodies.append(p.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
    result = []
    for path in files:
        if not path.is_file() or path.is_symlink() or path.stat().st_size != 0:
            continue
        if path.name == "__init__.py" or path in refs:
            continue
        if path.name != ".gitkeep" and any(path.name in body or
            path.relative_to(ROOT).as_posix() in body for body in text_bodies):
            continue
        if path.name == ".gitkeep":
            others = [q for q in path.parent.iterdir() if q.is_file() and q != path and q.name != "__init__.py"]
            if not others:
                result.append(path)
        elif path.suffix.lower() in (".md", ".txt", ".rst", ".json", ".yaml", ".yml", ".csv", ".png", ".svg"):
            if path.name.lower() not in ("license", "license.md", "readme.md"):
                result.append(path)
    return sorted(result)


def audit(prune=False, backup_root=None):
    files = all_relevant_files()
    refs, broken = local_md_references(ROOT)
    empty = [p for p in files if p.is_file() and p.stat().st_size == 0]
    candidates = safe_empty_candidates(files, refs)
    deleted = []
    if prune:
        if not backup_root:
            raise ValueError("backup_root required for pruning")
        for path in candidates:
            backup(path, backup_root)
            path.unlink()
            deleted.append(path.relative_to(ROOT).as_posix())
        # Empty directories have no representation in Git; remove only now-empty non-private dirs.
        for parent, ds, fs in os.walk(ROOT, topdown=False):
            p = Path(parent)
            if p == ROOT or any(k in p.parts for k in (".git", ".venv", "__pycache__", "lab_evidence", "node_modules")):
                continue
            try:
                if not any(p.iterdir()):
                    p.rmdir()
            except OSError:
                pass
        files = all_relevant_files()
        refs, broken = local_md_references(ROOT)
    duplicates = defaultdict(list)
    image_files = [p for p in files if p.is_file() and p.suffix.lower() in (".png", ".jpg", ".jpeg", ".webp", ".svg", ".gif")]
    for p in image_files:
        duplicates[hashlib.sha256(p.read_bytes()).hexdigest()].append(p.relative_to(ROOT).as_posix())
    image_dupes = [items for items in duplicates.values() if len(items) > 1]
    unused_images = [p.relative_to(ROOT).as_posix() for p in image_files if p.resolve() not in refs]
    module_count = Counter((p.relative_to(ROOT).parts[0] if len(p.relative_to(ROOT).parts)>1 else "(root)")
                           for p in files if p.is_file())
    header = ["# Repository audit and cleanup review", "",
              "Generated from the **actual local Git checkout** by `tools/finalize_research_repo.py`. This report covers Git-tracked files and non-ignored untracked files, not private Git-ignored evidence. It never claims to scan files that are not in the checkout.", "",
              "## Summary", "",
              "- Source checkout: this repository root (absolute local workstation path intentionally omitted)",
              f"- Files scanned (tracked + non-ignored untracked): **{sum(p.is_file() for p in files)}**",
              f"- Git-tracked files: **{sum(p.is_file() for p in git_files())}**",
              f"- Zero-byte files found: **{len(empty)}** (not all are deletable)",
              f"- Safe empty placeholder candidates: **{len(candidates)}**",
              f"- Safely removed during this run: **{len(deleted)}**",
              f"- Identical-content image groups: **{len(image_dupes)}**",
              f"- Images with no Markdown reference: **{len(unused_images)}** (report only; may be used by code or historical docs)",
              f"- Local Markdown relative links not found: **{len(broken)}**",
              "", "## File count by top-level location", "",
              "| Directory | Files |", "|---|---:|"]
    for key,count in sorted(module_count.items()):
        header.append(f"| `{key}` | {count} |")
    header += ["", "## Zero-byte files (structural package markers are intentionally kept)", ""]
    header += [f"- `{p.relative_to(ROOT).as_posix()}` {'(structural Python package; retained)' if p.name=='__init__.py' else ''}" for p in empty] or ["None."]
    header += ["", "## Safe empty-file deletion candidates", ""]
    header += [f"- `{p.relative_to(ROOT).as_posix()}`" for p in candidates] or ["None."]
    header += ["", "## Files moved to local backup and removed", ""]
    header += [f"- `{p}`" for p in deleted] or ["None."]
    header += ["", "## Byte-identical images (do not delete until references are audited)", ""]
    for group in image_dupes:
        header.append("- " + ", ".join(f"`{p}`" for p in group))
    if not image_dupes: header.append("None.")
    header += ["", "## Images not referenced directly by Markdown (review only)", ""]
    header += [f"- `{p}`" for p in sorted(unused_images)] or ["None."]
    header += ["", "## Broken relative Markdown links (review before final push)", ""]
    header += [f"- `{path}` → `{target}`" for path,target in broken] or ["None found by this static check."]
    header += ["", "## Cleanup policy", "",
              "1. **Empty directories cannot exist in GitHub Git trees.** An explicit `.gitkeep` can preserve a placeholder directory; the safe prune option removes it only when no meaningful file remains.",
              "2. Keep intentionally zero-byte `__init__.py` package markers; deleting them can affect Python import behavior.",
              "3. Preserve archived research papers, experiment logs and screenshots even if not all are linked from README. A 'not referenced' image is not proof of redundancy.",
              "4. The script only removes genuinely empty, nonstructural placeholders when `--prune-safe-empty` is explicitly supplied. Full duplicates and active code require deliberate manual review.",
              "5. Restorable backups of changed or pruned files are stored under `.git/repo_refresh_backups/`, not published.",
              "6. After cleanup, run `python3 -m unittest discover -s tests -q`, `git diff --check`, review `git status --short`, and **only then** commit and push the reviewed changes.", ""]
    target = ROOT / "docs/REPOSITORY_AUDIT.md"
    target.parent.mkdir(parents=True,exist_ok=True)
    target.write_text("\n".join(header), encoding="utf-8")
    print(f"AUDITED: {sum(p.is_file() for p in files)} files; {len(empty)} zero-byte; {len(candidates)} safe empty candidates")
    print(f"IMAGE DUPLICATE GROUPS: {len(image_dupes)}; MISSING LOCAL LINKS: {len(broken)}")
    print("REPORT:", target)
    return broken


def apply_refresh(prune):
    for required in ("src/demo/wazuh_pipeline.py", "src/demo/soc_demo.py", "docs/wazuh_ai_final_results.md",
                     "docs/assets/soc-2026-11-09/wazuh-filtered-400-events.png"):
        if not (ROOT / required).is_file():
            raise SystemExit(f"REFUSING: prerequisite {required} missing from this checkout")
    templates_available = all((TEMPLATES / key).is_file() for key in
                              ("README.md", "SETUP_FROM_SCRATCH.md", "RESEARCH_JOURNEY_AND_LIMITATIONS.md"))
    if not templates_available and not all((ROOT / key).is_file() for key in
                                           ("README.md", "docs/SETUP_FROM_SCRATCH.md",
                                            "docs/RESEARCH_JOURNEY_AND_LIMITATIONS.md")):
        raise SystemExit("REFUSING: update templates missing and generated docs are not yet installed")
    now = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_root = ROOT / ".git" / "repo_refresh_backups" / now
    changed = []
    if templates_available:
        for template, target in (("README.md", "README.md"),
                                 ("SETUP_FROM_SCRATCH.md", "docs/SETUP_FROM_SCRATCH.md"),
                                 ("RESEARCH_JOURNEY_AND_LIMITATIONS.md", "docs/RESEARCH_JOURNEY_AND_LIMITATIONS.md")):
            path = ROOT / target
            data = (TEMPLATES / template).read_bytes()
            if path.exists() and path.read_bytes() == data:
                continue
            backup(path, backup_root)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            changed.append(target)
    for name, content in APPENDS.items():
        path=ROOT/name
        if append_once(path,content,backup_root):
            changed.append(name)
    for name in PREPEND_TO_HISTORICAL:
        path=ROOT/name
        if prepend_once(path,backup_root):
            changed.append(name)
    # Clarify formerly-checkboxed completion criteria rather than falsely leaving them open.
    runbook = ROOT/"docs/wazuh_ai_completion_runbook.md"
    if runbook.is_file():
        content=runbook.read_text(encoding="utf-8")
        current=re.sub(r"^- \[ \] \*\*(P[01])\.", r"- [x] **\1.", content, flags=re.MULTILINE)
        if current!=content:
            backup(runbook, backup_root)
            runbook.write_text(current,encoding="utf-8")
            changed.append(str(runbook.relative_to(ROOT)))
    # The ZIP templates are temporary installation payload, not permanent repo clutter.
    # Preserve them outside Git's worktree before doing the final audit.
    if TEMPLATES.is_dir():
        backup_root.mkdir(parents=True, exist_ok=True)
        shutil.move(str(TEMPLATES), str(backup_root / "_installation_templates"))
        print("STAGING TEMPLATES: moved to local .git backup (not committed)")
    print("REFRESHED:", ", ".join(dict.fromkeys(changed)) or "nothing (already current)")
    if backup_root.exists():
        print("LOCAL BACKUPS:", backup_root)
    return audit(prune=prune, backup_root=backup_root)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--audit",action="store_true",help="Inspect actual checkout, write docs/REPOSITORY_AUDIT.md; no cleanup")
    group.add_argument("--apply",action="store_true",help="Rebuild README/docs and make local backups")
    parser.add_argument("--prune-safe-empty",action="store_true",help="With --apply only: backup and delete empty nonstructural placeholders")
    args=parser.parse_args()
    if not (ROOT/".git").exists():
        raise SystemExit(f"Not a Git checkout: {ROOT}")
    if args.prune_safe_empty and not args.apply:
        parser.error("--prune-safe-empty requires --apply")
    errors=apply_refresh(args.prune_safe_empty) if args.apply else audit()
    print("NEXT: python3 -m unittest discover -s tests -q; git diff --check; git status --short")
    if errors:
        print("REVIEW: some relative links are unresolved; see docs/REPOSITORY_AUDIT.md")


if __name__ == "__main__":
    main()
