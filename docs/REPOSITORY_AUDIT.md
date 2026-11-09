# Repository audit and cleanup review

Generated from the **actual local Git checkout** by `tools/finalize_research_repo.py`. This report covers Git-tracked files and non-ignored untracked files, not private Git-ignored evidence. It never claims to scan files that are not in the checkout.

## Summary

- Source checkout: this repository root (absolute local workstation path intentionally omitted)
- Files scanned (tracked + non-ignored untracked): **113**
- Git-tracked files: **105**
- Zero-byte files found: **1** (not all are deletable)
- Safe empty placeholder candidates: **0**
- Safely removed during this run: **0**
- Identical-content image groups: **0**
- Images with no Markdown reference: **8** (report only; may be used by code or historical docs)
- Local Markdown relative links not found: **0**

## File count by top-level location

| Directory | Files |
|---|---:|
| `(root)` | 3 |
| `data` | 11 |
| `deploy` | 3 |
| `docs` | 45 |
| `schemas` | 3 |
| `src` | 28 |
| `tests` | 16 |
| `tools` | 4 |

## Zero-byte files (structural package markers are intentionally kept)

- `src/demo/__init__.py` (structural Python package; retained)

## Safe empty-file deletion candidates

None.

## Files moved to local backup and removed

None.

## Byte-identical images (do not delete until references are audited)

None.

## Images not referenced directly by Markdown (review only)

- `docs/assets/diagrams/soc-evidence-pipeline.png`
- `docs/assets/diagrams/soc-evidence-pipeline.svg`
- `docs/assets/screenshots/01-wazuh-login-page.png`
- `docs/assets/screenshots/02-wazuh-dashboard-overview.png`
- `docs/assets/screenshots/03-ubuntu-controlled-authentication.png`
- `docs/assets/screenshots/04-wazuh-raw-alert-query.png`
- `docs/assets/screenshots/05-threat-hunting-rule-5503.png`
- `docs/assets/screenshots/06-threat-hunting-rule-5301.png`

## Broken relative Markdown links (review before final push)

None found by this static check.

## Cleanup policy

1. **Empty directories cannot exist in GitHub Git trees.** An explicit `.gitkeep` can preserve a placeholder directory; the safe prune option removes it only when no meaningful file remains.
2. Keep intentionally zero-byte `__init__.py` package markers; deleting them can affect Python import behavior.
3. Preserve archived research papers, experiment logs and screenshots even if not all are linked from README. A 'not referenced' image is not proof of redundancy.
4. The script only removes genuinely empty, nonstructural placeholders when `--prune-safe-empty` is explicitly supplied. Full duplicates and active code require deliberate manual review.
5. Restorable backups of changed or pruned files are stored under `.git/repo_refresh_backups/`, not published.
6. After cleanup, run `python3 -m unittest discover -s tests -q`, `git diff --check`, review `git status --short`, and **only then** commit and push the reviewed changes.
