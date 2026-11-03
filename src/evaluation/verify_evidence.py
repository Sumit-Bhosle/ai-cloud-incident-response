"""Verify SHA-256 checksums of laboratory evidence files."""

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE_ROOT = (ROOT / "data" / "lab_evidence").resolve()


def calculate_sha256(path):
    """Calculate a file checksum without loading it all into RAM."""
    digest = hashlib.sha256()

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def verify_evidence(manifest_path):
    """Compare actual file checksums with manifest records."""
    with manifest_path.open(encoding="utf-8") as file:
        manifest = json.load(file)

    artifacts = manifest.get("evidence_artifacts")

    if not isinstance(artifacts, list) or not artifacts:
        print("VERIFICATION FAILED: No evidence artifacts recorded.")
        return 1

    failures = 0

    for index, artifact in enumerate(artifacts, start=1):
        recorded_path = artifact.get("file_path")
        expected_hash = artifact.get("sha256")

        if not isinstance(recorded_path, str) or not recorded_path:
            print(f"[FAIL] Artifact {index}: Invalid file path")
            failures += 1
            continue

        if not isinstance(expected_hash, str) or len(expected_hash) != 64:
            print(f"[FAIL] Artifact {index}: Invalid checksum")
            failures += 1
            continue

        relative_path = Path(recorded_path)

        if relative_path.is_absolute() or ".." in relative_path.parts:
            print(f"[FAIL] Artifact {index}: Unsafe file path")
            failures += 1
            continue

        evidence_path = (ROOT / relative_path).resolve()

        if not evidence_path.is_relative_to(EVIDENCE_ROOT):
            print(f"[FAIL] Artifact {index}: Outside evidence directory")
            failures += 1
            continue

        if not evidence_path.is_file():
            print(f"[FAIL] Artifact {index}: Evidence file missing")
            failures += 1
            continue

        try:
            actual_hash = calculate_sha256(evidence_path)
        except OSError as error:
            print(f"[FAIL] Artifact {index}: {error}")
            failures += 1
            continue

        if actual_hash.lower() == expected_hash.lower():
            print(f"[PASS] {recorded_path}")
        else:
            print(f"[FAIL] {recorded_path}: SHA-256 mismatch")
            failures += 1

    print()
    if failures:
        print(f"EVIDENCE VERIFICATION FAILED: {failures} issue(s)")
        return 1

    print(f"EVIDENCE VERIFICATION PASSED: {len(artifacts)} file(s)")
    return 0


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 verify_evidence.py <execution_manifest.json>")
        return 2

    try:
        return verify_evidence(Path(sys.argv[1]))
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
