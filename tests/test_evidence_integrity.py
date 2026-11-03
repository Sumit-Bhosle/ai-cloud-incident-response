"""Automated tests for laboratory evidence SHA-256 verification."""

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "src/evaluation/verify_evidence.py"
EVIDENCE_ROOT = ROOT / "data/lab_evidence"


class EvidenceIntegrityTests(unittest.TestCase):

    def setUp(self):
        """Create an isolated temporary test directory."""
        self.created_root = not EVIDENCE_ROOT.exists()
        EVIDENCE_ROOT.mkdir(parents=True, exist_ok=True)

        self.temp = tempfile.TemporaryDirectory(
            dir=EVIDENCE_ROOT
        )

        self.directory = Path(self.temp.name)
        self.evidence = self.directory / "sample.log"

        self.evidence.write_text(
            "LOGIN_SUCCESS test-user\n",
            encoding="utf-8"
        )

        self.original_hash = hashlib.sha256(
            self.evidence.read_bytes()
        ).hexdigest()

    def tearDown(self):
        """Delete only files created for this test."""
        self.temp.cleanup()

        if self.created_root:
            EVIDENCE_ROOT.rmdir()

    def create_manifest(self, artifacts):
        manifest = {
            "run_id": "LAB-001-RUN-001",
            "evidence_artifacts": artifacts,
        }

        path = self.directory / "manifest.json"

        path.write_text(
            json.dumps(manifest, indent=2),
            encoding="utf-8"
        )

        return path

    def valid_artifact(self):
        return {
            "source_type": "linux_audit_log",
            "file_path": str(
                self.evidence.relative_to(ROOT)
            ),
            "sha256": self.original_hash,
        }

    def run_verifier(self, manifest_path):
        return subprocess.run(
            [
                sys.executable,
                str(VERIFIER),
                str(manifest_path),
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_original_evidence_passes(self):
        manifest = self.create_manifest([
            self.valid_artifact()
        ])

        result = self.run_verifier(manifest)

        self.assertEqual(
            result.returncode, 0,
            result.stdout + result.stderr
        )
        self.assertIn(
            "EVIDENCE VERIFICATION PASSED",
            result.stdout
        )

    def test_modified_evidence_fails(self):
        manifest = self.create_manifest([
            self.valid_artifact()
        ])

        self.evidence.write_text(
            "LOGIN_FAILED test-user\n",
            encoding="utf-8"
        )

        result = self.run_verifier(manifest)

        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "SHA-256 mismatch",
            result.stdout
        )

    def test_missing_evidence_fails(self):
        manifest = self.create_manifest([
            self.valid_artifact()
        ])

        self.evidence.unlink()

        result = self.run_verifier(manifest)

        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "Evidence file missing",
            result.stdout
        )

    def test_unsafe_path_fails(self):
        artifact = self.valid_artifact()
        artifact["file_path"] = (
            "data/lab_evidence/../outside.log"
        )

        manifest = self.create_manifest([artifact])
        result = self.run_verifier(manifest)

        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "Unsafe file path",
            result.stdout
        )

    def test_empty_evidence_manifest_fails(self):
        manifest = self.create_manifest([])

        result = self.run_verifier(manifest)

        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "No evidence artifacts recorded",
            result.stdout
        )


if __name__ == "__main__":
    unittest.main()
