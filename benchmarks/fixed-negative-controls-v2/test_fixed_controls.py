from __future__ import annotations

import copy
import importlib.util
import json
import shutil
import os
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("fixed_controls.py")
SPEC = importlib.util.spec_from_file_location("fixed_controls", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
fixed = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixed)


DIGEST = f"sha256:{'1' * 64}"
SHA = "a" * 40


def identity() -> dict[str, str]:
    return {
        "repository": "0sec-labs/foxguard",
        "commitSha": SHA,
        "treeDigest": DIGEST,
        "binaryDigest": DIGEST,
    }


def artifact() -> dict:
    corpus = fixed.corpus_binding(fixed.DEFAULT_MANIFEST)
    cases = [
        {
            "falsePositive": False,
            "findings": [],
            "id": case["id"],
            "knownNegative": True,
            "verdict": "passed",
        }
        for case in corpus["cases"]
    ]
    arm = {
        "id": "variant",
        "producer": identity(),
        "cases": cases,
        "score": {"cases": len(cases), "falsePositiveRate": 0.0, "inconclusiveRate": 0},
    }
    return {
        "schemaVersion": 2,
        "contract": fixed.CONTRACT,
        "candidateId": "foxguard_candidate_1",
        "corpus": corpus,
        "evaluatorDigest": fixed.evaluator_digest(),
        "arms": {"champion": copy.deepcopy(arm), "challenger": copy.deepcopy(arm)},
    }


def finding() -> dict:
    return {
        "column": 1,
        "description": "finding",
        "file": "fixture.py",
        "line": 1,
        "ruleId": "py/example",
        "severity": "medium",
        "snippet": "value",
    }
class FixedControlTests(unittest.TestCase):
    def test_clean_exact_case_artifact_validates(self) -> None:
        self.assertEqual(fixed.validate_artifact(artifact())["schemaVersion"], 2)

    def test_case_substitution_fails_even_when_totals_match(self) -> None:
        value = artifact()
        value["arms"]["challenger"]["cases"][0]["id"] = "substituted"
        with self.assertRaisesRegex(ValueError, "exact case ids"):
            fixed.validate_artifact(value)

    def test_forged_aggregate_fails(self) -> None:
        value = artifact()
        value["arms"]["challenger"]["cases"][0]["findings"] = [finding()]
        with self.assertRaisesRegex(ValueError, "verdict is not backed"):
            fixed.validate_artifact(value)

    def test_recomputed_false_positive_rate_is_required(self) -> None:
        value = artifact()
        case = value["arms"]["challenger"]["cases"][0]
        case["findings"] = [finding()]
        case["falsePositive"] = True
        case["verdict"] = "false_positive"
        with self.assertRaisesRegex(ValueError, "score is not recomputable"):
            fixed.validate_artifact(value)

    def test_manifest_byte_change_breaks_corpus_binding(self) -> None:
        value = artifact()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            original = json.loads(fixed.DEFAULT_MANIFEST.read_text())
            original["id"] = "replacement"
            manifest.write_text(json.dumps(original))
            shutil.copytree(fixed.DEFAULT_MANIFEST.parent / "fixtures", root / "fixtures")
            with self.assertRaisesRegex(ValueError, "sealed local bytes"):
                fixed.validate_artifact(value, manifest)

    def test_wrong_producer_repository_fails(self) -> None:
        value = artifact()
        value["arms"]["champion"]["producer"]["repository"] = "attacker/repo"
        with self.assertRaisesRegex(ValueError, "not approved"):
                fixed.validate_artifact(value)

    def test_lookalike_remote_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "approved Foxguard repository"):
            fixed.validate_approved_remote(
                "https://attacker.example/0sec-labs/foxguard.git"
            )

    def test_unsafe_finding_path_fails_offline(self) -> None:
        value = artifact()
        finding = {
            "column": 1,
            "description": "forged",
            "file": "../outside.py",
            "line": 1,
            "ruleId": "py/example",
            "severity": "medium",
            "snippet": "value",
        }
        case = value["arms"]["challenger"]["cases"][0]
        case.update({"findings": [finding], "falsePositive": True, "verdict": "false_positive"})
        value["arms"]["challenger"]["score"]["falsePositiveRate"] = 0.25
        with self.assertRaisesRegex(ValueError, "path is unsafe"):
            fixed.validate_artifact(value)

    def test_artifact_reference_binds_exact_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifact.json"
            path.write_bytes(fixed.canonical_bytes(artifact()))
            before = fixed.artifact_ref(path)
            path.write_bytes(path.read_bytes() + b" ")
            self.assertNotEqual(before, fixed.artifact_ref(path))

    def test_fixture_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "outside").write_text("secret")
            (root / "fixture").mkdir()
            (root / "fixture" / "link").symlink_to(root / "outside")
            with self.assertRaisesRegex(ValueError, "must not contain symlinks"):
                fixed.directory_digest(root / "fixture")

    def test_preexisting_report_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "report.json"
            report.write_text('{"findings": []}')
            with self.assertRaisesRegex(ValueError, "pre-existing report"):
                fixed.scan_case(Path("/usr/bin/true"), root, report, 1)

    def test_exit_code_must_match_finding_presence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = root / "fixture"
            fixture.mkdir()
            (fixture / "safe.py").write_text("value = 1\n")
            report = root / "report.json"
            native = {
                "config": {"path": "/dev/null", "source": "explicit"},
                "finding_counts": {
                    "by_severity": {"critical": 0, "high": 0, "low": 0, "medium": 1},
                    "total": 1,
                },
                "finding_schema_version": "1.0.0",
                "findings": [{
                    "column": 1,
                    "confidence": 1.0,
                    "cwe": None,
                    "description": "finding",
                    "end_column": 2,
                    "end_line": 1,
                    "file": str(fixture / "safe.py"),
                    "line": 1,
                    "rule_id": "py/example",
                    "severity": "medium",
                    "snippet": "value",
                }],
                "scanner": {"command": "scan", "name": "foxguard", "version": "test"},
                "schema_version": "1.0.0",
                "target": {
                    "changed_only": False,
                    "files_scanned": 1,
                    "kind": "directory",
                    "path": str(fixture),
                },
                "timing": {"duration_ms": 1},
            }
            binary = root / "fake.py"
            binary.write_text(
                "#!/usr/bin/env python3\n"
                "import json,sys\n"
                f"value={native!r}\n"
                "open(sys.argv[-1], 'w').write(json.dumps(value))\n"
            )
            os.chmod(binary, 0o755)
            with self.assertRaisesRegex(RuntimeError, "exit code does not match"):
                fixed.scan_case(binary, fixture, report, 5)

    def test_canonical_output_is_deterministic(self) -> None:
        self.assertEqual(fixed.canonical_bytes(artifact()), fixed.canonical_bytes(artifact()))


if __name__ == "__main__":
    unittest.main()
