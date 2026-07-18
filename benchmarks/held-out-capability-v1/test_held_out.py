from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("held_out.py")
SPEC = importlib.util.spec_from_file_location("held_out", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
held = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(held)

DIGEST = f"sha256:{'1' * 64}"
SHA = "a" * 40


def finding() -> dict:
    return {
        "column": 1,
        "description": "known vulnerability",
        "file": "fixture.py",
        "line": 1,
        "ruleId": "python/known-vulnerability",
        "severity": "high",
        "snippet": "dangerous(value)",
    }


def identity() -> dict:
    return {
        "binaryDigest": DIGEST,
        "commitSha": SHA,
        "gitTreeOid": SHA,
        "repository": held.REPOSITORY,
    }


def challenger_identity() -> dict:
    value = identity()
    value["binaryDigest"] = f"sha256:{'2' * 64}"
    value["commitSha"] = "b" * 40
    value["gitTreeOid"] = "b" * 40
    return value


def native_report(fixture: Path, *, detected: bool = True) -> dict:
    value = {
        "config": {"path": "/dev/null", "source": "explicit"},
        "finding_counts": {
            "by_severity": {"critical": 0, "high": 1, "low": 0, "medium": 0},
            "total": 1,
        },
        "finding_schema_version": "1.0.0",
        "findings": [{
            "column": 1,
            "confidence": 1.0,
            "cwe": "CWE-1",
            "description": "known vulnerability",
            "end_column": 17,
            "end_line": 1,
            "file": str(fixture / "fixture.py"),
            "line": 1,
            "rule_id": "python/known-vulnerability",
            "severity": "high",
            "snippet": "dangerous(value)",
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
    if not detected:
        value["findings"] = []
        value["finding_counts"] = {
            "by_severity": {"critical": 0, "high": 0, "low": 0, "medium": 0},
            "total": 0,
        }
    return value


def write_manifest(root: Path, *, calibration: bool = False, count: int = 4) -> Path:
    cases = []
    for index in range(count):
        case_id = f"case-{index + 1}"
        fixture = root / "fixtures" / case_id
        fixture.mkdir(parents=True)
        (fixture / "fixture.py").write_text("dangerous(value)\n")
        cases.append({
            "expectedFindings": [finding()],
            "fixtureDigest": held.directory_digest(fixture),
            "id": case_id,
            "knownPositive": True,
            "oracleRef": f"sha256:{index + 1:064x}",
            "path": f"fixtures/{case_id}",
        })
    manifest = root / "manifest.json"
    manifest.write_bytes(held.canonical_bytes({
        "calibration": calibration,
        "cases": cases,
        "id": "private-held-out-v1",
        "requireSignificance": True,
        "schemaVersion": 1,
    }))
    return manifest


def artifact(manifest: Path) -> dict:
    source = held.load_manifest(manifest, require_trusted=False)
    champion_cases = []
    challenger_cases = []
    for item in source["cases"]:
        fixture = manifest.parent / item["path"]
        champion_cases.append(held.make_case(
            item,
            held.canonical_bytes(native_report(fixture, detected=False)),
            identity()["binaryDigest"],
            0,
            fixture,
        ))
        challenger_cases.append(held.make_case(
            item,
            held.canonical_bytes(native_report(fixture)),
            challenger_identity()["binaryDigest"],
            1,
            fixture,
        ))
    arms = {
        "champion": {
            "cases": champion_cases,
            "id": "champion",
            "producer": identity(),
            "score": held.score(champion_cases),
        },
        "challenger": {
            "cases": challenger_cases,
            "id": "challenger",
            "producer": challenger_identity(),
            "score": held.score(challenger_cases),
        },
    }
    return {
        "arms": arms,
        "authority": {"draftPr": False, "merge": False, "publish": False},
        "candidateId": "candidate-1",
        "contract": held.CONTRACT,
        "corpus": held.corpus_binding(manifest, require_trusted=False),
        "decision": {
            "capabilityGatePassed": not source["calibration"],
            "reason": "calibration_only" if source["calibration"] else "significant_improvement",
            "significant": True,
        },
        "evaluatorDigest": held.evaluator_digest(),
        "schemaVersion": 1,
    }


class HeldOutTests(unittest.TestCase):
    def test_four_perfect_disjoint_cases_are_significant(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = write_manifest(Path(directory))
            value = artifact(manifest)
            held.validate_artifact(value, manifest, require_trusted=False)
            self.assertTrue(value["decision"]["capabilityGatePassed"])
            self.assertGreater(
                value["arms"]["challenger"]["score"]["wilson95"][0],
                value["arms"]["champion"]["score"]["wilson95"][1],
            )

    def test_three_cases_are_rejected_before_evaluation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = write_manifest(Path(directory), count=3)
            with self.assertRaisesRegex(ValueError, "at least four"):
                held.load_manifest(manifest, require_trusted=False)

    def test_direct_non_calibration_execution_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = write_manifest(root)
            binary = root / "foxguard"
            binary.write_bytes(b"not executed")
            producer = identity()
            producer["binaryDigest"] = held.sha256_file(binary)
            with self.assertRaisesRegex(ValueError, "controller sandbox broker"):
                held.evaluate_arm(
                    arm_id="champion",
                    binary=binary,
                    producer=producer,
                    manifest_path=manifest,
                    results_dir=root / "results",
                    timeout_seconds=1,
                    require_trusted=False,
                )

    def test_calibration_corpus_can_never_promote(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = write_manifest(Path(directory), calibration=True)
            value = artifact(manifest)
            held.validate_artifact(value, manifest, require_trusted=False)
            self.assertEqual(value["decision"]["reason"], "calibration_only")
            self.assertFalse(value["decision"]["capabilityGatePassed"])

    def test_forged_aggregate_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = write_manifest(Path(directory))
            value = artifact(manifest)
            value["arms"]["challenger"]["score"]["detected"] = 3
            with self.assertRaisesRegex(ValueError, "not recomputable"):
                held.validate_artifact(value, manifest, require_trusted=False)

    def test_forged_decision_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = write_manifest(Path(directory), calibration=True)
            value = artifact(manifest)
            value["decision"]["capabilityGatePassed"] = True
            with self.assertRaisesRegex(ValueError, "decision is not recomputable"):
                held.validate_artifact(value, manifest, require_trusted=False)

    def test_capability_artifact_cannot_claim_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = write_manifest(Path(directory))
            value = artifact(manifest)
            value["authority"]["draftPr"] = True
            with self.assertRaisesRegex(ValueError, "must not carry"):
                held.validate_artifact(value, manifest, require_trusted=False)

    def test_identical_producers_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = write_manifest(Path(directory))
            value = artifact(manifest)
            value["arms"]["challenger"]["producer"] = copy.deepcopy(value["arms"]["champion"]["producer"])
            with self.assertRaisesRegex(ValueError, "producer identities must differ"):
                held.validate_artifact(value, manifest, require_trusted=False)

    def test_embedded_native_report_tamper_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = write_manifest(Path(directory))
            value = artifact(manifest)
            case = value["arms"]["challenger"]["cases"][0]
            case["nativeReport"]["value"] += "AAAA"
            with self.assertRaisesRegex(ValueError, "native report JSON"):
                held.validate_artifact(value, manifest, require_trusted=False)

    def test_arm_id_cannot_escape_results_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = write_manifest(root, calibration=True)
            binary = root / "foxguard"
            binary.write_bytes(b"not executed")
            producer = identity()
            producer["binaryDigest"] = held.sha256_file(binary)
            with self.assertRaisesRegex(ValueError, "safe identifier"):
                held.evaluate_arm(
                    arm_id="../escape",
                    binary=binary,
                    producer=producer,
                    manifest_path=manifest,
                    results_dir=root / "results",
                    timeout_seconds=1,
                    require_trusted=False,
                )

    def test_case_substitution_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = write_manifest(Path(directory))
            value = artifact(manifest)
            value["arms"]["challenger"]["cases"][0]["id"] = "substituted"
            with self.assertRaisesRegex(ValueError, "exact case ids"):
                held.validate_artifact(value, manifest, require_trusted=False)

    def test_expected_finding_change_breaks_oracle_binding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = write_manifest(Path(directory))
            value = artifact(manifest)
            source = json.loads(manifest.read_text())
            source["cases"][0]["expectedFindings"][0]["line"] = 2
            manifest.write_bytes(held.canonical_bytes(source))
            with self.assertRaisesRegex(ValueError, "local corpus"):
                held.validate_artifact(value, manifest, require_trusted=False)

    def test_default_manifest_policy_rejects_developer_owned_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = write_manifest(Path(directory))
            with self.assertRaisesRegex(ValueError, "root-owned"):
                held.load_manifest(manifest.resolve())

    def test_trusted_manifest_rejects_symlinked_parent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real = root / "real"
            real.mkdir()
            manifest = write_manifest(real)
            alias = root / "alias"
            alias.symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "canonical.*symlink"):
                held.require_private_manifest(alias / manifest.name)

    def test_artifact_reference_binds_exact_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = write_manifest(root)
            output = root / "evidence.json"
            output.write_bytes(held.canonical_bytes(artifact(manifest)))
            before = held.artifact_ref(output)
            output.write_bytes(output.read_bytes() + b" ")
            self.assertNotEqual(before, held.artifact_ref(output))

    def test_fixture_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "outside").write_text("secret")
            fixture = root / "fixture"
            fixture.mkdir()
            (fixture / "link").symlink_to(root / "outside")
            with self.assertRaisesRegex(ValueError, "must not contain symlinks"):
                held.directory_digest(fixture)

    def test_duplicate_findings_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unique"):
            held.canonical_findings([finding(), copy.deepcopy(finding())], "findings")

    def test_native_report_binds_exact_target_and_counts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "fixture"
            fixture.mkdir()
            (fixture / "fixture.py").write_text("dangerous(value)\n")
            self.assertEqual(held.normalize_native_findings(native_report(fixture), fixture), [finding()])
            wrong_target = native_report(fixture)
            wrong_target["target"]["path"] = str(fixture.parent)
            with self.assertRaisesRegex(ValueError, "target"):
                held.normalize_native_findings(wrong_target, fixture)
            wrong_count = native_report(fixture)
            wrong_count["finding_counts"]["total"] = 2
            with self.assertRaisesRegex(ValueError, "counts"):
                held.normalize_native_findings(wrong_count, fixture)

    def test_duplicate_native_findings_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "fixture"
            fixture.mkdir()
            (fixture / "fixture.py").write_text("dangerous(value)\n")
            report = native_report(fixture)
            report["findings"].append(copy.deepcopy(report["findings"][0]))
            report["finding_counts"]["total"] = 2
            report["finding_counts"]["by_severity"]["high"] = 2
            with self.assertRaisesRegex(ValueError, "duplicate"):
                held.normalize_native_findings(report, fixture)


if __name__ == "__main__":
    unittest.main()
