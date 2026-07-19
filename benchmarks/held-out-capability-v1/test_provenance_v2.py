from __future__ import annotations

import base64
import copy
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import MappingProxyType
from unittest import mock


HERE = Path(__file__).resolve().parent


def load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


held = load("held_for_provenance_test", "held_out.py")
prov = load("provenance_v2_test", "provenance_v2.py")


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


def native_report(fixture: Path, detected: bool) -> bytes:
    findings = []
    if detected:
        findings = [{
            "column": 1, "confidence": 1.0, "cwe": "CWE-1",
            "description": "known vulnerability", "end_column": 17,
            "end_line": 1, "file": str(fixture / "fixture.py"), "line": 1,
            "rule_id": "python/known-vulnerability", "severity": "high",
            "snippet": "dangerous(value)",
        }]
    return held.canonical_bytes({
        "config": {"path": "/dev/null", "source": "explicit"},
        "finding_counts": {
            "by_severity": {"critical": 0, "high": len(findings), "low": 0, "medium": 0},
            "total": len(findings),
        },
        "finding_schema_version": "1.0.0",
        "findings": findings,
        "scanner": {"command": "scan", "name": "foxguard", "version": "test"},
        "schema_version": "1.0.0",
        "target": {"changed_only": False, "files_scanned": 1, "kind": "directory", "path": str(fixture)},
        "timing": {"duration_ms": 1},
    })


class Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.candidate = "candidate-1"
        self.repo = root / "repo"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "user.name", "Test Custodian"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run([
            "git", "-C", str(self.repo), "remote", "add", "origin",
            "https://github.com/0sec-labs/foxguard.git",
        ], check=True)
        (self.repo / "src" / "rules").mkdir(parents=True)
        (self.repo / "Cargo.toml").write_bytes(b"[package]\nname='foxguard'\nversion='0.0.0'\n")
        (self.repo / "Cargo.lock").write_bytes(b"version = 4\n")
        (self.repo / "src" / "rules" / "x.rs").write_bytes(b"pub const RULE: bool = false;\n")
        subprocess.run(["git", "-C", str(self.repo), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.repo), "commit", "-q", "-m", "base"], check=True)
        self.base_identity = prov.source_change.commit_identity(self.repo)
        (self.repo / "src" / "rules" / "x.rs").write_bytes(b"pub const RULE: bool = true;\n")
        subprocess.run(["git", "-C", str(self.repo), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.repo), "commit", "-q", "-m", "candidate"], check=True)
        self.head_identity = prov.source_change.commit_identity(self.repo)
        self.base_sha = self.base_identity["commitSha"]
        self.head_sha = self.head_identity["commitSha"]
        self.base_tree = self.base_identity["gitTreeOid"]
        self.head_tree = self.head_identity["gitTreeOid"]
        self.champion = self.write("champion.bin", b"champion binary")
        self.challenger = self.write("challenger.bin", b"challenger binary")
        self.oracles: dict[str, Path] = {}
        cases = []
        for index in range(4):
            case_id = f"case-{index + 1}"
            fixture = root / "corpus" / "fixtures" / case_id
            fixture.mkdir(parents=True)
            (fixture / "fixture.py").write_bytes(b"dangerous(value)\n")
            oracle = self.write(f"oracle-{case_id}.json", prov.canonical_bytes({"oracle": case_id, "verdict": "known-positive"}))
            self.oracles[case_id] = oracle
            cases.append({
                "expectedFindings": [finding()],
                "fixtureDigest": held.directory_digest(fixture),
                "id": case_id,
                "knownPositive": True,
                "oracleRef": prov.digest(oracle.read_bytes()),
                "path": f"fixtures/{case_id}",
            })
        self.manifest = root / "corpus" / "manifest.json"
        self.manifest.write_bytes(held.canonical_bytes({
            "calibration": False, "cases": cases, "id": "private-corpus",
            "requireSignificance": True, "schemaVersion": 1,
        }))
        captured = held.capture_corpus(self.manifest, require_trusted=False)
        producers = {
            "champion": {
                "binaryDigest": prov.digest(self.champion.read_bytes()),
                "commitSha": self.base_sha, "gitTreeOid": self.base_tree,
                "repository": held.REPOSITORY,
            },
            "challenger": {
                "binaryDigest": prov.digest(self.challenger.read_bytes()),
                "commitSha": self.head_sha, "gitTreeOid": self.head_tree,
                "repository": held.REPOSITORY,
            },
        }
        self.reports: dict[tuple[str, str], Path] = {}
        arms = {}
        for arm, detected in (("champion", False), ("challenger", True)):
            arm_cases = []
            for item in captured.manifest["cases"]:
                fixture = self.manifest.parent / item["path"]
                report = native_report(fixture, detected)
                report_path = self.write(f"report-{arm}-{item['id']}.json", report)
                self.reports[(arm, item["id"])] = report_path
                arm_cases.append(held.make_case(
                    item, report, producers[arm]["binaryDigest"], 1 if detected else 0, fixture,
                ))
            arms[arm] = {
                "cases": arm_cases, "id": arm, "producer": producers[arm],
                "score": held.score(arm_cases),
            }
        significant = arms["challenger"]["score"]["wilson95"][0] > arms["champion"]["score"]["wilson95"][1]
        artifact = {
            "arms": arms,
            "authority": {"draftPr": False, "merge": False, "publish": False},
            "candidateId": self.candidate,
            "contract": held.CONTRACT,
            "corpus": held.corpus_binding(captured),
            "decision": {"capabilityGatePassed": significant, "reason": "significant_improvement", "significant": significant},
            "evaluatorDigest": prov.digest(b"foxguard-held-out-capability-evaluator-v1\0" + (HERE / "held_out.py").read_bytes()),
            "schemaVersion": 1,
        }
        self.capability = self.write("capability.json", held.canonical_bytes(artifact))

        self.cargo_toml = self.repo / "Cargo.toml"
        self.cargo_lock = self.repo / "Cargo.lock"
        self.rustc = self.write("rustc.txt", b"rustc 1.test\n")
        self.cargo_version = self.write("cargo-version.txt", b"cargo 1.test\n")
        self.build_argv = self.write("build-argv.json", prov.canonical_bytes(prov.source_change.BUILD_ARGV))
        patch = prov.source_change.patch_bytes(self.repo, self.base_sha, self.head_sha)
        base = self.base_identity
        head = self.head_identity
        changes = prov.source_change.changed_entries(self.repo, self.base_sha, self.head_sha)
        basis = {"base": base, "head": head, "patchDigest": prov.digest(patch), "changedPaths": ["src/rules/x.rs"], "changes": changes}
        ci_receipt = {
            "conclusion": "success", "headCommitSha": self.head_sha,
            "headTreeOid": self.head_tree, "repository": held.REPOSITORY,
            "runId": "123", "workflowRef": f"0sec-labs/foxguard/.github/workflows/ci.yml@{self.head_sha}",
        }
        self.ci_receipt = self.write("ci-receipt.json", prov.canonical_bytes(ci_receipt))
        descriptor = {
            "base": base,
            "binaryDigests": {arm: producer["binaryDigest"] for arm, producer in producers.items()},
            "buildArgv": prov.source_change.BUILD_ARGV,
            "candidateChangeDigest": prov.digest(b"foxguard-executed-source-change-v1\0" + prov.canonical_bytes(basis)),
            "candidateId": self.candidate,
            "ciReceipt": ci_receipt,
            "contract": prov.source_change.CONTRACT,
            "head": head,
            "patch": {
                "changedPaths": ["src/rules/x.rs"], "changes": changes,
                "digest": prov.digest(patch), "encoding": "base64",
                "format": "git-binary-full-index-v1", "value": base64.b64encode(patch).decode(),
            },
            "provenance": {"buildVerified": False, "ciVerified": False},
            "repository": held.REPOSITORY,
            "schemaVersion": 1,
            "toolchain": {
                "cargoLockDigest": prov.digest(self.cargo_lock.read_bytes()),
                "cargoTomlDigest": prov.digest(self.cargo_toml.read_bytes()),
                "rustcVerboseDigest": prov.digest(self.rustc.read_bytes()),
            },
        }
        self.descriptor = self.write("descriptor.json", prov.canonical_bytes(descriptor))
        self.bundle = root / "repository.bundle"
        subprocess.run([
            "git", "-C", str(self.repo), "bundle", "create", str(self.bundle), "--all",
        ], check=True)
        self.policy = self.write("promotion-policy.json", b'{"promotion":"human-only"}\n')
        self.controller = self.write("controller.json", b'{"receipt":"retained-not-verified"}\n')
        self.key = root / "custodian"
        result = subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.key)],
            capture_output=True, check=False,
        )
        if result.returncode:
            raise RuntimeError(result.stderr.decode())
        public = (root / "custodian.pub").read_text().strip()
        self.allowed = self.write("allowed_signers", f"custodian {public}\n".encode())

    def write(self, name: str, data: bytes) -> Path:
        path = self.root / name
        path.write_bytes(data)
        return path

    def inputs(self, **overrides) -> prov.ProvenanceInputs:
        values = {
            "candidate_id": self.candidate,
            "capability_evidence": self.capability,
            "source_descriptor": self.descriptor,
            "corpus_manifest": self.manifest,
            "champion_binary": self.champion,
            "challenger_binary": self.challenger,
            "source_bundle": self.bundle,
            "oracle_receipts": self.oracles,
            "raw_reports": self.reports,
            "evaluator_files": {"held_out.py": HERE / "held_out.py", "source_change.py": HERE / "source_change.py"},
            "build_inputs": {
                "Cargo.toml": self.cargo_toml,
                "Cargo.lock": self.cargo_lock,
                "build-argv.json": self.build_argv,
                "cargo-version.txt": self.cargo_version,
                "rustc-version-verbose.txt": self.rustc,
            },
            "policy_inputs": {"evidence": self.allowed, "promotion": self.policy},
            "ci_receipt": self.ci_receipt,
            "controller_receipts": {"controller": self.controller},
        }
        values.update(overrides)
        return prov.ProvenanceInputs(**values)


class ProvenanceV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.fixture = Fixture(self.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def build(self, name: str = "package", inputs=None) -> Path:
        return prov.build_package(inputs or self.fixture.inputs(), self.root / name, self.fixture.key, "custodian")

    def resign(self, package: Path) -> None:
        root_path = package / "root.json"
        value = json.loads(root_path.read_bytes())
        entries = []
        for path in sorted((package / "payload").rglob("*")):
            if path.is_file():
                data = path.read_bytes()
                entries.append({
                    "digest": prov.digest(data),
                    "path": path.relative_to(package).as_posix(),
                    "size": len(data),
                })
        value["entries"] = entries
        value["payloadTreeDigest"] = prov.digest(
            b"foxguard-held-out-provenance-v2:payload-tree\0" + prov.canonical_bytes(entries)
        )
        material = prov.canonical_bytes(value)
        root_path.write_bytes(material)
        (package / "root.json.sig").write_bytes(prov._sign(material, self.fixture.key))

    def test_happy_path_is_private_inert_and_returns_immutable_bytes(self) -> None:
        package = self.build()
        view = prov.verify_package(package, self.fixture.allowed, "custodian")
        self.assertIsInstance(view, MappingProxyType)
        self.assertEqual(package.stat().st_mode & 0o077, 0)
        root = json.loads(view["root.json"])
        self.assertTrue(root["authority"]["privateRetentionAllowed"])
        self.assertTrue(root["authority"]["offlineAuditAllowed"])
        self.assertTrue(all(
            value is False for key, value in root["authority"].items()
            if key not in {"privateRetentionAllowed", "offlineAuditAllowed"}
        ))
        self.assertTrue(root["bindings"]["offlineSourceReplayVerified"])
        self.assertFalse(root["bindings"]["opaqueReceiptsExternallyVerified"])
        self.assertEqual(
            [item["status"] for item in root["receiptStatus"]],
            ["descriptor-bound-not-independently-verified", "opaque-not-independently-verified"],
        )
        with self.assertRaises(TypeError):
            view["new"] = b"no"  # type: ignore[index]

    def test_payload_tamper_is_rejected(self) -> None:
        package = self.build()
        (package / "payload/evidence/capability.json").write_bytes(b"{}\n")
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            prov.verify_package(package, self.fixture.allowed, "custodian")

    def test_raw_report_cross_substitution_is_rejected(self) -> None:
        reports = dict(self.fixture.reports)
        reports[("challenger", "case-1")] = reports[("champion", "case-1")]
        with self.assertRaisesRegex(ValueError, "raw report is not cross-bound"):
            self.build(inputs=self.fixture.inputs(raw_reports=reports))

    def test_oracle_substitution_is_rejected(self) -> None:
        oracles = dict(self.fixture.oracles)
        oracles["case-1"] = oracles["case-2"]
        with self.assertRaisesRegex(ValueError, "oracle receipt"):
            self.build(inputs=self.fixture.inputs(oracle_receipts=oracles))

    def test_corrupt_source_bundle_is_rejected_by_offline_git(self) -> None:
        corrupt = self.fixture.write("corrupt.bundle", b"not a Git bundle\n")
        with self.assertRaisesRegex(ValueError, "source bundle"):
            self.build(inputs=self.fixture.inputs(source_bundle=corrupt))

    def test_raw_ci_receipt_must_equal_descriptor_receipt(self) -> None:
        wrong = self.fixture.write("wrong-ci.json", prov.canonical_bytes({"conclusion": "failure"}))
        with self.assertRaisesRegex(ValueError, "raw CI receipt"):
            self.build(inputs=self.fixture.inputs(ci_receipt=wrong))

    def test_exact_build_input_set_is_required(self) -> None:
        build_inputs = dict(self.fixture.inputs().build_inputs)
        del build_inputs["cargo-version.txt"]
        with self.assertRaisesRegex(ValueError, "build inputs are incomplete"):
            self.build(inputs=self.fixture.inputs(build_inputs=build_inputs))

    def test_resigned_package_cannot_omit_build_preimages(self) -> None:
        package = self.build()
        (package / "payload/build/cargo-version.txt").unlink()
        self.resign(package)
        with self.assertRaisesRegex(ValueError, "build inputs are incomplete"):
            prov.verify_package(package, self.fixture.allowed, "custodian")

    def test_resigned_package_cannot_substitute_source_evaluator(self) -> None:
        package = self.build()
        (package / "payload/evaluators/source_change.py").write_bytes(b"# substituted\n")
        self.resign(package)
        with self.assertRaisesRegex(ValueError, "trusted local verifier"):
            prov.verify_package(package, self.fixture.allowed, "custodian")

    def test_resigned_package_cannot_substitute_cargo_input(self) -> None:
        package = self.build()
        (package / "payload/build/Cargo.toml").write_bytes(b"[package]\nname='other'\n")
        self.resign(package)
        with self.assertRaisesRegex(ValueError, "build inputs do not match"):
            prov.verify_package(package, self.fixture.allowed, "custodian")

    def test_git_object_inventory_limit_is_preflighted(self) -> None:
        descriptor = json.loads(self.fixture.descriptor.read_bytes())

        def oversized(_repository: Path, _home: Path, output: Path) -> None:
            output.write_bytes(
                f"{'a' * 40} blob {prov.MAX_TOTAL_BYTES + 1} 1\n".encode()
            )

        with mock.patch.object(prov, "_git_object_inventory", side_effect=oversized):
            with self.assertRaisesRegex(ValueError, "inventory exceeds replay limits"):
                prov._verify_source_bundle(self.fixture.bundle.read_bytes(), descriptor)

    def test_pack_count_limit_is_rejected_before_git_runs(self) -> None:
        bundle = bytearray(self.fixture.bundle.read_bytes())
        pack = bundle.index(b"PACK")
        bundle[pack + 8:pack + 12] = (100_001).to_bytes(4, "big")
        descriptor = json.loads(self.fixture.descriptor.read_bytes())
        with mock.patch.object(prov, "_run_git") as run_git:
            with self.assertRaisesRegex(ValueError, "pack header exceeds replay limits"):
                prov._verify_source_bundle(bytes(bundle), descriptor)
        run_git.assert_not_called()

    def test_replay_ignores_inherited_git_environment(self) -> None:
        descriptor = json.loads(self.fixture.descriptor.read_bytes())
        injected = {
            "PATH": str(self.root / "no-such-path"),
            "GIT_OBJECT_DIRECTORY": str(self.root / "foreign-objects"),
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(self.root / "foreign-alternates"),
            "GIT_CONFIG_GLOBAL": str(self.root / "foreign-config"),
        }
        with mock.patch.dict(os.environ, injected, clear=False):
            prov._verify_source_bundle(self.fixture.bundle.read_bytes(), descriptor)

    def test_failed_prepublish_verification_leaves_no_destination(self) -> None:
        output = self.root / "failed-package"
        with mock.patch.object(prov, "verify_package", side_effect=ValueError("injected verification failure")):
            with self.assertRaisesRegex(ValueError, "injected verification failure"):
                prov.build_package(self.fixture.inputs(), output, self.fixture.key, "custodian")
        self.assertFalse(output.exists())

    def test_wrong_external_policy_is_rejected(self) -> None:
        package = self.build()
        other = self.root / "other"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(other)], check=True)
        wrong = self.fixture.write("wrong_allowed", f"custodian {(self.root / 'other.pub').read_text().strip()}\n".encode())
        with self.assertRaisesRegex(ValueError, "does not exactly match"):
            prov.verify_package(package, wrong, "custodian")

    def test_no_overwrite(self) -> None:
        package = self.build()
        marker = package / "root.json"
        before = marker.read_bytes()
        with self.assertRaises(FileExistsError):
            self.build()
        self.assertEqual(marker.read_bytes(), before)

    def test_aggregate_limit_is_enforced(self) -> None:
        with mock.patch.object(prov, "MAX_TOTAL_BYTES", 64):
            with self.assertRaisesRegex(ValueError, "aggregate"):
                self.build()

    def test_verified_view_is_a_captured_snapshot(self) -> None:
        package = self.build()
        view = prov.verify_package(package, self.fixture.allowed, "custodian")
        before = view["payload/policies/promotion.policy"]
        (package / "payload/policies/promotion.policy").write_bytes(b"changed\n")
        self.assertEqual(view["payload/policies/promotion.policy"], before)

    def test_payload_hardlink_is_rejected(self) -> None:
        package = self.build()
        source = package / "payload/policies/promotion.policy"
        source.unlink()
        source.hardlink_to(package / "payload/policies/evidence.policy")
        with self.assertRaisesRegex(ValueError, "single-link"):
            prov.verify_package(package, self.fixture.allowed, "custodian")

    def test_signed_but_semantically_forged_decision_is_rejected(self) -> None:
        package = self.build()
        capability_path = package / "payload/evidence/capability.json"
        capability = json.loads(capability_path.read_bytes())
        capability["decision"]["capabilityGatePassed"] = False
        forged = prov.canonical_bytes(capability)
        capability_path.write_bytes(forged)
        root_path = package / "root.json"
        root = json.loads(root_path.read_bytes())
        for record in root["entries"]:
            if record["path"] == "payload/evidence/capability.json":
                record["digest"] = prov.digest(forged)
                record["size"] = len(forged)
        root["bindings"]["capabilityEvidenceDigest"] = prov.digest(forged)
        root["payloadTreeDigest"] = prov.digest(
            b"foxguard-held-out-provenance-v2:payload-tree\0" + prov.canonical_bytes(root["entries"])
        )
        material = prov.canonical_bytes(root)
        root_path.write_bytes(material)
        (package / "root.json.sig").write_bytes(prov._sign(material, self.fixture.key))
        with self.assertRaisesRegex(ValueError, "decision is not recomputable"):
            prov.verify_package(package, self.fixture.allowed, "custodian")

    def test_resigned_authority_escalation_is_still_rejected(self) -> None:
        package = self.build()
        root_path = package / "root.json"
        value = json.loads(root_path.read_bytes())
        value["authority"]["executionAllowed"] = True
        material = prov.canonical_bytes(value)
        root_path.write_bytes(material)
        signature = prov._sign(material, self.fixture.key)
        (package / "root.json.sig").write_bytes(signature)
        with self.assertRaisesRegex(ValueError, "authority"):
            prov.verify_package(package, self.fixture.allowed, "custodian")


if __name__ == "__main__":
    unittest.main()
