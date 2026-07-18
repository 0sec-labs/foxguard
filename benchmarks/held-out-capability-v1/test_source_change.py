from __future__ import annotations

import argparse
import copy
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("source_change.py")
SPEC = importlib.util.spec_from_file_location("source_change", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
change = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(change)


def command(root: Path, *args: str) -> str:
    process = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True)
    if process.returncode:
        raise RuntimeError(process.stderr)
    return process.stdout.strip()


def commit(root: Path, message: str) -> str:
    env = dict(os.environ)
    env.update({
        "GIT_AUTHOR_NAME": "test",
        "GIT_AUTHOR_EMAIL": "test@example.invalid",
        "GIT_COMMITTER_NAME": "test",
        "GIT_COMMITTER_EMAIL": "test@example.invalid",
    })
    process = subprocess.run(
        ["git", "-C", str(root), "commit", "-m", message],
        capture_output=True, text=True, env=env,
    )
    if process.returncode:
        raise RuntimeError(process.stderr)
    return command(root, "rev-parse", "HEAD")


class RepositoryFixture:
    def __init__(self, root: Path) -> None:
        self.head = root / "head"
        self.base = root / "base"
        self.head.mkdir()
        command(self.head, "init")
        command(self.head, "remote", "add", "origin", "https://github.com/0sec-labs/foxguard.git")
        (self.head / "src" / "rules").mkdir(parents=True)
        (self.head / "Cargo.toml").write_text('[package]\nname = "fixture"\nversion = "0.1.0"\n')
        (self.head / "Cargo.lock").write_text("# lock\n")
        (self.head / "src" / "rules" / "example.rs").write_text("const RULE: u8 = 1;\n")
        command(self.head, "add", ".")
        self.base_sha = commit(self.head, "base")
        (self.head / "src" / "rules" / "example.rs").write_text("const RULE: u8 = 2;\n")
        (self.head / "tests").mkdir()
        (self.head / "tests" / "example.rs").write_text("// regression\n")
        command(self.head, "add", ".")
        self.head_sha = commit(self.head, "head")
        command(self.head, "worktree", "add", "--detach", str(self.base), self.base_sha)
        self.champion = root / "champion"
        self.challenger = root / "challenger"
        self.champion.write_bytes(b"champion")
        self.challenger.write_bytes(b"challenger")
        head_identity = change.commit_identity(self.head)
        self.receipt = root / "receipt.json"
        self.receipt.write_bytes(change.canonical_bytes({
            "conclusion": "success",
            "headCommitSha": head_identity["commitSha"],
            "headTreeOid": head_identity["gitTreeOid"],
            "repository": change.REPOSITORY,
            "runId": "12345",
            "workflowRef": f"0sec-labs/foxguard/.github/workflows/ci.yml@{self.head_sha}",
        }))

    def args(self) -> argparse.Namespace:
        return argparse.Namespace(
            base_source_root=self.base,
            candidate_id="candidate-1",
            challenger_binary=self.challenger,
            champion_binary=self.champion,
            ci_receipt=self.receipt,
            head_source_root=self.head,
        )


class SourceChangeTests(unittest.TestCase):
    def test_exact_patch_reproduces_head_tree(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = RepositoryFixture(Path(directory))
            value = change.build_descriptor(fixture.args())
            change.validate_descriptor(value, repository_root=fixture.base)
            self.assertEqual(value["patch"]["changedPaths"], [
                "src/rules/example.rs", "tests/example.rs",
            ])
            self.assertEqual(value["head"]["commitSha"], fixture.head_sha)

    def test_patch_byte_change_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = RepositoryFixture(Path(directory))
            value = change.build_descriptor(fixture.args())
            value["patch"]["value"] += "AAAA"
            with self.assertRaisesRegex(ValueError, "encoding|digest"):
                change.validate_descriptor(value)

    def test_ci_receipt_must_bind_exact_head(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = RepositoryFixture(Path(directory))
            value = change.build_descriptor(fixture.args())
            value["ciReceipt"]["headCommitSha"] = fixture.base_sha
            with self.assertRaisesRegex(ValueError, "exact head"):
                change.validate_descriptor(value)

    def test_ci_receipt_must_name_exact_main_workflow_at_head(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = RepositoryFixture(Path(directory))
            value = change.build_descriptor(fixture.args())
            value["ciReceipt"]["workflowRef"] = (
                f"0sec-labs/foxguard/.github/workflows/lookalike.yml@{fixture.head_sha}"
            )
            with self.assertRaisesRegex(ValueError, "exact head"):
                change.validate_descriptor(value)

    def test_candidate_change_digest_is_recomputed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = RepositoryFixture(Path(directory))
            value = change.build_descriptor(fixture.args())
            value["candidateChangeDigest"] = f"sha256:{'0' * 64}"
            with self.assertRaisesRegex(ValueError, "not recomputable"):
                change.validate_descriptor(value)

    def test_descriptor_cannot_claim_verified_build_or_ci(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = RepositoryFixture(Path(directory))
            value = change.build_descriptor(fixture.args())
            value["provenance"]["ciVerified"] = True
            with self.assertRaisesRegex(ValueError, "must not claim"):
                change.validate_descriptor(value)

    def test_non_rule_candidate_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = RepositoryFixture(root)
            command(fixture.head, "reset", "--hard", fixture.base_sha)
            (fixture.head / "README.md").write_text("outside profile\n")
            command(fixture.head, "add", ".")
            fixture.head_sha = commit(fixture.head, "outside")
            head_identity = change.commit_identity(fixture.head)
            fixture.receipt.write_bytes(change.canonical_bytes({
                "conclusion": "success",
                "headCommitSha": head_identity["commitSha"],
                "headTreeOid": head_identity["gitTreeOid"],
                "repository": change.REPOSITORY,
                "runId": "12346",
                "workflowRef": f"0sec-labs/foxguard/.github/workflows/ci.yml@{fixture.head_sha}",
            }))
            with self.assertRaisesRegex(ValueError, "outside the first Foxguard profile"):
                change.build_descriptor(fixture.args())

    def test_symlink_rule_change_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = RepositoryFixture(root)
            command(fixture.head, "reset", "--hard", fixture.base_sha)
            (fixture.head / "src" / "rules" / "link.rs").symlink_to("../../../outside")
            command(fixture.head, "add", ".")
            fixture.head_sha = commit(fixture.head, "symlink")
            head_identity = change.commit_identity(fixture.head)
            fixture.receipt.write_bytes(change.canonical_bytes({
                "conclusion": "success",
                "headCommitSha": head_identity["commitSha"],
                "headTreeOid": head_identity["gitTreeOid"],
                "repository": change.REPOSITORY,
                "runId": "12347",
                "workflowRef": f"0sec-labs/foxguard/.github/workflows/ci.yml@{fixture.head_sha}",
            }))
            with self.assertRaisesRegex(ValueError, "regular Git blobs"):
                change.build_descriptor(fixture.args())

    def test_descriptor_reference_binds_exact_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = RepositoryFixture(root)
            output = root / "descriptor.json"
            output.write_bytes(change.canonical_bytes(change.build_descriptor(fixture.args())))
            before = change.artifact_ref(output)
            output.write_bytes(output.read_bytes() + b" ")
            self.assertNotEqual(before, change.artifact_ref(output))


if __name__ == "__main__":
    unittest.main()
