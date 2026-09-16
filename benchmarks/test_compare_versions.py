"""Exercise checkout ownership with real local Git repositories and Cargo builds."""

import argparse
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from . import compare_versions as compare


class WorktreeOwnershipTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="foxguard-worktree-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.pool = self.root / "pool"
        self.pool.mkdir()
        environment = patch.dict(os.environ)
        environment.start()
        self.addCleanup(environment.stop)
        os.environ.pop("CARGO_TARGET_DIR", None)
        self.git("init", "-b", "main")
        (self.repo / "Cargo.toml").write_text(
            '[package]\nname = "foxguard"\nversion = "0.0.0"\nedition = "2021"\n'
        )
        (self.repo / "src").mkdir()
        (self.repo / "src/main.rs").write_text("fn main() {}\n")
        self.git("add", "Cargo.toml", "src/main.rs")
        self.git(
            "commit", "-m", "Fixture",
            env={
                **os.environ,
                "GIT_AUTHOR_NAME": "Fixture",
                "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
                "GIT_COMMITTER_NAME": "Fixture",
                "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
            },
        )
        self.git("branch", "stable")

    def git(self, *args, **kwargs):
        return subprocess.run(
            ["git", *args], cwd=self.repo, check=True, text=True,
            capture_output=True, **kwargs,
        )

    def existing_checkout(self, name):
        checkout = self.pool / name
        self.git("worktree", "add", "--detach", str(checkout), "HEAD")
        marker = checkout / "operator-data"
        marker.write_text("preserve this checkout")
        return marker

    def test_build_preserves_existing_checkout(self):
        marker = self.existing_checkout("stable")
        binary = compare.build_ref(self.repo, "stable", self.pool)
        self.assertEqual(marker.read_text(), "preserve this checkout")
        self.assertNotEqual(binary.parents[2], marker.parent)

    def test_invalid_ref_does_not_remove_existing_checkout(self):
        marker = self.existing_checkout("missing-ref")
        with self.assertRaises(subprocess.CalledProcessError):
            compare.build_ref(self.repo, "missing-ref", self.pool)
        self.assertEqual(marker.read_text(), "preserve this checkout")

    def test_colliding_ref_names_get_separate_checkouts(self):
        self.git("branch", "feature/x")
        self.git("branch", "feature-x")
        first = compare.build_ref(self.repo, "feature/x", self.pool)
        marker = first.parents[2] / "operator-data"
        marker.write_text("first build still owned")
        second = compare.build_ref(self.repo, "feature-x", self.pool)
        self.assertNotEqual(first, second)
        self.assertEqual(marker.read_text(), "first build still owned")

    def test_cleanup_preserves_unrelated_worktree_pool(self):
        benches = self.repo / "benchmarks"
        foreign = benches / ".version-worktrees" / "foreign"
        foreign.mkdir(parents=True)
        marker = foreign / "operator-data"
        marker.write_text("unrelated data")
        (benches / "repos" / "fixture").mkdir(parents=True)
        args = argparse.Namespace(
            refs="stable", iterations=1, warmup=0,
            output="benchmarks/result.md", keep_worktrees=False,
        )
        original_run = compare.run

        def local_run(cmd, cwd=None):
            if cmd == ["git", "fetch", "--tags", "origin"]:
                return subprocess.CompletedProcess(cmd, 0, "", "")
            return original_run(cmd, cwd=cwd)

        with (
            patch.object(compare, "__file__", str(benches / "compare_versions.py")),
            patch.object(compare, "parse_args", return_value=args),
            patch.dict(compare.REPOS, {"fixture": "unused:local-fixture"}, clear=True),
            patch.object(compare, "run", side_effect=local_run),
        ):
            self.assertEqual(compare.main(), 0)
        self.assertEqual(marker.read_text(), "unrelated data")
        self.assertEqual(list(benches.glob(".version-worktrees-*")), [])


if __name__ == "__main__":
    unittest.main()
