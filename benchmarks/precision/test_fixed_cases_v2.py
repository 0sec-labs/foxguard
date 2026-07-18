from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import subprocess
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("fixed_cases_v2.py")
SPEC = importlib.util.spec_from_file_location("fixed_cases_v2", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
fixed = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixed)


DIGEST = f"sha256:{'1' * 64}"


def producer() -> dict[str, str]:
    return fixed.producer_identity(commit_sha="a" * 40, tree_digest=DIGEST, binary_digest=DIGEST)


def reviewed_findings() -> list[dict]:
    labels = fixed.load_labels(fixed.DEFAULT_LABELS)
    rows = []
    for case_id in fixed.load_case_manifest(fixed.DEFAULT_CASES)["caseIds"]:
        label = labels[case_id]
        rows.append({
            "column": 1,
            "duplicate_index": 1,
            "file": label["file"],
            "id": case_id,
            "justification": label["justification"],
            "label": label["label"],
            "line": label["line"],
            "repo": label["repo"],
            "rule_id": label["rule_id"],
            "severity": "medium",
            "snippet": "fixture",
        })
    return rows


def write_findings(root: Path, name: str, rows: list[dict]) -> Path:
    path = root / name
    path.write_text(json.dumps(rows))
    return path


def build_arm(path: Path, arm_id: str = "arm") -> dict:
    identity = producer()
    findings = fixed.load_findings(path, fixed.load_labels(fixed.DEFAULT_LABELS))
    corpus = fixed.corpus_binding()
    checkouts = [
        {"id": item["id"], "commitSha": item["commitSha"], "treeDigest": DIGEST}
        for item in fixed.corpus_repositories(fixed.DEFAULT_CORPUS)
    ]
    native_reports = [
        {"id": item["id"], "semanticDigest": DIGEST}
        for item in fixed.corpus_repositories(fixed.DEFAULT_CORPUS)
    ]
    return fixed.build_arm(
        arm_id=arm_id,
        findings_path=path,
        producer=identity,
        scan_receipt=fixed.make_scan_receipt(
            findings, identity, corpus, checkouts, native_reports
        ),
    )


class FixedOssCaseTests(unittest.TestCase):
    def test_lookalike_remote_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "approved Foxguard repository"):
            fixed.validate_approved_remote(
                "https://attacker.example/0sec-labs/foxguard.git"
            )

    def test_removing_known_false_positive_lowers_rate_and_stays_gradeable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            champion_rows = reviewed_findings()
            challenger_rows = champion_rows[1:]
            champion = build_arm(write_findings(root, "champion.json", champion_rows), "champion")
            challenger = build_arm(write_findings(root, "challenger.json", challenger_rows), "challenger")
            pair = fixed.build_pair(candidate_id="candidate", champion=champion, challenger=challenger)
            self.assertEqual(pair["arms"]["champion"]["score"]["falsePositiveRate"], 1.0)
            self.assertEqual(pair["arms"]["challenger"]["score"]["falsePositiveRate"], 0.95)

    def test_same_total_with_substituted_case_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = write_findings(Path(directory), "empty.json", [])
            arm = build_arm(path)
            pair = fixed.build_pair(candidate_id="candidate", champion=arm, challenger=copy.deepcopy(arm))
            pair["arms"]["challenger"]["cases"][0]["id"] = "substituted"
            with self.assertRaisesRegex(ValueError, "exact case ids"):
                fixed.validate_pair(pair)

    def test_unknown_finding_fails_closed(self) -> None:
        row = reviewed_findings()[0]
        row["id"] = "unknown"
        with tempfile.TemporaryDirectory() as directory:
            path = write_findings(Path(directory), "unknown.json", [row])
            with self.assertRaisesRegex(ValueError, "unreviewed"):
                build_arm(path)

    def test_tampered_metric_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = write_findings(Path(directory), "empty.json", [])
            arm = build_arm(path)
            pair = fixed.build_pair(candidate_id="candidate", champion=arm, challenger=copy.deepcopy(arm))
            pair["arms"]["challenger"]["score"]["falsePositiveRate"] = 0.5
            with self.assertRaisesRegex(ValueError, "score is not recomputable"):
                fixed.validate_pair(pair)

    def test_tampered_scan_receipt_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = write_findings(Path(directory), "empty.json", [])
            arm = build_arm(path)
            pair = fixed.build_pair(candidate_id="candidate", champion=arm, challenger=copy.deepcopy(arm))
            pair["arms"]["challenger"]["scanReceipt"]["binaryDigest"] = f"sha256:{'2' * 64}"
            with self.assertRaisesRegex(ValueError, "scan receipt"):
                fixed.validate_pair(pair)

    def test_tampered_finding_identity_is_rejected_offline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            findings = write_findings(root, "findings.json", reviewed_findings()[:1])
            arm = build_arm(findings)
            pair = fixed.build_pair(candidate_id="candidate", champion=arm, challenger=copy.deepcopy(arm))
            for location in (
                pair["arms"]["challenger"]["observedFindings"][0],
                pair["arms"]["challenger"]["cases"][0]["finding"],
            ):
                location["file"] = "substituted.py"
            pair["arms"]["challenger"]["semanticReportDigest"] = fixed.digest_bytes(
                b"foxguard-semantic-findings-v2\0"
                + fixed.canonical_bytes(pair["arms"]["challenger"]["observedFindings"])
            )
            with self.assertRaisesRegex(ValueError, "reviewed identity"):
                fixed.validate_pair(pair)

    def test_case_manifest_byte_change_breaks_pair(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            findings = write_findings(root, "empty.json", [])
            arm = build_arm(findings)
            pair = fixed.build_pair(candidate_id="candidate", champion=arm, challenger=copy.deepcopy(arm))
            cases = json.loads(fixed.DEFAULT_CASES.read_text())
            cases["id"] = "changed"
            changed = root / "cases.json"
            changed.write_text(json.dumps(cases))
            with self.assertRaisesRegex(ValueError, "sealed case bytes"):
                fixed.validate_pair(pair, cases_path=changed)

    def test_semantic_order_is_canonical(self) -> None:
        rows = reviewed_findings()[:2]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = build_arm(write_findings(root, "first.json", rows))
            second = build_arm(write_findings(root, "second.json", list(reversed(rows))))
            self.assertEqual(first, second)

    def test_isolated_corpus_uses_committed_bytes_and_detects_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cache = root / "cache" / "repo"
            cache.mkdir(parents=True)
            subprocess.run(["git", "init", "-q", str(cache)], check=True)
            subprocess.run(["git", "-C", str(cache), "config", "user.email", "test@example.com"], check=True)
            subprocess.run(["git", "-C", str(cache), "config", "user.name", "Test"], check=True)
            (cache / "safe.py").write_text("committed = True\n")
            subprocess.run(["git", "-C", str(cache), "add", "safe.py"], check=True)
            subprocess.run(["git", "-C", str(cache), "commit", "-q", "-m", "fixture"], check=True)
            commit = subprocess.check_output(
                ["git", "-C", str(cache), "rev-parse", "HEAD"], text=True
            ).strip()
            remote = "https://example.com/repo.git"
            subprocess.run(["git", "-C", str(cache), "remote", "add", "origin", remote], check=True)
            (cache / "safe.py").write_text("dirty = True\n")
            corpus = root / "corpus.toml"
            corpus.write_text(
                "[[repos]]\n"
                'name = "repo"\n'
                f'url = "{remote}"\n'
                f'ref = "{commit}"\n'
                'language = "python"\n'
            )
            isolated = root / "isolated"
            attestations = fixed.materialize_corpus(
                arm_id="champion",
                cache_workdir=root / "cache",
                isolated_workdir=isolated,
                corpus_path=corpus,
                timeout_seconds=30,
            )
            self.assertEqual((isolated / "repo" / "safe.py").read_text(), "committed = True\n")
            self.assertEqual(attestations[0]["commitSha"], commit)
            (isolated / "repo" / "safe.py").write_text("mutated = True\n")
            with self.assertRaisesRegex(ValueError, "dirty"):
                fixed.require_clean_checkout(isolated / "repo", "challenger/repo")


if __name__ == "__main__":
    unittest.main()
