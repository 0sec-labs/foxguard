from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("zero_research.py")
SPEC = importlib.util.spec_from_file_location("zero_research", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
zero_research = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(zero_research)


def summary(*, tp: int, fp: int, unsure: int = 0) -> dict:
    reviewed = tp + fp
    labeled = reviewed + unsure
    return {
        "schema_version": 1,
        "aggregate": {
            "total": labeled,
            "labeled": labeled,
            "reviewed": reviewed,
            "true_positive": tp,
            "false_positive": fp,
            "unsure": unsure,
            "reviewed_noise_rate": fp / reviewed,
        },
        "missing_labels": 0,
        "stale_labels": 0,
        "negative_control_corpus_digest": zero_research.control_corpus_digest(),
        "evaluator_digest": zero_research.control_evaluator_digest(),
    }


class ZeroResearchAdapterTests(unittest.TestCase):
    def test_builds_separate_negative_control_fragment(self) -> None:
        fragment = zero_research.build_negative_control_fragment(
            candidate_id="imp_foxguard_123",
            champion_summary=summary(tp=10, fp=10),
            challenger_summary=summary(tp=15, fp=5),
            evidence_refs=["artifact:champion.json", "artifact:challenger.json"],
        )
        self.assertEqual(
            fragment["negativeControls"]["champion"]["falsePositiveRate"], 0.5
        )
        self.assertEqual(
            fragment["negativeControls"]["challenger"]["falsePositiveRate"], 0.25
        )
        self.assertEqual(
            set(fragment["negativeControls"]["champion"]),
            {"cases", "falsePositiveRate", "inconclusiveRate"},
        )
        self.assertNotIn("heldOut", fragment)
        self.assertEqual(
            fragment["evaluatorDigestBefore"], fragment["evaluatorDigestAfter"]
        )

    def test_load_rejects_label_drift(self) -> None:
        value = summary(tp=1, fp=1)
        value["stale_labels"] = 1
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "summary.json"
            path.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, "label drift"):
                zero_research.load_summary(path)

    def test_load_rejects_unlabeled_findings(self) -> None:
        value = summary(tp=1, fp=1)
        value["aggregate"]["total"] = 3
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "summary.json"
            path.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, "every emitted finding"):
                zero_research.load_summary(path)

    def test_digest_changes_when_evaluator_changes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "corpus.toml"
            labels = root / "labels.jsonl"
            evaluator = root / "precision.py"
            manifest.write_text("corpus")
            labels.write_text("labels")
            evaluator.write_text("v1")
            corpus_digest = zero_research.control_corpus_digest(manifest, labels)
            first_evaluator_digest = zero_research.control_evaluator_digest(evaluator)
            champion = summary(tp=1, fp=1)
            challenger = summary(tp=1, fp=1)
            for value in (champion, challenger):
                value["negative_control_corpus_digest"] = corpus_digest
                value["evaluator_digest"] = first_evaluator_digest
            first = zero_research.build_negative_control_fragment(
                candidate_id="imp_foxguard_123",
                champion_summary=champion,
                challenger_summary=challenger,
                manifest_path=manifest,
                labels_path=labels,
                evaluator_path=evaluator,
                evidence_refs=["artifact:result.json"],
            )
            evaluator.write_text("v2")
            second_evaluator_digest = zero_research.control_evaluator_digest(evaluator)
            for value in (champion, challenger):
                value["evaluator_digest"] = second_evaluator_digest
            second = zero_research.build_negative_control_fragment(
                candidate_id="imp_foxguard_123",
                champion_summary=champion,
                challenger_summary=challenger,
                manifest_path=manifest,
                labels_path=labels,
                evaluator_path=evaluator,
                evidence_refs=["artifact:result.json"],
            )
            self.assertNotEqual(
                first["evaluatorDigestBefore"], second["evaluatorDigestBefore"]
            )

    def test_labels_are_attested_as_corpus_not_evaluator(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "corpus.toml"
            labels = root / "labels.jsonl"
            evaluator = root / "precision.py"
            manifest.write_text("corpus")
            labels.write_text("labels-v1")
            evaluator.write_text("evaluator")
            corpus_before = zero_research.control_corpus_digest(manifest, labels)
            evaluator_before = zero_research.control_evaluator_digest(evaluator)
            labels.write_text("labels-v2")
            self.assertNotEqual(
                corpus_before,
                zero_research.control_corpus_digest(manifest, labels),
            )
            self.assertEqual(
                evaluator_before,
                zero_research.control_evaluator_digest(evaluator),
            )

    def test_rejects_summary_from_different_evaluator(self) -> None:
        challenger = summary(tp=2, fp=1)
        challenger["evaluator_digest"] = "sha256:different"
        with self.assertRaisesRegex(ValueError, "challenger summary evaluator digest"):
            zero_research.build_negative_control_fragment(
                candidate_id="imp_foxguard_123",
                champion_summary=summary(tp=1, fp=1),
                challenger_summary=challenger,
                evidence_refs=["artifact:result.json"],
            )


if __name__ == "__main__":
    unittest.main()
