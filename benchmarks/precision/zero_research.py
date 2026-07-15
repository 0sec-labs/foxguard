#!/usr/bin/env python3
"""Project foxguard precision summaries into a 0research control result.

The labeled OSS precision corpus is a negative-control evaluator.  It must not
be conflated with the held-out vulnerable corpus used to measure research
success.  This adapter emits only the negative-control fragment that 0brain
composes into an ImprovementExperimentResult.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


PRECISION_DIR = Path(__file__).resolve().parent
DEFAULT_MANIFEST = PRECISION_DIR / "corpus.toml"
DEFAULT_LABELS = PRECISION_DIR / "labels.jsonl"
DEFAULT_EVALUATOR = PRECISION_DIR / "precision.py"


def digest_files(domain: str, paths: list[Path]) -> str:
    digest = hashlib.sha256()
    digest.update(domain.encode())
    digest.update(b"\0")
    for path in paths:
        digest.update(path.name.encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return f"sha256:{digest.hexdigest()}"


def control_corpus_digest(
    manifest_path: Path = DEFAULT_MANIFEST,
    labels_path: Path = DEFAULT_LABELS,
) -> str:
    return digest_files(
        "foxguard-negative-control-corpus-v1",
        [manifest_path, labels_path],
    )


def control_evaluator_digest(
    evaluator_path: Path = DEFAULT_EVALUATOR,
) -> str:
    return digest_files(
        "foxguard-negative-control-evaluator-v1",
        [evaluator_path, Path(__file__).resolve()],
    )


def load_summary(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ValueError(f"{path}: expected precision summary schema_version 1")
    aggregate = value.get("aggregate")
    if not isinstance(aggregate, dict):
        raise ValueError(f"{path}: aggregate must be an object")
    if value.get("missing_labels", 0) != 0 or value.get("stale_labels", 0) != 0:
        raise ValueError(f"{path}: label drift makes the control result ungradeable")
    required = (
        "total",
        "labeled",
        "reviewed",
        "true_positive",
        "false_positive",
        "unsure",
        "reviewed_noise_rate",
    )
    if any(not isinstance(aggregate.get(key), (int, float)) for key in required):
        raise ValueError(f"{path}: aggregate metrics are incomplete")
    if aggregate["total"] != aggregate["labeled"]:
        raise ValueError(f"{path}: every emitted finding must be labeled")
    if aggregate["labeled"] <= 0:
        raise ValueError(f"{path}: negative control must contain labeled findings")
    if aggregate["reviewed"] != (
        aggregate["true_positive"] + aggregate["false_positive"]
    ):
        raise ValueError(f"{path}: reviewed count is internally inconsistent")
    if aggregate["labeled"] != aggregate["reviewed"] + aggregate["unsure"]:
        raise ValueError(f"{path}: labeled count is internally inconsistent")
    noise = float(aggregate["reviewed_noise_rate"])
    if not 0 <= noise <= 1:
        raise ValueError(f"{path}: reviewed_noise_rate must be in [0, 1]")
    return value


def control_score(summary: dict[str, Any]) -> dict[str, int | float]:
    aggregate = summary["aggregate"]
    return {
        "cases": int(aggregate["labeled"]),
        "falsePositiveRate": float(aggregate["reviewed_noise_rate"]),
        "inconclusiveRate": float(aggregate["unsure"] / aggregate["labeled"]),
    }


def build_negative_control_fragment(
    *,
    candidate_id: str,
    champion_summary: dict[str, Any],
    challenger_summary: dict[str, Any],
    manifest_path: Path = DEFAULT_MANIFEST,
    labels_path: Path = DEFAULT_LABELS,
    evaluator_path: Path = DEFAULT_EVALUATOR,
    evidence_refs: list[str],
) -> dict[str, Any]:
    if not candidate_id.strip():
        raise ValueError("candidate_id must not be empty")
    if not evidence_refs or any(not ref.strip() for ref in evidence_refs):
        raise ValueError("evidence_refs must contain non-empty references")
    corpus_digest = control_corpus_digest(manifest_path, labels_path)
    evaluator_digest = control_evaluator_digest(evaluator_path)
    for label, summary in (
        ("champion", champion_summary),
        ("challenger", challenger_summary),
    ):
        if summary.get("negative_control_corpus_digest") != corpus_digest:
            raise ValueError(f"{label} summary corpus digest does not match")
        if summary.get("evaluator_digest") != evaluator_digest:
            raise ValueError(f"{label} summary evaluator digest does not match")
    return {
        "schemaVersion": 1,
        "candidateId": candidate_id,
        "negativeControlCorpusDigest": corpus_digest,
        "evaluatorDigestBefore": evaluator_digest,
        "evaluatorDigestAfter": evaluator_digest,
        "negativeControls": {
            "champion": control_score(champion_summary),
            "challenger": control_score(challenger_summary),
        },
        "evidenceRefs": evidence_refs,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Export foxguard precision comparison for 0research"
    )
    parser.add_argument("--candidate-id", required=True)
    parser.add_argument("--champion-summary", type=Path, required=True)
    parser.add_argument("--challenger-summary", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--labels", type=Path, default=DEFAULT_LABELS)
    parser.add_argument("--evaluator", type=Path, default=DEFAULT_EVALUATOR)
    parser.add_argument("--evidence-ref", action="append", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    fragment = build_negative_control_fragment(
        candidate_id=args.candidate_id,
        champion_summary=load_summary(args.champion_summary),
        challenger_summary=load_summary(args.challenger_summary),
        manifest_path=args.manifest,
        labels_path=args.labels,
        evaluator_path=args.evaluator,
        evidence_refs=args.evidence_ref,
    )
    rendered = json.dumps(fragment, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered)
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
