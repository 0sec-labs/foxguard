#!/usr/bin/env python3
"""Project the reviewed OSS false positives as exact fixed cases.

Unlike the legacy aggregate adapter, a selected case exists whether or not a
scanner emits its old finding. Absence is therefore a passing negative control.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import resource
import signal
import stat
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
DEFAULT_CASES = ROOT / "negative-controls-v2.json"
DEFAULT_LABELS = ROOT / "labels.jsonl"
DEFAULT_CORPUS = ROOT / "corpus.toml"
DEFAULT_EVALUATOR = ROOT / "precision.py"
REPOSITORY = "0sec-labs/foxguard"
CONTRACT = "foxguard-reviewed-negative-controls-v2"
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
MAX_FINDINGS_BYTES = 16 * 1024 * 1024
MAX_RAW_REPORT_BYTES = 16 * 1024 * 1024
MAX_RAW_FINDINGS = 20_000
MAX_WRAPPER_FILE_BYTES = 32 * 1024 * 1024
APPROVED_REMOTES = {
    "https://github.com/0sec-labs/foxguard",
    "https://github.com/0sec-labs/foxguard.git",
    "git@github.com:0sec-labs/foxguard",
    "git@github.com:0sec-labs/foxguard.git",
    "ssh://git@github.com/0sec-labs/foxguard",
    "ssh://git@github.com/0sec-labs/foxguard.git",
}
FINDING_KEYS = {
    "column", "duplicate_index", "file", "id", "justification", "label",
    "line", "repo", "rule_id", "severity", "snippet",
}


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def digest_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def digest_file(path: Path) -> str:
    return digest_bytes(path.read_bytes())


def load_json_object(path: Path, label: str) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def load_labels(path: Path) -> dict[str, dict[str, Any]]:
    labels: dict[str, dict[str, Any]] = {}
    required = {"file", "id", "justification", "label", "line", "repo", "rule_id"}
    for line_number, line in enumerate(path.read_text().splitlines(), start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        value = json.loads(line)
        if not isinstance(value, dict) or set(value) != required:
            raise ValueError(f"labels row {line_number} has unsupported or missing fields")
        case_id = value["id"]
        if (
            not isinstance(case_id, str)
            or not SAFE_ID_RE.fullmatch(case_id)
            or case_id in labels
        ):
            raise ValueError(f"labels row {line_number} has an invalid or duplicate id")
        if value["label"] not in {"true_positive", "false_positive", "unsure"}:
            raise ValueError(f"labels row {line_number} has an invalid label")
        if isinstance(value["line"], bool) or not isinstance(value["line"], int) or value["line"] < 1:
            raise ValueError(f"labels row {line_number} has an invalid line")
        for key in required - {"line"}:
            if not isinstance(value[key], str) or not value[key].strip():
                raise ValueError(f"labels row {line_number} has an invalid {key}")
        labels[case_id] = value
    return labels


def load_case_manifest(path: Path) -> dict[str, Any]:
    value = load_json_object(path, "case manifest")
    if set(value) != {"caseIds", "id", "schemaVersion"} or value.get("schemaVersion") != 2:
        raise ValueError("case manifest schema has unsupported or missing fields")
    ids = value.get("caseIds")
    if not isinstance(value.get("id"), str) or not SAFE_ID_RE.fullmatch(value["id"]):
        raise ValueError("case manifest id must be a safe identifier")
    if (
        not isinstance(ids, list)
        or not ids
        or any(not isinstance(item, str) or not SAFE_ID_RE.fullmatch(item) for item in ids)
    ):
        raise ValueError("case manifest caseIds must be safe identifiers")
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise ValueError("case manifest caseIds must be unique and sorted")
    return value


def corpus_binding(
    cases_path: Path = DEFAULT_CASES,
    labels_path: Path = DEFAULT_LABELS,
    corpus_path: Path = DEFAULT_CORPUS,
) -> dict[str, Any]:
    manifest = load_case_manifest(cases_path)
    labels = load_labels(labels_path)
    definitions = []
    for case_id in manifest["caseIds"]:
        if case_id not in labels:
            raise ValueError(f"fixed case {case_id} is missing its reviewed label")
        definition = labels[case_id]
        if definition["label"] != "false_positive":
            raise ValueError(f"fixed case {case_id} is not a reviewed false positive")
        definitions.append(dict(definition))
    base = {
        "id": manifest["id"],
        "caseIds": list(manifest["caseIds"]),
        "caseDefinitions": definitions,
        "caseManifestDigest": digest_file(cases_path),
        "reviewedLabelsDigest": digest_file(labels_path),
        "precisionCorpusDigest": digest_file(corpus_path),
    }
    return {
        **base,
        "digest": digest_bytes(b"foxguard-reviewed-negative-corpus-v2\0" + canonical_bytes(base)),
    }


def evaluator_digest(
    projector_path: Path | None = None,
    evaluator_path: Path = DEFAULT_EVALUATOR,
) -> str:
    projector = projector_path or Path(__file__).resolve()
    return digest_bytes(
        b"foxguard-reviewed-negative-evaluator-v2\0"
        + evaluator_path.read_bytes() + b"\0" + projector.read_bytes()
    )


def producer_identity(
    *, commit_sha: str, tree_digest: str, binary_digest: str,
) -> dict[str, str]:
    value = {
        "repository": REPOSITORY,
        "commitSha": commit_sha,
        "treeDigest": tree_digest,
        "binaryDigest": binary_digest,
    }
    return validate_producer(value)


def run_git(root: Path, *args: str) -> bytes:
    process = subprocess.run(
        ["git", "-C", str(root.resolve()), *args], capture_output=True
    )  # noqa: S603
    if process.returncode != 0:
        raise ValueError(
            f"git {' '.join(args)} failed for {root}: "
            f"{process.stderr.decode(errors='replace').strip()}"
        )
    return process.stdout


def source_tree_digest(root: Path) -> str:
    names = run_git(
        root, "ls-files", "--cached", "--others", "--exclude-standard", "-z"
    ).split(b"\0")
    digest = hashlib.sha256()
    digest.update(b"foxguard-source-tree-v1\0")
    for raw_name in sorted(name for name in names if name):
        name = raw_name.decode("utf-8", errors="strict")
        path = root / name
        if path.is_symlink():
            data = path.readlink().as_posix().encode()
        elif path.is_file():
            data = path.read_bytes()
        else:
            raise ValueError(f"tracked source path is not a file: {name}")
        digest.update(len(raw_name).to_bytes(8, "big"))
        digest.update(raw_name)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return f"sha256:{digest.hexdigest()}"


def checkout_content_digest(root: Path) -> str:
    digest = hashlib.sha256()
    digest.update(b"foxguard-corpus-checkout-v1\0")
    paths = sorted(
        (path for path in root.rglob("*") if ".git" not in path.relative_to(root).parts),
        key=lambda path: path.relative_to(root).as_posix(),
    )
    for path in paths:
        relative = path.relative_to(root).as_posix().encode()
        if path.is_symlink():
            data = path.readlink().as_posix().encode()
        elif path.is_file():
            data = path.read_bytes()
        else:
            continue
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return f"sha256:{digest.hexdigest()}"


def corpus_repositories(corpus_path: Path) -> list[dict[str, str]]:
    with corpus_path.open("rb") as handle:
        value = tomllib.load(handle)
    repositories = []
    for index, item in enumerate(value.get("repos", [])):
        if not isinstance(item, dict):
            raise ValueError(f"corpus repo {index} must be an object")
        name, url, commit = item.get("name"), item.get("url"), item.get("ref")
        scan_subdir = item.get("scan_subdir", ".")
        if (
            not isinstance(name, str)
            or not SAFE_ID_RE.fullmatch(name)
            or not isinstance(url, str)
            or not url.startswith("https://")
            or not isinstance(commit, str)
            or not SHA_RE.fullmatch(commit)
            or not isinstance(scan_subdir, str)
            or Path(scan_subdir).is_absolute()
            or ".." in Path(scan_subdir).parts
        ):
            raise ValueError(f"corpus repo {index} identity is invalid")
        repositories.append({
            "id": name, "url": url, "commitSha": commit,
            "scanSubdir": scan_subdir,
        })
    if not repositories or len({item["id"] for item in repositories}) != len(repositories):
        raise ValueError("corpus repositories must be non-empty and unique")
    return sorted(repositories, key=lambda item: item["id"])


def require_clean_checkout(root: Path, label: str) -> None:
    status = run_git(root, "status", "--porcelain=v1", "--untracked-files=all")
    if status:
        raise ValueError(f"{label} corpus checkout is dirty")


def materialize_corpus(
    *, arm_id: str, cache_workdir: Path, isolated_workdir: Path,
    corpus_path: Path, timeout_seconds: int,
) -> list[dict[str, str]]:
    if isolated_workdir.exists():
        raise ValueError(f"isolated corpus directory already exists: {isolated_workdir}")
    isolated_workdir.mkdir(parents=True)
    attestations = []
    for repository in corpus_repositories(corpus_path):
        source = cache_workdir / repository["id"]
        target = isolated_workdir / repository["id"]
        if not (source / ".git").exists():
            raise ValueError(f"missing cached corpus repository: {source}")
        remote = run_git(source, "remote", "get-url", "origin").decode().strip()
        if remote.removesuffix(".git") != repository["url"].removesuffix(".git"):
            raise ValueError(f"cached corpus remote does not match for {repository['id']}")
        process = subprocess.run(  # noqa: S603
            ["git", "clone", "--shared", "--no-checkout", str(source.resolve()), str(target)],
            capture_output=True, text=True, timeout=timeout_seconds,
        )
        if process.returncode != 0:
            raise ValueError(
                f"failed to isolate {arm_id} corpus repo {repository['id']}: "
                f"{process.stderr.strip()}"
            )
        run_git(target, "checkout", "--detach", repository["commitSha"])
        actual = run_git(target, "rev-parse", "HEAD").decode().strip()
        if actual != repository["commitSha"]:
            raise ValueError(f"isolated corpus commit does not match for {repository['id']}")
        require_clean_checkout(target, f"{arm_id}/{repository['id']}")
        attestations.append({
            "id": repository["id"],
            "commitSha": actual,
            "treeDigest": checkout_content_digest(target),
        })
    return attestations


def validate_checkout_attestations(
    value: Any, corpus_path: Path,
) -> list[dict[str, str]]:
    repositories = corpus_repositories(corpus_path)
    if not isinstance(value, list) or len(value) != len(repositories):
        raise ValueError("scan receipt corpus checkout coverage does not match")
    normalized = []
    for index, (item, repository) in enumerate(zip(value, repositories, strict=True)):
        if not isinstance(item, dict) or set(item) != {"commitSha", "id", "treeDigest"}:
            raise ValueError(f"scan receipt corpus checkout {index} is invalid")
        if (
            item["id"] != repository["id"]
            or item["commitSha"] != repository["commitSha"]
            or not isinstance(item["treeDigest"], str)
            or not DIGEST_RE.fullmatch(item["treeDigest"])
        ):
            raise ValueError(f"scan receipt corpus checkout {index} does not match manifest")
        normalized.append(dict(item))
    return normalized


def validate_native_finding(value: Any, label: str, repository_root: Path) -> dict[str, Any]:
    required = {
        "column", "confidence", "cwe", "description", "end_column", "end_line",
        "file", "line", "rule_id", "severity", "snippet",
    }
    if not isinstance(value, dict) or not required.issubset(value):
        raise ValueError(f"{label} does not satisfy finding schema v1")
    for key in ("line", "column", "end_line", "end_column"):
        if isinstance(value[key], bool) or not isinstance(value[key], int) or value[key] < 1:
            raise ValueError(f"{label}.{key} is invalid")
    confidence = value["confidence"]
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
        raise ValueError(f"{label}.confidence is invalid")
    if value["severity"] not in {"low", "medium", "high", "critical"}:
        raise ValueError(f"{label}.severity is invalid")
    if value["cwe"] is not None and not isinstance(value["cwe"], str):
        raise ValueError(f"{label}.cwe is invalid")
    for key in ("file", "rule_id", "description", "snippet"):
        if not isinstance(value[key], str):
            raise ValueError(f"{label}.{key} is invalid")
    path = Path(value["file"])
    try:
        relative = path.resolve().relative_to(repository_root.resolve()).as_posix()
    except ValueError as exc:
        raise ValueError(f"{label}.file escapes the pinned repository") from exc
    semantic = dict(value)
    semantic["file"] = relative
    return semantic


def validate_native_report(
    path: Path, repository: dict[str, str], repository_root: Path,
) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"missing regular native report for {repository['id']}")
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_RAW_REPORT_BYTES:
        raise ValueError(f"native report for {repository['id']} exceeds the size limit")
    report = load_json_object(path, f"native report {repository['id']}")
    required = {
        "config", "finding_counts", "finding_schema_version", "findings",
        "scanner", "schema_version", "target", "timing",
    }
    if not required.issubset(report):
        raise ValueError(f"native report {repository['id']} is missing envelope fields")
    if report["schema_version"] != "1.0.0" or report["finding_schema_version"] != "1.0.0":
        raise ValueError(f"native report {repository['id']} schema is unsupported")
    if report["config"] != {"path": "/dev/null", "source": "explicit"}:
        raise ValueError(f"native report {repository['id']} config does not match")
    scanner = report["scanner"]
    if (
        not isinstance(scanner, dict)
        or scanner.get("name") != "foxguard"
        or scanner.get("command") != "scan"
        or not isinstance(scanner.get("version"), str)
        or not scanner["version"]
    ):
        raise ValueError(f"native report {repository['id']} scanner identity is invalid")
    target = report["target"]
    expected_target = (repository_root / repository["scanSubdir"]).resolve()
    if (
        not isinstance(target, dict)
        or target.get("kind") != "directory"
        or target.get("changed_only") is not False
        or isinstance(target.get("files_scanned"), bool)
        or not isinstance(target.get("files_scanned"), int)
        or target["files_scanned"] < 1
        or Path(str(target.get("path", ""))).resolve() != expected_target
    ):
        raise ValueError(f"native report {repository['id']} target does not match")
    raw_findings = report["findings"]
    if not isinstance(raw_findings, list) or len(raw_findings) > MAX_RAW_FINDINGS:
        raise ValueError(f"native report {repository['id']} findings are invalid")
    findings = [
        validate_native_finding(value, f"{repository['id']}.findings[{index}]", repository_root)
        for index, value in enumerate(raw_findings)
    ]
    counts = report["finding_counts"]
    severities = ("critical", "high", "low", "medium")
    expected_by_severity = {
        severity: sum(finding["severity"] == severity for finding in findings)
        for severity in severities
    }
    if (
        not isinstance(counts, dict)
        or counts.get("total") != len(findings)
        or counts.get("by_severity") != expected_by_severity
    ):
        raise ValueError(f"native report {repository['id']} counts do not match findings")
    semantic = {
        "findingSchemaVersion": report["finding_schema_version"],
        "findings": findings,
        "scannerVersion": scanner["version"],
        "schemaVersion": report["schema_version"],
    }
    return {
        "id": repository["id"],
        "semanticDigest": digest_bytes(
            b"foxguard-native-report-v1\0" + canonical_bytes(semantic)
        ),
    }


def validate_native_report_attestations(value: Any, corpus_path: Path) -> list[dict[str, str]]:
    repositories = corpus_repositories(corpus_path)
    if not isinstance(value, list) or len(value) != len(repositories):
        raise ValueError("scan receipt native report coverage does not match")
    normalized = []
    for index, (item, repository) in enumerate(zip(value, repositories, strict=True)):
        if (
            not isinstance(item, dict)
            or set(item) != {"id", "semanticDigest"}
            or item["id"] != repository["id"]
            or not isinstance(item["semanticDigest"], str)
            or not DIGEST_RE.fullmatch(item["semanticDigest"])
        ):
            raise ValueError(f"scan receipt native report {index} is invalid")
        normalized.append(dict(item))
    return normalized


def producer_from_paths(source_root: Path, binary: Path) -> dict[str, str]:
    remote = run_git(source_root, "remote", "get-url", "origin").decode().strip()
    validate_approved_remote(remote)
    return producer_identity(
        commit_sha=run_git(source_root, "rev-parse", "HEAD").decode().strip(),
        tree_digest=source_tree_digest(source_root),
        binary_digest=digest_file(binary),
    )


def validate_approved_remote(remote: str) -> None:
    if remote not in APPROVED_REMOTES:
        raise ValueError("producer source root is not the approved Foxguard repository")


def validate_producer(value: Any) -> dict[str, str]:
    expected = {"repository", "commitSha", "treeDigest", "binaryDigest"}
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError("producer has unsupported or missing fields")
    if value["repository"] != REPOSITORY:
        raise ValueError("producer repository is not approved")
    if not isinstance(value["commitSha"], str) or not SHA_RE.fullmatch(value["commitSha"]):
        raise ValueError("producer commitSha must be a full lowercase SHA")
    for key in ("treeDigest", "binaryDigest"):
        if not isinstance(value[key], str) or not DIGEST_RE.fullmatch(value[key]):
            raise ValueError(f"producer {key} must be a sha256 digest")
    return dict(value)


def normalize_finding(value: Any, index: int) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != FINDING_KEYS:
        raise ValueError(f"finding {index} has unsupported or missing fields")
    for key in ("line", "column", "duplicate_index"):
        if isinstance(value[key], bool) or not isinstance(value[key], int) or value[key] < 0:
            raise ValueError(f"finding {index} has invalid {key}")
    for key in FINDING_KEYS - {"line", "column", "duplicate_index"}:
        if value[key] is not None and not isinstance(value[key], str):
            raise ValueError(f"finding {index} has invalid {key}")
    if not value["id"]:
        raise ValueError(f"finding {index} id must not be empty")
    return dict(value)


def load_findings(path: Path, labels: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    value = json.loads(path.read_text())
    if not isinstance(value, list):
        raise ValueError("findings artifact must be an array")
    findings = [normalize_finding(item, index) for index, item in enumerate(value)]
    findings.sort(key=lambda item: item["id"])
    ids = [item["id"] for item in findings]
    if len(ids) != len(set(ids)):
        raise ValueError("findings artifact contains duplicate ids")
    validate_finding_labels(findings, labels)
    return findings


def validate_finding_labels(
    findings: list[dict[str, Any]], labels: dict[str, dict[str, Any]]
) -> None:
    for finding in findings:
        label = labels.get(finding["id"])
        if label is None:
            raise ValueError(f"unknown emitted finding {finding['id']} is unreviewed")
        for source, target in (("repo", "repo"), ("rule_id", "rule_id"), ("file", "file"), ("line", "line")):
            if finding[source] != label[target]:
                raise ValueError(f"finding {finding['id']} does not match its reviewed identity")
        if finding["label"] != label["label"] or finding["justification"] != label["justification"]:
            raise ValueError(f"finding {finding['id']} label evidence does not match")


def score(cases: list[dict[str, Any]]) -> dict[str, int | float]:
    count = len(cases)
    false_positives = sum(case["falsePositive"] for case in cases)
    return {
        "cases": count,
        "falsePositives": false_positives,
        "inconclusive": 0,
        "falsePositiveRate": false_positives / count,
        "inconclusiveRate": 0,
    }


def make_scan_receipt(
    findings: list[dict[str, Any]], producer: dict[str, str], corpus: dict[str, Any],
    corpus_checkouts: list[dict[str, str]],
    native_reports: list[dict[str, str]],
    evaluator_path: Path = DEFAULT_EVALUATOR,
) -> dict[str, Any]:
    return {
        "binaryDigest": producer["binaryDigest"],
        "commitSha": producer["commitSha"],
        "corpusDigest": corpus["digest"],
        "corpusCheckouts": corpus_checkouts,
        "evaluatorDigest": evaluator_digest(),
        "exitCode": 0,
        "findingsDigest": digest_bytes(
            b"foxguard-precision-findings-v2\0" + canonical_bytes(findings)
        ),
        "nativeReports": native_reports,
        "runner": "benchmarks/precision/precision.py",
        "runnerDigest": digest_file(evaluator_path),
        "treeDigest": producer["treeDigest"],
    }


def build_arm(
    *, arm_id: str, findings_path: Path, producer: dict[str, str],
    scan_receipt: dict[str, Any],
    cases_path: Path = DEFAULT_CASES, labels_path: Path = DEFAULT_LABELS,
    corpus_path: Path = DEFAULT_CORPUS,
) -> dict[str, Any]:
    if not SAFE_ID_RE.fullmatch(arm_id):
        raise ValueError("arm id must be a safe identifier")
    corpus = corpus_binding(cases_path, labels_path, corpus_path)
    labels = load_labels(labels_path)
    findings = load_findings(findings_path, labels)
    by_id = {finding["id"]: finding for finding in findings}
    cases = []
    for case_id in corpus["caseIds"]:
        finding = by_id.get(case_id)
        cases.append({
            "falsePositive": finding is not None,
            "finding": finding,
            "id": case_id,
            "knownNegative": True,
            "verdict": "false_positive" if finding is not None else "passed",
        })
    checkouts = validate_checkout_attestations(scan_receipt.get("corpusCheckouts"), corpus_path)
    native_reports = validate_native_report_attestations(
        scan_receipt.get("nativeReports"), corpus_path
    )
    expected_receipt = make_scan_receipt(
        findings, producer, corpus, checkouts, native_reports
    )
    if scan_receipt != expected_receipt:
        raise ValueError("scan receipt does not bind the executed runner, binary, and findings")
    return {
        "id": arm_id,
        "producer": validate_producer(producer),
        "observedFindings": findings,
        "semanticReportDigest": digest_bytes(
            b"foxguard-semantic-findings-v2\0" + canonical_bytes(findings)
        ),
        "scanReceipt": scan_receipt,
        "cases": cases,
        "score": score(cases),
    }


def validate_arm(
    arm: Any, corpus: dict[str, Any], labels: dict[str, dict[str, Any]],
    corpus_path: Path, label: str,
) -> None:
    expected = {
        "cases", "id", "observedFindings", "producer", "scanReceipt", "score",
        "semanticReportDigest",
    }
    if not isinstance(arm, dict) or set(arm) != expected:
        raise ValueError(f"{label} arm has unsupported or missing fields")
    if not isinstance(arm["id"], str) or not SAFE_ID_RE.fullmatch(arm["id"]):
        raise ValueError(f"{label} arm id must be a safe identifier")
    producer = validate_producer(arm["producer"])
    findings = [normalize_finding(item, index) for index, item in enumerate(arm["observedFindings"])]
    if findings != sorted(findings, key=lambda item: item["id"]):
        raise ValueError(f"{label} observed findings must be sorted")
    ids = [finding["id"] for finding in findings]
    if len(ids) != len(set(ids)) or any(case_id not in labels for case_id in ids):
        raise ValueError(f"{label} observed findings are duplicate or unreviewed")
    validate_finding_labels(findings, labels)
    receipt = arm["scanReceipt"]
    if not isinstance(receipt, dict):
        raise ValueError(f"{label} scan receipt must be an object")
    checkouts = validate_checkout_attestations(receipt.get("corpusCheckouts"), corpus_path)
    native_reports = validate_native_report_attestations(
        receipt.get("nativeReports"), corpus_path
    )
    if receipt != make_scan_receipt(
        findings, producer, corpus, checkouts, native_reports
    ):
        raise ValueError(f"{label} scan receipt does not bind runner, binary, and findings")
    semantic_digest = digest_bytes(b"foxguard-semantic-findings-v2\0" + canonical_bytes(findings))
    if arm["semanticReportDigest"] != semantic_digest:
        raise ValueError(f"{label} semantic report digest does not match findings")
    cases = arm["cases"]
    if not isinstance(cases, list) or [case.get("id") for case in cases if isinstance(case, dict)] != corpus["caseIds"]:
        raise ValueError(f"{label} exact case ids do not match")
    by_id = {finding["id"]: finding for finding in findings}
    for index, case in enumerate(cases):
        if set(case) != {"falsePositive", "finding", "id", "knownNegative", "verdict"}:
            raise ValueError(f"{label} case {index} has unsupported or missing fields")
        expected_finding = by_id.get(case["id"])
        expected_fp = expected_finding is not None
        if (
            case["knownNegative"] is not True
            or case["finding"] != expected_finding
            or case["falsePositive"] is not expected_fp
            or case["verdict"] != ("false_positive" if expected_fp else "passed")
        ):
            raise ValueError(f"{label} case {index} is not backed by exact findings")
    if arm["score"] != score(cases):
        raise ValueError(f"{label} score is not recomputable")


def build_pair(
    *, candidate_id: str, champion: dict[str, Any], challenger: dict[str, Any],
    cases_path: Path = DEFAULT_CASES, labels_path: Path = DEFAULT_LABELS,
    corpus_path: Path = DEFAULT_CORPUS,
) -> dict[str, Any]:
    if not SAFE_ID_RE.fullmatch(candidate_id):
        raise ValueError("candidate id must be a safe identifier")
    value = {
        "schemaVersion": 2,
        "contract": CONTRACT,
        "candidateId": candidate_id,
        "corpus": corpus_binding(cases_path, labels_path, corpus_path),
        "evaluatorDigest": evaluator_digest(),
        "arms": {"champion": champion, "challenger": challenger},
    }
    return validate_pair(value, cases_path, labels_path, corpus_path)


def validate_pair(
    value: Any, cases_path: Path = DEFAULT_CASES,
    labels_path: Path = DEFAULT_LABELS, corpus_path: Path = DEFAULT_CORPUS,
) -> dict[str, Any]:
    expected = {"arms", "candidateId", "contract", "corpus", "evaluatorDigest", "schemaVersion"}
    if not isinstance(value, dict) or set(value) != expected or value.get("schemaVersion") != 2:
        raise ValueError("pair schema has unsupported or missing fields")
    if value.get("contract") != CONTRACT:
        raise ValueError("pair contract discriminator is invalid")
    if not isinstance(value["candidateId"], str) or not SAFE_ID_RE.fullmatch(value["candidateId"]):
        raise ValueError("pair candidate id must be a safe identifier")
    corpus = corpus_binding(cases_path, labels_path, corpus_path)
    if value["corpus"] != corpus:
        raise ValueError("pair corpus does not match sealed case bytes")
    if value["evaluatorDigest"] != evaluator_digest():
        raise ValueError("pair evaluator digest does not match")
    if not isinstance(value["arms"], dict) or set(value["arms"]) != {"champion", "challenger"}:
        raise ValueError("pair must contain exactly champion and challenger arms")
    labels = load_labels(labels_path)
    validate_arm(value["arms"]["champion"], corpus, labels, corpus_path, "champion")
    validate_arm(value["arms"]["challenger"], corpus, labels, corpus_path, "challenger")
    return value


def artifact_ref(path: Path) -> str:
    return f"foxguard-reviewed-negative-controls-v2:{digest_file(path)}"


def limit_wrapper_files() -> None:
    resource.setrlimit(
        resource.RLIMIT_FSIZE,
        (MAX_WRAPPER_FILE_BYTES, MAX_WRAPPER_FILE_BYTES),
    )


def read_capped(handle: Any, limit: int = 64 * 1024) -> str:
    handle.seek(0)
    value = handle.read(limit + 1)
    if len(value) > limit:
        return value[:limit].decode(errors="replace") + "\n[output truncated]"
    return value.decode(errors="replace")


def run_precision_scan(
    *, arm_id: str, binary: Path, producer: dict[str, str], results_root: Path,
    source_root: Path, cache_workdir: Path, cases_path: Path, corpus_path: Path,
    labels_path: Path, timeout_seconds: int,
) -> tuple[Path, dict[str, Any]]:
    if timeout_seconds < 1:
        raise ValueError("timeout seconds must be positive")
    results_dir = results_root / arm_id
    if results_dir.exists():
        raise ValueError(f"scan results directory already exists: {results_dir}")
    results_root.mkdir(parents=True, exist_ok=True)
    isolated_workdir = results_root / "corpus" / arm_id
    checkout_attestations = materialize_corpus(
        arm_id=arm_id,
        cache_workdir=cache_workdir,
        isolated_workdir=isolated_workdir,
        corpus_path=corpus_path,
        timeout_seconds=timeout_seconds,
    )
    command = [
        sys.executable,
        str(DEFAULT_EVALUATOR),
        "run",
        "--foxguard",
        str(binary.resolve()),
        "--manifest",
        str(corpus_path.resolve()),
        "--labels",
        str(labels_path.resolve()),
        "--results-dir",
        str(results_dir.resolve()),
        "--workdir",
        str(isolated_workdir.resolve()),
    ]
    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        process = subprocess.Popen(  # noqa: S603
            command, stdout=stdout_file, stderr=stderr_file,
            start_new_session=True, preexec_fn=limit_wrapper_files,
        )
        try:
            process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise ValueError(f"{arm_id} precision scan timed out") from exc
        stdout = read_capped(stdout_file)
        stderr = read_capped(stderr_file)
    if process.returncode != 0:
        raise ValueError(
            f"{arm_id} precision scan failed with {process.returncode}: "
            f"{stderr.strip() or stdout.strip()}"
        )
    findings_path = results_dir / "findings.json"
    if findings_path.is_symlink() or not findings_path.is_file():
        raise ValueError(f"{arm_id} precision scan did not retain a regular findings artifact")
    metadata = findings_path.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_FINDINGS_BYTES:
        raise ValueError(f"{arm_id} findings artifact exceeds the size limit")
    findings = load_findings(findings_path, load_labels(labels_path))
    native_reports = [
        validate_native_report(
            results_dir / f"{repository['id']}.foxguard.json",
            repository,
            isolated_workdir / repository["id"],
        )
        for repository in corpus_repositories(corpus_path)
    ]
    for attestation in checkout_attestations:
        checkout = isolated_workdir / attestation["id"]
        require_clean_checkout(checkout, f"{arm_id}/{attestation['id']} post-scan")
        if checkout_content_digest(checkout) != attestation["treeDigest"]:
            raise ValueError(f"{arm_id} scan mutated corpus repo {attestation['id']}")
    if producer_from_paths(source_root, binary) != producer:
        raise ValueError(f"{arm_id} producer bytes changed during evaluation")
    corpus = corpus_binding(cases_path, labels_path, corpus_path)
    return findings_path, make_scan_receipt(
        findings, producer, corpus, checkout_attestations, native_reports
    )


def project(args: argparse.Namespace) -> int:
    if args.champion_id == args.challenger_id:
        raise ValueError("champion and challenger ids must differ")
    if args.results_dir.exists() and any(args.results_dir.iterdir()):
        raise ValueError("results directory must be absent or empty")
    champion_producer = producer_from_paths(args.champion_source_root, args.champion_binary)
    challenger_producer = producer_from_paths(args.challenger_source_root, args.challenger_binary)
    kwargs = {"cases_path": args.cases, "labels_path": args.labels, "corpus_path": args.corpus}
    champion_findings, champion_receipt = run_precision_scan(
        arm_id=args.champion_id, binary=args.champion_binary, producer=champion_producer,
        results_root=args.results_dir, source_root=args.champion_source_root,
        cache_workdir=args.workdir, cases_path=args.cases,
        corpus_path=args.corpus,
        labels_path=args.labels, timeout_seconds=args.timeout_seconds,
    )
    challenger_findings, challenger_receipt = run_precision_scan(
        arm_id=args.challenger_id, binary=args.challenger_binary, producer=challenger_producer,
        results_root=args.results_dir, source_root=args.challenger_source_root,
        cache_workdir=args.workdir, cases_path=args.cases,
        corpus_path=args.corpus,
        labels_path=args.labels, timeout_seconds=args.timeout_seconds,
    )
    value = build_pair(
        candidate_id=args.candidate_id,
        champion=build_arm(
            arm_id=args.champion_id, findings_path=champion_findings,
            producer=champion_producer, scan_receipt=champion_receipt, **kwargs,
        ),
        challenger=build_arm(
            arm_id=args.challenger_id, findings_path=challenger_findings,
            producer=challenger_producer, scan_receipt=challenger_receipt, **kwargs,
        ),
        **kwargs,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(canonical_bytes(value))
    print(artifact_ref(args.output))
    before = value["arms"]["champion"]["score"]["falsePositiveRate"]
    after = value["arms"]["challenger"]["score"]["falsePositiveRate"]
    if after > before:
        print("::error::challenger reviewed fixed-case false-positive rate regressed", file=sys.stderr)
        return 1
    return 0


def verify(args: argparse.Namespace) -> int:
    validate_pair(load_json_object(args.artifact, "pair"), args.cases, args.labels, args.corpus)
    ref = artifact_ref(args.artifact)
    if args.ref is not None and args.ref != ref:
        raise ValueError("pair reference does not match retained bytes")
    print(ref)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    project_parser = subparsers.add_parser("project")
    project_parser.add_argument("--candidate-id", required=True)
    project_parser.add_argument("--champion-id", default="champion")
    project_parser.add_argument("--challenger-id", default="challenger")
    for arm in ("champion", "challenger"):
        project_parser.add_argument(f"--{arm}-source-root", required=True, type=Path)
        project_parser.add_argument(f"--{arm}-binary", required=True, type=Path)
    project_parser.add_argument("--output", required=True, type=Path)
    project_parser.add_argument("--results-dir", required=True, type=Path)
    project_parser.add_argument("--workdir", required=True, type=Path)
    project_parser.add_argument("--timeout-seconds", type=int, default=1800)
    project_parser.set_defaults(func=project)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--artifact", required=True, type=Path)
    verify_parser.add_argument("--ref")
    verify_parser.set_defaults(func=verify)
    for subparser in (project_parser, verify_parser):
        subparser.add_argument("--cases", type=Path, default=DEFAULT_CASES)
        subparser.add_argument("--labels", type=Path, default=DEFAULT_LABELS)
        subparser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    args = parser.parse_args()
    try:
        return int(args.func(args))
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
