#!/usr/bin/env python3
"""Run and verify Foxguard's sealed 0research negative-control lane."""

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
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
DEFAULT_MANIFEST = ROOT / "manifest.json"
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY = "0sec-labs/foxguard"
CONTRACT = "foxguard-fixed-negative-controls-v2"
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
MAX_REPORT_BYTES = 8 * 1024 * 1024
MAX_FINDINGS = 10_000
APPROVED_REMOTES = {
    "https://github.com/0sec-labs/foxguard",
    "https://github.com/0sec-labs/foxguard.git",
    "git@github.com:0sec-labs/foxguard",
    "git@github.com:0sec-labs/foxguard.git",
    "ssh://git@github.com/0sec-labs/foxguard",
    "ssh://git@github.com/0sec-labs/foxguard.git",
}


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def relative_files(root: Path) -> list[Path]:
    paths = []
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"sealed fixture must not contain symlinks: {path}")
        if path.is_file():
            paths.append(path)
    return sorted(paths, key=lambda path: path.relative_to(root).as_posix())


def directory_digest(root: Path) -> str:
    digest = hashlib.sha256()
    digest.update(b"foxguard-fixed-negative-control-directory-v2\0")
    for path in relative_files(root):
        relative = path.relative_to(root).as_posix().encode()
        data = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return f"sha256:{digest.hexdigest()}"


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


def producer_from_paths(source_root: Path, binary: Path) -> dict[str, str]:
    remote = run_git(source_root, "remote", "get-url", "origin").decode().strip()
    validate_approved_remote(remote)
    commit_sha = run_git(source_root, "rev-parse", "HEAD").decode().strip()
    return validate_producer({
        "repository": REPOSITORY,
        "commitSha": commit_sha,
        "treeDigest": source_tree_digest(source_root),
        "binaryDigest": sha256_file(binary),
    }, "producer")


def validate_approved_remote(remote: str) -> None:
    if remote not in APPROVED_REMOTES:
        raise ValueError("producer source root is not the approved Foxguard repository")


def load_manifest(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict) or set(value) != {"cases", "id", "schemaVersion"}:
        raise ValueError("manifest must contain exactly cases, id, and schemaVersion")
    if (
        value["schemaVersion"] != 2
        or not isinstance(value["id"], str)
        or not SAFE_ID_RE.fullmatch(value["id"])
    ):
        raise ValueError("manifest identity/schema is invalid")
    cases = value["cases"]
    if not isinstance(cases, list) or not cases:
        raise ValueError("manifest cases must be non-empty")
    ids: list[str] = []
    for index, item in enumerate(cases):
        if not isinstance(item, dict) or set(item) != {"id", "knownNegative", "path"}:
            raise ValueError(f"manifest case {index} has unsupported or missing fields")
        if item["knownNegative"] is not True:
            raise ValueError(f"manifest case {index} must be a known negative")
        case_id = item["id"]
        relative = item["path"]
        if (
            not isinstance(case_id, str)
            or not SAFE_ID_RE.fullmatch(case_id)
            or not isinstance(relative, str)
        ):
            raise ValueError(f"manifest case {index} identity is invalid")
        candidate = Path(relative)
        if candidate.is_absolute() or ".." in candidate.parts:
            raise ValueError(f"manifest case {index} path must stay beneath the corpus")
        fixture = (path.parent / candidate).resolve()
        try:
            fixture.relative_to(path.parent.resolve())
        except ValueError as exc:
            raise ValueError(f"manifest case {index} escapes the corpus") from exc
        if not fixture.is_dir() or not relative_files(fixture):
            raise ValueError(f"manifest case {index} fixture is missing or empty")
        ids.append(case_id)
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise ValueError("manifest case ids must be unique and sorted")
    return value


def corpus_binding(manifest_path: Path) -> dict[str, Any]:
    manifest = load_manifest(manifest_path)
    cases = []
    for item in manifest["cases"]:
        fixture = manifest_path.parent / item["path"]
        cases.append({
            "id": item["id"],
            "fixtureDigest": directory_digest(fixture),
        })
    bound = {
        "id": manifest["id"],
        "manifestDigest": sha256_file(manifest_path),
        "cases": cases,
    }
    return {
        **bound,
        "digest": sha256_bytes(
            b"foxguard-fixed-negative-control-corpus-v2\0" + canonical_bytes(bound)
        ),
    }


def validate_producer(value: dict[str, str], label: str) -> dict[str, str]:
    expected = {"repository", "commitSha", "treeDigest", "binaryDigest"}
    if set(value) != expected:
        raise ValueError(f"{label} producer identity has unsupported or missing fields")
    if value["repository"] != REPOSITORY:
        raise ValueError(f"{label} producer repository is not approved")
    if not SHA_RE.fullmatch(value["commitSha"]):
        raise ValueError(f"{label} producer commitSha is invalid")
    for key in ("treeDigest", "binaryDigest"):
        if not DIGEST_RE.fullmatch(value[key]):
            raise ValueError(f"{label} producer {key} is invalid")
    return dict(value)


def normalize_findings(report: Any, fixture: Path) -> list[dict[str, Any]]:
    if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
        raise ValueError("Foxguard report must contain a findings array")
    if len(report["findings"]) > MAX_FINDINGS:
        raise ValueError("Foxguard report exceeds the finding-count limit")
    normalized = []
    for index, raw in enumerate(report["findings"]):
        validate_native_finding(raw, f"finding {index}")
        path = Path(str(raw.get("file", "")))
        try:
            file_name = path.resolve().relative_to(fixture.resolve()).as_posix()
        except ValueError as exc:
            raise ValueError(f"finding {index} path escapes its fixed case") from exc
        normalized.append({
            "column": int(raw.get("column", 0)),
            "description": str(raw.get("description", "")),
            "file": file_name,
            "line": int(raw.get("line", 0)),
            "ruleId": str(raw.get("rule_id", "")),
            "severity": str(raw.get("severity", "")),
            "snippet": re.sub(r"\s+", " ", str(raw.get("snippet", "")).strip()),
        })
    return sorted(
        normalized,
        key=lambda item: (
            item["file"], item["line"], item["column"], item["ruleId"],
            item["snippet"], item["severity"], item["description"],
        ),
    )


def validate_native_finding(value: Any, label: str) -> None:
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


def limit_child_files() -> None:
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_REPORT_BYTES, MAX_REPORT_BYTES))


def read_capped(handle: Any, limit: int = 64 * 1024) -> str:
    handle.seek(0)
    value = handle.read(limit + 1)
    if len(value) > limit:
        return value[:limit].decode(errors="replace") + "\n[output truncated]"
    return value.decode(errors="replace")


def validate_normalized_findings(findings: Any, label: str) -> list[dict[str, Any]]:
    expected = {"column", "description", "file", "line", "ruleId", "severity", "snippet"}
    if not isinstance(findings, list):
        raise ValueError(f"{label} findings must be an array")
    values = []
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict) or set(finding) != expected:
            raise ValueError(f"{label} finding {index} has unsupported or missing fields")
        for key in ("line", "column"):
            if isinstance(finding[key], bool) or not isinstance(finding[key], int) or finding[key] < 0:
                raise ValueError(f"{label} finding {index} has invalid {key}")
        for key in expected - {"line", "column"}:
            if not isinstance(finding[key], str):
                raise ValueError(f"{label} finding {index} has invalid {key}")
        path = Path(finding["file"])
        if path.is_absolute() or ".." in path.parts:
            raise ValueError(f"{label} finding {index} path is unsafe")
        values.append(dict(finding))
    ordered = sorted(
        values,
        key=lambda item: (
            item["file"], item["line"], item["column"], item["ruleId"],
            item["snippet"], item["severity"], item["description"],
        ),
    )
    if values != ordered:
        raise ValueError(f"{label} findings must be canonically sorted")
    if len({canonical_bytes(item) for item in values}) != len(values):
        raise ValueError(f"{label} findings must not contain duplicates")
    return values


def validate_native_report(report: Any, fixture: Path) -> list[dict[str, Any]]:
    required = {
        "config", "finding_counts", "finding_schema_version", "findings",
        "scanner", "schema_version", "target", "timing",
    }
    if not isinstance(report, dict) or not required.issubset(report):
        raise ValueError("Foxguard report is not a native versioned envelope")
    if report["schema_version"] != "1.0.0" or report["finding_schema_version"] != "1.0.0":
        raise ValueError("Foxguard report schema version is unsupported")
    config = report["config"]
    scanner = report["scanner"]
    target = report["target"]
    timing = report["timing"]
    counts = report["finding_counts"]
    if config != {"path": "/dev/null", "source": "explicit"}:
        raise ValueError("Foxguard report config does not match the sealed invocation")
    if (
        not isinstance(scanner, dict)
        or scanner.get("name") != "foxguard"
        or scanner.get("command") != "scan"
        or not isinstance(scanner.get("version"), str)
        or not scanner["version"]
    ):
        raise ValueError("Foxguard report scanner identity is invalid")
    if (
        not isinstance(target, dict)
        or target.get("kind") != "directory"
        or target.get("changed_only") is not False
        or not isinstance(target.get("files_scanned"), int)
        or isinstance(target.get("files_scanned"), bool)
        or target["files_scanned"] < 1
        or Path(str(target.get("path", ""))).resolve() != fixture.resolve()
    ):
        raise ValueError("Foxguard report target does not match the sealed case")
    if (
        not isinstance(timing, dict)
        or isinstance(timing.get("duration_ms"), bool)
        or not isinstance(timing.get("duration_ms"), int)
        or timing["duration_ms"] < 0
    ):
        raise ValueError("Foxguard report timing is invalid")
    findings = normalize_findings(report, fixture)
    by_severity = counts.get("by_severity") if isinstance(counts, dict) else None
    severities = ("critical", "high", "low", "medium")
    expected_counts = {severity: sum(item["severity"] == severity for item in findings) for severity in severities}
    total = counts.get("total") if isinstance(counts, dict) else None
    if total != len(findings) or by_severity != expected_counts:
        raise ValueError("Foxguard report finding counts do not match findings")
    return findings


def scan_case(
    binary: Path, fixture: Path, report_path: Path, timeout_seconds: int
) -> list[dict[str, Any]]:
    if report_path.exists() or report_path.is_symlink():
        raise ValueError(f"refusing pre-existing report path: {report_path}")
    command = [
        str(binary.resolve()), "--config", "/dev/null", str(fixture.resolve()),
        "-f", "json", "--output", str(report_path.resolve()),
    ]
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen(  # noqa: S603
            command, stdout=stdout, stderr=stderr, start_new_session=True,
            preexec_fn=limit_child_files,
        )
        try:
            process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise RuntimeError(f"Foxguard timed out for {fixture.name}") from exc
        error_output = read_capped(stderr) or read_capped(stdout)
    if process.returncode not in (0, 1):
        raise RuntimeError(
            f"Foxguard exited {process.returncode} for {fixture.name}: "
            f"{error_output.strip()}"
        )
    if report_path.is_symlink() or not report_path.is_file():
        raise RuntimeError(f"Foxguard did not write a report for {fixture.name}")
    metadata = report_path.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_REPORT_BYTES:
        raise RuntimeError(f"Foxguard report is not a bounded regular file for {fixture.name}")
    findings = validate_native_report(json.loads(report_path.read_text()), fixture)
    expected_exit = 1 if findings else 0
    if process.returncode != expected_exit:
        raise RuntimeError(f"Foxguard exit code does not match findings for {fixture.name}")
    return findings


def run_arm(
    *, arm_id: str, binary: Path, producer: dict[str, str], manifest_path: Path,
    results_dir: Path, timeout_seconds: int,
) -> dict[str, Any]:
    if not SAFE_ID_RE.fullmatch(arm_id):
        raise ValueError("arm id must be a safe identifier")
    producer = validate_producer(producer, arm_id)
    actual_binary_digest = sha256_file(binary)
    if actual_binary_digest != producer["binaryDigest"]:
        raise ValueError(f"{arm_id} producer binaryDigest does not match executed bytes")
    manifest = load_manifest(manifest_path)
    cases = []
    for item in manifest["cases"]:
        fixture = manifest_path.parent / item["path"]
        findings = scan_case(
            binary, fixture, results_dir / f"{arm_id}-{item['id']}.json",
            timeout_seconds,
        )
        cases.append({
            "falsePositive": bool(findings),
            "findings": findings,
            "id": item["id"],
            "knownNegative": True,
            "verdict": "false_positive" if findings else "passed",
        })
    false_positives = sum(case["falsePositive"] for case in cases)
    return {
        "id": arm_id,
        "producer": producer,
        "cases": cases,
        "score": {
            "cases": len(cases),
            "falsePositiveRate": false_positives / len(cases),
            "inconclusiveRate": 0,
        },
    }


def validate_artifact(value: Any, manifest_path: Path = DEFAULT_MANIFEST) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("artifact must be an object")
    expected = {"arms", "candidateId", "contract", "corpus", "evaluatorDigest", "schemaVersion"}
    if set(value) != expected or value.get("schemaVersion") != 2:
        raise ValueError("artifact schema has unsupported or missing fields")
    if value.get("contract") != CONTRACT:
        raise ValueError("artifact contract discriminator is invalid")
    if not isinstance(value.get("candidateId"), str) or not SAFE_ID_RE.fullmatch(value["candidateId"]):
        raise ValueError("artifact candidateId must be a safe identifier")
    corpus = corpus_binding(manifest_path)
    if value.get("corpus") != corpus:
        raise ValueError("artifact corpus does not match the sealed local bytes")
    if value.get("evaluatorDigest") != evaluator_digest():
        raise ValueError("artifact evaluator digest does not match")
    arms = value.get("arms")
    if not isinstance(arms, dict) or set(arms) != {"champion", "challenger"}:
        raise ValueError("artifact must contain exactly champion and challenger arms")
    case_ids = [case["id"] for case in corpus["cases"]]
    for label in ("champion", "challenger"):
        arm = arms[label]
        if not isinstance(arm, dict) or set(arm) != {"cases", "id", "producer", "score"}:
            raise ValueError(f"{label} arm has unsupported or missing fields")
        if not isinstance(arm["id"], str) or not arm["id"].strip():
            raise ValueError(f"{label} arm id must not be empty")
        validate_producer(arm["producer"], label)
        cases = arm["cases"]
        if not isinstance(cases, list) or [case.get("id") for case in cases if isinstance(case, dict)] != case_ids:
            raise ValueError(f"{label} exact case ids do not match the sealed corpus")
        false_positives = 0
        for index, case in enumerate(cases):
            if set(case) != {"falsePositive", "findings", "id", "knownNegative", "verdict"}:
                raise ValueError(f"{label} case {index} has unsupported or missing fields")
            findings = validate_normalized_findings(case["findings"], f"{label} case {index}")
            if case["knownNegative"] is not True:
                raise ValueError(f"{label} case {index} is invalid")
            expected_fp = bool(findings)
            expected_verdict = "false_positive" if expected_fp else "passed"
            if case["falsePositive"] is not expected_fp or case["verdict"] != expected_verdict:
                raise ValueError(f"{label} case {index} verdict is not backed by findings")
            false_positives += expected_fp
        expected_score = {
            "cases": len(cases),
            "falsePositiveRate": false_positives / len(cases),
            "inconclusiveRate": 0,
        }
        if arm["score"] != expected_score:
            raise ValueError(f"{label} score is not recomputable from exact cases")
    return value


def evaluator_digest() -> str:
    return sha256_bytes(
        b"foxguard-fixed-negative-control-evaluator-v2\0"
        + Path(__file__).resolve().read_bytes()
    )


def artifact_ref(path: Path) -> str:
    return f"foxguard-negative-controls-v2:{sha256_file(path)}"


def run_command(args: argparse.Namespace) -> int:
    if args.timeout_seconds < 1:
        raise ValueError("timeout seconds must be positive")
    if args.results_dir.exists() and any(args.results_dir.iterdir()):
        raise ValueError("results directory must be absent or empty")
    args.results_dir.mkdir(parents=True, exist_ok=True)
    if args.champion_id == args.challenger_id:
        raise ValueError("champion and challenger ids must differ")
    champion_producer = producer_from_paths(args.champion_source_root, args.champion_binary)
    challenger_producer = producer_from_paths(args.challenger_source_root, args.challenger_binary)
    value = {
        "schemaVersion": 2,
        "contract": CONTRACT,
        "candidateId": args.candidate_id,
        "corpus": corpus_binding(args.manifest),
        "evaluatorDigest": evaluator_digest(),
        "arms": {
            "champion": run_arm(
                arm_id=args.champion_id, binary=args.champion_binary,
                producer=champion_producer,
                manifest_path=args.manifest, results_dir=args.results_dir,
                timeout_seconds=args.timeout_seconds,
            ),
            "challenger": run_arm(
                arm_id=args.challenger_id, binary=args.challenger_binary,
                producer=challenger_producer,
                manifest_path=args.manifest, results_dir=args.results_dir,
                timeout_seconds=args.timeout_seconds,
            ),
        },
    }
    if producer_from_paths(args.champion_source_root, args.champion_binary) != champion_producer:
        raise ValueError("champion producer bytes changed during evaluation")
    if producer_from_paths(args.challenger_source_root, args.challenger_binary) != challenger_producer:
        raise ValueError("challenger producer bytes changed during evaluation")
    validate_artifact(value, args.manifest)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(canonical_bytes(value))
    print(artifact_ref(args.output))
    champion = value["arms"]["champion"]["score"]["falsePositiveRate"]
    challenger = value["arms"]["challenger"]["score"]["falsePositiveRate"]
    if challenger != 0:
        print("::error::challenger must have zero fixed-case false positives", file=sys.stderr)
        return 1
    return 0


def verify_command(args: argparse.Namespace) -> int:
    value = json.loads(args.artifact.read_text())
    validate_artifact(value, args.manifest)
    if args.ref and args.ref != artifact_ref(args.artifact):
        raise ValueError("artifact reference does not match retained bytes")
    print(artifact_ref(args.artifact))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    run = subparsers.add_parser("run")
    run.add_argument("--candidate-id", required=True)
    run.add_argument("--champion-id", default="champion")
    run.add_argument("--challenger-id", default="challenger")
    run.add_argument("--champion-binary", required=True, type=Path)
    run.add_argument("--challenger-binary", required=True, type=Path)
    run.add_argument("--champion-source-root", required=True, type=Path)
    run.add_argument("--challenger-source-root", required=True, type=Path)
    run.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    run.add_argument("--results-dir", type=Path, required=True)
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--timeout-seconds", type=int, default=120)
    run.set_defaults(func=run_command)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--artifact", required=True, type=Path)
    verify.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    verify.add_argument("--ref")
    verify.set_defaults(func=verify_command)
    args = parser.parse_args()
    try:
        return int(args.func(args))
    except (ValueError, RuntimeError, OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
