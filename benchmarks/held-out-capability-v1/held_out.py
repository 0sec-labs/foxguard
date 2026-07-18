#!/usr/bin/env python3
"""Produce and verify sealed, held-out Foxguard capability evidence."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
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
CONTRACT = "foxguard-held-out-capability-v1"
REPOSITORY = "0sec-labs/foxguard"
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
MAX_REPORT_BYTES = 8 * 1024 * 1024
MAX_FINDINGS = 10_000
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
APPROVED_REMOTES = {
    "https://github.com/0sec-labs/foxguard",
    "https://github.com/0sec-labs/foxguard.git",
    "git@github.com:0sec-labs/foxguard",
    "git@github.com:0sec-labs/foxguard.git",
    "ssh://git@github.com/0sec-labs/foxguard",
    "ssh://git@github.com/0sec-labs/foxguard.git",
}
FINDING_FIELDS = {
    "column", "description", "file", "line", "ruleId", "severity", "snippet",
}


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def write_new_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)


def read_stable_report(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_REPORT_BYTES:
            raise RuntimeError(f"Foxguard report is not a bounded regular file: {path}")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            data = handle.read(MAX_REPORT_BYTES + 1)
        after = os.fstat(descriptor)
        if len(data) > MAX_REPORT_BYTES or (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
            raise RuntimeError(f"Foxguard report changed while it was being read: {path}")
        return data
    finally:
        os.close(descriptor)


def relative_files(root: Path) -> list[Path]:
    files = []
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"held-out fixture must not contain symlinks: {path}")
        if path.is_file():
            files.append(path)
    return sorted(files, key=lambda path: path.relative_to(root).as_posix())


def directory_digest(root: Path) -> str:
    digest = hashlib.sha256()
    digest.update(b"foxguard-held-out-capability-directory-v1\0")
    for path in relative_files(root):
        name = path.relative_to(root).as_posix().encode()
        data = path.read_bytes()
        digest.update(len(name).to_bytes(8, "big") + name)
        digest.update(len(data).to_bytes(8, "big") + data)
    return f"sha256:{digest.hexdigest()}"


def require_private_manifest(path: Path) -> None:
    lexical = Path(os.path.abspath(path))
    try:
        resolved = path.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ValueError("held-out manifest path does not exist") from exc
    if lexical != resolved:
        raise ValueError("held-out manifest path must be canonical and contain no symlink components")
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("held-out manifest must be a regular file")
    if metadata.st_uid != 0 or metadata.st_mode & 0o027:
        raise ValueError("held-out manifest must be root-owned, group-readable at most, and never group/other writable")
    current = lexical.parent
    while True:
        parent_metadata = current.stat()
        if parent_metadata.st_uid != 0 or parent_metadata.st_mode & 0o022:
            raise ValueError(f"held-out corpus ancestor must be root-owned and non-writable by the evaluator: {current}")
        if current == current.parent:
            break
        current = current.parent


def read_manifest_bytes(path: Path, *, require_trusted: bool) -> bytes:
    if require_trusted:
        require_private_manifest(path)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_MANIFEST_BYTES:
            raise ValueError("held-out manifest must be a bounded regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            data = handle.read(MAX_MANIFEST_BYTES + 1)
        after = os.fstat(descriptor)
        if len(data) > MAX_MANIFEST_BYTES or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError("held-out manifest changed while it was being read")
        return data
    finally:
        os.close(descriptor)


def require_immutable_fixture(root: Path) -> None:
    paths = [root, *sorted(root.rglob("*"))]
    for path in paths:
        metadata = path.stat()
        if metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise ValueError(f"held-out fixture must be root-owned and immutable to the evaluator: {path}")


def validate_finding(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != FINDING_FIELDS:
        raise ValueError(f"{label} has unsupported or missing fields")
    for key in ("line", "column"):
        if isinstance(value[key], bool) or not isinstance(value[key], int) or value[key] < 1:
            raise ValueError(f"{label}.{key} is invalid")
    for key in FINDING_FIELDS - {"line", "column"}:
        if not isinstance(value[key], str):
            raise ValueError(f"{label}.{key} is invalid")
    if value["severity"] not in {"low", "medium", "high", "critical"}:
        raise ValueError(f"{label}.severity is invalid")
    path = Path(value["file"])
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"{label}.file is unsafe")
    return dict(value)


def canonical_findings(values: Any, label: str) -> list[dict[str, Any]]:
    if not isinstance(values, list) or not values:
        raise ValueError(f"{label} must be a non-empty array")
    findings = [validate_finding(value, f"{label} {index}") for index, value in enumerate(values)]
    ordered = sorted(findings, key=lambda item: canonical_bytes(item))
    if findings != ordered or len({canonical_bytes(item) for item in findings}) != len(findings):
        raise ValueError(f"{label} must be unique and canonically sorted")
    return findings


def load_manifest(path: Path, *, require_trusted: bool = True) -> dict[str, Any]:
    value = json.loads(read_manifest_bytes(path, require_trusted=require_trusted))
    expected = {"calibration", "cases", "id", "requireSignificance", "schemaVersion"}
    if not isinstance(value, dict) or set(value) != expected or value["schemaVersion"] != 1:
        raise ValueError("manifest schema has unsupported or missing fields")
    if not isinstance(value["id"], str) or not SAFE_ID_RE.fullmatch(value["id"]):
        raise ValueError("manifest id is invalid")
    if not isinstance(value["calibration"], bool) or value["requireSignificance"] is not True:
        raise ValueError("manifest must explicitly require significance")
    cases = value["cases"]
    if not isinstance(cases, list) or len(cases) < 4:
        raise ValueError("held-out capability corpus requires at least four cases")
    ids = []
    for index, case in enumerate(cases):
        fields = {"expectedFindings", "fixtureDigest", "id", "knownPositive", "oracleRef", "path"}
        if not isinstance(case, dict) or set(case) != fields:
            raise ValueError(f"manifest case {index} has unsupported or missing fields")
        if case["knownPositive"] is not True or not DIGEST_RE.fullmatch(str(case["oracleRef"])):
            raise ValueError(f"manifest case {index} lacks an independent positive oracle")
        case_id, relative = case["id"], case["path"]
        if not isinstance(case_id, str) or not SAFE_ID_RE.fullmatch(case_id) or not isinstance(relative, str):
            raise ValueError(f"manifest case {index} identity is invalid")
        candidate = Path(relative)
        if candidate.is_absolute() or ".." in candidate.parts:
            raise ValueError(f"manifest case {index} path is unsafe")
        fixture = (path.parent / candidate).resolve()
        try:
            fixture.relative_to(path.parent.resolve())
        except ValueError as exc:
            raise ValueError(f"manifest case {index} escapes the corpus") from exc
        if not fixture.is_dir() or not relative_files(fixture):
            raise ValueError(f"manifest case {index} fixture is missing or empty")
        if require_trusted:
            require_immutable_fixture(fixture)
        if case["fixtureDigest"] != directory_digest(fixture):
            raise ValueError(f"manifest case {index} fixture digest does not match bytes")
        canonical_findings(case["expectedFindings"], f"manifest case {index} expectedFindings")
        ids.append(case_id)
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise ValueError("manifest case ids must be unique and sorted")
    return value


def corpus_binding(path: Path, *, require_trusted: bool = True) -> dict[str, Any]:
    manifest = load_manifest(path, require_trusted=require_trusted)
    bound = {
        "calibration": manifest["calibration"],
        "id": manifest["id"],
        "manifestDigest": sha256_bytes(read_manifest_bytes(path, require_trusted=require_trusted)),
        "cases": [
            {"fixtureDigest": case["fixtureDigest"], "id": case["id"], "oracleRef": case["oracleRef"]}
            for case in manifest["cases"]
        ],
    }
    return {**bound, "digest": sha256_bytes(b"foxguard-held-out-capability-corpus-v1\0" + canonical_bytes(bound))}


def run_git(root: Path, *args: str) -> bytes:
    process = subprocess.run(["git", "-C", str(root.resolve()), *args], capture_output=True)
    if process.returncode:
        raise ValueError(process.stderr.decode(errors="replace").strip())
    return process.stdout


def producer_from_paths(source_root: Path, binary: Path) -> dict[str, str]:
    remote = run_git(source_root, "remote", "get-url", "origin").decode().strip()
    if remote not in APPROVED_REMOTES:
        raise ValueError("source root is not the approved Foxguard repository")
    commit = run_git(source_root, "rev-parse", "HEAD").decode().strip()
    tree = run_git(source_root, "rev-parse", "HEAD^{tree}").decode().strip()
    return validate_producer({
        "repository": REPOSITORY, "commitSha": commit, "gitTreeOid": tree,
        "binaryDigest": sha256_file(binary),
    }, "producer")


def validate_producer(value: Any, label: str) -> dict[str, str]:
    fields = {"binaryDigest", "commitSha", "gitTreeOid", "repository"}
    if not isinstance(value, dict) or set(value) != fields or value["repository"] != REPOSITORY:
        raise ValueError(f"{label} producer identity is invalid")
    if not SHA_RE.fullmatch(value["commitSha"]) or not SHA_RE.fullmatch(value["gitTreeOid"]):
        raise ValueError(f"{label} source identity is invalid")
    if not DIGEST_RE.fullmatch(value["binaryDigest"]):
        raise ValueError(f"{label} binary digest is invalid")
    return dict(value)


def normalize_native_findings(report: Any, fixture: Path) -> list[dict[str, Any]]:
    envelope = {
        "config", "finding_counts", "finding_schema_version", "findings",
        "scanner", "schema_version", "target", "timing",
    }
    if (
        not isinstance(report, dict)
        or not envelope.issubset(report)
        or report.get("schema_version") != "1.0.0"
        or report.get("finding_schema_version") != "1.0.0"
    ):
        raise ValueError("Foxguard report schema is unsupported")
    if report["config"] != {"path": "/dev/null", "source": "explicit"}:
        raise ValueError("Foxguard report config does not match the sealed invocation")
    scanner, target, timing = report["scanner"], report["target"], report["timing"]
    if (
        not isinstance(scanner, dict)
        or scanner.get("name") != "foxguard"
        or scanner.get("command") != "scan"
        or not isinstance(scanner.get("version"), str)
        or not scanner["version"]
    ):
        raise ValueError("Foxguard scanner identity is invalid")
    if (
        not isinstance(target, dict)
        or target.get("kind") != "directory"
        or target.get("changed_only") is not False
        or isinstance(target.get("files_scanned"), bool)
        or not isinstance(target.get("files_scanned"), int)
        or target["files_scanned"] < 1
        or Path(str(target.get("path", ""))).resolve() != fixture.resolve()
    ):
        raise ValueError("Foxguard report target does not match the held-out case")
    if (
        not isinstance(timing, dict)
        or isinstance(timing.get("duration_ms"), bool)
        or not isinstance(timing.get("duration_ms"), int)
        or timing["duration_ms"] < 0
    ):
        raise ValueError("Foxguard report timing is invalid")
    raw_findings = report.get("findings")
    if not isinstance(raw_findings, list) or len(raw_findings) > MAX_FINDINGS:
        raise ValueError("Foxguard findings are invalid or unbounded")
    normalized = []
    for index, raw in enumerate(raw_findings):
        required = {
            "column", "confidence", "cwe", "description", "end_column", "end_line",
            "file", "line", "rule_id", "severity", "snippet",
        }
        if not isinstance(raw, dict) or not required.issubset(raw):
            raise ValueError(f"native finding {index} is invalid")
        for key in ("line", "column", "end_line", "end_column"):
            if isinstance(raw[key], bool) or not isinstance(raw[key], int) or raw[key] < 1:
                raise ValueError(f"native finding {index}.{key} is invalid")
        confidence = raw["confidence"]
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
            raise ValueError(f"native finding {index}.confidence is invalid")
        try:
            name = Path(str(raw["file"])).resolve().relative_to(fixture.resolve()).as_posix()
        except ValueError as exc:
            raise ValueError(f"native finding {index} escapes its fixture") from exc
        normalized.append(validate_finding({
            "column": raw["column"], "description": str(raw["description"]), "file": name,
            "line": raw["line"], "ruleId": str(raw["rule_id"]),
            "severity": str(raw["severity"]),
            "snippet": re.sub(r"\s+", " ", str(raw["snippet"]).strip()),
        }, f"native finding {index}"))
    normalized = sorted(normalized, key=lambda item: canonical_bytes(item))
    if len({canonical_bytes(item) for item in normalized}) != len(normalized):
        raise ValueError("Foxguard report contains duplicate normalized findings")
    counts = report["finding_counts"]
    severities = ("critical", "high", "low", "medium")
    expected_counts = {
        severity: sum(item["severity"] == severity for item in normalized)
        for severity in severities
    }
    if (
        not isinstance(counts, dict)
        or counts.get("total") != len(normalized)
        or counts.get("by_severity") != expected_counts
    ):
        raise ValueError("Foxguard report counts do not match its findings")
    return normalized


def limit_child_files() -> None:
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_REPORT_BYTES, MAX_REPORT_BYTES))


def scan_case(binary: Path, fixture: Path, report_path: Path, timeout_seconds: int) -> tuple[bytes, int]:
    if report_path.exists() or report_path.is_symlink():
        raise ValueError(f"refusing pre-existing report path: {report_path}")
    command = [str(binary.resolve()), "--config", "/dev/null", str(fixture.resolve()), "-f", "json", "--output", str(report_path.resolve())]
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen(  # foxguard: ignore[py/no-command-injection]
            command, stdout=stdout, stderr=stderr, start_new_session=True,
            preexec_fn=limit_child_files,
        )
        try:
            process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise RuntimeError(f"Foxguard timed out for {fixture.name}") from exc
    if process.returncode not in (0, 1) or not report_path.is_file() or report_path.is_symlink():
        raise RuntimeError(f"Foxguard failed to produce a valid report for {fixture.name}")
    report_bytes = read_stable_report(report_path)
    try:
        report = json.loads(report_bytes)
    except json.JSONDecodeError as exc:
        raise ValueError("native report JSON is invalid") from exc
    findings = normalize_native_findings(report, fixture)
    if process.returncode != (1 if findings else 0):
        raise RuntimeError(f"Foxguard exit code does not match findings for {fixture.name}")
    return report_bytes, process.returncode


def wilson_interval(successes: int, trials: int, z: float = 1.959963984540054) -> list[float]:
    if trials < 1 or successes < 0 or successes > trials:
        raise ValueError("invalid Wilson interval inputs")
    p = successes / trials
    denominator = 1 + z * z / trials
    centre = (p + z * z / (2 * trials)) / denominator
    margin = z * math.sqrt((p * (1 - p) + z * z / (4 * trials)) / trials) / denominator
    return [centre - margin, centre + margin]


def invocation_digest(binary_digest: str, fixture_digest: str, case_id: str) -> str:
    basis = {
        "binaryDigest": binary_digest,
        "caseId": case_id,
        "config": {"path": "/dev/null", "source": "explicit"},
        "fixtureDigest": fixture_digest,
        "format": "json",
        "operation": "scan-directory",
    }
    return sha256_bytes(b"foxguard-held-out-invocation-v1\0" + canonical_bytes(basis))


def make_case(
    item: dict[str, Any], report_bytes: bytes, binary_digest: str,
    exit_code: int, fixture: Path,
) -> dict[str, Any]:
    if not report_bytes or len(report_bytes) > MAX_REPORT_BYTES:
        raise ValueError("native report bytes are empty or unbounded")
    try:
        report = json.loads(report_bytes)
    except json.JSONDecodeError as exc:
        raise ValueError("native report JSON is invalid") from exc
    findings = normalize_native_findings(report, fixture)
    if exit_code != (1 if findings else 0):
        raise ValueError("recorded exit code does not match native findings")
    expected = canonical_findings(item["expectedFindings"], "expectedFindings")
    matched = all(finding in findings for finding in expected)
    return {
        "detected": matched, "expectedFindings": expected, "findings": findings,
        "execution": {
            "binaryDigest": binary_digest,
            "exitCode": exit_code,
            "fixtureDigest": item["fixtureDigest"],
            "invocationDigest": invocation_digest(binary_digest, item["fixtureDigest"], item["id"]),
            "reportDigest": sha256_bytes(report_bytes),
        },
        "id": item["id"], "knownPositive": True,
        "nativeReport": {"encoding": "base64", "value": base64.b64encode(report_bytes).decode()},
        "verdict": "detected" if matched else "missed",
    }


def score(cases: list[dict[str, Any]]) -> dict[str, Any]:
    detected = sum(case["detected"] is True for case in cases)
    return {"cases": len(cases), "detected": detected, "detectionRate": detected / len(cases), "wilson95": wilson_interval(detected, len(cases))}


def evaluate_arm(*, arm_id: str, binary: Path, producer: dict[str, str], manifest_path: Path, results_dir: Path, timeout_seconds: int, require_trusted: bool = True) -> dict[str, Any]:
    if not SAFE_ID_RE.fullmatch(arm_id):
        raise ValueError("arm id must be a safe identifier")
    producer = validate_producer(producer, arm_id)
    if sha256_file(binary) != producer["binaryDigest"]:
        raise ValueError(f"{arm_id} binary bytes do not match producer identity")
    manifest = load_manifest(manifest_path, require_trusted=require_trusted)
    if manifest["calibration"] is not True:
        raise ValueError("direct execution is calibration-only; production execution requires the controller sandbox broker")
    cases = []
    for item in manifest["cases"]:
        fixture = manifest_path.parent / item["path"]
        report_bytes, exit_code = scan_case(
            binary, fixture, results_dir / f"{arm_id}-{item['id']}.json", timeout_seconds,
        )
        cases.append(make_case(
            item, report_bytes, producer["binaryDigest"], exit_code, fixture,
        ))
    return {"cases": cases, "id": arm_id, "producer": producer, "score": score(cases)}


def evaluator_digest() -> str:
    return sha256_bytes(b"foxguard-held-out-capability-evaluator-v1\0" + Path(__file__).read_bytes())


def validate_artifact(value: Any, manifest_path: Path, *, require_trusted: bool = True) -> dict[str, Any]:
    fields = {"arms", "authority", "candidateId", "contract", "corpus", "decision", "evaluatorDigest", "schemaVersion"}
    if not isinstance(value, dict) or set(value) != fields or value["schemaVersion"] != 1 or value["contract"] != CONTRACT:
        raise ValueError("artifact schema or contract is invalid")
    if not isinstance(value["candidateId"], str) or not SAFE_ID_RE.fullmatch(value["candidateId"]):
        raise ValueError("candidateId is invalid")
    corpus = corpus_binding(manifest_path, require_trusted=require_trusted)
    if value["corpus"] != corpus or value["evaluatorDigest"] != evaluator_digest():
        raise ValueError("artifact does not bind the local corpus and evaluator")
    manifest = load_manifest(manifest_path, require_trusted=require_trusted)
    ids = [case["id"] for case in manifest["cases"]]
    arms = value["arms"]
    if not isinstance(arms, dict) or set(arms) != {"champion", "challenger"}:
        raise ValueError("artifact must contain exactly two arms")
    if value["authority"] != {"draftPr": False, "merge": False, "publish": False}:
        raise ValueError("capability evidence must not carry promotion or publication authority")
    if (
        isinstance(arms["champion"], dict)
        and isinstance(arms["challenger"], dict)
        and arms["champion"].get("producer") == arms["challenger"].get("producer")
    ):
        raise ValueError("champion and challenger producer identities must differ")
    for label in ("champion", "challenger"):
        arm = arms[label]
        if not isinstance(arm, dict) or set(arm) != {"cases", "id", "producer", "score"}:
            raise ValueError(f"{label} arm schema is invalid")
        if not isinstance(arm["id"], str) or not SAFE_ID_RE.fullmatch(arm["id"]):
            raise ValueError(f"{label} arm id is invalid")
        validate_producer(arm["producer"], label)
        if [case.get("id") for case in arm["cases"] if isinstance(case, dict)] != ids:
            raise ValueError(f"{label} exact case ids do not match the held-out corpus")
        rebuilt = []
        for index, (case, item) in enumerate(zip(arm["cases"], manifest["cases"])):
            expected_fields = {"detected", "execution", "expectedFindings", "findings", "id", "knownPositive", "nativeReport", "verdict"}
            if not isinstance(case, dict) or set(case) != expected_fields or case["knownPositive"] is not True:
                raise ValueError(f"{label} case {index} schema is invalid")
            native = case["nativeReport"]
            if not isinstance(native, dict) or set(native) != {"encoding", "value"} or native["encoding"] != "base64":
                raise ValueError(f"{label} case {index} native report encoding is invalid")
            try:
                report_bytes = base64.b64decode(native["value"], validate=True)
            except (ValueError, TypeError) as exc:
                raise ValueError(f"{label} case {index} native report encoding is invalid") from exc
            execution = case["execution"]
            if not isinstance(execution, dict) or set(execution) != {"binaryDigest", "exitCode", "fixtureDigest", "invocationDigest", "reportDigest"}:
                raise ValueError(f"{label} case {index} execution receipt is invalid")
            rebuilt.append(make_case(
                item, report_bytes, arm["producer"]["binaryDigest"],
                execution["exitCode"], manifest_path.parent / item["path"],
            ))
        if arm["cases"] != rebuilt or arm["score"] != score(rebuilt):
            raise ValueError(f"{label} verdict or score is not recomputable")
    if arms["champion"]["id"] == arms["challenger"]["id"]:
        raise ValueError("champion and challenger arm ids must differ")
    champion_upper = arms["champion"]["score"]["wilson95"][1]
    challenger_lower = arms["challenger"]["score"]["wilson95"][0]
    significant = challenger_lower > champion_upper
    expected_decision = {
        "capabilityGatePassed": significant and not corpus["calibration"],
        "reason": "significant_improvement" if significant and not corpus["calibration"] else ("calibration_only" if corpus["calibration"] else "not_significant"),
        "significant": significant,
    }
    if value["decision"] != expected_decision:
        raise ValueError("promotion decision is not recomputable")
    return value


def artifact_ref(path: Path) -> str:
    return f"foxguard-held-out-capability-v1:{sha256_file(path)}"


def run_command(args: argparse.Namespace) -> int:
    if args.champion_id == args.challenger_id or args.timeout_seconds < 1:
        raise ValueError("arm ids must differ and timeout must be positive")
    if args.results_dir.exists() and any(args.results_dir.iterdir()):
        raise ValueError("results directory must be absent or empty")
    args.results_dir.mkdir(parents=True, exist_ok=True)
    manifest = load_manifest(args.manifest, require_trusted=False)
    if manifest["calibration"] is not True:
        raise ValueError("direct execution is calibration-only; production execution requires the controller sandbox broker")
    champion = producer_from_paths(args.champion_source_root, args.champion_binary)
    challenger = producer_from_paths(args.challenger_source_root, args.challenger_binary)
    arms = {
        "champion": evaluate_arm(arm_id=args.champion_id, binary=args.champion_binary, producer=champion, manifest_path=args.manifest, results_dir=args.results_dir, timeout_seconds=args.timeout_seconds, require_trusted=False),
        "challenger": evaluate_arm(arm_id=args.challenger_id, binary=args.challenger_binary, producer=challenger, manifest_path=args.manifest, results_dir=args.results_dir, timeout_seconds=args.timeout_seconds, require_trusted=False),
    }
    significant = arms["challenger"]["score"]["wilson95"][0] > arms["champion"]["score"]["wilson95"][1]
    calibration = manifest["calibration"]
    value = {
        "schemaVersion": 1, "contract": CONTRACT, "candidateId": args.candidate_id,
        "corpus": corpus_binding(args.manifest, require_trusted=False), "evaluatorDigest": evaluator_digest(), "arms": arms,
        "authority": {"draftPr": False, "merge": False, "publish": False},
        "decision": {"capabilityGatePassed": significant and not calibration, "reason": "significant_improvement" if significant and not calibration else ("calibration_only" if calibration else "not_significant"), "significant": significant},
    }
    if producer_from_paths(args.champion_source_root, args.champion_binary) != champion or producer_from_paths(args.challenger_source_root, args.challenger_binary) != challenger:
        raise ValueError("producer bytes changed during evaluation")
    validate_artifact(value, args.manifest, require_trusted=False)
    write_new_private(args.output, canonical_bytes(value))
    print(artifact_ref(args.output))
    return 0


def verify_command(args: argparse.Namespace) -> int:
    manifest = load_manifest(args.manifest, require_trusted=False)
    if manifest["calibration"] is not True:
        raise ValueError("this verifier is calibration-only; production verification belongs to the controller composite")
    validate_artifact(json.loads(args.artifact.read_text()), args.manifest, require_trusted=False)
    if args.ref and args.ref != artifact_ref(args.artifact):
        raise ValueError("artifact reference does not match retained bytes")
    print(artifact_ref(args.artifact))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("calibrate")
    run.add_argument("--candidate-id", required=True)
    run.add_argument("--champion-id", default="champion")
    run.add_argument("--challenger-id", default="challenger")
    run.add_argument("--champion-binary", required=True, type=Path)
    run.add_argument("--challenger-binary", required=True, type=Path)
    run.add_argument("--champion-source-root", required=True, type=Path)
    run.add_argument("--challenger-source-root", required=True, type=Path)
    run.add_argument("--manifest", required=True, type=Path)
    run.add_argument("--results-dir", required=True, type=Path)
    run.add_argument("--output", required=True, type=Path)
    run.add_argument("--timeout-seconds", type=int, default=120)
    run.set_defaults(func=run_command)
    verify = commands.add_parser("verify")
    verify.add_argument("--artifact", required=True, type=Path)
    verify.add_argument("--manifest", required=True, type=Path)
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
