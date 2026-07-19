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
from typing import Any, NamedTuple


ROOT = Path(__file__).resolve().parent
CONTRACT = "foxguard-held-out-capability-v1"
REPOSITORY = "0sec-labs/foxguard"
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
MAX_REPORT_BYTES = 8 * 1024 * 1024
MAX_FINDINGS = 10_000
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_ARTIFACT_BYTES = 128 * 1024 * 1024
MAX_BINARY_BYTES = 256 * 1024 * 1024
MAX_FIXTURE_FILES = 2_000
MAX_FIXTURE_BYTES = 384 * 1024 * 1024
MAX_FIXTURE_ENTRIES = 4_000
MAX_FIXTURE_DEPTH = 64
MAX_CASES = 256
_SCAN_DIRECTORY = os.scandir
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


class CapturedCorpus(NamedTuple):
    manifest_path: Path
    manifest_bytes: bytes
    manifest: dict[str, Any]
    fixtures: dict[str, tuple[tuple[Path, bytes], ...]]


class ExecutionSnapshot(NamedTuple):
    root: Path
    root_identity: tuple[int, ...]
    binary: Path
    binary_bytes: bytes
    binary_identity: tuple[int, ...]
    fixtures: dict[str, Path]
    fixture_files: dict[str, tuple[tuple[Path, bytes], ...]]
    fixture_identities: dict[str, dict[Path, tuple[Any, ...]]]


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def path_identity(path: Path) -> tuple[int, ...]:
    info = path.lstat()
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def read_stable_file(path: Path, label: str, maximum: int) -> bytes:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size < 1
            or before.st_size > maximum
        ):
            raise ValueError(f"{label} must be a bounded single-link regular file")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(descriptor, min(1024 * 1024, maximum + 1)):
            total += len(chunk)
            if total > maximum:
                raise ValueError(f"{label} exceeds its byte limit")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        identity = lambda info: (
            info.st_dev,
            info.st_ino,
            info.st_mode,
            info.st_nlink,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )
        if identity(before) != identity(after) or total != before.st_size:
            raise ValueError(f"{label} changed while it was read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def sha256_file(path: Path, maximum: int = MAX_BINARY_BYTES) -> str:
    return sha256_bytes(read_stable_file(path, "hashed file", maximum))


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


def capture_directory(
    root: Path,
    *,
    require_trusted: bool = False,
    corpus_budget: dict[str, int] | None = None,
    identity_view: dict[Path, tuple[Any, ...]] | None = None,
) -> list[tuple[Path, bytes]]:
    requested = root.resolve(strict=True)
    if root.is_symlink():
        raise ValueError("held-out fixture path must not be a symlink")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    files: list[tuple[Path, bytes]] = []
    entries = 0
    total_bytes = 0

    def trusted(info: os.stat_result, label: str) -> None:
        if require_trusted and (info.st_uid != 0 or info.st_mode & 0o022):
            raise ValueError(
                f"held-out fixture must be root-owned and immutable to the evaluator: {label}"
            )

    def directory_identity(info: os.stat_result) -> tuple[int, ...]:
        return (
            info.st_dev,
            info.st_ino,
            info.st_mode,
            info.st_nlink,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )

    def file_identity(info: os.stat_result) -> tuple[int, ...]:
        return (*directory_identity(info), info.st_size)

    def walk(directory: int, prefix: Path, depth: int) -> None:
        nonlocal entries, total_bytes
        if depth > MAX_FIXTURE_DEPTH:
            raise ValueError("held-out fixture exceeds its depth limit")
        opened = os.fstat(directory)
        trusted(opened, str(requested / prefix))
        names: list[str] = []
        # The input is a pinned directory descriptor, never a filesystem path.
        with _SCAN_DIRECTORY(directory) as iterator:
            for entry in iterator:
                entries += 1
                if entries > MAX_FIXTURE_ENTRIES:
                    raise ValueError("held-out fixture exceeds its entry limit")
                if corpus_budget is not None:
                    corpus_budget["entries"] += 1
                    if corpus_budget["entries"] > MAX_FIXTURE_ENTRIES:
                        raise ValueError("held-out corpus exceeds its entry limit")
                name = entry.name
                if name in {"", ".", ".."} or "/" in name or "\0" in name:
                    raise ValueError("held-out fixture contains an unsafe entry name")
                names.append(name)
        for name in sorted(names):
            relative = prefix / name
            info = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode):
                raise ValueError(f"held-out fixture must not contain symlinks: {relative}")
            trusted(info, str(requested / relative))
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, flags, dir_fd=directory)
                try:
                    child_info = os.fstat(child)
                    if directory_identity(info) != directory_identity(child_info):
                        raise ValueError("held-out fixture directory changed while opened")
                    walk(child, relative, depth + 1)
                    after = os.fstat(child)
                    if directory_identity(child_info) != directory_identity(after):
                        raise ValueError("held-out fixture directory changed while read")
                finally:
                    os.close(child)
                continue
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("held-out fixture contains an unsupported entry")
            if len(files) >= MAX_FIXTURE_FILES:
                raise ValueError("held-out fixture exceeds its file limit")
            if (
                corpus_budget is not None
                and corpus_budget["files"] >= MAX_FIXTURE_FILES
            ):
                raise ValueError("held-out corpus exceeds its file limit")
            if info.st_size > MAX_FIXTURE_BYTES - total_bytes:
                raise ValueError("held-out fixture exceeds its aggregate byte limit")
            if (
                corpus_budget is not None
                and info.st_size > MAX_FIXTURE_BYTES - corpus_budget["bytes"]
            ):
                raise ValueError("held-out corpus exceeds its aggregate byte limit")
            descriptor = os.open(
                name,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=directory,
            )
            try:
                actual = os.fstat(descriptor)
                if file_identity(info) != file_identity(actual):
                    raise ValueError("held-out fixture file changed while opened")
                chunks: list[bytes] = []
                remaining = MAX_FIXTURE_BYTES - total_bytes
                if corpus_budget is not None:
                    remaining = min(
                        remaining, MAX_FIXTURE_BYTES - corpus_budget["bytes"]
                    )
                while chunk := os.read(descriptor, min(1024 * 1024, remaining + 1)):
                    remaining -= len(chunk)
                    if remaining < 0:
                        raise ValueError("held-out fixture exceeds its aggregate byte limit")
                    chunks.append(chunk)
                after = os.fstat(descriptor)
                data = b"".join(chunks)
                if file_identity(actual) != file_identity(after) or len(data) != actual.st_size:
                    raise ValueError("held-out fixture file changed while read")
            finally:
                os.close(descriptor)
            total_bytes += len(data)
            if corpus_budget is not None:
                corpus_budget["files"] += 1
                corpus_budget["bytes"] += len(data)
            files.append((relative, data))
            if identity_view is not None:
                identity_view[relative] = ("file", *file_identity(after))
        finished = os.fstat(directory)
        if directory_identity(opened) != directory_identity(finished):
            raise ValueError("held-out fixture directory changed while read")
        if identity_view is not None:
            identity_view[prefix] = ("directory", *directory_identity(finished))

    root_descriptor = os.open(requested, flags)
    try:
        before = os.fstat(root_descriptor)
        walk(root_descriptor, Path(), 0)
        after = os.fstat(root_descriptor)
        if directory_identity(before) != directory_identity(after):
            raise ValueError("held-out fixture root changed while read")
    finally:
        os.close(root_descriptor)
    return files


def relative_files(root: Path) -> list[Path]:
    return [root / relative for relative, _ in capture_directory(root)]


def captured_directory_digest(files: list[tuple[Path, bytes]]) -> str:
    digest = hashlib.sha256()
    digest.update(b"foxguard-held-out-capability-directory-v1\0")
    for relative, data in files:
        name = relative.as_posix().encode()
        digest.update(len(name).to_bytes(8, "big") + name)
        digest.update(len(data).to_bytes(8, "big") + data)
    return f"sha256:{digest.hexdigest()}"


def directory_digest(root: Path, *, require_trusted: bool = False) -> str:
    return captured_directory_digest(
        capture_directory(root, require_trusted=require_trusted)
    )


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
    return read_stable_file(path, "held-out manifest", MAX_MANIFEST_BYTES)


def require_immutable_fixture(root: Path) -> None:
    capture_directory(root, require_trusted=True)


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


def capture_corpus(path: Path, *, require_trusted: bool = True) -> CapturedCorpus:
    manifest_path = path.resolve(strict=True)
    manifest_bytes = read_manifest_bytes(path, require_trusted=require_trusted)
    value = json.loads(manifest_bytes)
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
    if len(cases) > MAX_CASES:
        raise ValueError(f"held-out capability corpus exceeds its {MAX_CASES}-case limit")
    ids = []
    corpus_budget = {"entries": 0, "files": 0, "bytes": 0}
    fixtures: dict[str, tuple[tuple[Path, bytes], ...]] = {}
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
        fixture = (manifest_path.parent / candidate).resolve()
        try:
            fixture.relative_to(manifest_path.parent)
        except ValueError as exc:
            raise ValueError(f"manifest case {index} escapes the corpus") from exc
        if not fixture.is_dir():
            raise ValueError(f"manifest case {index} fixture is missing or empty")
        captured = capture_directory(
            fixture,
            require_trusted=require_trusted,
            corpus_budget=corpus_budget,
        )
        if not captured:
            raise ValueError(f"manifest case {index} fixture is missing or empty")
        if case["fixtureDigest"] != captured_directory_digest(captured):
            raise ValueError(f"manifest case {index} fixture digest does not match bytes")
        canonical_findings(case["expectedFindings"], f"manifest case {index} expectedFindings")
        ids.append(case_id)
        fixtures[case_id] = tuple(captured)
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise ValueError("manifest case ids must be unique and sorted")
    return CapturedCorpus(manifest_path, manifest_bytes, value, fixtures)


def load_manifest(path: Path, *, require_trusted: bool = True) -> dict[str, Any]:
    return capture_corpus(path, require_trusted=require_trusted).manifest


def corpus_binding(
    source: Path | CapturedCorpus, *, require_trusted: bool = True
) -> dict[str, Any]:
    captured = (
        source
        if isinstance(source, CapturedCorpus)
        else capture_corpus(source, require_trusted=require_trusted)
    )
    manifest = captured.manifest
    bound = {
        "calibration": manifest["calibration"],
        "id": manifest["id"],
        "manifestDigest": sha256_bytes(captured.manifest_bytes),
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


def prepare_execution_snapshot(
    captured: CapturedCorpus,
    binary: Path,
    binary_digest: str,
    root: Path,
) -> ExecutionSnapshot:
    if root.exists() or root.is_symlink():
        raise ValueError("execution snapshot path must not already exist")
    root.parent.mkdir(parents=True, exist_ok=True)
    root.mkdir(mode=0o700)
    binary_bytes = read_stable_file(binary, "executed Foxguard binary", MAX_BINARY_BYTES)
    if sha256_bytes(binary_bytes) != binary_digest:
        raise ValueError("executed Foxguard binary does not match producer identity")
    snapshot_binary = root / "foxguard"
    write_new_private(snapshot_binary, binary_bytes)
    snapshot_binary.chmod(0o500)
    fixtures_root = root / "fixtures"
    fixtures_root.mkdir(mode=0o700)
    fixture_paths: dict[str, Path] = {}
    fixture_files: dict[str, tuple[tuple[Path, bytes], ...]] = {}
    fixture_identities: dict[str, dict[Path, tuple[Any, ...]]] = {}
    for case in captured.manifest["cases"]:
        case_id = case["id"]
        destination = fixtures_root / case_id
        destination.mkdir(mode=0o700)
        for relative, data in captured.fixtures[case_id]:
            write_new_private(destination / relative, data)
        directories = [
            path for path in destination.rglob("*") if path.is_dir()
        ]
        for path in sorted(directories, key=lambda item: len(item.parts), reverse=True):
            path.chmod(0o500)
        for path in destination.rglob("*"):
            if path.is_file():
                path.chmod(0o400)
        destination.chmod(0o500)
        identities: dict[Path, tuple[Any, ...]] = {}
        files = tuple(capture_directory(destination, identity_view=identities))
        expected = captured.fixtures[case_id]
        if files != expected:
            raise ValueError("execution fixture snapshot does not match captured bytes")
        fixture_paths[case_id] = destination
        fixture_files[case_id] = files
        fixture_identities[case_id] = identities
    fixtures_root.chmod(0o500)
    root.chmod(0o500)
    return ExecutionSnapshot(
        root=root,
        root_identity=path_identity(root),
        binary=snapshot_binary,
        binary_bytes=binary_bytes,
        binary_identity=path_identity(snapshot_binary),
        fixtures=fixture_paths,
        fixture_files=fixture_files,
        fixture_identities=fixture_identities,
    )


def assert_execution_snapshot(snapshot: ExecutionSnapshot) -> None:
    if path_identity(snapshot.root) != snapshot.root_identity:
        raise ValueError("execution snapshot root changed during evaluation")
    if (
        path_identity(snapshot.binary) != snapshot.binary_identity
        or read_stable_file(
            snapshot.binary, "executed Foxguard binary", MAX_BINARY_BYTES
        )
        != snapshot.binary_bytes
    ):
        raise ValueError("executed Foxguard binary changed during evaluation")
    for case_id, fixture in snapshot.fixtures.items():
        identities: dict[Path, tuple[Any, ...]] = {}
        files = tuple(capture_directory(fixture, identity_view=identities))
        if (
            files != snapshot.fixture_files[case_id]
            or identities != snapshot.fixture_identities[case_id]
        ):
            raise ValueError("execution fixture snapshot changed during evaluation")


def expected_entry_identity(
    path: Path, expected: tuple[Any, ...]
) -> tuple[Any, ...]:
    info = path.lstat()
    if expected[0] == "directory":
        return (
            "directory",
            info.st_dev,
            info.st_ino,
            info.st_mode,
            info.st_nlink,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )
    return (
        "file",
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_mtime_ns,
        info.st_ctime_ns,
        info.st_size,
    )


def assert_execution_metadata(snapshot: ExecutionSnapshot) -> None:
    if (
        path_identity(snapshot.root) != snapshot.root_identity
        or path_identity(snapshot.binary) != snapshot.binary_identity
    ):
        raise ValueError("execution snapshot metadata changed during evaluation")
    for case_id, fixture in snapshot.fixtures.items():
        for relative, expected in snapshot.fixture_identities[case_id].items():
            path = fixture if relative == Path() else fixture / relative
            if expected_entry_identity(path, expected) != expected:
                raise ValueError("execution snapshot metadata changed during evaluation")


def assert_execution_case(snapshot: ExecutionSnapshot, case_id: str) -> None:
    assert_execution_metadata(snapshot)
    identities: dict[Path, tuple[Any, ...]] = {}
    files = tuple(
        capture_directory(snapshot.fixtures[case_id], identity_view=identities)
    )
    if (
        files != snapshot.fixture_files[case_id]
        or identities != snapshot.fixture_identities[case_id]
    ):
        raise ValueError("execution fixture snapshot changed during evaluation")


def evaluate_arm(
    *,
    arm_id: str,
    binary: Path,
    producer: dict[str, str],
    manifest_path: Path,
    results_dir: Path,
    timeout_seconds: int,
    require_trusted: bool = True,
    captured_corpus: CapturedCorpus | None = None,
    evidence_budget: dict[str, int] | None = None,
) -> dict[str, Any]:
    if not SAFE_ID_RE.fullmatch(arm_id):
        raise ValueError("arm id must be a safe identifier")
    producer = validate_producer(producer, arm_id)
    if sha256_file(binary) != producer["binaryDigest"]:
        raise ValueError(f"{arm_id} binary bytes do not match producer identity")
    captured = captured_corpus or capture_corpus(
        manifest_path, require_trusted=require_trusted
    )
    manifest = captured.manifest
    if manifest["calibration"] is not True:
        raise ValueError("direct execution is calibration-only; production execution requires the controller sandbox broker")
    snapshot = prepare_execution_snapshot(
        captured,
        binary,
        producer["binaryDigest"],
        results_dir / f".{arm_id}-execution-inputs",
    )
    cases = []
    retained_budget = evidence_budget if evidence_budget is not None else {"bytes": 0}
    assert_execution_snapshot(snapshot)
    for item in manifest["cases"]:
        fixture = snapshot.fixtures[item["id"]]
        assert_execution_case(snapshot, item["id"])
        report_bytes, exit_code = scan_case(
            snapshot.binary,
            fixture,
            results_dir / f"{arm_id}-{item['id']}.json",
            timeout_seconds,
        )
        assert_execution_case(snapshot, item["id"])
        case = make_case(
            item, report_bytes, producer["binaryDigest"], exit_code, fixture,
        )
        retained = retained_budget["bytes"] + len(canonical_bytes(case))
        if retained > MAX_ARTIFACT_BYTES * 3 // 4:
            raise ValueError("generated evidence exceeds its retained byte budget")
        retained_budget["bytes"] = retained
        cases.append(case)
    assert_execution_snapshot(snapshot)
    return {"cases": cases, "id": arm_id, "producer": producer, "score": score(cases)}


def evaluator_digest() -> str:
    return sha256_bytes(b"foxguard-held-out-capability-evaluator-v1\0" + Path(__file__).read_bytes())


def validate_artifact(
    value: Any,
    manifest_path: Path,
    *,
    require_trusted: bool = True,
    captured_corpus: CapturedCorpus | None = None,
) -> dict[str, Any]:
    fields = {"arms", "authority", "candidateId", "contract", "corpus", "decision", "evaluatorDigest", "schemaVersion"}
    if not isinstance(value, dict) or set(value) != fields or value["schemaVersion"] != 1 or value["contract"] != CONTRACT:
        raise ValueError("artifact schema or contract is invalid")
    if not isinstance(value["candidateId"], str) or not SAFE_ID_RE.fullmatch(value["candidateId"]):
        raise ValueError("candidateId is invalid")
    captured = captured_corpus or capture_corpus(
        manifest_path, require_trusted=require_trusted
    )
    corpus = corpus_binding(captured)
    if value["corpus"] != corpus or value["evaluatorDigest"] != evaluator_digest():
        raise ValueError("artifact does not bind the local corpus and evaluator")
    manifest = captured.manifest
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
            try:
                native_value = json.loads(report_bytes)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"{label} case {index} native report JSON is invalid"
                ) from exc
            try:
                execution_target = Path(native_value["target"]["path"])
            except (KeyError, TypeError) as exc:
                raise ValueError(
                    f"{label} case {index} native report target is invalid"
                ) from exc
            if not execution_target.is_absolute():
                raise ValueError(f"{label} case {index} native report target is invalid")
            source_target = captured.manifest_path.parent / item["path"]
            snapshot_suffix = (
                f".{arm['id']}-execution-inputs",
                "fixtures",
                item["id"],
            )
            if (
                execution_target.resolve() != source_target.resolve()
                and tuple(execution_target.parts[-3:]) != snapshot_suffix
            ):
                raise ValueError(
                    f"{label} case {index} native report target does not bind the expected arm and case"
                )
            execution = case["execution"]
            if not isinstance(execution, dict) or set(execution) != {"binaryDigest", "exitCode", "fixtureDigest", "invocationDigest", "reportDigest"}:
                raise ValueError(f"{label} case {index} execution receipt is invalid")
            rebuilt.append(make_case(
                item, report_bytes, arm["producer"]["binaryDigest"],
                execution["exitCode"], execution_target,
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
    return artifact_ref_bytes(
        read_stable_file(path, "held-out capability artifact", MAX_ARTIFACT_BYTES)
    )


def artifact_ref_bytes(data: bytes) -> str:
    if not 0 < len(data) <= MAX_ARTIFACT_BYTES:
        raise ValueError("held-out capability artifact exceeds its byte limit")
    return f"foxguard-held-out-capability-v1:{sha256_bytes(data)}"


def run_command(args: argparse.Namespace) -> int:
    if args.champion_id == args.challenger_id or args.timeout_seconds < 1:
        raise ValueError("arm ids must differ and timeout must be positive")
    if args.results_dir.exists() and any(args.results_dir.iterdir()):
        raise ValueError("results directory must be absent or empty")
    args.results_dir.mkdir(parents=True, exist_ok=True)
    captured = capture_corpus(args.manifest, require_trusted=False)
    manifest = captured.manifest
    if manifest["calibration"] is not True:
        raise ValueError("direct execution is calibration-only; production execution requires the controller sandbox broker")
    champion = producer_from_paths(args.champion_source_root, args.champion_binary)
    challenger = producer_from_paths(args.challenger_source_root, args.challenger_binary)
    evidence_budget = {"bytes": 0}
    arms = {
        "champion": evaluate_arm(arm_id=args.champion_id, binary=args.champion_binary, producer=champion, manifest_path=args.manifest, results_dir=args.results_dir, timeout_seconds=args.timeout_seconds, require_trusted=False, captured_corpus=captured, evidence_budget=evidence_budget),
        "challenger": evaluate_arm(arm_id=args.challenger_id, binary=args.challenger_binary, producer=challenger, manifest_path=args.manifest, results_dir=args.results_dir, timeout_seconds=args.timeout_seconds, require_trusted=False, captured_corpus=captured, evidence_budget=evidence_budget),
    }
    significant = arms["challenger"]["score"]["wilson95"][0] > arms["champion"]["score"]["wilson95"][1]
    calibration = manifest["calibration"]
    value = {
        "schemaVersion": 1, "contract": CONTRACT, "candidateId": args.candidate_id,
        "corpus": corpus_binding(captured), "evaluatorDigest": evaluator_digest(), "arms": arms,
        "authority": {"draftPr": False, "merge": False, "publish": False},
        "decision": {"capabilityGatePassed": significant and not calibration, "reason": "significant_improvement" if significant and not calibration else ("calibration_only" if calibration else "not_significant"), "significant": significant},
    }
    if producer_from_paths(args.champion_source_root, args.champion_binary) != champion or producer_from_paths(args.challenger_source_root, args.challenger_binary) != challenger:
        raise ValueError("producer bytes changed during evaluation")
    validate_artifact(
        value, args.manifest, require_trusted=False, captured_corpus=captured
    )
    artifact_bytes = canonical_bytes(value)
    retained_ref = artifact_ref_bytes(artifact_bytes)
    write_new_private(args.output, artifact_bytes)
    print(retained_ref)
    return 0


def verify_command(args: argparse.Namespace) -> int:
    captured = capture_corpus(args.manifest, require_trusted=False)
    manifest = captured.manifest
    if manifest["calibration"] is not True:
        raise ValueError("this verifier is calibration-only; production verification belongs to the controller composite")
    artifact_bytes = read_stable_file(
        args.artifact, "held-out capability artifact", MAX_ARTIFACT_BYTES
    )
    validate_artifact(
        json.loads(artifact_bytes),
        args.manifest,
        require_trusted=False,
        captured_corpus=captured,
    )
    retained_ref = artifact_ref_bytes(artifact_bytes)
    if args.ref and args.ref != retained_ref:
        raise ValueError("artifact reference does not match retained bytes")
    print(retained_ref)
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
