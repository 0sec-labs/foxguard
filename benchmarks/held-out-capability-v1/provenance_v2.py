#!/usr/bin/env python3
"""Private, signed custody packages for held-out Foxguard evidence.

This module authenticates retained bytes.  It deliberately does not execute a
binary, import a retained evaluator, contact a provider, or turn an opaque
receipt into an independently verified claim.
"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import io
import importlib.util
import json
import os
import re
import resource
import shutil
import stat
import subprocess
import sys
import tempfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from types import MappingProxyType, SimpleNamespace
from typing import Any, Mapping


HERE = Path(__file__).resolve().parent


def _load(name: str, filename: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {filename}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


held = _load("foxguard_held_out_v1_for_provenance", "held_out.py")
source_change = _load("foxguard_source_change_v1_for_provenance", "source_change.py")

CONTRACT = "foxguard-held-out-provenance-v2"
SIGNATURE_NAMESPACE = "foxguard-held-out-provenance-v2:package-root"
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
MAX_FILES = 2_000
MAX_ENTRIES = 4_000
MAX_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_ROOT_BYTES = 4 * 1024 * 1024
MAX_SIGNATURE_BYTES = 64 * 1024
MAX_DEPTH = 16
_SCAN_DIRECTORY = os.scandir
AUTHORITY = {
    "privateRetentionAllowed": True,
    "offlineAuditAllowed": True,
    "executionAllowed": False,
    "retainedCodeExecutionAllowed": False,
    "providerAccessAllowed": False,
    "spendAllowed": False,
    "promotionAllowed": False,
    "trainingAllowed": False,
    "globalTrainingEligible": False,
    "modelWriteAllowed": False,
    "githubWriteAllowed": False,
    "draftPrAllowed": False,
    "mergeAllowed": False,
    "deploymentAllowed": False,
    "publicationAllowed": False,
    "disclosureAllowed": False,
}


@dataclass(frozen=True)
class ProvenanceInputs:
    candidate_id: str
    capability_evidence: Path
    source_descriptor: Path
    corpus_manifest: Path
    champion_binary: Path
    challenger_binary: Path
    source_bundle: Path
    oracle_receipts: Mapping[str, Path]
    raw_reports: Mapping[tuple[str, str], Path]
    evaluator_files: Mapping[str, Path]
    build_inputs: Mapping[str, Path]
    policy_inputs: Mapping[str, Path]
    ci_receipt: Path
    controller_receipts: Mapping[str, Path] = field(default_factory=dict)


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _safe_component(value: str, label: str) -> str:
    if not isinstance(value, str) or not SAFE_ID.fullmatch(value):
        raise ValueError(f"{label} is not a safe identifier")
    return value


def _safe_payload_path(value: str) -> str:
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or not value
        or len(path.parts) > MAX_DEPTH
        or any(part in {"", ".", ".."} or not SAFE_ID.fullmatch(part) for part in path.parts)
    ):
        raise ValueError(f"unsafe package path: {value}")
    return path.as_posix()


class _Capture:
    def __init__(self) -> None:
        self._cache: dict[Path, bytes] = {}
        self._total = 0

    def file(self, path: Path, label: str, maximum: int = MAX_FILE_BYTES) -> bytes:
        resolved = path.resolve(strict=True)
        if path.is_symlink():
            raise ValueError(f"{label} must not be a symlink")
        if resolved not in self._cache:
            data = held.read_stable_file(resolved, label, maximum)
            if self._total + len(data) > MAX_TOTAL_BYTES:
                raise ValueError("captured inputs exceed their aggregate byte limit")
            self._cache[resolved] = data
            self._total += len(data)
        data = self._cache[resolved]
        if len(data) > maximum:
            raise ValueError(f"{label} exceeds its byte limit")
        return data


def _json(data: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _write_new(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        offset = 0
        while offset < len(data):
            offset += os.write(descriptor, data[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _add(entries: dict[str, bytes], path: str, data: bytes) -> None:
    name = _safe_payload_path(path)
    if name in entries:
        raise ValueError(f"duplicate package path: {name}")
    if not data or len(data) > MAX_FILE_BYTES:
        raise ValueError(f"package entry {name} is empty or too large")
    if len(entries) >= MAX_FILES or sum(map(len, entries.values())) + len(data) > MAX_TOTAL_BYTES:
        raise ValueError("package exceeds its aggregate custody limit")
    entries[name] = data


def _set_process_limits(file_bytes: int = MAX_TOTAL_BYTES) -> None:
    resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
    resource.setrlimit(resource.RLIMIT_FSIZE, (file_bytes, file_bytes))
    if sys.platform.startswith("linux") and hasattr(resource, "RLIMIT_AS"):
        resource.setrlimit(resource.RLIMIT_AS, (MAX_TOTAL_BYTES, MAX_TOTAL_BYTES))


def _run_git(
    args: list[str], *, cwd: Path | None = None, home: Path, timeout: int = 30,
    input_bytes: bytes | None = None, extra_env: Mapping[str, str] | None = None,
    maximum_output: int = MAX_ROOT_BYTES, file_limit: int = MAX_TOTAL_BYTES,
) -> bytes:
    environment = {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_TEMPLATE_DIR": str(home / "empty-template"),
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    if extra_env:
        environment.update(extra_env)
    (home / "empty-template").mkdir(exist_ok=True)
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.run(  # foxguard: ignore[py/no-command-injection]
            ["git", *args], cwd=cwd, input=input_bytes, stdout=stdout, stderr=stderr,
            check=False, env=environment, timeout=timeout,
            preexec_fn=lambda: _set_process_limits(file_limit),
        )
        stdout.seek(0)
        result = stdout.read(maximum_output + 1)
        stderr.seek(0)
        error_output = stderr.read(MAX_ROOT_BYTES + 1)
    if process.returncode:
        detail = error_output.decode(errors="replace").strip()
        raise ValueError(f"offline Git replay failed: {detail[:500]}")
    if len(result) > maximum_output or len(error_output) > MAX_ROOT_BYTES:
        raise ValueError("offline Git command output exceeds its limit")
    return result


def _git_object_inventory(repository: Path, home: Path, output: Path) -> None:
    environment = {
        "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0", "HOME": str(home), "LANG": "C",
        "LC_ALL": "C", "PATH": "/usr/bin:/bin",
    }
    with output.open("xb") as handle:
        process = subprocess.run(  # foxguard: ignore[py/no-command-injection]
            [
                "git", "cat-file", "--batch-all-objects",
                "--batch-check=%(objectname) %(objecttype) %(objectsize) %(objectsize:disk)",
            ],
            cwd=repository, stdout=handle, stderr=subprocess.PIPE, check=False,
            env=environment, timeout=30,
            preexec_fn=lambda: _set_process_limits(16 * 1024 * 1024),
        )
    if process.returncode:
        detail = process.stderr.decode(errors="replace").strip()
        raise ValueError(f"offline Git object inventory failed: {detail[:500]}")


def _delta_result_size(prefix: bytes) -> int:
    offset = 0
    values = []
    for _ in range(2):
        value = 0
        shift = 0
        while True:
            if offset >= len(prefix) or shift > 63:
                raise ValueError("Git delta header is malformed")
            byte = prefix[offset]
            offset += 1
            value |= (byte & 0x7F) << shift
            if not byte & 0x80:
                break
            shift += 7
        values.append(value)
    return values[1]


def _preflight_bundle_pack(bundle: bytes) -> None:
    """Bound every packed object before invoking Git on Darwin or Linux."""
    stream = io.BytesIO(bundle)
    header_bytes = 0
    first = stream.readline()
    if first not in {b"# v2 git bundle\n", b"# v3 git bundle\n"}:
        raise ValueError("source bundle header is invalid")
    while True:
        line = stream.readline()
        header_bytes += len(line)
        if not line or header_bytes > 16 * 1024 * 1024:
            raise ValueError("source bundle header exceeds its limit")
        if line == b"\n":
            break
    if stream.read(4) != b"PACK":
        raise ValueError("source bundle has no Git pack")
    version = int.from_bytes(stream.read(4), "big")
    count = int.from_bytes(stream.read(4), "big")
    if version not in {2, 3} or not 0 < count <= 100_000:
        raise ValueError("source bundle pack header exceeds replay limits")
    logical_total = 0
    instruction_total = 0
    buffered = b""
    for _ in range(count):
        if buffered:
            first_byte, buffered = buffered[0], buffered[1:]
        else:
            raw = stream.read(1)
            if not raw:
                raise ValueError("source bundle pack is truncated")
            first_byte = raw[0]
        object_type = (first_byte >> 4) & 7
        declared = first_byte & 0x0F
        shift = 4
        byte = first_byte
        while byte & 0x80:
            raw = buffered[:1] or stream.read(1)
            buffered = buffered[1:] if buffered else buffered
            if not raw or shift > 63:
                raise ValueError("source bundle object header is malformed")
            byte = raw[0]
            declared |= (byte & 0x7F) << shift
            shift += 7
        if object_type not in {1, 2, 3, 4, 6, 7} or declared > MAX_FILE_BYTES:
            raise ValueError("source bundle object exceeds replay limits")
        if object_type == 6:
            raw = buffered[:1] or stream.read(1)
            buffered = buffered[1:] if buffered else buffered
            if not raw:
                raise ValueError("source bundle delta base is truncated")
            byte = raw[0]
            while byte & 0x80:
                raw = buffered[:1] or stream.read(1)
                buffered = buffered[1:] if buffered else buffered
                if not raw:
                    raise ValueError("source bundle delta base is truncated")
                byte = raw[0]
        elif object_type == 7:
            needed = 20
            available = buffered[:needed]
            buffered = buffered[len(available):]
            available += stream.read(needed - len(available))
            if len(available) != needed:
                raise ValueError("source bundle delta base is truncated")
        decompressor = zlib.decompressobj()
        produced = 0
        prefix = bytearray()
        while not decompressor.eof:
            chunk = buffered or stream.read(1024 * 1024)
            buffered = b""
            if not chunk:
                raise ValueError("source bundle compressed object is truncated")
            while chunk and not decompressor.eof:
                output = decompressor.decompress(chunk, 1024 * 1024)
                chunk = decompressor.unconsumed_tail
                produced += len(output)
                if len(prefix) < 32:
                    prefix.extend(output[: 32 - len(prefix)])
                if produced > declared:
                    raise ValueError("source bundle object exceeds its declared size")
            if decompressor.eof:
                buffered = decompressor.unused_data + chunk
        if produced != declared:
            raise ValueError("source bundle object size is inconsistent")
        instruction_total += declared
        result_size = _delta_result_size(bytes(prefix)) if object_type in {6, 7} else declared
        logical_total += result_size
        if result_size > MAX_FILE_BYTES or instruction_total > MAX_TOTAL_BYTES or logical_total > MAX_TOTAL_BYTES:
            raise ValueError("source bundle expansion exceeds replay limits")
    trailing = buffered + stream.read()
    if len(trailing) != 20:
        raise ValueError("source bundle pack trailer is invalid")


def _git_commit_identity(repository: Path, ref: str, home: Path) -> dict[str, str]:
    commit = _run_git(["rev-parse", ref], cwd=repository, home=home).decode().strip()
    tree = _run_git(["rev-parse", f"{ref}^{{tree}}"], cwd=repository, home=home).decode().strip()
    records = _run_git(
        ["ls-tree", "-r", "-z", "--full-tree", ref], cwd=repository, home=home,
        maximum_output=64 * 1024 * 1024, file_limit=64 * 1024 * 1024,
    )
    return {
        "commitSha": commit,
        "contentTreeDigest": digest(b"foxguard-git-content-tree-v1\0" + records),
        "gitTreeOid": tree,
    }


def _git_tree_mode(repository: Path, ref: str, path: str, home: Path) -> str | None:
    record = _run_git(
        ["ls-tree", "-z", ref, "--", path], cwd=repository, home=home,
        maximum_output=MAX_ROOT_BYTES, file_limit=MAX_ROOT_BYTES,
    )
    if not record:
        return None
    header, separator, recorded_path = record.rstrip(b"\0").partition(b"\t")
    if not separator or recorded_path.decode("utf-8", errors="strict") != path:
        raise ValueError("offline Git returned an invalid tree record")
    mode, object_type, _object_id = header.decode("ascii").split(" ")
    if object_type != "blob" or mode not in {"100644", "100755"}:
        raise ValueError("candidate paths must remain regular Git blobs")
    return mode


def _git_changed_entries(repository: Path, base: str, head: str, home: Path) -> list[dict[str, str]]:
    raw = [item for item in _run_git(
        ["diff", "--name-status", "--no-renames", "-z", base, head],
        cwd=repository, home=home, maximum_output=MAX_ROOT_BYTES, file_limit=MAX_ROOT_BYTES,
    ).split(b"\0") if item]
    if len(raw) % 2:
        raise ValueError("offline Git returned an invalid changed-path stream")
    entries = []
    for index in range(0, len(raw), 2):
        status = raw[index].decode("ascii", errors="strict")
        path = raw[index + 1].decode("utf-8", errors="strict")
        if status not in {"A", "D", "M"}:
            raise ValueError("offline Git returned an unsupported path status")
        source_change.validate_path(path)
        base_mode = _git_tree_mode(repository, base, path, home)
        head_mode = _git_tree_mode(repository, head, path, home)
        if (
            (status == "A" and (base_mode is not None or head_mode is None))
            or (status == "D" and (base_mode is None or head_mode is not None))
            or (status == "M" and (base_mode is None or head_mode is None))
        ):
            raise ValueError("candidate status does not match retained tree objects")
        entries.append({"path": path, "status": status})
    entries.sort(key=lambda item: item["path"])
    return entries


def _git_applied_tree(repository: Path, base: str, patch: bytes, home: Path) -> str:
    index = home / "replay.index"
    environment = {"GIT_INDEX_FILE": str(index)}
    _run_git(["read-tree", base], cwd=repository, home=home, extra_env=environment)
    _run_git(
        ["apply", "--cached", "--whitespace=nowarn", "-"], cwd=repository,
        home=home, input_bytes=patch, extra_env=environment,
    )
    return _run_git(
        ["write-tree"], cwd=repository, home=home, extra_env=environment,
    ).decode().strip()


def _verify_source_bundle(bundle: bytes, descriptor: dict[str, Any]) -> None:
    """Replay retained Git objects and the exact patch without network access."""
    _preflight_bundle_pack(bundle)
    with tempfile.TemporaryDirectory(prefix="foxguard-provenance-git-") as directory:
        root = Path(directory)
        bundle_path = root / "repository.bundle"
        audit = root / "audit.git"
        _write_new(bundle_path, bundle)
        _run_git(["init", "--bare", str(audit)], home=root)
        _run_git(["bundle", "verify", str(bundle_path)], cwd=audit, home=root)
        _run_git(["bundle", "unbundle", str(bundle_path)], cwd=audit, home=root)
        inventory_path = root / "object-inventory"
        _git_object_inventory(audit, root, inventory_path)
        count = 0
        logical_bytes = 0
        disk_bytes = 0
        with inventory_path.open("rb") as inventory:
            for line in inventory:
                fields = line.split()
                if len(fields) != 4 or fields[1] not in {b"blob", b"tree", b"commit", b"tag"}:
                    raise ValueError("offline Git object inventory is malformed")
                try:
                    logical_size, disk_size = int(fields[2]), int(fields[3])
                except ValueError as exc:
                    raise ValueError("offline Git object inventory is malformed") from exc
                count += 1
                logical_bytes += logical_size
                disk_bytes += disk_size
                if (
                    count > 100_000
                    or logical_size > MAX_FILE_BYTES
                    or logical_bytes > MAX_TOTAL_BYTES
                    or disk_bytes > MAX_TOTAL_BYTES
                ):
                    raise ValueError("offline Git object inventory exceeds replay limits")
        if not count:
            raise ValueError("offline Git bundle contains no objects")

        base = descriptor["base"]
        head = descriptor["head"]
        if _git_commit_identity(audit, base["commitSha"], root) != base:
            raise ValueError("descriptor base identity does not match retained Git objects")
        if _git_commit_identity(audit, head["commitSha"], root) != head:
            raise ValueError("descriptor head identity does not match retained Git objects")
        try:
            _run_git(
                ["merge-base", "--is-ancestor", base["commitSha"], head["commitSha"]],
                cwd=audit, home=root,
            )
        except ValueError as exc:
            raise ValueError("descriptor head is not a descendant of its base") from exc
        toolchain = descriptor["toolchain"]
        cargo_toml = _run_git(
            ["show", f"{head['commitSha']}:Cargo.toml"], cwd=audit, home=root,
            maximum_output=MAX_ROOT_BYTES, file_limit=MAX_ROOT_BYTES,
        )
        cargo_lock = _run_git(
            ["show", f"{head['commitSha']}:Cargo.lock"], cwd=audit, home=root,
            maximum_output=MAX_ROOT_BYTES, file_limit=MAX_ROOT_BYTES,
        )
        if (
            digest(cargo_toml) != toolchain["cargoTomlDigest"]
            or digest(cargo_lock) != toolchain["cargoLockDigest"]
            or _git_changed_entries(audit, base["commitSha"], head["commitSha"], root) != descriptor["patch"]["changes"]
        ):
            raise ValueError("retained Git objects do not match descriptor inputs")
        raw_patch = base64.b64decode(descriptor["patch"]["value"], validate=True)
        replayed_patch = _run_git(
            [
                "diff", "--no-ext-diff", "--no-textconv", "--no-renames",
                "--binary", "--full-index", base["commitSha"], head["commitSha"],
            ],
            cwd=audit, home=root, maximum_output=source_change.MAX_PATCH_BYTES,
            file_limit=source_change.MAX_PATCH_BYTES,
        )
        if replayed_patch != raw_patch:
            raise ValueError("retained patch does not match Git objects")
        if _git_applied_tree(audit, base["commitSha"], raw_patch, root) != head["gitTreeOid"]:
            raise ValueError("retained patch does not reproduce the exact head tree")


def _validate_semantics(
    inputs: ProvenanceInputs,
    capability_bytes: bytes,
    capability: dict[str, Any],
    descriptor_bytes: bytes,
    descriptor: dict[str, Any],
    corpus: Any,
    held_evaluator: bytes,
    binaries: Mapping[str, bytes],
    reports: Mapping[tuple[str, str], bytes],
    oracles: Mapping[str, bytes],
    source_bundle: bytes,
    ci_receipt: bytes,
) -> dict[str, Any]:
    candidate = _safe_component(inputs.candidate_id, "candidate id")
    if capability.get("candidateId") != candidate or descriptor.get("candidateId") != candidate:
        raise ValueError("candidate id is not cross-bound across retained evidence")
    source_change.validate_descriptor(descriptor)
    _verify_source_bundle(source_bundle, descriptor)
    expected_evaluator = digest(b"foxguard-held-out-capability-evaluator-v1\0" + held_evaluator)
    if capability.get("evaluatorDigest") != expected_evaluator:
        raise ValueError("capability evidence does not bind the retained evaluator")

    _recompute_capability(capability, corpus, expected_evaluator)

    if capability["authority"] != {"draftPr": False, "merge": False, "publish": False}:
        raise ValueError("capability evidence carries authority")
    if descriptor["provenance"] != {"buildVerified": False, "ciVerified": False}:
        raise ValueError("source receipt must remain explicitly unverified")
    if ci_receipt != canonical_bytes(descriptor["ciReceipt"]):
        raise ValueError("raw CI receipt does not exactly match the source descriptor")

    manifest_cases = {case["id"]: case for case in corpus.manifest["cases"]}
    if set(oracles) != set(manifest_cases):
        raise ValueError("oracle receipt set is not exact")
    for case_id, item in manifest_cases.items():
        if digest(oracles[case_id]) != item["oracleRef"]:
            raise ValueError(f"oracle receipt does not match manifest: {case_id}")

    arms = capability["arms"]
    expected_report_keys = {
        (arm, case_id) for arm in ("champion", "challenger") for case_id in manifest_cases
    }
    if set(reports) != expected_report_keys:
        raise ValueError("raw native report set is not exact")
    for arm in ("champion", "challenger"):
        producer = arms[arm]["producer"]
        if producer["binaryDigest"] != digest(binaries[arm]):
            raise ValueError(f"{arm} binary does not match executed producer")
        identity = descriptor["base" if arm == "champion" else "head"]
        if producer["commitSha"] != identity["commitSha"] or producer["gitTreeOid"] != identity["gitTreeOid"]:
            raise ValueError(f"{arm} source identity is not cross-bound")
        if descriptor["binaryDigests"][arm] != producer["binaryDigest"]:
            raise ValueError(f"{arm} binary digest is not cross-bound")
        cases = {case["id"]: case for case in arms[arm]["cases"]}
        if set(cases) != set(manifest_cases):
            raise ValueError(f"{arm} case set is not exact")
        for case_id, case in cases.items():
            try:
                embedded = base64.b64decode(case["nativeReport"]["value"], validate=True)
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError("embedded native report is malformed") from exc
            if embedded != reports[(arm, case_id)] or case["execution"]["reportDigest"] != digest(embedded):
                raise ValueError(f"{arm}/{case_id} raw report is not cross-bound")
            item = manifest_cases[case_id]
            if (
                case["execution"]["fixtureDigest"] != item["fixtureDigest"]
                or case["execution"]["binaryDigest"] != producer["binaryDigest"]
            ):
                raise ValueError(f"{arm}/{case_id} execution is not cross-bound")
    return {
        "candidateId": candidate,
        "capabilityEvidenceDigest": digest(capability_bytes),
        "sourceDescriptorDigest": digest(descriptor_bytes),
        "manifestDigest": digest(corpus.manifest_bytes),
        "corpusDigest": capability["corpus"]["digest"],
        "evaluatorDigest": expected_evaluator,
        "baseCommitSha": descriptor["base"]["commitSha"],
        "headCommitSha": descriptor["head"]["commitSha"],
        "offlineSourceReplayVerified": True,
        "opaqueReceiptsExternallyVerified": False,
    }


def _recompute_capability(capability: dict[str, Any], corpus: Any, evaluator: str) -> None:
    fields = {"arms", "authority", "candidateId", "contract", "corpus", "decision", "evaluatorDigest", "schemaVersion"}
    if set(capability) != fields or capability["schemaVersion"] != 1 or capability["contract"] != held.CONTRACT:
        raise ValueError("capability artifact contract is invalid")
    if capability["corpus"] != held.corpus_binding(corpus) or capability["evaluatorDigest"] != evaluator:
        raise ValueError("capability corpus or evaluator binding is invalid")
    if capability["authority"] != {"draftPr": False, "merge": False, "publish": False}:
        raise ValueError("capability evidence carries authority")
    arms = capability["arms"]
    if not isinstance(arms, dict) or set(arms) != {"champion", "challenger"}:
        raise ValueError("capability arms are invalid")
    ids = [item["id"] for item in corpus.manifest["cases"]]
    for arm_name in ("champion", "challenger"):
        arm = arms[arm_name]
        if not isinstance(arm, dict) or set(arm) != {"cases", "id", "producer", "score"}:
            raise ValueError(f"{arm_name} arm is invalid")
        held.validate_producer(arm["producer"], arm_name)
        if not SAFE_ID.fullmatch(str(arm["id"])) or [case.get("id") for case in arm["cases"]] != ids:
            raise ValueError(f"{arm_name} case identities are invalid")
        rebuilt = []
        for item, case in zip(corpus.manifest["cases"], arm["cases"]):
            try:
                report = base64.b64decode(case["nativeReport"]["value"], validate=True)
                target = Path(json.loads(report)["target"]["path"])
                exit_code = case["execution"]["exitCode"]
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise ValueError(f"{arm_name} native report is invalid") from exc
            if not target.is_absolute():
                raise ValueError(f"{arm_name} native report target is not absolute")
            rebuilt.append(held.make_case(
                item, report, arm["producer"]["binaryDigest"], exit_code, target,
            ))
        if arm["cases"] != rebuilt or arm["score"] != held.score(rebuilt):
            raise ValueError(f"{arm_name} capability result is not recomputable")
    if arms["champion"]["id"] == arms["challenger"]["id"] or arms["champion"]["producer"] == arms["challenger"]["producer"]:
        raise ValueError("capability arms are not disjoint")
    significant = arms["challenger"]["score"]["wilson95"][0] > arms["champion"]["score"]["wilson95"][1]
    calibration = capability["corpus"]["calibration"]
    expected = {
        "capabilityGatePassed": significant and not calibration,
        "reason": "significant_improvement" if significant and not calibration else ("calibration_only" if calibration else "not_significant"),
        "significant": significant,
    }
    if capability["decision"] != expected:
        raise ValueError("capability decision is not recomputable")


def _validate_retained_evaluators(evaluators: Mapping[str, bytes]) -> None:
    required = {"held_out.py", "source_change.py"}
    if set(evaluators) != required:
        raise ValueError("evaluator files must be exactly held_out.py and source_change.py")
    for name in sorted(required):
        trusted = held.read_stable_file(HERE / name, f"trusted local {name}", MAX_ROOT_BYTES)
        if evaluators[name] != trusted:
            raise ValueError(f"retained {name} does not match the trusted local verifier")


def _validate_build_inputs(descriptor: dict[str, Any], build: Mapping[str, bytes]) -> None:
    required = {
        "Cargo.toml", "Cargo.lock", "build-argv.json", "cargo-version.txt",
        "rustc-version-verbose.txt",
    }
    if set(build) != required:
        raise ValueError("build inputs are incomplete")
    if descriptor["toolchain"] != {
        "cargoLockDigest": digest(build["Cargo.lock"]),
        "cargoTomlDigest": digest(build["Cargo.toml"]),
        "rustcVerboseDigest": digest(build["rustc-version-verbose.txt"]),
    }:
        raise ValueError("build inputs do not match the source descriptor")
    if build["build-argv.json"] != canonical_bytes(descriptor["buildArgv"]):
        raise ValueError("retained build argv does not match the source descriptor")
    if not build["cargo-version.txt"].startswith(b"cargo ") or b"\n" not in build["cargo-version.txt"]:
        raise ValueError("retained cargo version is malformed")


def _sign(material: bytes, key: Path) -> bytes:
    if key.is_symlink() or not key.is_file() or key.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ValueError("signing key is missing, symlinked, or too broadly accessible")
    with tempfile.TemporaryDirectory(prefix="foxguard-provenance-sign-") as directory:
        target = Path(directory) / "root.json"
        target.write_bytes(material)
        result = subprocess.run(  # foxguard: ignore[py/no-command-injection]
            ["ssh-keygen", "-q", "-Y", "sign", "-f", str(key.resolve()), "-n", SIGNATURE_NAMESPACE, str(target)],
            capture_output=True,
            timeout=10,
            check=False,
            env={**os.environ, "SSH_ASKPASS_REQUIRE": "never"},
        )
        signature = Path(str(target) + ".sig")
        if result.returncode or not signature.is_file():
            raise ValueError("OpenSSH package signing failed")
        return held.read_stable_file(signature, "OpenSSH signature", MAX_SIGNATURE_BYTES)


def _publish_no_replace(stage: Path, output: Path) -> None:
    if output.exists() or output.is_symlink():
        raise FileExistsError(f"package destination already exists: {output}")
    libc = ctypes.CDLL(None, use_errno=True)
    renamex = getattr(libc, "renamex_np", None)
    if renamex is not None:
        renamex.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        renamex.restype = ctypes.c_int
        if renamex(os.fsencode(stage), os.fsencode(output), 0x00000004) != 0:  # RENAME_EXCL
            error = ctypes.get_errno()
            if error == 17:
                raise FileExistsError(output)
            raise OSError(error, os.strerror(error), output)
        return
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is not None:
        renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        renameat2.restype = ctypes.c_int
        if renameat2(-100, os.fsencode(stage), -100, os.fsencode(output), 1) != 0:  # AT_FDCWD, RENAME_NOREPLACE
            error = ctypes.get_errno()
            if error == 17:
                raise FileExistsError(output)
            raise OSError(error, os.strerror(error), output)
        return
    raise OSError("the platform has no atomic no-replace directory rename primitive")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _seal_stage(root: Path) -> None:
    for directory, _, _ in os.walk(root, topdown=False, followlinks=False):
        path = Path(directory)
        os.chmod(path, 0o700)
        _fsync_directory(path)


def build_package(inputs: ProvenanceInputs, output: Path, signing_key: Path, signer_identity: str) -> Path:
    _safe_component(signer_identity, "signer identity")
    capture = _Capture()
    capability_bytes = capture.file(inputs.capability_evidence, "capability evidence", held.MAX_ARTIFACT_BYTES)
    descriptor_bytes = capture.file(inputs.source_descriptor, "source descriptor", MAX_ROOT_BYTES)
    capability = _json(capability_bytes, "capability evidence")
    descriptor = _json(descriptor_bytes, "source descriptor")
    corpus = held.capture_corpus(inputs.corpus_manifest, require_trusted=False)

    evaluators = {name: capture.file(path, name, MAX_ROOT_BYTES) for name, path in inputs.evaluator_files.items()}
    _validate_retained_evaluators(evaluators)
    build = {name: capture.file(path, name, MAX_ROOT_BYTES) for name, path in inputs.build_inputs.items()}
    _validate_build_inputs(descriptor, build)
    if "evidence" not in inputs.policy_inputs:
        raise ValueError("the external evidence allowed-signers policy snapshot is required")
    policies = {
        name: capture.file(path, name, MAX_ROOT_BYTES)
        for name, path in inputs.policy_inputs.items()
    }

    binaries = {
        "champion": capture.file(inputs.champion_binary, "champion binary"),
        "challenger": capture.file(inputs.challenger_binary, "challenger binary"),
    }
    reports = {(arm, case): capture.file(path, f"{arm}/{case} report", held.MAX_REPORT_BYTES) for (arm, case), path in inputs.raw_reports.items()}
    oracles = {case: capture.file(path, f"{case} oracle", held.MAX_REPORT_BYTES) for case, path in inputs.oracle_receipts.items()}
    source_bundle = capture.file(inputs.source_bundle, "source object bundle")
    ci_receipt = capture.file(inputs.ci_receipt, "raw CI receipt", MAX_ROOT_BYTES)
    bindings = _validate_semantics(
        inputs, capability_bytes, capability, descriptor_bytes, descriptor, corpus,
        evaluators["held_out.py"], binaries, reports, oracles, source_bundle, ci_receipt,
    )

    entries: dict[str, bytes] = {}
    _add(entries, "payload/evidence/capability.json", capability_bytes)
    _add(entries, "payload/source/descriptor.json", descriptor_bytes)
    _add(entries, "payload/source/repository.bundle", source_bundle)
    _add(entries, "payload/corpus/manifest.json", corpus.manifest_bytes)
    for case in corpus.manifest["cases"]:
        case_id = _safe_component(case["id"], "case id")
        for relative, data in corpus.fixtures[case_id]:
            suffix = "/".join(_safe_component(part, "fixture path component") for part in relative.parts)
            _add(entries, f"payload/corpus/fixtures/{case_id}/{suffix}", data)
        _add(entries, f"payload/corpus/oracles/{case_id}.receipt", oracles[case_id])
    for (arm, case_id), data in sorted(reports.items()):
        _add(entries, f"payload/reports/{_safe_component(arm, 'arm')}/{_safe_component(case_id, 'case id')}.json", data)
    for arm, data in binaries.items():
        _add(entries, f"payload/binaries/{arm}.bin", data)
    for name, data in evaluators.items():
        _add(entries, f"payload/evaluators/{name}", data)
    for name, data in build.items():
        _add(entries, f"payload/build/{name}", data)
    _add(entries, "payload/receipts/ci.receipt", ci_receipt)
    for name, data in sorted(policies.items()):
        _add(entries, f"payload/policies/{_safe_component(name, 'policy name')}.policy", data)
    for name, path in sorted(inputs.controller_receipts.items()):
        _add(entries, f"payload/receipts/{_safe_component(name, 'receipt name')}.receipt", capture.file(path, name, MAX_ROOT_BYTES))

    tree = [{"path": path, "size": len(data), "digest": digest(data)} for path, data in sorted(entries.items())]
    tree_digest = digest(b"foxguard-held-out-provenance-v2:payload-tree\0" + canonical_bytes(tree))
    receipt_status = [{
        "digest": digest(ci_receipt),
        "name": "ci",
        "path": "payload/receipts/ci.receipt",
        "status": "descriptor-bound-not-independently-verified",
    }]
    for name, path in sorted(inputs.controller_receipts.items()):
        payload_path = f"payload/receipts/{_safe_component(name, 'receipt name')}.receipt"
        receipt_status.append({
            "digest": digest(entries[payload_path]),
            "name": name,
            "path": payload_path,
            "status": "opaque-not-independently-verified",
        })
    receipt_status.sort(key=lambda item: item["name"])
    root = {
        "schemaVersion": 2,
        "contract": CONTRACT,
        "signature": {"algorithm": "openssh", "identity": signer_identity, "namespace": SIGNATURE_NAMESPACE},
        "authority": AUTHORITY,
        "custody": {
            "private": True,
            "retainedPayloadsInert": True,
            "receiptsAreOpaqueEvidence": True,
            "allowedSignersTrustedOnlyFromExternalExactMatch": True,
        },
        "bindings": bindings,
        "receiptStatus": receipt_status,
        "entries": tree,
        "payloadTreeDigest": tree_digest,
    }
    root_bytes = canonical_bytes(root)
    if len(root_bytes) > MAX_ROOT_BYTES:
        raise ValueError("package root exceeds its byte limit")
    signature = _sign(root_bytes, signing_key)

    output = Path(os.path.abspath(output))
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=f".{output.name}.stage-", dir=output.parent))
    try:
        stage.chmod(0o700)
        for path, data in entries.items():
            _write_new(stage / path, data)
        _write_new(stage / "root.json", root_bytes)
        _write_new(stage / "root.json.sig", signature)
        _seal_stage(stage)
        with tempfile.TemporaryDirectory(prefix="foxguard-provenance-policy-") as policy_directory:
            captured_policy = Path(policy_directory) / "allowed_signers"
            _write_new(captured_policy, policies["evidence"])
            verify_package(stage, captured_policy, signer_identity)
            _publish_no_replace(stage, output)
            _fsync_directory(output.parent)
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise
    return output


def _verify_signature(material: bytes, signature: bytes, policy: bytes, identity: str) -> None:
    with tempfile.TemporaryDirectory(prefix="foxguard-provenance-verify-") as directory:
        root = Path(directory)
        signature_path = root / "root.sig"
        policy_path = root / "allowed_signers"
        signature_path.write_bytes(signature)
        policy_path.write_bytes(policy)
        result = subprocess.run(  # foxguard: ignore[py/no-command-injection]
            ["ssh-keygen", "-Y", "verify", "-f", str(policy_path), "-I", identity, "-n", SIGNATURE_NAMESPACE, "-s", str(signature_path)],
            input=material,
            capture_output=True,
            timeout=10,
            check=False,
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        )
    if result.returncode:
        raise ValueError("package OpenSSH signature is invalid")


def _capture_package(root: Path) -> list[tuple[Path, bytes]]:
    output: list[tuple[Path, bytes]] = []
    total = 0
    entry_count = 0
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)

    def identity(value: os.stat_result) -> tuple[int, ...]:
        return (
            value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns,
        )

    def read_file(directory_fd: int, name: str, relative: Path, before: os.stat_result) -> bytes:
        nonlocal total
        descriptor = os.open(
            name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd,
        )
        try:
            opened = os.fstat(descriptor)
            if identity(before) != identity(opened) or not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
                raise ValueError("package files must be stable single-link regular files")
            if opened.st_size > MAX_FILE_BYTES or total + opened.st_size > MAX_TOTAL_BYTES:
                raise ValueError("package exceeds aggregate verification limits")
            chunks: list[bytes] = []
            remaining = opened.st_size
            while remaining:
                chunk = os.read(descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    raise ValueError(f"package entry changed while captured: {relative}")
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                raise ValueError(f"package entry grew while captured: {relative}")
            after_open = os.fstat(descriptor)
            after_name = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if identity(opened) != identity(after_open) or identity(before) != identity(after_name):
                raise ValueError(f"package entry changed while captured: {relative}")
            data = b"".join(chunks)
            total += len(data)
            return data
        finally:
            os.close(descriptor)

    def visit(directory_fd: int, relative: Path, depth: int) -> None:
        nonlocal entry_count
        if depth > MAX_DEPTH:
            raise ValueError("package exceeds its depth limit")
        before_directory = os.fstat(directory_fd)
        if not stat.S_ISDIR(before_directory.st_mode):
            raise ValueError("package contains an unsupported directory entry")
        names: list[str] = []
        with _SCAN_DIRECTORY(directory_fd) as iterator:
            for entry in iterator:
                entry_count += 1
                if entry_count > MAX_ENTRIES:
                    raise ValueError("package exceeds its entry limit")
                names.append(entry.name)
        for name in sorted(names):
            before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            child = relative / name
            if stat.S_ISDIR(before.st_mode):
                child_fd = os.open(name, flags, dir_fd=directory_fd)
                try:
                    if identity(before) != identity(os.fstat(child_fd)):
                        raise ValueError(f"package directory changed while captured: {child}")
                    visit(child_fd, child, depth + 1)
                    if identity(before) != identity(os.stat(name, dir_fd=directory_fd, follow_symlinks=False)):
                        raise ValueError(f"package directory changed while captured: {child}")
                finally:
                    os.close(child_fd)
            elif stat.S_ISREG(before.st_mode):
                if len(output) >= MAX_FILES:
                    raise ValueError("package exceeds its file limit")
                output.append((child, read_file(directory_fd, name, child, before)))
            else:
                raise ValueError("package contains a symlink or unsupported entry")
        if identity(before_directory) != identity(os.fstat(directory_fd)):
            raise ValueError(f"package directory changed while captured: {relative}")

    root_fd = os.open(root, flags)
    try:
        visit(root_fd, Path(), 0)
    except OSError as exc:
        raise ValueError("package root or entry is missing, symlinked, or unstable") from exc
    finally:
        os.close(root_fd)
    return sorted(output, key=lambda item: item[0].as_posix())


def verify_package(package: Path, allowed_signers: Path, signer_identity: str) -> Mapping[str, bytes]:
    _safe_component(signer_identity, "signer identity")
    policy = held.read_stable_file(allowed_signers, "external allowed-signers policy", MAX_ROOT_BYTES)
    captured = _capture_package(package)
    if len(captured) > MAX_FILES or sum(len(data) for _, data in captured) > MAX_TOTAL_BYTES:
        raise ValueError("package exceeds aggregate verification limits")
    view = {path.as_posix(): data for path, data in captured}
    if "root.json" not in view or "root.json.sig" not in view:
        raise ValueError("package root or signature is missing")
    if len(view["root.json"]) > MAX_ROOT_BYTES or len(view["root.json.sig"]) > MAX_SIGNATURE_BYTES:
        raise ValueError("package root or signature is too large")
    root = _json(view["root.json"], "package root")
    if canonical_bytes(root) != view["root.json"]:
        raise ValueError("package root is not canonical")
    expected_fields = {
        "authority", "bindings", "contract", "custody", "entries",
        "payloadTreeDigest", "receiptStatus", "schemaVersion", "signature",
    }
    if set(root) != expected_fields or root["schemaVersion"] != 2 or root["contract"] != CONTRACT:
        raise ValueError("package root contract is invalid")
    if root["authority"] != AUTHORITY or root["custody"] != {
        "private": True,
        "retainedPayloadsInert": True,
        "receiptsAreOpaqueEvidence": True,
        "allowedSignersTrustedOnlyFromExternalExactMatch": True,
    }:
        raise ValueError("package authority or custody declaration is invalid")
    if root["signature"] != {"algorithm": "openssh", "identity": signer_identity, "namespace": SIGNATURE_NAMESPACE}:
        raise ValueError("package signer identity or namespace is invalid")
    entries = root["entries"]
    if not isinstance(entries, list) or len(entries) > MAX_FILES - 2:
        raise ValueError("package entry index is invalid")
    indexed: dict[str, dict[str, Any]] = {}
    for record in entries:
        if not isinstance(record, dict) or set(record) != {"digest", "path", "size"}:
            raise ValueError("package entry record is invalid")
        path = _safe_payload_path(record["path"])
        if not path.startswith("payload/") or path in indexed:
            raise ValueError("package entry index is duplicate or outside payload")
        indexed[path] = record
    if [record["path"] for record in entries] != sorted(indexed):
        raise ValueError("package entry index is not canonical")
    if set(view) != set(indexed) | {"root.json", "root.json.sig"}:
        raise ValueError("package contains missing or unindexed bytes")
    for path, record in indexed.items():
        if record["size"] != len(view[path]) or record["digest"] != digest(view[path]):
            raise ValueError(f"package entry digest mismatch: {path}")
    if root["payloadTreeDigest"] != digest(
        b"foxguard-held-out-provenance-v2:payload-tree\0" + canonical_bytes(entries)
    ):
        raise ValueError("package payload tree digest is invalid")
    evidence_policy = view.get("payload/policies/evidence.policy")
    if evidence_policy is None or evidence_policy != policy:
        raise ValueError("external allowed-signers policy does not exactly match retained evidence policy")
    _verify_signature(view["root.json"], view["root.json.sig"], policy, signer_identity)
    bindings = root.get("bindings")
    if not isinstance(bindings, dict) or bindings.get("offlineSourceReplayVerified") is not True or bindings.get("opaqueReceiptsExternallyVerified") is not False:
        raise ValueError("package overstates retained evidence verification")
    statuses = root.get("receiptStatus")
    if not isinstance(statuses, list) or not statuses:
        raise ValueError("package receipt status index is invalid")
    expected_statuses = []
    for record in statuses:
        if not isinstance(record, dict) or set(record) != {"digest", "name", "path", "status"}:
            raise ValueError("package receipt status record is invalid")
        name = _safe_component(record["name"], "receipt name")
        path = _safe_payload_path(record["path"])
        if path != f"payload/receipts/{name}.receipt" or path not in view or record["digest"] != digest(view[path]):
            raise ValueError("package receipt status binding is invalid")
        status = (
            "descriptor-bound-not-independently-verified" if name == "ci"
            else "opaque-not-independently-verified"
        )
        if record["status"] != status:
            raise ValueError("package receipt verification is overstated")
        expected_statuses.append(record)
    status_names = [item["name"] for item in statuses]
    status_paths = [item["path"] for item in statuses]
    retained_receipts = {path for path in view if path.startswith("payload/receipts/")}
    if (
        statuses != sorted(expected_statuses, key=lambda item: item["name"])
        or len(status_names) != len(set(status_names))
        or len(status_paths) != len(set(status_paths))
        or set(status_paths) != retained_receipts
        or sum(item["name"] == "ci" for item in statuses) != 1
    ):
        raise ValueError("package receipt status index is not canonical")
    if bindings.get("capabilityEvidenceDigest") != digest(view["payload/evidence/capability.json"]):
        raise ValueError("capability binding is invalid")
    if bindings.get("sourceDescriptorDigest") != digest(view["payload/source/descriptor.json"]):
        raise ValueError("source binding is invalid")
    if bindings.get("manifestDigest") != digest(view["payload/corpus/manifest.json"]):
        raise ValueError("manifest binding is invalid")
    capability_bytes = view["payload/evidence/capability.json"]
    descriptor_bytes = view["payload/source/descriptor.json"]
    capability = _json(capability_bytes, "retained capability evidence")
    descriptor = _json(descriptor_bytes, "retained source descriptor")
    evaluator_prefix = "payload/evaluators/"
    evaluators = {
        path[len(evaluator_prefix):]: data
        for path, data in view.items() if path.startswith(evaluator_prefix)
    }
    _validate_retained_evaluators(evaluators)
    build_prefix = "payload/build/"
    build = {
        path[len(build_prefix):]: data
        for path, data in view.items() if path.startswith(build_prefix)
    }
    _validate_build_inputs(descriptor, build)
    manifest = _json(view["payload/corpus/manifest.json"], "retained corpus manifest")
    with tempfile.TemporaryDirectory(prefix="foxguard-provenance-corpus-") as directory:
        corpus_root = Path(directory)
        _write_new(corpus_root / "manifest.json", view["payload/corpus/manifest.json"])
        for case in manifest.get("cases", []):
            if not isinstance(case, dict):
                raise ValueError("retained corpus case is invalid")
            case_id = _safe_component(case.get("id"), "case id")
            relative = PurePosixPath(str(case.get("path", "")))
            if relative.is_absolute() or ".." in relative.parts or not relative.parts:
                raise ValueError("retained corpus fixture path is unsafe")
            prefix = f"payload/corpus/fixtures/{case_id}/"
            fixture_entries = [(path[len(prefix):], data) for path, data in view.items() if path.startswith(prefix)]
            if not fixture_entries:
                raise ValueError("retained corpus fixture is missing")
            for suffix, data in fixture_entries:
                target = corpus_root.joinpath(*relative.parts, *PurePosixPath(suffix).parts)
                _write_new(target, data)
        corpus = held.capture_corpus(corpus_root / "manifest.json", require_trusted=False)
    cases = [case["id"] for case in corpus.manifest["cases"]]
    reports = {
        (arm, case): view[f"payload/reports/{arm}/{case}.json"]
        for arm in ("champion", "challenger") for case in cases
    }
    oracles = {case: view[f"payload/corpus/oracles/{case}.receipt"] for case in cases}
    binaries = {arm: view[f"payload/binaries/{arm}.bin"] for arm in ("champion", "challenger")}
    recomputed = _validate_semantics(
        SimpleNamespace(candidate_id=bindings.get("candidateId")),
        capability_bytes,
        capability,
        descriptor_bytes,
        descriptor,
        corpus,
        evaluators["held_out.py"],
        binaries,
        reports,
        oracles,
        view["payload/source/repository.bundle"],
        view["payload/receipts/ci.receipt"],
    )
    if bindings != recomputed:
        raise ValueError("signed semantic bindings are not exactly recomputable")
    return MappingProxyType(dict(view))
