#!/usr/bin/env python3
"""Bind a Foxguard candidate to the exact source change and executed binaries."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


CONTRACT = "foxguard-executed-source-change-v1"
REPOSITORY = "0sec-labs/foxguard"
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
MAX_PATCH_BYTES = 2 * 1024 * 1024
BUILD_ARGV = ["cargo", "build", "--locked", "--release", "--bin", "foxguard"]
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


def git(root: Path, *args: str, input_bytes: bytes | None = None, env: dict[str, str] | None = None) -> bytes:
    process = subprocess.run(
        ["git", "-C", str(root.resolve()), *args], input=input_bytes,
        capture_output=True, env=env,
    )
    if process.returncode:
        raise ValueError(
            f"git {' '.join(args)} failed: {process.stderr.decode(errors='replace').strip()}"
        )
    return process.stdout


def approved_checkout(root: Path) -> None:
    remote = git(root, "remote", "get-url", "origin").decode().strip()
    if remote not in APPROVED_REMOTES:
        raise ValueError("source root is not the approved Foxguard repository")
    if git(root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise ValueError("source checkout must be clean")


def commit_identity_at(root: Path, ref: str) -> dict[str, str]:
    commit_sha = git(root, "rev-parse", ref).decode().strip()
    tree_oid = git(root, "rev-parse", f"{ref}^{{tree}}").decode().strip()
    records = git(root, "ls-tree", "-r", "-z", "--full-tree", ref)
    return {
        "commitSha": commit_sha,
        "contentTreeDigest": sha256_bytes(b"foxguard-git-content-tree-v1\0" + records),
        "gitTreeOid": tree_oid,
    }


def commit_identity(root: Path) -> dict[str, str]:
    return commit_identity_at(root, "HEAD")


def validate_path(path: str) -> None:
    candidate = Path(path)
    if candidate.is_absolute() or ".." in candidate.parts or not path:
        raise ValueError(f"changed path is unsafe: {path}")
    if not (path.startswith("src/rules/") or path.startswith("tests/")):
        raise ValueError(f"changed path is outside the first Foxguard profile: {path}")


def tree_mode(root: Path, ref: str, path: str) -> str | None:
    record = git(root, "ls-tree", "-z", ref, "--", path)
    if not record:
        return None
    header, separator, recorded_path = record.rstrip(b"\0").partition(b"\t")
    if not separator or recorded_path.decode("utf-8", errors="strict") != path:
        raise ValueError(f"git returned an invalid tree record for {path}")
    mode, object_type, _object_id = header.decode("ascii").split(" ")
    if object_type != "blob" or mode not in {"100644", "100755"}:
        raise ValueError(f"candidate paths must remain regular Git blobs: {path}")
    return mode


def changed_entries(root: Path, base: str, head: str) -> list[dict[str, str]]:
    raw = [item for item in git(
        root, "diff", "--name-status", "--no-renames", "-z", base, head,
    ).split(b"\0") if item]
    if len(raw) % 2:
        raise ValueError("git returned an invalid changed-path stream")
    entries = []
    for index in range(0, len(raw), 2):
        status = raw[index].decode("ascii", errors="strict")
        path = raw[index + 1].decode("utf-8", errors="strict")
        if status not in {"A", "D", "M"}:
            raise ValueError(f"unsupported candidate path status: {status}")
        validate_path(path)
        base_mode = tree_mode(root, base, path)
        head_mode = tree_mode(root, head, path)
        if (
            (status == "A" and (base_mode is not None or head_mode is None))
            or (status == "D" and (base_mode is None or head_mode is not None))
            or (status == "M" and (base_mode is None or head_mode is None))
        ):
            raise ValueError(f"candidate status does not match tree objects: {path}")
        entries.append({"path": path, "status": status})
    entries.sort(key=lambda item: item["path"])
    paths = [entry["path"] for entry in entries]
    if not paths or not any(path.startswith("src/rules/") for path in paths):
        raise ValueError("candidate must change at least one src/rules path")
    return entries


def patch_bytes(root: Path, base: str, head: str) -> bytes:
    value = git(
        root, "diff", "--no-ext-diff", "--no-textconv", "--no-renames",
        "--binary", "--full-index", base, head,
    )
    if not value or len(value) > MAX_PATCH_BYTES:
        raise ValueError("candidate patch must be non-empty and bounded")
    return value


def applied_tree_oid(root: Path, base: str, patch: bytes) -> str:
    with tempfile.TemporaryDirectory() as directory:
        index = Path(directory) / "index"
        env = dict(os.environ)
        env["GIT_INDEX_FILE"] = str(index)
        git(root, "read-tree", base, env=env)
        git(root, "apply", "--cached", "--whitespace=nowarn", "-", input_bytes=patch, env=env)
        return git(root, "write-tree", env=env).decode().strip()


def load_ci_receipt(path: Path, head: dict[str, str]) -> dict[str, Any]:
    value = json.loads(path.read_text())
    fields = {"conclusion", "headCommitSha", "headTreeOid", "repository", "runId", "workflowRef"}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("CI receipt schema is invalid")
    if (
        value["repository"] != REPOSITORY
        or value["conclusion"] != "success"
        or value["headCommitSha"] != head["commitSha"]
        or value["headTreeOid"] != head["gitTreeOid"]
        or not isinstance(value["runId"], str)
        or not value["runId"].isdigit()
        or not isinstance(value["workflowRef"], str)
        or value["workflowRef"] != f"0sec-labs/foxguard/.github/workflows/ci.yml@{head['commitSha']}"
    ):
        raise ValueError("CI receipt is not a successful exact-head Foxguard run")
    return value


def toolchain_identity(root: Path) -> dict[str, str]:
    process = subprocess.run(["rustc", "--version", "--verbose"], capture_output=True)
    if process.returncode:
        raise ValueError("rustc toolchain identity is unavailable")
    return {
        "cargoLockDigest": sha256_file(root / "Cargo.lock"),
        "cargoTomlDigest": sha256_file(root / "Cargo.toml"),
        "rustcVerboseDigest": sha256_bytes(process.stdout),
    }


def validate_identity(value: Any, label: str) -> dict[str, str]:
    fields = {"commitSha", "contentTreeDigest", "gitTreeOid"}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"{label} identity schema is invalid")
    if not SHA_RE.fullmatch(value["commitSha"]) or not SHA_RE.fullmatch(value["gitTreeOid"]):
        raise ValueError(f"{label} git identity is invalid")
    if not DIGEST_RE.fullmatch(value["contentTreeDigest"]):
        raise ValueError(f"{label} content tree digest is invalid")
    return dict(value)


def validate_descriptor(value: Any, *, repository_root: Path | None = None) -> dict[str, Any]:
    fields = {
        "base", "binaryDigests", "buildArgv", "candidateChangeDigest", "candidateId",
        "ciReceipt", "contract", "head", "patch", "provenance", "repository", "schemaVersion", "toolchain",
    }
    if not isinstance(value, dict) or set(value) != fields or value["schemaVersion"] != 1 or value["contract"] != CONTRACT:
        raise ValueError("executed-change descriptor schema or contract is invalid")
    if value["repository"] != REPOSITORY or not isinstance(value["candidateId"], str) or not SAFE_ID_RE.fullmatch(value["candidateId"]):
        raise ValueError("executed-change descriptor identity is invalid")
    if value["provenance"] != {"buildVerified": False, "ciVerified": False}:
        raise ValueError("source descriptor must not claim trusted build or CI provenance")
    base = validate_identity(value["base"], "base")
    head = validate_identity(value["head"], "head")
    if base["commitSha"] == head["commitSha"]:
        raise ValueError("base and head commits must differ")
    patch = value["patch"]
    patch_fields = {"changedPaths", "changes", "digest", "encoding", "format", "value"}
    if not isinstance(patch, dict) or set(patch) != patch_fields or patch["encoding"] != "base64" or patch["format"] != "git-binary-full-index-v1":
        raise ValueError("patch schema is invalid")
    try:
        raw_patch = base64.b64decode(patch["value"], validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("patch encoding is invalid") from exc
    if not raw_patch or len(raw_patch) > MAX_PATCH_BYTES or patch["digest"] != sha256_bytes(raw_patch):
        raise ValueError("patch digest or size is invalid")
    paths = patch["changedPaths"]
    if (
        not isinstance(paths, list)
        or not all(isinstance(path, str) for path in paths)
        or paths != sorted(set(paths))
        or not any(path.startswith("src/rules/") for path in paths)
    ):
        raise ValueError("changed paths are invalid")
    for path in paths:
        validate_path(path)
    changes = patch["changes"]
    if (
        not isinstance(changes, list)
        or changes != sorted(changes, key=lambda item: item.get("path", "") if isinstance(item, dict) else "")
        or any(not isinstance(item, dict) or set(item) != {"path", "status"} or item["status"] not in {"A", "D", "M"} for item in changes)
        or [item["path"] for item in changes] != paths
    ):
        raise ValueError("changed path/status entries are invalid")
    binaries = value["binaryDigests"]
    if not isinstance(binaries, dict) or set(binaries) != {"challenger", "champion"} or not all(DIGEST_RE.fullmatch(str(item)) for item in binaries.values()):
        raise ValueError("binary digests are invalid")
    argv = value["buildArgv"]
    if argv != BUILD_ARGV:
        raise ValueError("build argv must match the fixed Foxguard release build")
    toolchain = value["toolchain"]
    if not isinstance(toolchain, dict) or set(toolchain) != {"cargoLockDigest", "cargoTomlDigest", "rustcVerboseDigest"} or not all(DIGEST_RE.fullmatch(str(item)) for item in toolchain.values()):
        raise ValueError("toolchain identity is invalid")
    receipt = value["ciReceipt"]
    receipt_fields = {"conclusion", "headCommitSha", "headTreeOid", "repository", "runId", "workflowRef"}
    if (
        not isinstance(receipt, dict)
        or set(receipt) != receipt_fields
        or receipt["conclusion"] != "success"
        or receipt["repository"] != REPOSITORY
        or receipt["headCommitSha"] != head["commitSha"]
        or receipt["headTreeOid"] != head["gitTreeOid"]
        or not isinstance(receipt["runId"], str)
        or not receipt["runId"].isdigit()
        or not isinstance(receipt["workflowRef"], str)
        or receipt["workflowRef"] != f"0sec-labs/foxguard/.github/workflows/ci.yml@{head['commitSha']}"
    ):
        raise ValueError("CI receipt does not bind the exact head")
    change_basis = {
        "base": base,
        "head": head,
        "patchDigest": patch["digest"],
        "changedPaths": paths,
        "changes": changes,
    }
    expected_change_digest = sha256_bytes(b"foxguard-executed-source-change-v1\0" + canonical_bytes(change_basis))
    if value["candidateChangeDigest"] != expected_change_digest:
        raise ValueError("candidate change digest is not recomputable")
    if repository_root is not None:
        approved_checkout(repository_root)
        if commit_identity(repository_root) != base:
            raise ValueError("verification checkout does not match descriptor base")
        ancestor = subprocess.run(
            ["git", "-C", str(repository_root.resolve()), "merge-base", "--is-ancestor", base["commitSha"], head["commitSha"]],
            capture_output=True,
        )
        if ancestor.returncode != 0:
            raise ValueError("descriptor head is not a descendant of its base")
        if commit_identity_at(repository_root, head["commitSha"]) != head:
            raise ValueError("descriptor head identity does not match repository objects")
        if (
            sha256_bytes(git(repository_root, "show", f"{head['commitSha']}:Cargo.toml")) != toolchain["cargoTomlDigest"]
            or sha256_bytes(git(repository_root, "show", f"{head['commitSha']}:Cargo.lock")) != toolchain["cargoLockDigest"]
        ):
            raise ValueError("Cargo input digests do not match the exact head")
        if changed_entries(repository_root, base["commitSha"], head["commitSha"]) != changes:
            raise ValueError("changed path/status entries do not match repository objects")
        if patch_bytes(repository_root, base["commitSha"], head["commitSha"]) != raw_patch:
            raise ValueError("patch bytes do not match repository objects")
        if applied_tree_oid(repository_root, base["commitSha"], raw_patch) != head["gitTreeOid"]:
            raise ValueError("retained patch does not reproduce the exact head tree")
    return value


def build_descriptor(args: argparse.Namespace) -> dict[str, Any]:
    approved_checkout(args.base_source_root)
    approved_checkout(args.head_source_root)
    base = commit_identity(args.base_source_root)
    head = commit_identity(args.head_source_root)
    ancestor = subprocess.run(
        ["git", "-C", str(args.base_source_root.resolve()), "merge-base", "--is-ancestor", base["commitSha"], head["commitSha"]],
        capture_output=True,
    )
    if ancestor.returncode != 0:
        raise ValueError("candidate head must descend from its base")
    changes = changed_entries(args.base_source_root, base["commitSha"], head["commitSha"])
    paths = [item["path"] for item in changes]
    patch = patch_bytes(args.base_source_root, base["commitSha"], head["commitSha"])
    if applied_tree_oid(args.base_source_root, base["commitSha"], patch) != head["gitTreeOid"]:
        raise ValueError("patch does not reproduce the exact head tree")
    patch_digest = sha256_bytes(patch)
    change_basis = {
        "base": base, "head": head, "patchDigest": patch_digest,
        "changedPaths": paths, "changes": changes,
    }
    value = {
        "schemaVersion": 1,
        "contract": CONTRACT,
        "candidateId": args.candidate_id,
        "repository": REPOSITORY,
        "provenance": {"buildVerified": False, "ciVerified": False},
        "base": base,
        "head": head,
        "patch": {
            "changedPaths": paths,
            "changes": changes,
            "digest": patch_digest,
            "encoding": "base64",
            "format": "git-binary-full-index-v1",
            "value": base64.b64encode(patch).decode(),
        },
        "candidateChangeDigest": sha256_bytes(b"foxguard-executed-source-change-v1\0" + canonical_bytes(change_basis)),
        "binaryDigests": {
            "champion": sha256_file(args.champion_binary),
            "challenger": sha256_file(args.challenger_binary),
        },
        "buildArgv": BUILD_ARGV,
        "toolchain": toolchain_identity(args.head_source_root),
        "ciReceipt": load_ci_receipt(args.ci_receipt, head),
    }
    return validate_descriptor(value, repository_root=args.base_source_root)


def artifact_ref(path: Path) -> str:
    return f"foxguard-executed-source-change-v1:{sha256_file(path)}"


def main() -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build")
    build.add_argument("--candidate-id", required=True)
    build.add_argument("--base-source-root", required=True, type=Path)
    build.add_argument("--head-source-root", required=True, type=Path)
    build.add_argument("--champion-binary", required=True, type=Path)
    build.add_argument("--challenger-binary", required=True, type=Path)
    build.add_argument("--ci-receipt", required=True, type=Path)
    build.add_argument("--output", required=True, type=Path)
    verify = commands.add_parser("verify")
    verify.add_argument("--artifact", required=True, type=Path)
    verify.add_argument("--base-source-root", required=True, type=Path)
    verify.add_argument("--ref")
    args = parser.parse_args()
    try:
        if args.command == "build":
            value = build_descriptor(args)
            write_new_private(args.output, canonical_bytes(value))
            print(artifact_ref(args.output))
        else:
            validate_descriptor(json.loads(args.artifact.read_text()), repository_root=args.base_source_root)
            if args.ref and args.ref != artifact_ref(args.artifact):
                raise ValueError("artifact reference does not match retained bytes")
            print(artifact_ref(args.artifact))
        return 0
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
