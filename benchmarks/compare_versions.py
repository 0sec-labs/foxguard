#!/usr/bin/env python3
"""Cross-version foxguard benchmark harness.

Builds foxguard at multiple git refs in isolated worktrees, then benchmarks each
binary against the same repository fixtures.
"""

from __future__ import annotations

import argparse
import shutil
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


REPOS = {
    "express": "https://github.com/expressjs/express.git",
    "flask": "https://github.com/pallets/flask.git",
    "gin": "https://github.com/gin-gonic/gin.git",
}


@dataclass
class BenchSummary:
    avg_ms: float
    p50_ms: float
    p95_ms: float


def run(cmd: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def ensure_repo_checkout(path: Path, url: str) -> None:
    if path.exists():
        return
    run(["git", "clone", "--depth", "1", url, str(path)])


def sanitize_ref(ref: str) -> str:
    return ref.replace("/", "-").replace(" ", "-")


def build_ref(repo_root: Path, ref: str, worktree_root: Path) -> Path:
    worktree = worktree_root / sanitize_ref(ref)
    if worktree.exists():
        run(["git", "worktree", "remove", "--force", str(worktree)], cwd=repo_root)
    run(["git", "worktree", "add", "--detach", str(worktree), ref], cwd=repo_root)
    run(["cargo", "build", "--release"], cwd=worktree)
    binary = worktree / "target" / "release" / "foxguard"
    if not binary.exists():
        raise RuntimeError(f"foxguard binary not found after build at ref {ref}")
    return binary


def benchmark_binary(
    binary: Path,
    target: Path,
    warmup_runs: int,
    iterations: int,
) -> BenchSummary:
    for _ in range(warmup_runs):
        subprocess.run(
            [str(binary), str(target)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )

    samples = []
    for _ in range(iterations):
        start = time.perf_counter()
        subprocess.run(
            [str(binary), str(target)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        samples.append(elapsed_ms)

    ordered = sorted(samples)
    p95_index = max(0, int(0.95 * len(ordered)) - 1)
    return BenchSummary(
        avg_ms=statistics.mean(samples),
        p50_ms=statistics.median(samples),
        p95_ms=ordered[p95_index],
    )


def markdown_table(
    refs: list[str],
    results: dict[tuple[str, str], BenchSummary],
    iterations: int,
    warmup_runs: int,
) -> str:
    lines = []
    lines.append("# foxguard version comparison benchmark")
    lines.append("")
    lines.append(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append(f"Iterations per target: {iterations}")
    lines.append(f"Warmup runs per target: {warmup_runs}")
    lines.append("")
    lines.append("| Ref | Repo | avg (ms) | p50 (ms) | p95 (ms) |")
    lines.append("|-----|------|----------|----------|----------|")
    for ref in refs:
        for repo_name in REPOS:
            summary = results[(ref, repo_name)]
            lines.append(
                f"| `{ref}` | {repo_name} | {summary.avg_ms:.2f} | {summary.p50_ms:.2f} | {summary.p95_ms:.2f} |"
            )
    lines.append("")
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--refs",
        default="v0.4.0,v0.6.3,main",
        help="comma-separated git refs to benchmark",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=10,
        help="timed scan runs per repo",
    )
    parser.add_argument(
        "--warmup",
        type=int,
        default=2,
        help="warmup runs per repo before timed iterations",
    )
    parser.add_argument(
        "--output",
        default="benchmarks/results-version-compare.md",
        help="output markdown file path",
    )
    parser.add_argument(
        "--keep-worktrees",
        action="store_true",
        help="keep temporary worktrees after completion",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = Path(__file__).resolve().parents[1]
    benchmarks_root = repo_root / "benchmarks"
    repos_root = benchmarks_root / "repos"
    worktree_root = benchmarks_root / ".version-worktrees"
    output_path = repo_root / args.output

    refs = [part.strip() for part in args.refs.split(",") if part.strip()]
    if not refs:
        print("No refs provided", file=sys.stderr)
        return 2

    run(["git", "fetch", "--tags", "origin"], cwd=repo_root)

    repos_root.mkdir(parents=True, exist_ok=True)
    for name, url in REPOS.items():
        ensure_repo_checkout(repos_root / name, url)

    worktree_root.mkdir(parents=True, exist_ok=True)
    results: dict[tuple[str, str], BenchSummary] = {}

    try:
        for ref in refs:
            print(f"[build] {ref}")
            binary = build_ref(repo_root, ref, worktree_root)
            for repo_name in REPOS:
                target = repos_root / repo_name
                print(f"[bench] {ref} :: {repo_name}")
                summary = benchmark_binary(
                    binary=binary,
                    target=target,
                    warmup_runs=args.warmup,
                    iterations=args.iterations,
                )
                results[(ref, repo_name)] = summary
                print(
                    f"        avg={summary.avg_ms:.2f}ms p50={summary.p50_ms:.2f}ms p95={summary.p95_ms:.2f}ms"
                )

        report = markdown_table(
            refs=refs,
            results=results,
            iterations=args.iterations,
            warmup_runs=args.warmup,
        )
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(report, encoding="utf-8")
        print(f"\nWrote {output_path}")
        return 0
    finally:
        if not args.keep_worktrees and worktree_root.exists():
            for child in worktree_root.iterdir():
                if child.is_dir():
                    subprocess.run(
                        ["git", "worktree", "remove", "--force", str(child)],
                        cwd=repo_root,
                        check=False,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
            shutil.rmtree(worktree_root, ignore_errors=True)
            subprocess.run(
                ["git", "worktree", "prune"],
                cwd=repo_root,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )


if __name__ == "__main__":
    raise SystemExit(main())
