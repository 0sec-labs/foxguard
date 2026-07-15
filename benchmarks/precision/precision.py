#!/usr/bin/env python3
"""Labeled precision corpus runner for foxguard.

The harness scans pinned OSS repositories, joins findings against reviewed
labels, and writes per-rule / aggregate precision metrics. It is intentionally
stdlib-only so CI can run it without Python package setup.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from zero_research import control_corpus_digest, control_evaluator_digest

try:
    import tomllib  # type: ignore[import-not-found]
except ModuleNotFoundError:  # Python < 3.11
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:
        sys.stderr.write(
            "error: this harness needs Python 3.11+ or `pip install tomli`.\n"
        )
        sys.exit(2)


REPO_ROOT = Path(__file__).resolve().parents[2]
PRECISION_DIR = Path(__file__).resolve().parent
DEFAULT_MANIFEST = PRECISION_DIR / "corpus.toml"
DEFAULT_LABELS = PRECISION_DIR / "labels.jsonl"
DEFAULT_EXPECTED = PRECISION_DIR / "expected.json"
DEFAULT_RESULTS = PRECISION_DIR / "results"
DEFAULT_WORKDIR = PRECISION_DIR / "clones"
LABELS = {"true_positive", "false_positive", "unsure"}


@dataclass
class Settings:
    fail_on_missing_labels: bool = True
    warn_precision_drop_pp: float = 5.0
    fail_precision_drop_pp: float = 10.0
    warn_noise_increase_pp: float = 5.0
    fail_noise_increase_pp: float = 10.0


@dataclass
class RepoEntry:
    name: str
    url: str
    ref: str
    language: str
    scan_subdir: str = "."
    exclude: list[str] = field(default_factory=list)
    skip: bool = False
    notes: str = ""


@dataclass(frozen=True)
class Label:
    id: str
    repo: str
    rule_id: str
    file: str
    line: int
    label: str
    justification: str


@dataclass
class NormalizedFinding:
    id: str
    repo: str
    rule_id: str
    file: str
    line: int
    column: int
    snippet: str
    severity: str
    description: str
    duplicate_index: int
    label: str | None = None
    justification: str | None = None


def run_process(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    try:
        # Commands come from the pinned corpus manifest or the explicit
        # --foxguard binary path, never from scanned repository contents.
        return subprocess.run(  # noqa: S603  # foxguard: ignore[py/no-command-injection]
            args,
            cwd=cwd,
            text=True,
            capture_output=True,
        )
    except OSError as exc:
        command = args[0] if args else "<empty command>"
        raise SystemExit(f"error: failed to run {command!r}: {exc}") from exc


def run_cmd(args: list[str], cwd: Path | None = None, allow_findings: bool = False) -> str:
    proc = run_process(args, cwd=cwd)
    if proc.returncode == 0 or (allow_findings and proc.returncode == 1):
        return proc.stdout
    sys.stderr.write(proc.stdout)
    sys.stderr.write(proc.stderr)
    raise SystemExit(proc.returncode if proc.returncode else 2)


def try_cmd(args: list[str], cwd: Path | None = None) -> str | None:
    proc = run_process(args, cwd=cwd)
    if proc.returncode == 0:
        return proc.stdout
    return None


def load_manifest(path: Path) -> tuple[list[RepoEntry], Settings]:
    with path.open("rb") as fh:
        data = tomllib.load(fh)
    raw_settings = data.get("settings", {})
    settings = Settings(
        fail_on_missing_labels=bool(raw_settings.get("fail_on_missing_labels", True)),
        warn_precision_drop_pp=float(raw_settings.get("warn_precision_drop_pp", 5.0)),
        fail_precision_drop_pp=float(raw_settings.get("fail_precision_drop_pp", 10.0)),
        warn_noise_increase_pp=float(raw_settings.get("warn_noise_increase_pp", 5.0)),
        fail_noise_increase_pp=float(raw_settings.get("fail_noise_increase_pp", 10.0)),
    )
    repos = [
        RepoEntry(
            name=raw["name"],
            url=raw["url"],
            ref=raw["ref"],
            language=raw["language"],
            scan_subdir=raw.get("scan_subdir", "."),
            exclude=list(raw.get("exclude", [])),
            skip=bool(raw.get("skip", False)),
            notes=raw.get("notes", ""),
        )
        for raw in data.get("repos", [])
    ]
    return repos, settings


def load_labels(path: Path) -> dict[str, Label]:
    labels: dict[str, Label] = {}
    if not path.exists():
        return labels
    for lineno, line in enumerate(path.read_text().splitlines(), start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"{path}:{lineno}: invalid JSON: {exc}") from exc
        label = str(raw.get("label", ""))
        justification = str(raw.get("justification", "")).strip()
        if label not in LABELS:
            raise SystemExit(f"{path}:{lineno}: invalid label {label!r}")
        if not justification or "\n" in justification:
            raise SystemExit(f"{path}:{lineno}: justification must be one line")
        try:
            item = Label(
                id=str(raw["id"]),
                repo=str(raw["repo"]),
                rule_id=str(raw["rule_id"]),
                file=str(raw["file"]),
                line=int(raw["line"]),
                label=label,
                justification=justification,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise SystemExit(f"{path}:{lineno}: invalid label row: {exc}") from exc
        if item.id in labels:
            raise SystemExit(f"{path}:{lineno}: duplicate label id {item.id}")
        labels[item.id] = item
    if set(labels) == {"placeholder"}:
        return {}
    return labels


def ensure_repo(repo: RepoEntry, workdir: Path) -> Path:
    target = workdir / repo.name
    if not target.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
        run_cmd(["git", "clone", "--filter=blob:none", repo.url, str(target)])
    else:
        head = (try_cmd(["git", "rev-parse", "HEAD"], cwd=target) or "").strip()
        wanted = (
            try_cmd(["git", "rev-parse", f"{repo.ref}^{{commit}}"], cwd=target) or ""
        ).strip()
        if head != wanted:
            run_cmd(["git", "fetch", "--tags", "--prune", "origin"], cwd=target)
    run_cmd(["git", "checkout", "--detach", repo.ref], cwd=target)
    return target


def normalize_snippet(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip())


def finding_base(repo: str, finding: dict[str, Any]) -> str:
    parts = [
        repo,
        str(finding.get("rule_id", "")),
        str(finding.get("file", "")),
        str(finding.get("line", 0)),
        str(finding.get("column", 0)),
        normalize_snippet(str(finding.get("snippet", ""))),
    ]
    return "\0".join(parts)


def finding_id(repo: str, finding: dict[str, Any], duplicate_index: int) -> str:
    payload = finding_base(repo, finding) + "\0" + str(duplicate_index)
    return hashlib.sha256(payload.encode()).hexdigest()[:20]


def rel_file(path_value: str, repo_dir: Path) -> str:
    path = Path(path_value)
    try:
        return path.resolve().relative_to(repo_dir.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def scan_repo(repo: RepoEntry, repo_dir: Path, foxguard: Path, results_dir: Path) -> list[NormalizedFinding]:
    out_path = results_dir / f"{repo.name}.foxguard.json"
    scan_path = repo_dir / repo.scan_subdir
    args = [
        str(foxguard),
        "--config",
        "/dev/null",
        str(scan_path),
        "-f",
        "json",
        "--output",
        str(out_path),
    ]
    for pattern in repo.exclude:
        args.extend(["--exclude", pattern])
    run_cmd(args, allow_findings=True)

    report = json.loads(out_path.read_text())
    raw_findings = report.get("findings", [])
    normalized_raw: list[dict[str, Any]] = []
    for finding in raw_findings:
        item = dict(finding)
        item["file"] = rel_file(str(item.get("file", "")), repo_dir)
        normalized_raw.append(item)

    counts: dict[str, int] = {}
    normalized: list[NormalizedFinding] = []
    for item in sorted(
        normalized_raw,
        key=lambda f: (
            str(f.get("file", "")),
            int(f.get("line", 0)),
            int(f.get("column", 0)),
            str(f.get("rule_id", "")),
            normalize_snippet(str(f.get("snippet", ""))),
        ),
    ):
        base = finding_base(repo.name, item)
        counts[base] = counts.get(base, 0) + 1
        duplicate_index = counts[base]
        normalized.append(
            NormalizedFinding(
                id=finding_id(repo.name, item, duplicate_index),
                repo=repo.name,
                rule_id=str(item.get("rule_id", "")),
                file=str(item.get("file", "")),
                line=int(item.get("line", 0)),
                column=int(item.get("column", 0)),
                snippet=normalize_snippet(str(item.get("snippet", ""))),
                severity=str(item.get("severity", "")),
                description=str(item.get("description", "")),
                duplicate_index=duplicate_index,
            )
        )
    return normalized


def apply_labels(findings: list[NormalizedFinding], labels: dict[str, Label]) -> tuple[list[NormalizedFinding], list[str], list[str]]:
    seen: set[str] = set()
    missing: list[str] = []
    for finding in findings:
        label = labels.get(finding.id)
        if label:
            finding.label = label.label
            finding.justification = label.justification
            seen.add(finding.id)
        else:
            missing.append(finding.id)
    stale = sorted(set(labels) - seen)
    return findings, missing, stale


def empty_bucket() -> dict[str, Any]:
    return {
        "total": 0,
        "labeled": 0,
        "true_positive": 0,
        "false_positive": 0,
        "unsure": 0,
        "reviewed": 0,
        "reviewed_precision": 0.0,
        "reviewed_noise_rate": 0.0,
    }


def add_to_bucket(bucket: dict[str, Any], label: str | None) -> None:
    bucket["total"] += 1
    if label is None:
        return
    bucket["labeled"] += 1
    if label == "true_positive":
        bucket["true_positive"] += 1
        bucket["reviewed"] += 1
    elif label == "false_positive":
        bucket["false_positive"] += 1
        bucket["reviewed"] += 1
    elif label == "unsure":
        bucket["unsure"] += 1


def finalize_bucket(bucket: dict[str, Any]) -> dict[str, Any]:
    reviewed = bucket["reviewed"]
    if reviewed:
        bucket["reviewed_precision"] = round(bucket["true_positive"] / reviewed, 4)
        bucket["reviewed_noise_rate"] = round(bucket["false_positive"] / reviewed, 4)
    return bucket


def build_metrics(findings: list[NormalizedFinding], repos: list[RepoEntry]) -> dict[str, Any]:
    aggregate = empty_bucket()
    by_repo: dict[str, dict[str, Any]] = {repo.name: empty_bucket() for repo in repos if not repo.skip}
    by_rule: dict[str, dict[str, Any]] = {}
    for finding in findings:
        add_to_bucket(aggregate, finding.label)
        add_to_bucket(by_repo.setdefault(finding.repo, empty_bucket()), finding.label)
        add_to_bucket(by_rule.setdefault(finding.rule_id, empty_bucket()), finding.label)

    return {
        "schema_version": 1,
        "generated_by": "benchmarks/precision/precision.py",
        "aggregate": finalize_bucket(aggregate),
        "repos": {k: finalize_bucket(v) for k, v in sorted(by_repo.items())},
        "rules": {k: finalize_bucket(v) for k, v in sorted(by_rule.items())},
    }


def finding_record(finding: NormalizedFinding) -> dict[str, Any]:
    return {
        "id": finding.id,
        "repo": finding.repo,
        "rule_id": finding.rule_id,
        "file": finding.file,
        "line": finding.line,
        "column": finding.column,
        "duplicate_index": finding.duplicate_index,
        "severity": finding.severity,
        "label": finding.label,
        "justification": finding.justification,
        "snippet": finding.snippet,
    }


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def write_summary_md(path: Path, metrics: dict[str, Any], missing: list[str], stale: list[str]) -> None:
    agg = metrics["aggregate"]
    lines = [
        "# foxguard precision corpus",
        "",
        "Generated by `benchmarks/precision/run.sh`.",
        "",
        "## Aggregate",
        "",
        "| Findings | Labeled | TP | FP | Unsure | Reviewed precision | Reviewed noise |",
        "|---------:|--------:|---:|---:|-------:|-------------------:|---------------:|",
        (
            f"| {agg['total']} | {agg['labeled']} | {agg['true_positive']} | "
            f"{agg['false_positive']} | {agg['unsure']} | "
            f"{agg['reviewed_precision']:.1%} | {agg['reviewed_noise_rate']:.1%} |"
        ),
        "",
        "## Per Rule",
        "",
        "| Rule | Findings | TP | FP | Unsure | Reviewed precision |",
        "|------|---------:|---:|---:|-------:|-------------------:|",
    ]
    for rule, data in metrics["rules"].items():
        lines.append(
            f"| `{rule}` | {data['total']} | {data['true_positive']} | "
            f"{data['false_positive']} | {data['unsure']} | {data['reviewed_precision']:.1%} |"
        )
    lines += [
        "",
        "## Per Repo",
        "",
        "| Repo | Findings | TP | FP | Unsure | Reviewed precision |",
        "|------|---------:|---:|---:|-------:|-------------------:|",
    ]
    for repo, data in metrics["repos"].items():
        lines.append(
            f"| `{repo}` | {data['total']} | {data['true_positive']} | "
            f"{data['false_positive']} | {data['unsure']} | {data['reviewed_precision']:.1%} |"
        )
    if missing or stale:
        lines += ["", "## Label Drift", ""]
        if missing:
            lines.append(f"- Missing labels: {len(missing)}")
        if stale:
            lines.append(f"- Stale labels: {len(stale)}")
    path.write_text("\n".join(lines) + "\n")


def write_label_skeleton(path: Path, findings: list[NormalizedFinding], labels: dict[str, Label]) -> None:
    rows: list[dict[str, Any]] = []
    for finding in findings:
        label = labels.get(finding.id)
        rows.append(
            {
                "id": finding.id,
                "repo": finding.repo,
                "rule_id": finding.rule_id,
                "file": finding.file,
                "line": finding.line,
                "label": label.label if label else "unsure",
                "justification": label.justification if label else "Needs review.",
            }
        )
    path.write_text("\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n")


def compare_bucket(
    label: str,
    current_bucket: dict[str, Any],
    expected_bucket: dict[str, Any],
    settings: Settings,
) -> bool:
    prior_precision = float(expected_bucket.get("reviewed_precision", 0.0))
    cur_precision = float(current_bucket.get("reviewed_precision", 0.0))
    prior_noise = float(expected_bucket.get("reviewed_noise_rate", 0.0))
    cur_noise = float(current_bucket.get("reviewed_noise_rate", 0.0))

    precision_delta_pp = (cur_precision - prior_precision) * 100
    noise_delta_pp = (cur_noise - prior_noise) * 100
    failed = False

    if -precision_delta_pp > settings.fail_precision_drop_pp:
        print(
            f"::error::{label} reviewed precision dropped "
            f"{abs(precision_delta_pp):.1f}pp "
            f"({prior_precision:.1%} -> {cur_precision:.1%})"
        )
        failed = True
    elif -precision_delta_pp > settings.warn_precision_drop_pp:
        print(
            f"::warning::{label} reviewed precision dropped "
            f"{abs(precision_delta_pp):.1f}pp "
            f"({prior_precision:.1%} -> {cur_precision:.1%})"
        )

    if noise_delta_pp > settings.fail_noise_increase_pp:
        print(
            f"::error::{label} reviewed noise increased {noise_delta_pp:.1f}pp "
            f"({prior_noise:.1%} -> {cur_noise:.1%})"
        )
        failed = True
    elif noise_delta_pp > settings.warn_noise_increase_pp:
        print(
            f"::warning::{label} reviewed noise increased {noise_delta_pp:.1f}pp "
            f"({prior_noise:.1%} -> {cur_noise:.1%})"
        )

    return failed


def compare_bucket_map(
    section: str,
    current_map: dict[str, Any],
    expected_map: dict[str, Any],
    settings: Settings,
) -> bool:
    failed = False
    singular = section[:-1]
    for key in sorted(set(current_map) | set(expected_map)):
        if key not in expected_map:
            print(
                f"::error::precision snapshot drift: new {singular} {key!r}; "
                "review labels and run --update-expected"
            )
            failed = True
            continue
        if key not in current_map:
            print(
                f"::error::precision snapshot drift: missing {singular} {key!r}; "
                "restore coverage or run --update-expected intentionally"
            )
            failed = True
            continue
        failed |= compare_bucket(
            f"{singular} {key!r}",
            current_map[key],
            expected_map[key],
            settings,
        )
    return failed


def expected_snapshot(metrics: dict[str, Any]) -> dict[str, Any]:
    return {
        k: v
        for k, v in metrics.items()
        if k not in {"duration_s", "missing_labels", "stale_labels"}
    }


def compare_expected(current: dict[str, Any], expected_path: Path, settings: Settings) -> int:
    if not expected_path.exists():
        print(f"::warning::missing expected snapshot: {expected_path}")
        return 0
    expected = json.loads(expected_path.read_text())
    failed = compare_bucket(
        "aggregate",
        current["aggregate"],
        expected.get("aggregate", {}),
        settings,
    )
    failed |= compare_bucket_map(
        "rules",
        current.get("rules", {}),
        expected.get("rules", {}),
        settings,
    )
    failed |= compare_bucket_map(
        "repos",
        current.get("repos", {}),
        expected.get("repos", {}),
        settings,
    )
    return 1 if failed else 0


def validate(manifest_path: Path, labels_path: Path, expected_path: Path) -> int:
    repos, _settings = load_manifest(manifest_path)
    names: set[str] = set()
    sha_re = re.compile(r"^[0-9a-f]{40}$")
    errors: list[str] = []
    for repo in repos:
        if repo.name in names:
            errors.append(f"duplicate repo name: {repo.name}")
        names.add(repo.name)
        if not sha_re.match(repo.ref):
            errors.append(f"{repo.name}: ref must be a full 40-character SHA")
        if not repo.url.startswith("https://"):
            errors.append(f"{repo.name}: url must be https")
    labels = load_labels(labels_path)
    for label in labels.values():
        if label.repo not in names:
            errors.append(f"{label.id}: unknown repo {label.repo}")
    if not expected_path.exists():
        errors.append(f"missing expected snapshot: {expected_path}")
    else:
        expected = json.loads(expected_path.read_text())
        if expected.get("schema_version") != 1:
            errors.append("expected.json schema_version must be 1")
        aggregate = expected.get("aggregate", {})
        if aggregate.get("labeled") != len(labels):
            errors.append(
                "expected.json aggregate.labeled must match labels.jsonl row count"
            )
        label_total = (
            int(aggregate.get("true_positive", 0))
            + int(aggregate.get("false_positive", 0))
            + int(aggregate.get("unsure", 0))
        )
        if label_total != len(labels):
            errors.append(
                "expected.json TP + FP + unsure must match labels.jsonl row count"
            )
    for error in errors:
        print(f"::error::{error}")
    if errors:
        return 1
    print(f"validated {len(repos)} repos and {len(labels)} labels")
    return 0


def run(args: argparse.Namespace) -> int:
    if args.check and args.update_expected:
        print("::error::--check and --update-expected cannot be used together")
        return 2

    repos, settings = load_manifest(args.manifest)
    labels = load_labels(args.labels)
    args.results_dir.mkdir(parents=True, exist_ok=True)
    all_findings: list[NormalizedFinding] = []
    start = time.perf_counter()

    for repo in repos:
        if repo.skip:
            continue
        print(f"[precision] {repo.name}: checkout {repo.ref}")
        repo_dir = ensure_repo(repo, args.workdir)
        print(f"[precision] {repo.name}: scan {repo.scan_subdir}")
        all_findings.extend(scan_repo(repo, repo_dir, args.foxguard, args.results_dir))

    all_findings, missing, stale = apply_labels(all_findings, labels)
    metrics = build_metrics(all_findings, repos)
    metrics["negative_control_corpus_digest"] = control_corpus_digest(
        args.manifest, args.labels
    )
    metrics["evaluator_digest"] = control_evaluator_digest(Path(__file__).resolve())
    metrics["duration_s"] = round(time.perf_counter() - start, 3)
    metrics["missing_labels"] = len(missing)
    metrics["stale_labels"] = len(stale)

    write_json(args.results_dir / "findings.json", [finding_record(f) for f in all_findings])
    write_json(args.results_dir / "summary.json", metrics)
    write_summary_md(args.results_dir / "summary.md", metrics, missing, stale)

    if args.write_label_skeleton:
        write_label_skeleton(args.write_label_skeleton, all_findings, labels)

    if missing:
        print(f"::error::{len(missing)} finding(s) are missing labels")
    if stale:
        print(f"::warning::{len(stale)} label(s) did not match current findings")
    if missing and settings.fail_on_missing_labels and not args.write_label_skeleton:
        return 1

    if args.check:
        return compare_expected(metrics, args.expected, settings)
    if args.update_expected:
        write_json(args.expected, expected_snapshot(metrics))
        print(f"[precision] updated {args.expected}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="scan the precision corpus")
    run_p.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    run_p.add_argument("--labels", type=Path, default=DEFAULT_LABELS)
    run_p.add_argument("--expected", type=Path, default=DEFAULT_EXPECTED)
    run_p.add_argument("--results-dir", type=Path, default=DEFAULT_RESULTS)
    run_p.add_argument("--workdir", type=Path, default=DEFAULT_WORKDIR)
    run_p.add_argument("--foxguard", type=Path, required=True)
    run_p.add_argument("--check", action="store_true")
    run_p.add_argument("--update-expected", action="store_true")
    run_p.add_argument("--write-label-skeleton", type=Path)
    run_p.set_defaults(func=run)

    validate_p = sub.add_parser("validate", help="validate manifest, labels, and snapshot")
    validate_p.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    validate_p.add_argument("--labels", type=Path, default=DEFAULT_LABELS)
    validate_p.add_argument("--expected", type=Path, default=DEFAULT_EXPECTED)
    validate_p.set_defaults(
        func=lambda ns: validate(ns.manifest, ns.labels, ns.expected)
    )

    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
