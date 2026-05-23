#!/usr/bin/env python3
"""Semgrep-vs-foxguard parity harness.

Runs both scanners against a manifest of real-world OSS repos and writes a
Markdown diff report. See benchmarks/parity/README.md for usage.

Design notes:
 - Repos are cloned shallow into a temp directory (or a `--workdir`) and pinned
   to a specific ref so re-runs are reproducible.
 - Findings are normalized to (file, line, rule_family) tuples. rule_family
   strips namespace prefixes so `py/no-eval` and `python.lang.no-eval` collapse
   to the same key. We additionally compute a "site parity" rate keyed on
   (file, line) alone — useful when both scanners flag the same location with
   semantically-equivalent but lexically-different rule IDs.
 - If Semgrep is missing, the run skips gracefully with a clear message rather
   than failing. The harness is documentation-grade tooling, not a CI gate.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
try:
    import tomllib  # type: ignore[import-not-found]
except ModuleNotFoundError:  # Python < 3.11
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:
        sys.stderr.write(
            "error: this harness needs Python 3.11+ (for tomllib) or `pip install tomli`.\n"
        )
        sys.exit(2)
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

REPO_ROOT = Path(__file__).resolve().parents[2]
PARITY_DIR = Path(__file__).resolve().parent
DEFAULT_FOXGUARD = REPO_ROOT / "target" / "release" / "foxguard"


# ---------------------------------------------------------------------------
# manifest loading


@dataclass
class RepoEntry:
    name: str
    url: str
    ref: str
    language: str
    semgrep_ruleset: str
    scan_subdir: str = "."
    skip: bool = False
    notes: str = ""
    semgrep_version: str = ""


def load_manifest(manifest_path: Path) -> tuple[list[RepoEntry], dict]:
    with manifest_path.open("rb") as fh:
        data = tomllib.load(fh)
    entries: list[RepoEntry] = []
    for raw in data.get("repos", []):
        entries.append(
            RepoEntry(
                name=raw["name"],
                url=raw["url"],
                ref=raw["ref"],
                language=raw["language"],
                semgrep_ruleset=raw["semgrep_ruleset"],
                scan_subdir=raw.get("scan_subdir", "."),
                skip=bool(raw.get("skip", False)),
                notes=raw.get("notes", ""),
                semgrep_version=raw.get(
                    "semgrep_version", data.get("semgrep_default_version", "")
                ),
            )
        )
    return entries, data


# ---------------------------------------------------------------------------
# scanner output normalization


# rule_id parts we strip when building a "family" key. These show up as
# prefixes inside both foxguard slugs (e.g. `py/`, `go/`) and Semgrep dotted
# paths (e.g. `python.lang.security.audit.`) but carry no semantic weight
# for parity comparison.
_FAMILY_STRIP_TOKENS = {
    # language tags
    "py", "python",
    "js", "javascript", "ts", "typescript",
    "go", "golang",
    "rs", "rust",
    "java", "kotlin", "kt",
    "c", "cpp", "cxx",
    # category buckets
    "lang", "security", "audit", "best-practice", "correctness",
    "best", "practice", "cwe", "owasp",
    # foxguard prefixes
    "taint", "no",
}


def _tokenize_rule_id(rule_id: str) -> list[str]:
    # Split on / . _ and -. We keep hyphenated tokens intact (so `no-eval` stays
    # `no-eval`) but ditch leading namespace segments.
    parts = re.split(r"[./_]", rule_id)
    return [p for p in parts if p]


def rule_family(rule_id: str) -> str:
    """Collapse a rule_id to a comparable family key.

    Examples (foxguard <-> semgrep):
      py/no-eval                                            -> no-eval
      python.lang.security.audit.eval-detected.eval-detected -> eval-detected
      py/taint-sql-injection                                -> taint-sql-injection
      javascript.express.audit.xss.direct-response-write     -> direct-response-write
    """
    if not rule_id:
        return ""
    tokens = _tokenize_rule_id(rule_id)
    # Strip language/namespace prefix tokens from the front
    while tokens and tokens[0].lower() in _FAMILY_STRIP_TOKENS:
        tokens.pop(0)
    if not tokens:
        return rule_id.lower()
    # Many Semgrep rules duplicate the leaf (`.../eval-detected.eval-detected`).
    if len(tokens) >= 2 and tokens[-1] == tokens[-2]:
        tokens.pop()
    return tokens[-1].lower()


@dataclass(frozen=True)
class Finding:
    file: str
    line: int
    rule_id: str
    rule_family: str
    message: str
    scanner: str  # "foxguard" or "semgrep"

    def site_key(self) -> tuple[str, int]:
        return (self.file, self.line)

    def family_key(self) -> tuple[str, int, str]:
        return (self.file, self.line, self.rule_family)


def _normalize_path(path: str, repo_root: Path) -> str:
    p = Path(path)
    try:
        if p.is_absolute():
            p = p.relative_to(repo_root)
    except ValueError:
        # path was absolute but lived outside repo_root (shouldn't happen);
        # fall back to its raw form
        return path.replace("\\", "/").lstrip("./")
    s = str(p).replace("\\", "/")
    return s[2:] if s.startswith("./") else s


def parse_foxguard(output: bytes, repo_root: Path) -> list[Finding]:
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return []
    findings = data.get("findings", []) if isinstance(data, dict) else []
    out: list[Finding] = []
    for raw in findings:
        rid = raw.get("rule_id", "")
        out.append(
            Finding(
                file=_normalize_path(raw.get("file", ""), repo_root),
                line=int(raw.get("line", 0)),
                rule_id=rid,
                rule_family=rule_family(rid),
                message=raw.get("description", "") or raw.get("message", ""),
                scanner="foxguard",
            )
        )
    return out


def parse_semgrep(output: bytes, repo_root: Path) -> list[Finding]:
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return []
    results = data.get("results", []) if isinstance(data, dict) else []
    out: list[Finding] = []
    for raw in results:
        rid = raw.get("check_id", "")
        out.append(
            Finding(
                file=_normalize_path(raw.get("path", ""), repo_root),
                line=int(raw.get("start", {}).get("line", 0)),
                rule_id=rid,
                rule_family=rule_family(rid),
                message=raw.get("extra", {}).get("message", ""),
                scanner="semgrep",
            )
        )
    return out


# ---------------------------------------------------------------------------
# diff math


@dataclass
class RepoResult:
    entry: RepoEntry
    foxguard: list[Finding] = field(default_factory=list)
    semgrep: list[Finding] = field(default_factory=list)
    foxguard_duration_s: float = 0.0
    semgrep_duration_s: float = 0.0
    foxguard_error: str = ""
    semgrep_error: str = ""
    skipped_reason: str = ""

    def family_parity(self) -> dict:
        fox_keys = {f.family_key() for f in self.foxguard}
        sem_keys = {f.family_key() for f in self.semgrep}
        shared = fox_keys & sem_keys
        fox_only = fox_keys - sem_keys
        sem_only = sem_keys - fox_keys
        union = fox_keys | sem_keys
        rate = (len(shared) / len(union)) if union else 1.0
        return {
            "shared": len(shared),
            "foxguard_only": len(fox_only),
            "semgrep_only": len(sem_only),
            "union": len(union),
            "rate": rate,
        }

    def site_parity(self) -> dict:
        # Looser: do both tools flag this (file, line) at all?
        fox_keys = {f.site_key() for f in self.foxguard}
        sem_keys = {f.site_key() for f in self.semgrep}
        shared = fox_keys & sem_keys
        union = fox_keys | sem_keys
        rate = (len(shared) / len(union)) if union else 1.0
        return {
            "shared": len(shared),
            "foxguard_only": len(fox_keys - sem_keys),
            "semgrep_only": len(sem_keys - fox_keys),
            "union": len(union),
            "rate": rate,
        }


# ---------------------------------------------------------------------------
# scanners


def _have_cmd(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def _run_capture(
    argv: list[str], cwd: Path | None = None, timeout: int = 600
) -> tuple[bytes, bytes, int, float]:
    start = time.monotonic()
    try:
        proc = subprocess.run(
            argv,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        elapsed = time.monotonic() - start
        return b"", f"timeout after {timeout}s".encode(), 124, elapsed
    elapsed = time.monotonic() - start
    return proc.stdout, proc.stderr, proc.returncode, elapsed


def run_foxguard(foxguard_bin: Path, scan_root: Path) -> tuple[list[Finding], float, str]:
    if not foxguard_bin.exists():
        return [], 0.0, f"foxguard binary not found at {foxguard_bin}"
    stdout, stderr, rc, elapsed = _run_capture(
        [str(foxguard_bin), str(scan_root), "--format", "json"],
        cwd=scan_root,
    )
    if not stdout:
        return [], elapsed, f"foxguard returned no output (rc={rc}): {stderr.decode(errors='replace')[:500]}"
    findings = parse_foxguard(stdout, scan_root)
    return findings, elapsed, ""


def run_semgrep(
    semgrep_bin: str, ruleset: str, scan_root: Path
) -> tuple[list[Finding], float, str]:
    if not semgrep_bin:
        return [], 0.0, "semgrep not installed"
    if not shutil.which(semgrep_bin) and not Path(semgrep_bin).exists():
        return [], 0.0, f"semgrep binary not found at {semgrep_bin!r}"
    stdout, stderr, rc, elapsed = _run_capture(
        [
            semgrep_bin,
            "--config",
            ruleset,
            "--json",
            "--quiet",
            "--no-git-ignore",
            "--metrics=off",
            str(scan_root),
        ],
        cwd=scan_root,
        timeout=900,
    )
    if not stdout:
        return [], elapsed, f"semgrep returned no output (rc={rc}): {stderr.decode(errors='replace')[:500]}"
    findings = parse_semgrep(stdout, scan_root)
    return findings, elapsed, ""


# ---------------------------------------------------------------------------
# repo handling


def clone_repo(entry: RepoEntry, dest: Path) -> None:
    """Clone `entry` into `dest`, pinned to entry.ref."""
    if dest.exists():
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    # Use a partial clone + fetch of the specific ref so we can pin to a SHA
    # without pulling the full history.
    subprocess.run(
        ["git", "init", "--quiet", str(dest)],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(dest), "remote", "add", "origin", entry.url],
        check=True,
    )
    # Try fetching the ref directly. Works for tags, branches, and SHAs on
    # servers that allow uploadpack.allowReachableSHA1InWant (GitHub does).
    result = subprocess.run(
        ["git", "-C", str(dest), "fetch", "--depth", "1", "origin", entry.ref],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        # Fall back to a full shallow fetch of the default branch and then
        # try to check out the ref locally. Slower but more robust for
        # servers that reject fetch-by-sha.
        subprocess.run(
            ["git", "-C", str(dest), "fetch", "--depth", "50", "origin"],
            check=True,
            capture_output=True,
        )
    subprocess.run(
        ["git", "-C", str(dest), "checkout", "--quiet", "FETCH_HEAD"],
        check=False,
        capture_output=True,
    )
    # If FETCH_HEAD checkout failed (e.g. when we fell back to the default
    # fetch), try the ref directly.
    head_check = subprocess.run(
        ["git", "-C", str(dest), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
    )
    if head_check.returncode != 0 or not head_check.stdout.strip():
        subprocess.run(
            ["git", "-C", str(dest), "checkout", "--quiet", entry.ref],
            check=True,
            capture_output=True,
        )


# ---------------------------------------------------------------------------
# reporting


def _top_n_findings(findings: Iterable[Finding], n: int = 10) -> list[Finding]:
    seen: set[tuple[str, int, str]] = set()
    out: list[Finding] = []
    for f in findings:
        key = (f.file, f.line, f.rule_family)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
        if len(out) >= n:
            break
    return out


def write_repo_report(result: RepoResult, out_path: Path) -> None:
    e = result.entry
    lines: list[str] = []
    lines.append(f"# Parity report: {e.name}")
    lines.append("")
    lines.append(f"- **url:** {e.url}")
    lines.append(f"- **ref:** `{e.ref}`")
    lines.append(f"- **language:** {e.language}")
    lines.append(f"- **scan subdir:** `{e.scan_subdir}`")
    lines.append(f"- **semgrep ruleset:** `{e.semgrep_ruleset}`")
    if e.notes:
        lines.append(f"- **notes:** {e.notes}")
    lines.append("")

    if result.skipped_reason:
        lines.append(f"_Skipped: {result.skipped_reason}_")
        out_path.write_text("\n".join(lines) + "\n")
        return

    lines.append("## Totals")
    lines.append("")
    lines.append("| Scanner | Findings | Duration |")
    lines.append("|---------|----------|----------|")
    lines.append(
        f"| foxguard | {len(result.foxguard)} | {result.foxguard_duration_s:.2f}s |"
    )
    lines.append(
        f"| semgrep  | {len(result.semgrep)} | {result.semgrep_duration_s:.2f}s |"
    )
    lines.append("")

    if result.foxguard_error:
        lines.append(f"> foxguard error: {result.foxguard_error}")
        lines.append("")
    if result.semgrep_error:
        lines.append(f"> semgrep error: {result.semgrep_error}")
        lines.append("")

    fam = result.family_parity()
    site = result.site_parity()
    lines.append("## Parity")
    lines.append("")
    lines.append("| Metric | Shared | foxguard-only | semgrep-only | Union | Rate |")
    lines.append("|--------|-------:|--------------:|-------------:|------:|-----:|")
    lines.append(
        f"| by `(file, line, rule_family)` | {fam['shared']} | {fam['foxguard_only']} | {fam['semgrep_only']} | {fam['union']} | {fam['rate']:.1%} |"
    )
    lines.append(
        f"| by `(file, line)` | {site['shared']} | {site['foxguard_only']} | {site['semgrep_only']} | {site['union']} | {site['rate']:.1%} |"
    )
    lines.append("")

    fox_keys = {f.family_key(): f for f in result.foxguard}
    sem_keys = {f.family_key(): f for f in result.semgrep}
    fox_only_findings = [fox_keys[k] for k in fox_keys.keys() - sem_keys.keys()]
    sem_only_findings = [sem_keys[k] for k in sem_keys.keys() - fox_keys.keys()]

    lines.append("## Top 10 foxguard-only findings")
    lines.append("")
    lines.append("Could be foxguard differentiation, could be false positives. Eyeball before celebrating.")
    lines.append("")
    if fox_only_findings:
        lines.append("| File | Line | Rule | Message |")
        lines.append("|------|-----:|------|---------|")
        for f in _top_n_findings(fox_only_findings, 10):
            msg = (f.message or "").replace("\n", " ").strip()[:80]
            lines.append(f"| `{f.file}` | {f.line} | `{f.rule_id}` | {msg} |")
    else:
        lines.append("_None._")
    lines.append("")

    lines.append("## Top 10 semgrep-only findings")
    lines.append("")
    lines.append("Coverage gaps to triage. Each row is a Semgrep finding foxguard missed.")
    lines.append("")
    if sem_only_findings:
        lines.append("| File | Line | Rule | Message |")
        lines.append("|------|-----:|------|---------|")
        for f in _top_n_findings(sem_only_findings, 10):
            msg = (f.message or "").replace("\n", " ").strip()[:80]
            lines.append(f"| `{f.file}` | {f.line} | `{f.rule_id}` | {msg} |")
    else:
        lines.append("_None._")
    lines.append("")

    # Per-rule-family parity
    fams = set(f.rule_family for f in result.foxguard) | set(
        f.rule_family for f in result.semgrep
    )
    fam_rows: list[tuple[str, int, int, float]] = []
    for fam_name in fams:
        if not fam_name:
            continue
        fox_n = sum(1 for f in result.foxguard if f.rule_family == fam_name)
        sem_n = sum(1 for f in result.semgrep if f.rule_family == fam_name)
        denom = max(fox_n, sem_n)
        rate = min(fox_n, sem_n) / denom if denom else 0.0
        fam_rows.append((fam_name, fox_n, sem_n, rate))
    fam_rows.sort(key=lambda row: -(row[1] + row[2]))
    if fam_rows:
        lines.append("## Per-rule-family counts")
        lines.append("")
        lines.append("| Family | foxguard | semgrep | Parity (min/max) |")
        lines.append("|--------|---------:|--------:|-----------------:|")
        for fam_name, fox_n, sem_n, rate in fam_rows[:25]:
            lines.append(f"| `{fam_name}` | {fox_n} | {sem_n} | {rate:.0%} |")
        lines.append("")

    out_path.write_text("\n".join(lines) + "\n")


def write_summary(results: list[RepoResult], out_path: Path) -> dict:
    lines: list[str] = []
    lines.append("# Real-repo Semgrep parity — summary")
    lines.append("")
    lines.append("Generated by `benchmarks/parity/run.sh` (issue #376).")
    lines.append("")
    lines.append(
        "Each row aggregates findings from one pinned OSS repo. "
        "Per-repo detail lives in `report-<name>.md`."
    )
    lines.append("")
    lines.append(
        "| Repo | Language | foxguard | semgrep | Shared (family) | foxguard-only | semgrep-only | Family parity | Site parity |"
    )
    lines.append(
        "|------|----------|---------:|--------:|----------------:|--------------:|-------------:|--------------:|------------:|"
    )

    agg_shared = agg_fox_only = agg_sem_only = agg_union = 0
    agg_site_shared = agg_site_union = 0
    snapshot: dict = {"repos": {}, "aggregate": {}}

    for r in results:
        if r.skipped_reason:
            lines.append(
                f"| {r.entry.name} | {r.entry.language} | _skipped: {r.skipped_reason}_ | | | | | | |"
            )
            snapshot["repos"][r.entry.name] = {"skipped": r.skipped_reason}
            continue
        fam = r.family_parity()
        site = r.site_parity()
        lines.append(
            f"| {r.entry.name} | {r.entry.language} | {len(r.foxguard)} | {len(r.semgrep)} | "
            f"{fam['shared']} | {fam['foxguard_only']} | {fam['semgrep_only']} | "
            f"{fam['rate']:.1%} | {site['rate']:.1%} |"
        )
        agg_shared += fam["shared"]
        agg_fox_only += fam["foxguard_only"]
        agg_sem_only += fam["semgrep_only"]
        agg_union += fam["union"]
        agg_site_shared += site["shared"]
        agg_site_union += site["union"]
        snapshot["repos"][r.entry.name] = {
            "ref": r.entry.ref,
            "foxguard_findings": len(r.foxguard),
            "semgrep_findings": len(r.semgrep),
            "family": fam,
            "site": site,
            "foxguard_duration_s": round(r.foxguard_duration_s, 3),
            "semgrep_duration_s": round(r.semgrep_duration_s, 3),
        }

    agg_family_rate = (agg_shared / agg_union) if agg_union else 0.0
    agg_site_rate = (agg_site_shared / agg_site_union) if agg_site_union else 0.0
    lines.append("")
    lines.append(
        f"**Aggregate family parity:** {agg_family_rate:.1%} "
        f"({agg_shared} shared / {agg_union} union)"
    )
    lines.append(
        f"**Aggregate site parity:** {agg_site_rate:.1%} "
        f"({agg_site_shared} shared / {agg_site_union} union)"
    )
    lines.append("")
    lines.append(
        "Family parity collapses rule IDs to their last semantic token, so a "
        "foxguard `py/no-eval` matches Semgrep `python.lang.security.audit.eval-detected.eval-detected`. "
        "Site parity ignores rule IDs entirely and just asks whether both scanners "
        "flagged the same `(file, line)`. Site parity is always >= family parity."
    )
    lines.append("")

    snapshot["aggregate"] = {
        "shared": agg_shared,
        "foxguard_only": agg_fox_only,
        "semgrep_only": agg_sem_only,
        "union": agg_union,
        "family_rate": round(agg_family_rate, 4),
        "site_shared": agg_site_shared,
        "site_union": agg_site_union,
        "site_rate": round(agg_site_rate, 4),
    }

    out_path.write_text("\n".join(lines) + "\n")
    return snapshot


# ---------------------------------------------------------------------------
# entry point


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument(
        "--manifest",
        type=Path,
        default=PARITY_DIR / "repos.toml",
        help="path to manifest TOML (default: benchmarks/parity/repos.toml)",
    )
    p.add_argument(
        "--workdir",
        type=Path,
        default=None,
        help="reuse this directory for clones (default: fresh temp dir, cleaned up on exit)",
    )
    p.add_argument(
        "--out",
        type=Path,
        default=PARITY_DIR / "results",
        help="output directory for reports (default: benchmarks/parity/results)",
    )
    p.add_argument(
        "--foxguard",
        type=Path,
        default=DEFAULT_FOXGUARD,
        help="foxguard binary (default: target/release/foxguard)",
    )
    p.add_argument(
        "--semgrep",
        type=str,
        default=os.environ.get("SEMGREP", ""),
        help="semgrep binary (default: $SEMGREP or PATH)",
    )
    p.add_argument(
        "--only",
        type=str,
        default="",
        help="comma-separated repo names to include (default: all non-skipped)",
    )
    p.add_argument(
        "--update-snapshot",
        action="store_true",
        help="overwrite expected.json with the current results",
    )
    p.add_argument(
        "--keep-clones",
        action="store_true",
        help="leave cloned repos on disk after the run (implies --workdir if unset)",
    )
    return p.parse_args()


def main() -> int:
    args = parse_args()
    if not args.manifest.exists():
        print(f"manifest not found: {args.manifest}", file=sys.stderr)
        return 2

    entries, _meta = load_manifest(args.manifest)
    if args.only:
        wanted = {s.strip() for s in args.only.split(",") if s.strip()}
        entries = [e for e in entries if e.name in wanted]

    semgrep_bin = args.semgrep or (shutil.which("semgrep") or "")
    if not semgrep_bin:
        print(
            "warning: semgrep not installed — foxguard will still run but "
            "Semgrep columns will be empty and parity rates will be 0.",
            file=sys.stderr,
        )

    args.out.mkdir(parents=True, exist_ok=True)

    cleanup_workdir = False
    if args.workdir is None:
        if args.keep_clones:
            workdir = PARITY_DIR / "clones"
            workdir.mkdir(parents=True, exist_ok=True)
        else:
            tmp = tempfile.mkdtemp(prefix="foxguard-parity-")
            workdir = Path(tmp)
            cleanup_workdir = True
    else:
        workdir = args.workdir
        workdir.mkdir(parents=True, exist_ok=True)

    print(f"workdir: {workdir}")
    print(f"foxguard: {args.foxguard}")
    print(f"semgrep:  {semgrep_bin or '(missing)'}")
    print("")

    results: list[RepoResult] = []
    try:
        for entry in entries:
            print(f"--- {entry.name} ({entry.language}) ---")
            result = RepoResult(entry=entry)
            if entry.skip:
                result.skipped_reason = "marked skip=true in manifest"
                print(f"  skipped: {result.skipped_reason}")
                results.append(result)
                continue

            clone_dest = workdir / entry.name
            try:
                if (clone_dest / ".git").exists() and args.keep_clones:
                    print(f"  using cached clone at {clone_dest}")
                else:
                    print(f"  cloning {entry.url} @ {entry.ref[:12]}...")
                    clone_repo(entry, clone_dest)
            except subprocess.CalledProcessError as exc:
                result.skipped_reason = f"clone failed: {exc.stderr.decode(errors='replace')[:200] if exc.stderr else exc}"
                print(f"  {result.skipped_reason}")
                results.append(result)
                continue

            scan_root = clone_dest / entry.scan_subdir
            if not scan_root.exists():
                result.skipped_reason = f"scan_subdir {entry.scan_subdir} missing in clone"
                print(f"  {result.skipped_reason}")
                results.append(result)
                continue

            print("  running foxguard...")
            result.foxguard, result.foxguard_duration_s, result.foxguard_error = run_foxguard(
                args.foxguard, scan_root
            )
            if result.foxguard_error:
                print(f"  foxguard: {result.foxguard_error}")
            print(
                f"  foxguard: {len(result.foxguard)} findings in {result.foxguard_duration_s:.2f}s"
            )

            if semgrep_bin:
                print(f"  running semgrep ({entry.semgrep_ruleset})...")
                (
                    result.semgrep,
                    result.semgrep_duration_s,
                    result.semgrep_error,
                ) = run_semgrep(semgrep_bin, entry.semgrep_ruleset, scan_root)
                if result.semgrep_error:
                    print(f"  semgrep: {result.semgrep_error}")
                print(
                    f"  semgrep:  {len(result.semgrep)} findings in {result.semgrep_duration_s:.2f}s"
                )
            else:
                result.semgrep_error = "semgrep not installed"

            report_path = args.out / f"report-{entry.name}.md"
            write_repo_report(result, report_path)
            print(f"  wrote {report_path.relative_to(REPO_ROOT)}")
            results.append(result)
    finally:
        if cleanup_workdir:
            shutil.rmtree(workdir, ignore_errors=True)

    # Partial runs (`--only foo`) write to a suffixed summary so they don't
    # clobber the canonical multi-repo summary.md.
    summary_name = "summary.md" if not args.only else f"summary-{args.only.replace(',', '_')}.md"
    summary_path = args.out / summary_name
    snapshot = write_summary(results, summary_path)
    print(f"\nwrote {summary_path.relative_to(REPO_ROOT)}")

    expected_path = PARITY_DIR / "expected.json"
    if args.update_snapshot:
        if args.only:
            print(
                "refusing to update snapshot during a partial (--only) run "
                "— rerun across the full corpus to bump expected.json"
            )
        else:
            expected_path.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n")
            print(f"updated snapshot at {expected_path.relative_to(REPO_ROOT)}")
    elif expected_path.exists() and not args.only:
        try:
            prior = json.loads(expected_path.read_text())
            prior_rate = prior.get("aggregate", {}).get("family_rate")
            curr_rate = snapshot.get("aggregate", {}).get("family_rate")
            if prior_rate is not None and curr_rate is not None:
                delta = (curr_rate - prior_rate) * 100
                print(
                    f"\nsnapshot delta: family parity {prior_rate:.1%} -> {curr_rate:.1%} "
                    f"({delta:+.1f} pp)"
                )
        except Exception as exc:
            print(f"could not read prior snapshot: {exc}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
