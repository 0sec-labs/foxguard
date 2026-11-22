#!/usr/bin/env python3
"""OWASP Benchmark (Java) recall/false-positive tracker for foxguard.

The labeled corpus in ``precision.py`` needs a reviewed label per finding,
which does not scale to the ~3,000 findings the OWASP Benchmark produces. This
companion tool instead joins findings to the Benchmark's own ground truth
(``expectedresults-1.2.csv``): a test file counts as detected when foxguard
reports the category's CWE in it. It tracks true-positive rate, false-positive
rate and finding volume against a blessed baseline (``owasp_java_expected.json``).

These numbers measure the deterministic pattern/taint layer only. They are an
internal regression signal and must not be published as Java accuracy; the
agent-layer benchmark in the `0` repo is the publishable measurement.

Usage:
    python3 benchmarks/precision/owasp_java.py --foxguard target/release/foxguard \
        --benchmark-dir /path/to/BenchmarkJava [--check | --update-expected]
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import subprocess
import sys
from pathlib import Path

PINNED_REF = "10dfcc54ad02dcfcb358b0ba4a0fef8c919a6d17"
URL = "https://github.com/OWASP-Benchmark/BenchmarkJava.git"
EXPECTED = Path(__file__).resolve().parent / "owasp_java_expected.json"
TOLERANCE_PP = 1.0


def load_truth(benchmark_dir: Path) -> dict[str, tuple[str, bool, str]]:
    truth = {}
    for line in (benchmark_dir / "expectedresults-1.2.csv").read_text().splitlines():
        if line.startswith("#") or not line.strip():
            continue
        name, category, real, cwe = line.split(",")[:4]
        truth[name] = (category, real == "true", f"CWE-{cwe}")
    return truth


def sarif_report(path: Path) -> dict:
    """Convert any scanner's SARIF 2.1.0 into the report shape `score` expects.

    A result counts once per CWE it is tagged with (rule `properties.tags` such as
    "CWE-89: ..." or `properties.cwe`), so tools can be scored on the same ground
    truth as foxguard. Results with no CWE tag are kept but can never match a
    category, which is the honest outcome for an untagged rule.
    """
    run = json.loads(path.read_text())["runs"][0]
    cwes: dict[str, list[str]] = {}
    for rule in run.get("tool", {}).get("driver", {}).get("rules", []) or []:
        props = rule.get("properties", {}) or {}
        found = []
        for tag in list(props.get("tags", []) or []) + [props.get("cwe")] if props.get("cwe") else list(props.get("tags", []) or []):
            m = re.search(r"CWE[-_ ]?(\d+)", str(tag), re.I)
            if m:
                found.append(f"CWE-{m.group(1)}")
        cwes[rule["id"]] = sorted(set(found))
    findings = []
    for res in run.get("results", []):
        locs = res.get("locations") or [{}]
        uri = locs[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
        ids = cwes.get(res.get("ruleId", ""), []) or [None]
        for cwe in ids:
            findings.append({"rule_id": res.get("ruleId", ""), "file": uri, "cwe": cwe})
    return {"findings": findings}


def scan(foxguard: Path, benchmark_dir: Path) -> dict:
    proc = subprocess.run(
        [str(foxguard), "-f", "json", "--file-timeout", "0",
         str(benchmark_dir / "src/main/java")],
        capture_output=True, text=True, check=False,
    )
    if proc.returncode not in (0, 1):
        sys.stderr.write(proc.stderr)
        raise SystemExit(f"foxguard exited {proc.returncode}")
    return json.loads(proc.stdout)


def score(truth: dict, report: dict) -> dict:
    detected: dict[str, set[str]] = collections.defaultdict(set)
    rules: collections.Counter = collections.Counter()
    for finding in report["findings"]:
        rules[finding["rule_id"]] += 1
        match = re.search(r"(BenchmarkTest\d+)\.java$", finding["file"])
        if match:
            detected[match.group(1)].add(finding.get("cwe"))
    cats: dict[str, dict[str, int]] = {}
    for name, (category, real, cwe) in truth.items():
        hit = cwe in detected.get(name, ())
        row = cats.setdefault(category, {"tp": 0, "fn": 0, "fp": 0, "tn": 0})
        row[("tp" if hit else "fn") if real else ("fp" if hit else "tn")] += 1
    total = {k: sum(r[k] for r in cats.values()) for k in ("tp", "fn", "fp", "tn")}
    tpr = total["tp"] / max(1, total["tp"] + total["fn"])
    fpr = total["fp"] / max(1, total["fp"] + total["tn"])
    precision = total["tp"] / max(1, total["tp"] + total["fp"])
    return {
        "aggregate": {
            **total,
            "tpr": round(tpr, 4),
            "fpr": round(fpr, 4),
            "precision": round(precision, 4),
            "benchmark_score": round(tpr - fpr, 4),
            "total_findings": len(report["findings"]),
        },
        "categories": dict(sorted(cats.items())),
        "findings_by_rule": dict(sorted(rules.items())),
        "benchmark_ref": PINNED_REF,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--foxguard", type=Path)
    ap.add_argument("--sarif", type=Path, help="score another scanner from its SARIF 2.1.0 output instead of running foxguard")
    ap.add_argument("--benchmark-dir", type=Path, required=True,
                    help=f"checkout of {URL} at {PINNED_REF}")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--update-expected", action="store_true")
    args = ap.parse_args()

    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=args.benchmark_dir,
                          capture_output=True, text=True).stdout.strip()
    if head != PINNED_REF:
        print(f"warning: benchmark checkout is {head or 'not a git repo'}, "
              f"baseline pinned to {PINNED_REF}", file=sys.stderr)
    if bool(args.foxguard) == bool(args.sarif):
        ap.error("give exactly one of --foxguard or --sarif")
    report = sarif_report(args.sarif) if args.sarif else scan(args.foxguard, args.benchmark_dir)
    result = score(load_truth(args.benchmark_dir), report)
    agg = result["aggregate"]
    print(f"TPR {agg['tpr']:.3f}  FPR {agg['fpr']:.3f}  precision {agg['precision']:.3f}  "
          f"findings {agg['total_findings']}")
    for cat, r in result["categories"].items():
        print(f"  {cat:13} tp={r['tp']:3} fn={r['fn']:3} fp={r['fp']:3} tn={r['tn']:3}")
    if args.update_expected:
        EXPECTED.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        print(f"wrote {EXPECTED}")
        return 0
    if args.check:
        base = json.loads(EXPECTED.read_text())["aggregate"]
        problems = []
        if agg["fpr"] > base["fpr"] + TOLERANCE_PP / 100:
            problems.append(f"FPR rose {base['fpr']} -> {agg['fpr']}")
        if agg["tpr"] < base["tpr"] - TOLERANCE_PP / 100:
            problems.append(f"TPR fell {base['tpr']} -> {agg['tpr']}")
        for p in problems:
            print(f"FAIL: {p}", file=sys.stderr)
        return 1 if problems else 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
