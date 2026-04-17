---
title: "Making foxguard taint tracking 2× faster in v0.7.1"
date: "2026-04-17"
description: "foxguard v0.7.1 closes a 3× performance regression in the Go and Python taint engines. Here is how we diagnosed it and what the fix looks like."
readTime: "5 min read"
---

We shipped [foxguard v0.7.0](https://foxguard.dev/blog/foxguard-0-7-0-tui-launch/) with a full interactive TUI yesterday. Today we are shipping **v0.7.1** — a performance release that makes Go taint scanning **2.2× faster** and Python taint scanning **1.3× faster**, without dropping a single rule or changing a single finding.

This post is about how we found the regression, what the fix looks like, and why we are comfortable calling it shipped.

## The problem

foxguard v0.4.0 scanned gin in ~110ms. v0.7.0 scanned it in ~360ms. That is a 3.3× slowdown over ten days.

Issue [#174](https://github.com/PwnKit-Labs/foxguard/issues/174) flagged this. The obvious reply — *we added cross-file taint tracking, of course it is slower* — is partially right. Features cost time. But the regression was uneven:

| Repo | v0.4.0 | v0.7.0 | Slowdown |
|------|-------:|-------:|---------:|
| express | 119ms | 180ms | +51% |
| flask | 133ms | 233ms | +75% |
| **gin** | **112ms** | **358ms** | **+220%** |

If the slowdown were purely "we added features", we would expect roughly uniform percentages. Gin being **~3× worse than express** is a signal that something specific to the Go taint engine was burning cycles, not the engine design in general.

## Three independent investigations

We ran three parallel investigations to triangulate:

1. **Bisect.** Run `compare_versions.py` across every published release between v0.4.0 and v0.7.0. Goal: find the commit that introduced the bulk of the slowdown.
2. **Profile.** Build a release binary with debug info, run `samply` on a gin scan, and look at where the time goes.
3. **Code review.** Read `src/rules/go_taint.rs` and compare to `src/rules/javascript_taint.rs` and `src/rules/python_taint.rs` to flag anything Go-specific.

All three pointed at the same thing.

**Bisect:** the regression was not one bad commit. It accumulated across every commit that added a Go taint rule — `log-injection` added ~34ms, `deserialization` added ~24ms, `nosql-injection` added ~60ms, `path-traversal` added another chunk. Each rule added roughly **20-60ms** to the gin scan.

**Profile:** `collect_function_defs` was 40.9% of all samples. `analyze_tree_with_cross_file` was 39.1%. Pass 2 (the per-rule full analysis) consumed **425ms of a ~500ms scan**.

**Code review:** `map_go_taint_findings` was calling `analyze_tree_with_cross_file` **once per registered Go taint rule**. For a file with 9 taint rules, the engine walked the AST nine times. Pass 1 summaries — the `params_to_return` analysis — are rule-agnostic. Eight of those nine walks were redundant.

## The fix

Every rule does not need its own pass. Group rules by sanitizer fingerprint and do one pass per group.

```rust
// Before: 9 walks per file (one per rule)
for rule in go_taint_rules {
    analyze_tree_with_cross_file(tree, &rule.spec);  // Pass 1 + Pass 2
}

// After: 2 walks per file (one per sanitizer group)
let groups = group_by_sanitizer_fingerprint(go_taint_rules);
for group in groups {
    analyze_tree_batched(tree, &group);  // shared Pass 1, batched sinks
}
```

For the nine Go taint rules in v0.7.0, exactly one — `path-traversal` — declares sanitizers. The other eight fall into a single sanitizer-free group. **Nine walks collapse to two.**

Findings get attributed back to the correct rule via a new `rule_id_hint: Option<String>` field on `TaintFinding`, populated when a sink matches.

The refactor lives in [PR #199](https://github.com/PwnKit-Labs/foxguard/pull/199) for Go and [PR #202](https://github.com/PwnKit-Labs/foxguard/pull/202) for Python. Same pattern for both.

## Results

Final benchmark, 15 iterations, 3 warmup, avg ms:

| Repo | v0.4.0 | v0.7.0 | **v0.7.1** | v0.7.1 vs v0.7.0 | v0.7.1 vs v0.4.0 |
|------|-------:|-------:|-----------:|-----------------:|-----------------:|
| express | 119 | 180 | **177** | -2% | +49% |
| flask | 133 | 233 | **178** | **-24%** | +34% |
| **gin** | **112** | **358** | **163** | **-55%** | +45% |

Gin is now **2.2× faster** than v0.7.0 and back within 1.5× of v0.4.0 — which predates cross-file taint tracking entirely. Flask is **1.3× faster** with the same Python port. Express moved within noise because JavaScript has fewer taint rules and `collect_summary_targets` already skipped nested scopes, so the waste was smaller.

## Correctness

The refactor is only interesting if findings stay identical. We verified three ways:

- **Byte-identical JSON diffs** on express, flask, and gin between main and the PR branches — zero difference after sorting.
- **Dogfood** — foxguard scanning its own Rust source reported the same 1,082 findings with identical severity breakdown before and after.
- **Full test suite** — 415 tests passing, clippy clean under `-D warnings`, format clean.

No correctness regressions. The refactor is purely orchestration.

## Why not match v0.4.0 exactly?

We probably will not. The remaining +34% to +49% vs v0.4.0 is the actual cost of the features we added: intraprocedural taint tracking (v0.5), cross-file taint tracking (v0.6), multi-hop propagation (v0.6.x). Those catch real vulnerabilities — SQL injection across file boundaries, user input flowing from Flask routes through helper modules into `eval`, command injection via Express controllers calling into utility files.

Matching v0.4.0 would mean dropping those features. We would rather ship a fast engine that does useful work than a faster one that misses the bugs.

## Try it

```sh
npx foxguard@0.7.1 .
```

v0.7.1 is a drop-in replacement for v0.7.0. Same rules, same output, faster.

---

*foxguard is an open-source security scanner written in Rust. 170+ built-in rules, 10 languages, cross-file taint tracking for Python, JavaScript, and Go. [Try it](https://github.com/PwnKit-Labs/foxguard): `npx foxguard .`*
