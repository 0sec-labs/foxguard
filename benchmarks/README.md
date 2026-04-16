# foxguard Benchmarks

Comparative benchmarks for foxguard against other security linters.

## Quick Start

```sh
# Build foxguard first
cargo build --release

# Product comparison: foxguard built-ins vs Semgrep/OpenGrep auto rules.
# Includes the large-corpus target (sentry) — expect tens of minutes
# on the semgrep leg if semgrep is installed.
./benchmarks/run.sh

# Quick matrix: skip the large-corpus target (sentry).
BENCH_SKIP_LARGE=1 ./benchmarks/run.sh

# Same-rules engine comparison.
BENCH_MODE=compat ./benchmarks/run.sh

# Pin tool paths explicitly if needed.
SEMGREP=/opt/homebrew/bin/semgrep OPENGREP=/path/to/opengrep ./benchmarks/run.sh

# Cross-version foxguard-only benchmark (issue #174).
python3 benchmarks/compare_versions.py --refs v0.4.0,v0.6.3,main

# Faster local smoke run.
python3 benchmarks/compare_versions.py --refs v0.4.0,v0.6.3,main --iterations 3 --warmup 1
```

### Required and optional tools

| Tool | Purpose | If missing |
|------|---------|------------|
| `cargo` | Build foxguard | Required |
| `python3` | Parse JSON findings output from each tool | Required |
| `tokei` | Compute LoC column | Install via `brew install tokei` (or `cargo install tokei`). LoC column shows `N/A` if absent. |
| `semgrep` | Comparison leg | Corresponding columns show `N/A`. |
| `opengrep` | Comparison leg | Corresponding columns show `N/A`. |

## Methodology

The benchmark suite measures foxguard, Semgrep, and OpenGrep against small and large open-source repositories covering different languages:

| Repository | Language | Scale | Description |
|------------|----------|-------|-------------|
| [express](https://github.com/expressjs/express) | JavaScript | small | Fast, unopinionated web framework for Node.js |
| [flask](https://github.com/pallets/flask) | Python | small | Lightweight WSGI web application framework |
| [gin](https://github.com/gin-gonic/gin) | Go | small | HTTP web framework written in Go |
| [sentry](https://github.com/getsentry/sentry) | Python | large (~500k LoC) | Production application monitoring platform — larger-corpus stress target |

The small targets stay in the matrix for a fast local loop; `sentry` is the larger-corpus target added under #8 to stress the benchmark beyond framework-sized repos. Skip it with `BENCH_SKIP_LARGE=1` when you want a fast run.

## Cross-version regression workflow

When investigating foxguard-to-foxguard performance changes, use:

`python3 benchmarks/compare_versions.py`

What it does:

1. Fetches tags/refs and creates isolated `git worktree` checkouts per ref
2. Builds each ref with `cargo build --release`
3. Benchmarks each built binary against the same local fixture repos (`express`, `flask`, `gin`)
4. Writes a markdown report to `benchmarks/results-version-compare.md` with `avg/p50/p95` in milliseconds

This keeps the benchmark apples-to-apples when validating regressions like #174.

### What is measured

- **Wall time** — Total elapsed time for the scan
- **Files scanned** — Count of source files in the repository (`.js`, `.ts`, `.py`, `.go`)
- **LoC** — Lines of code (comments and blanks excluded) as reported by `tokei`, scoped to the language foxguard scans on that repo. `express` counts `JavaScript,TypeScript,Jsx,Tsx` only; `flask`/`sentry` count `Python`; `gin` counts `Go`. Vendored HTML/CSS/JSON is not counted. See `tokei_types_for_lang` in `run.sh`.
- **Findings count** — Number of findings reported by each tool

### Reproduction recipe

When publishing numbers from `results-default.md` or `results-compat.md`, include the following so the run is reproducible:

- **Machine**: model, CPU, RAM (e.g. `Apple M2 Pro, 32GB`)
- **OS**: `uname -sr`
- **foxguard**: `foxguard --version`
- **semgrep**: `semgrep --version`
- **opengrep**: `opengrep --version | tail -1`
- **tokei**: `tokei --version`
- **Run command**: the exact `BENCH_MODE=... ./benchmarks/run.sh` invocation
- **Repo SHAs**: `git -C benchmarks/repos/<name> rev-parse HEAD` for each target (the benchmark uses `--depth 1` clones, so these change over time)
- **Cache state**: note whether semgrep rules were already cached locally (first run vs. second run of `--config auto` has materially different timings)

### Modes

- `default`
  foxguard built-in rules vs Semgrep/OpenGrep `auto`
- `compat`
  the same Semgrep-compatible YAML rules are used across foxguard, Semgrep, and OpenGrep

### How it works

1. Each repository is cloned at `--depth 1` into `benchmarks/repos/`
2. In `default` mode, foxguard runs its built-in rules and Semgrep/OpenGrep run `auto`
3. In `compat` mode, all three tools use the shared rules in `benchmarks/compat_rules/`
4. foxguard uses `--no-builtins --rules` in `compat` mode to keep the rule set aligned
5. Results are written to `benchmarks/results-default.md` or `benchmarks/results-compat.md`
6. If Semgrep or OpenGrep is missing locally, that tool is skipped and the results file records `N/A`

### Fairness

- All tools scan the same repository checkout
- `default` mode is a product comparison, not a same-rules comparison
- `compat` mode is the same-rules comparison
- Semgrep and OpenGrep use their default `auto` rulesets only in `default` mode
- Timing includes startup overhead
- Repos are cached after first clone; delete `benchmarks/repos/` to re-clone
- Results are local snapshots, not a hosted leaderboard

In `compat` mode, foxguard runs `--no-builtins --rules benchmarks/compat_rules` so the comparison stays explicitly focused on the same external YAML rules rather than foxguard's built-in coverage.

## Why only these competitors?

The default matrix focuses on cross-language tools that are reasonably comparable for foxguard's current scope.

Tools like Bandit or njsscan can still be useful, but they are language-specific and make the comparison less apples-to-apples across JavaScript, Python, and Go.

## Why these compat rules?

The shared rules in `benchmarks/compat_rules/` are intentionally small, narrow, and parser-aligned.

They are not meant to prove overall security coverage parity. They exist to answer a narrower question:

- how do foxguard, Semgrep, and OpenGrep compare when scanning the same repos with the same YAML rules?

That makes them closer to compatibility smoke tests than a comprehensive security suite.

## Results

After running `./benchmarks/run.sh`, see `results-default.md` or `results-compat.md` in this directory for the latest local snapshot.

If Semgrep or OpenGrep is unavailable on the machine where you run the suite, the corresponding result columns will show `N/A` rather than stale cached numbers.
