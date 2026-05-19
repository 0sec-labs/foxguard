<p align="center">
  <img src="assets/logo.png" width="96" alt="foxguard logo" />
</p>

<h1 align="center">𓃥 foxguard 𓃦</h1>

<p align="center">
  <strong>Fast local security scanning in a single Rust binary.</strong>
  <br/>
  scan &middot; diff &middot; secrets &middot; post-quantum crypto audit &middot; interactive TUI triage
  <br/>
  170+ built-in rules across 11 languages &middot; cross-file taint tracking &middot; Semgrep-compatible YAML and Coccinelle bridges
  <br/><br/>
  <a href="https://foxguard.dev">foxguard.dev</a> &middot; <a href="https://www.npmjs.com/package/foxguard">npm</a> &middot; <a href="https://crates.io/crates/foxguard">crates.io</a>
</p>

<p align="center">
  <a href="https://github.com/0sec-labs/foxguard/actions/workflows/ci.yml"><img src="https://github.com/0sec-labs/foxguard/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://github.com/0sec-labs/foxguard"><img src="https://img.shields.io/badge/foxguard-clean-3fb950?logo=data:image/svg%2bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA2NCA2NCIgZmlsbD0ibm9uZSI+PHBhdGggZD0iTTggOEwyMCAyOEwzMiAyMEw0NCAyOEw1NiA4TDUyIDMyTDQ0IDQ0TDM2IDUySDI4TDIwIDQ0TDEyIDMyTDggOFoiIGZpbGw9IiNGNTlFMEIiIGZpbGwtb3BhY2l0eT0iMC4zIiBzdHJva2U9IiNGNTlFMEIiIHN0cm9rZS13aWR0aD0iMyIgc3Ryb2tlLWxpbmVqb2luPSJyb3VuZCIvPjxjaXJjbGUgY3g9IjI0IiBjeT0iMzIiIHI9IjIuNSIgZmlsbD0iI0Y1OUUwQiIvPjxjaXJjbGUgY3g9IjQwIiBjeT0iMzIiIHI9IjIuNSIgZmlsbD0iI0Y1OUUwQiIvPjwvc3ZnPg==" alt="foxguard: clean" /></a>
  <a href="https://crates.io/crates/foxguard"><img src="https://img.shields.io/crates/v/foxguard?color=d97706&label=crates.io" alt="crates.io" /></a>
  <a href="https://www.npmjs.com/package/foxguard"><img src="https://img.shields.io/npm/v/foxguard?color=d97706&label=npm" alt="npm" /></a>
  <a href="https://github.com/0sec-labs/foxguard/stargazers"><img src="https://img.shields.io/github/stars/0sec-labs/foxguard?style=flat&color=e3b341&logo=github" alt="GitHub stars" /></a>
</p>

---

<p align="center">
  <img src="assets/demo.gif" alt="foxguard scan demo" width="640" />
</p>

<p align="center">
  <img src="assets/tui-findings.png" alt="foxguard TUI findings list with source/sink dataflow" width="640" />
  <br/><em><code>foxguard tui .</code> — interactive triage with scan, diff, secrets, and PQ modes. <a href="https://foxguard.dev/blog/foxguard-0-7-0-tui-launch">Launch post</a>.</em>
</p>

foxguard is a security scanner you can run on every save. A single Rust binary with 170+ built-in rules across 10 source languages, plus C via Semgrep-compatible YAML rule packs and Coccinelle-backed semantic patches (kernel/dirty-frag class shipped), cross-file taint tracking, Semgrep-compatible YAML loading, and four top-level modes — general scan, diff-against-branch, secrets, and post-quantum crypto audit — all reachable from the same CLI or interactive TUI.

It is fast enough for pre-commit hooks and the `--changed` path runs in milliseconds on a real repo. Output formats: terminal, JSON, SARIF (for GitHub Code Scanning), and CycloneDX 1.6 CBOM.

## Quick start

```sh
npx foxguard .                        # scan the repo
npx foxguard pqc .                    # post-quantum crypto audit
npx foxguard --format cbom .          # CycloneDX 1.6 CBOM for compliance
npx foxguard tui .                    # interactive triage (scan, diff, secrets, pqc)
```

Other common flags:

```sh
npx foxguard --changed .              # only modified files
npx foxguard diff main .              # new findings vs target branch
npx foxguard --explain .              # source-to-sink dataflow traces
npx foxguard --github-pr 42 .         # post as PR review comments
npx foxguard secrets .                # leaked credentials and private keys
npx foxguard init                     # install local pre-commit hook
```

## The four modes

| Mode | Command | What it does |
|------|---------|--------------|
| **Scan** | `foxguard .` | General security scan. 170+ built-in rules across JavaScript/TypeScript, Python, Go, Ruby, Java, PHP, Rust, C#, Swift, Kotlin. Framework-aware checks for Express, Next.js, Django, Flask, FastAPI, Rails, Spring, Laravel, Gin, .NET, and iOS. Intraprocedural taint flow with cross-file summaries for Python, JS, Go, Kotlin. |
| **Diff** | `foxguard diff main .` | Only findings that are new since a target branch. Pairs with `--changed` for staged/unstaged files only. |
| **Secrets** | `foxguard secrets .` | AWS keys, GitHub/GitLab/Slack/Stripe tokens, private keys. Redacted output, baseline support. |
| **PQC** | `foxguard pqc .` | Post-quantum crypto audit. PQ-vulnerable-crypto rules for 5 languages plus TLS/config files. Each finding annotated with its CNSA 2.0 migration deadline. FN-DSA (FIPS 206) and HQC awareness. |

All four are reachable from `foxguard tui .` — interactive triage with review, baseline, ignore, severity overrides, confidence filter, and a CNSA 2.0 compliance panel.

## Also in the box

| Area | What you get |
|------|--------------|
| **Outputs** | Terminal, JSON, SARIF (GitHub Code Scanning), CycloneDX 1.6 CBOM (`--format cbom`). Each CBOM component links back to a source location and severity. |
| **External rule bridges** | Loads a Semgrep/OpenGrep YAML subset and `engine: coccinelle` SmPL rules via `--rules`. Semgrep parity is tested in CI; Coccinelle rules shell out to `spatch` when installed. See [`COMPATIBILITY.md`](./COMPATIBILITY.md). |
| **CI integration** | Native GitHub Action (below), SARIF upload, `--github-pr` for PR review comments, exit code on findings. |
| **Config** | `.foxguard.yml` for per-rule enable/disable, severity overrides, entropy and taint-hop thresholds, per-rule options. |

## Post-quantum crypto audit

NSA's CNSA 2.0 suite ([CSI, Sept 2022; FAQ v2.1, Dec 2024](https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF)) mandates exclusive use of ML-KEM and ML-DSA by specific deadlines. Software and firmware signing are the earliest class — exclusive use by 2030 — with traditional networking, operating systems, and web browsers trailing through 2033. Every finding foxguard produces for a PQ-vulnerable algorithm carries the matching deadline in the output.

```sh
foxguard pqc .
```

```
src/tls/client.go
  42:14  HIGH      go/pq-vulnerable-crypto (CWE-327)
         ECDH P-256 is not post-quantum safe. CNSA 2.0 mandates ML-KEM-1024
         for NSS; ML-KEM-768 is the NIST default for commercial use.
         CNSA 2.0 deadline: traditional networking equipment, 2030.

WARNING 1 PQ finding in 18 files (0.04s): 1 high, 0 medium, 0 low
CNSA 2.0 migration: at-risk (1 finding with an NSA transition deadline)
```

As far as we can tell, foxguard is the first OSS source-code scanner that annotates each PQ finding with its CNSA 2.0 migration deadline. Remediation guidance surfaces ML-KEM-1024 / ML-DSA-87 for NSS workloads and ML-KEM-768 / ML-DSA-65 for commercial use, per the CNSA 2.0 algorithm table.

**CBOM export.** `foxguard --format cbom .` produces a CycloneDX 1.6 cryptographic bill of materials. Each component (algorithm, key, protocol) is linked back to the source location that emitted it and the severity of any finding on that site. Manifest findings also emit normalized dependency components with per-file occurrence evidence, so duplicate dependencies across manifests or lockfiles remain traceable without losing the package-level identity. IBM's [CBOMkit](https://github.com/IBM/cbomkit), [sonar-cryptography](https://github.com/IBM/sonar-cryptography), and [cdxgen](https://github.com/CycloneDX/cdxgen) all ship CBOM output; foxguard's contribution is that the scan and the inventory are one artifact, so `crypto-agility` scoring and CNSA 2.0 annotations travel with the BOM.

**Rule coverage.** PQ-vulnerable-crypto rules ship for Python, JavaScript/TypeScript, Go, Java, and Rust; TLS configuration files (OpenSSL, nginx, Apache) are also scanned for non-PQ cipher suites.

## Install

```sh
npx foxguard .                                           # no install needed
curl -fsSL https://foxguard.dev/install.sh | sh          # prebuilt binary (macOS/Linux)
cargo install foxguard                                   # crates.io
```

**Editors and agents:**

- [VS Code extension](https://marketplace.visualstudio.com/items?itemName=peaktwilight.foxguard) scans on save and shows findings inline.
- [Claude Code plugin](./plugins/claude-code) auto-scans files after Claude writes or edits them, adds `/foxguard:*` scan/triage/PQ/secrets skills, and injects secure-coding defaults into agent sessions.

```sh
claude --plugin-dir ./plugins/claude-code
```

Run `/foxguard:setup` inside Claude Code to verify the scanner is available. See [Claude Code integration](docs/claude-code-integration.md) for local plugin loading, hook behavior, and marketplace status.
Shared behavior for future agent/editor adapters is documented in [Agent and Editor Integration Contract](docs/agent-editor-integration.md).

## CI integration

```yaml
name: Security
on: [push, pull_request]
jobs:
  foxguard:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: 0sec-labs/foxguard/action@v0.8.1
        with:
          path: .
          severity: medium
          fail-on-findings: "true"
          upload-sarif: "true"
```

Findings land in **Security → Code Scanning**. On any other CI: `npx foxguard@latest --format sarif . > out.sarif`. For Claude Code and other agent/editor hooks, see [docs/claude-code-integration.md](docs/claude-code-integration.md) and [docs/agent-editor-integration.md](docs/agent-editor-integration.md).

**Pre-commit:**

```yaml
repos:
  - repo: https://github.com/0sec-labs/foxguard
    rev: v0.8.1
    hooks:
      - id: foxguard
```

## Benchmarks

Reproducible via `./benchmarks/run.sh`. Numbers below are from a local run on an Apple Silicon laptop with `foxguard 0.6.2`, `semgrep 1.156.0`, `tokei 14.0.0`. LoC is counted by tokei, scoped to the target language only (no vendored HTML/JSON).

| Repo | Files | LoC | foxguard | Semgrep | Speedup |
|------|-------|-----|----------|---------|---------|
| express (framework) | 141 | 15,804 JS | **0.276s** | 6.09s | **22x** |
| flask (framework) | 83 | 14,029 Py | **0.333s** | 6.51s | **20x** |
| gin (framework) | 99 | 17,669 Go | **0.499s** | 4.95s | **10x** |
| **sentry (production)** | **8,539** | **1,291,606 Py** | **35.4s** | 194.0s | **5x** |

Sentry is the stress target at ~1.3M Python LoC: foxguard scans the whole tree in ~35 seconds; Semgrep with `--config auto` takes ~3m14s. Run on one machine — reproduce locally with `./benchmarks/run.sh` (add `BENCH_SKIP_LARGE=1` to skip sentry). See [`benchmarks/README.md`](./benchmarks/README.md) for the reproduction recipe.

## Rules

170+ built-in rules across 10 source languages, plus C via Semgrep-compatible YAML rule packs (kernel/dirty-frag class shipped), covering SQL injection, XSS, SSRF, command injection, hardcoded secrets, weak crypto, unsafe deserialization, log injection, PQ-vulnerable crypto, crypto-agility, and framework-specific checks. Full per-rule coverage, precision tiers, and false-positive methodology live in [docs/precision.md](docs/precision.md) and on the [rules page at foxguard.dev](https://foxguard.dev/rules).

## Configuration

foxguard auto-discovers `.foxguard.yml` from the scan path upward.

```yaml
scan:
  baseline: .foxguard/baseline.json
  rules: ./semgrep-rules
  enable_rules: [py/no-sql-injection, py/no-xss]   # optional allowlist
  disable_rules: [py/no-eval]                      # optional denylist
  severity_overrides:
    py/no-hardcoded-secret: medium

secrets:
  baseline: .foxguard/secrets-baseline.json
  exclude_paths: [fixtures, testdata]
```

Inline suppressions work with `// foxguard: ignore[rule-id]` or `# foxguard: ignore` on the target line. Full configuration reference, rule options, and threshold tuning are documented at [foxguard.dev/docs](https://foxguard.dev/docs).

## What it is not

foxguard is not a full Semgrep or OpenGrep drop-in replacement. The intended model: foxguard built-ins for fast local feedback, a Semgrep/OpenGrep-compatible YAML subset as an adoption bridge, and Semgrep/OpenGrep themselves when you need the broadest external rule ecosystem. That boundary keeps local scans fast and compatibility claims testable.

## Contributing

Adding a rule is one struct implementing a trait. See [`CONTRIBUTING.md`](./CONTRIBUTING.md).

## Part of 0sec Labs

**Open-source adversarial security for the agentic AI era.** foxguard is one piece of the stack:

- **[pwnkit](https://github.com/0sec-labs/pwnkit)** — AI agent pentester (detect)
- **[foxguard](https://github.com/0sec-labs/foxguard)** — Rust security scanner (prevent)
- **[opensoar](https://github.com/opensoar-hq/opensoar-core)** — Python-native SOAR platform (respond)

## License

MIT OR Apache-2.0
