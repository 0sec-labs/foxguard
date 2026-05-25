<p align="center">
  <img src="assets/logo.png" width="80" alt="foxguard" />
</p>

<h1 align="center">foxguard</h1>

<p align="center">
  <strong>Fast security scanner. Single binary. 170+ rules. 11 languages.</strong>
</p>

<p align="center">
  <a href="https://github.com/0sec-labs/foxguard/actions/workflows/ci.yml"><img src="https://github.com/0sec-labs/foxguard/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://crates.io/crates/foxguard"><img src="https://img.shields.io/crates/v/foxguard?color=d97706&label=crates.io" alt="crates.io" /></a>
  <a href="https://www.npmjs.com/package/foxguard"><img src="https://img.shields.io/npm/v/foxguard?color=d97706&label=npm" alt="npm" /></a>
  <a href="https://github.com/apps/foxguard-app/installations/new"><img src="https://img.shields.io/badge/GitHub_App-Install-2ea44f?logo=github" alt="Install GitHub App" /></a>
</p>

```sh
npx foxguard .
```

<p align="center">
  <img src="assets/demo.gif" alt="foxguard scan demo" width="640" />
</p>

## Features

- **Sub-second scans** on real codebases -- fast enough for pre-commit hooks
- **170+ built-in rules** -- SQLi, XSS, SSRF, command injection, weak crypto, unsafe deserialization, and more
- **11 languages** -- JS/TS, Python, Go, Ruby, Java, PHP, Rust, C#, Swift, Kotlin, C
- **Cross-file taint tracking** with intraprocedural dataflow and cross-file summaries
- **Diff scans** -- only new findings since a target branch
- **Secrets scanning** -- AWS keys, GitHub/GitLab/Slack/Stripe tokens, private keys
- **Post-quantum crypto audit** -- CNSA 2.0 migration deadlines on every finding
- **Semgrep/OpenGrep-compatible YAML bridge** -- load external rule packs via `--rules`
- **Interactive TUI** -- triage, baseline, ignore, severity overrides
- **Output formats** -- terminal, JSON, SARIF, CycloneDX 1.6 CBOM
- **GitHub App** -- auto-scans PRs, posts inline comments, check runs

## Install

```sh
npx foxguard .                                      # zero install
curl -fsSL https://foxguard.dev/install.sh | sh     # prebuilt binary (macOS/Linux)
cargo install foxguard                              # from source
```

**GitHub Action:**

```yaml
- uses: 0sec-labs/foxguard/action@v0.8.1
  with:
    path: .
    severity: medium
    fail-on-findings: "true"
    upload-sarif: "true"
```

**VS Code:** [Install extension](https://marketplace.visualstudio.com/items?itemName=peaktwilight.foxguard) -- scans on save, inline findings.

**Claude Code:** `claude --plugin-dir ./plugins/claude-code` -- see [docs](docs/claude-code-integration.md).

## Quick start

```sh
foxguard .                    # scan everything
foxguard diff main .          # only new findings vs main
foxguard secrets .            # leaked credentials and keys
foxguard pqc .                # post-quantum crypto audit
foxguard tui .                # interactive triage UI
foxguard --format sarif . > results.sarif   # SARIF for CI
```

## GitHub App

[![Install foxguard on GitHub](https://img.shields.io/badge/Install_on_GitHub-foxguard--app-2ea44f?style=for-the-badge&logo=github)](https://github.com/apps/foxguard-app/installations/new)

Scans every pull request automatically. Posts inline comments on new findings and reports check run status. Zero config -- install and it works.

## Supported languages

| Language | Taint tracking | Framework-aware |
|----------|:-:|:-:|
| JavaScript / TypeScript | Yes | Express, Next.js |
| Python | Yes | Django, Flask, FastAPI |
| Go | Yes | Gin |
| Kotlin | Yes | Spring |
| Java | -- | Spring |
| Ruby | -- | Rails |
| PHP | -- | Laravel |
| Rust | -- | -- |
| C# | -- | .NET |
| Swift | -- | iOS |
| C | -- | via Semgrep YAML / Coccinelle |

## Post-quantum crypto audit

```sh
foxguard pqc .
```

```
src/tls/client.go
  42:14  HIGH  go/pq-vulnerable-crypto (CWE-327)
         ECDH P-256 is not post-quantum safe.
         CNSA 2.0 deadline: traditional networking equipment, 2030.
```

Each finding carries its CNSA 2.0 migration deadline. Covers Python, JS/TS, Go, Java, Rust, and TLS config files. Export as CycloneDX 1.6 CBOM with `--format cbom`.

## Configuration

foxguard auto-discovers `.foxguard.yml` from the scan path upward.

```yaml
scan:
  baseline: .foxguard/baseline.json
  disable_rules: [py/no-eval]
  severity_overrides:
    py/no-hardcoded-secret: medium

secrets:
  exclude_paths: [fixtures, testdata]
```

Inline suppression: `// foxguard: ignore[rule-id]`. Full reference at [foxguard.dev/docs](https://foxguard.dev/docs).

## Benchmarks

| Repo | LoC | foxguard | Semgrep | Speedup |
|------|-----|----------|---------|---------|
| express | 15K JS | 0.28s | 6.09s | **22x** |
| flask | 14K Py | 0.33s | 6.51s | **20x** |
| gin | 18K Go | 0.50s | 4.95s | **10x** |
| sentry | 1.3M Py | 35s | 194s | **5x** |

Reproduce: `./benchmarks/run.sh`. See [`benchmarks/README.md`](./benchmarks/README.md).

## Contributing

Adding a rule is one struct implementing a trait. See [`CONTRIBUTING.md`](./CONTRIBUTING.md).

## License

MIT OR Apache-2.0 -- [0sec Labs](https://0sec.ai)
