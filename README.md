<p align="center">
  <img src="assets/logo.png" width="128" alt="foxguard" />
</p>

<h1 align="center">foxguard</h1>

<p align="center">
  <strong>Fast local security scanning for code, secrets, dependencies, and crypto risk.</strong>
</p>

<p align="center">
  <a href="https://github.com/0sec-labs/foxguard/actions/workflows/ci.yml"><img src="https://github.com/0sec-labs/foxguard/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://github.com/0sec-labs/foxguard"><img src="https://img.shields.io/badge/foxguard-clean-3fb950" alt="foxguard: clean" /></a>
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

## Why

- 200+ built-in rules across 12 source languages, plus config and manifest checks
- Taint tracking for 14 languages, with cross-file analysis for Python, JavaScript, Go, Java, Ruby, PHP, C#, and Kotlin
- Fast local and CI scans, with diff mode for “what did this branch add?”
- Secrets scanning, OSV-backed dependency scanning, and post-quantum crypto audit
- Semgrep/OpenGrep-compatible YAML bridge that loads ~98% of the public registry ([coverage report](docs/parity/registry-coverage.md))
- Terminal, JSON, SARIF, CycloneDX 1.6 CBOM, and Semgrep-compatible JSON output

## Install

```sh
npx foxguard .                                      # zero install
curl -fsSL https://foxguard.dev/install.sh | sh     # prebuilt binary (macOS/Linux)
cargo install foxguard                              # from source
```

Prebuilt installs verify release binaries against `checksums.txt`. Release binaries also publish GitHub artifact attestations; use `gh attestation verify` for manual verification, or see [release provenance](docs/release-provenance.md).

**GitHub Action:**

```yaml
- uses: 0sec-labs/foxguard/action@v0.11.0
  with:
    path: .
    severity: medium
    fail-on-findings: "true"
    upload-sarif: "true"
```

**pre-commit:**

```yaml
repos:
  - repo: https://github.com/0sec-labs/foxguard
    rev: v0.11.0
    hooks:
      - id: foxguard
```

Integrations: [GitHub App](https://github.com/apps/foxguard-app/installations/new), [VS Code](https://marketplace.visualstudio.com/items?itemName=peaktwilight.foxguard), [Claude Code plugin](docs/claude-code-integration.md), and [MCP server](docs/mcp-server.md).

## Quick Start

```sh
foxguard .                              # scan everything
foxguard diff main .                    # only new findings vs main
foxguard secrets .                      # leaked credentials and keys
foxguard sca .                          # dependency vulnerabilities from OSV
foxguard pqc .                          # post-quantum crypto audit
foxguard --format sarif . > results.sarif
foxguard --format semgrep-json .        # Semgrep CLI-compatible JSON
```

## Language Coverage

| Language | Built-in rules | Taint tracking | Framework-aware rules |
|----------|:-:|:-:|---|
| JavaScript / TypeScript | Yes | Yes | Express, Next.js |
| Python | Yes | Yes | Django, Flask, FastAPI |
| Go | Yes | Yes | Gin |
| Kotlin | Yes | Yes | Spring |
| Java | Yes | Yes | Spring |
| Ruby | Yes | Yes | Rails |
| PHP | Yes | Yes | Laravel |
| Rust | Yes | -- | -- |
| C# | Yes | Yes | .NET |
| Swift | Yes | Yes | iOS |
| Haskell | Yes | -- | Cardano seed rules |

Taint tracking also covers C, Bash, and Solidity. Config, manifest, and external-rule scans cover Dockerfile, Nginx, Apache, HAProxy, HCL/Terraform, YAML/JSON/XML/HTML, C via Semgrep YAML/Coccinelle, and more.

## Security Modes

```sh
foxguard sca .
foxguard pqc .
foxguard --rules ./semgrep-rules .
```

SCA supports `Cargo.lock`, `package-lock.json`, `pnpm-lock.yaml`, `requirements.txt`, `poetry.lock`, and `Pipfile.lock`. The PQC audit is a two-sided scorecard: it flags quantum-vulnerable primitives (RSA, ECDSA/DSA, ECDH/DH) with CNSA 2.0 migration deadlines, and it also detects post-quantum algorithms already in use (ML-KEM, ML-DSA, SLH-DSA, FN-DSA, HQC, and hybrids like X25519MLKEM768) as informational, quantum-resistant inventory — reporting a migration-readiness percentage. Both sides export to a CycloneDX 1.6 CBOM, where post-quantum algorithms appear as quantum-resistant assets rather than vulnerabilities.

## Configuration

foxguard auto-discovers `.foxguard.yml` from the scan path upward.

```yaml
scan:
  baseline: .foxguard/baseline.json
  disable_rules: [py/no-eval]

secrets:
  exclude_paths: [fixtures, testdata]
```

Suppress an accepted finding inline with `// foxguard: ignore[rule-id]`.

## Benchmarks

| Repo | LoC | foxguard | Semgrep | Speedup |
|------|-----|----------|---------|---------|
| express | 15K JS | 0.28s | 6.09s | **22x** |
| flask | 14K Py | 0.33s | 6.51s | **20x** |
| gin | 18K Go | 0.50s | 4.95s | **10x** |
| sentry | 1.3M Py | 35s | 194s | **5x** |

Reproduce with `./benchmarks/run.sh`; results vary by machine. See [`benchmarks/README.md`](./benchmarks/README.md).

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for rule authoring, tests, and development setup.

## License

MIT OR Apache-2.0 -- [0sec Labs](https://0sec.ai)
