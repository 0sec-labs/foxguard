<p align="center">
  <img src="www/public/foxguard-logo.png" width="128" alt="foxguard" />
</p>

<h1 align="center">foxguard</h1>

<p align="center">
  <strong>Fast local security scanning for code, secrets, dependencies, and crypto risk.</strong>
  <br />
  <sub>Integrated into <a href="https://github.com/0sec-labs/0sec">0sec</a>, the open cybersecurity harness.</sub>
</p>

<p align="center">
  <a href="https://github.com/0sec-labs/foxguard/actions/workflows/ci.yml"><img src="https://github.com/0sec-labs/foxguard/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://github.com/0sec-labs/foxguard"><img src="https://img.shields.io/badge/foxguard-clean-3fb950" alt="foxguard: clean" /></a>
  <a href="https://crates.io/crates/foxguard"><img src="https://img.shields.io/crates/v/foxguard?color=d97706&label=crates.io" alt="crates.io" /></a>
  <a href="https://www.npmjs.com/package/foxguard"><img src="https://img.shields.io/npm/v/foxguard?color=d97706&label=npm" alt="npm" /></a>
  <a href="https://pypi.org/project/foxguard/"><img src="https://img.shields.io/pypi/v/foxguard?color=d97706&label=PyPI" alt="PyPI" /></a>
  <a href="https://github.com/apps/foxguard-app/installations/new"><img src="https://img.shields.io/badge/GitHub_App-Install-2ea44f?logo=github" alt="Install GitHub App" /></a>
</p>

```sh
npx foxguard .
```

<p align="center">
  <img src="assets/demo.gif" alt="foxguard scan demo" width="640" />
</p>

## Why

- <img height="14" src="https://raw.githubusercontent.com/0sec-labs/.github/main/profile/assets/icons/checklist.png" alt="">&nbsp; 200+ built-in rules across 12 source languages, plus config and manifest checks
- <img height="14" src="https://raw.githubusercontent.com/0sec-labs/.github/main/profile/assets/icons/git-branch.png" alt="">&nbsp; Taint tracking for 14 languages, with cross-file analysis for Python, JavaScript, Go, Java, Ruby, PHP, C#, and Kotlin
- <img height="14" src="https://raw.githubusercontent.com/0sec-labs/.github/main/profile/assets/icons/zap.png" alt="">&nbsp; Fast local and CI scans, with diff mode for “what did this branch add?”
- <img height="14" src="https://raw.githubusercontent.com/0sec-labs/.github/main/profile/assets/icons/key.png" alt="">&nbsp; Secrets scanning, OSV-backed dependency scanning, and post-quantum crypto audit
- <img height="14" src="https://raw.githubusercontent.com/0sec-labs/.github/main/profile/assets/icons/plug.png" alt="">&nbsp; Semgrep/OpenGrep-compatible YAML bridge that loads ~98% of the public registry ([coverage report](docs/parity/registry-coverage.md))
- <img height="14" src="https://raw.githubusercontent.com/0sec-labs/.github/main/profile/assets/icons/file-code.png" alt="">&nbsp; Terminal, JSON, SARIF, CycloneDX 1.6 CBOM, and Semgrep-compatible JSON output

## Install

```sh
npx foxguard .                                      # zero install
pipx install foxguard                               # prebuilt CLI from PyPI
curl -fsSL https://foxguard.dev/install.sh | sh     # prebuilt binary (macOS/Linux)
cargo install foxguard                              # from source
```

Standalone binary installers verify GitHub release binaries against `checksums.txt`. Release binaries also publish GitHub artifact attestations; use `gh attestation verify` for manual verification, or see [release provenance](docs/release-provenance.md).

PyPI wheels support Python 3.9+ on Linux glibc 2.28+ (x86_64/ARM64), macOS
(Intel/Apple Silicon), and Windows x86_64. In an existing Python virtual
environment, use `python -m pip install foxguard` instead. These install the native
CLI without a Rust compiler or a runtime binary download; no Python API is
provided. Alpine/musl users should use the standalone Linux release binaries.

**GitHub Action:**

```yaml
- uses: 0sec-labs/foxguard/action@v0.13.1
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
    rev: v0.13.1
    hooks:
      - id: foxguard
```

Integrations: [GitHub App](https://github.com/apps/foxguard-app/installations/new), [VS Code](https://marketplace.visualstudio.com/items?itemName=peaktwilight.foxguard), [Claude Code plugin](docs/claude-code-integration.md), and [MCP server](docs/mcp-server.md).

### Hosted GitHub App operations

`foxguard-github-app` writes newline-delimited JSON logs. Completed and failed
scans use `event=foxguard.scan.completed` and `event=foxguard.scan.failed`, with
delivery, installation, repository, PR, commit, duration, and `usage_scope`
fields for correlation. Keep identifiers as log fields, not metric labels.

Set `FOXGUARD_INTERNAL_ACCOUNTS` to a comma-separated list of your own GitHub
accounts and organizations. Matching is case-insensitive. Other owners are
classified as `external`; an unset list or missing owner produces `unknown`.
External activity is not proof of a paying customer, and scans are not people.

The installation registry is reconciled against all pages of GitHub's App
installation API at startup and hourly. Failed refreshes retain existing state;
concurrent webhooks take precedence. Sparse webhook metadata preserves known
account details and observed repository names. Those names are not a complete
inventory of an installation's accessible repositories.

Persist `FOXGUARD_INSTALLATIONS_PATH` and `FOXGUARD_PULL_REQUEST_JOBS_PATH` on
durable storage. Monitor `foxguard.installations.reconcile_failed` alongside
scan failures; `foxguard.installations.reconciled` reports the total and
internal/external/unknown installation counts after a successful refresh.
Size `FOXGUARD_PR_WORKERS` against measured scanner peak memory and the
container memory limit: child-process OOM kills can occur without restarting
the hosted application.

## Quick Start

```sh
foxguard .                              # scan everything
foxguard diff main .                    # only new findings vs main
foxguard tui .                          # interactive terminal review
foxguard secrets .                      # leaked credentials and keys
foxguard sca .                          # dependency vulnerabilities from OSV
foxguard pqc .                          # post-quantum crypto audit
foxguard --format sarif . > results.sarif
foxguard --format semgrep-json .        # Semgrep CLI-compatible JSON
```

Use `foxguard --fix src/` or `foxguard --fix src/app.py` to apply supported taint
fixes in place. Targets are checked against the canonical scan directory or the
selected file; findings outside that scope are skipped. Python command-injection
fixes add `import subprocess` when needed, preserving module docstrings and future
imports. Review generated changes before committing.

File read, metadata, and directory-traversal failures in the native code scanner
exit `2` instead of producing a successful report or overwriting a baseline.
Intentional exclusions and unsupported, binary, or oversized files remain skips;
inspect the skipped-file notices when checking scan coverage.

## Terminal Review

Run `foxguard tui .` and choose **Scan**, **Diff**, **Secrets**, or **PQC** with
the arrows or Tab. In Diff mode, type the target branch before pressing Enter.
Wide terminals show findings beside their detail; smaller terminals use a list
with an expandable detail view. Source context, dataflow, and fixes remain
scrollable whenever the finding provides them.
The loading card shows indeterminate activity and actual elapsed time, not a
percentage estimate. Ctrl+C exits during scanning.

| Key | Action |
|-----|--------|
| `j` / `k`, arrows, Home / End | Move between findings |
| `v` | Expand detail or return to the list/split view |
| PageUp / PageDown | Page the list, or scroll visible detail |
| `/`, Enter | Edit and apply a search |
| Ctrl+U | Clear the search being edited |
| Esc | Close a modal, cancel search edits, leave expanded detail, or clear applied filters |
| `0`–`4`, `c`, Shift+C | Minimum severity, confidence threshold, and sort order |
| `f` | Cycle All → Unreviewed → Todo → Reviewed → Ignore |
| `i` | Preview and apply triage actions |
| Space, `a`, `x` | Check one finding, toggle visible selections, and preview a batch action |
| Shift+F | Save, load, replace, or delete named filters; recover review storage |
| `b` | Cycle baseline categories when a comparison is available |
| Tab, Enter / `o` | Choose finding/source/sink and open it in your editor |
| `w`, `[` / `]` | Show notices and scroll their history; newest notices appear first |
| `e` | Export CBOM, JSON, or SARIF |
| `?`, `q` / Ctrl+C | Help and quit; Ctrl+C also works inside every modal |

Enter and `o` use a nonblank `$VISUAL`, then `$EDITOR`. Without either setting,
foxguard looks for `nvim`, `vim`, `nano`, or `vi` on `PATH` before considering an
available desktop opener. Headless terminals do not require `xdg-open`.
For example, run `VISUAL="nvim" foxguard tui .` or set
`EDITOR='code --wait'`. A broken explicit editor setting is reported rather than
silently replaced; if no editor is available, the TUI stays open with setup
guidance. Supported editors jump to the selected finding/source/sink line.

Review marks persist automatically in per-user storage, scoped to the canonical
project root and scan mode (including the target in Diff mode). Named filters
restore search, severity, confidence, review status, sorting, and baseline category
when loaded with Shift+F. They do not change repository scan configuration.
The list shows visible/total findings and review progress; changing filters or
sorting keeps the same finding selected when it remains visible. Canceling search
edits restores the previously applied query.

Checked findings survive filter changes. `x` opens batch actions; Enter shows the
exact targets, hidden-selection count, destination, and effect scope. Only `y`
applies the preview; Enter again does not confirm it, and Esc cancels without
writing. Baseline actions add exact fingerprints. Rule/file and project-wide
configuration actions can also affect unselected findings, as the preview warns.
If a configuration target fails, successful writes remain and outcomes are
reported; the batch is not a transaction.

Storage uses `$XDG_STATE_HOME/foxguard/tui` (or
`~/.local/state/foxguard/tui`) on Linux, Application Support on macOS, and
`%LOCALAPPDATA%` on Windows. Atomic writes and revision checks prevent one terminal
from silently overwriting another. Storage errors leave local changes visibly
**UNSAVED**. In Shift+F, `w` retries saving, `r` explicitly reloads from disk, and
Shift+R confirms a backup-and-reset of the current project/mode. Reload/reset can
discard unsaved changes; reset preserves the previous on-disk bytes, not unsaved
marks. Review storage contains fingerprints and filter settings, not source code.

Exports include the current scan's results, not just the visible filtered rows,
and are written to the current working directory. Existing regular files require
an explicit `y` confirmation; Esc cancels. Writes are atomic and destination
symlinks, including dangling links, are rejected.

Use `foxguard tui --baseline .foxguard/baseline.json .` to review a saved
baseline comparison. Unlike CLI suppression, terminal review retains current
findings and separates **introduced**, **recurring**, and **resolved** entries.
Resolved means absent from the current scan's output, not verified remediation:
compare equivalent scope, rules, and thresholds. Baseline identity includes the
file and source location, so moving a finding can appear as introduced plus
resolved. Resolved rows are read-only historical metadata; only search applies,
and `v` expands their scrollable details. Switch back to a current-finding category
to triage or export the current scan.
Git Diff remains a separate comparison against a branch.

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

## Documentation

Start with the [documentation index](./docs/README.md). Key references: [architecture](./docs/architecture.md), [Semgrep/OpenGrep compatibility](./docs/compatibility.md), and the [release runbook](./docs/releasing.md).

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
