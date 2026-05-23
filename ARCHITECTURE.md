# Architecture

foxguard is a Rust-native static analyzer with tree-sitter parsers for 11 programming languages (`src/lib.rs:43-60`) plus five configuration formats (nginx, Apache, HAProxy, Dockerfile, package manifests). It runs at linter speed locally and ships as a CLI, GitHub App, Claude Code plugin, VS Code extension, and GitHub Action.

## Rule model: Rust core + bundled YAML + external YAML

There are three rule surfaces.

**Rust canonical core (188 rules).** Every Rust rule is a struct registered at startup in `RuleRegistry::new()` (`src/rules/mod.rs:316-543`). Rules live in one file per language under `src/rules/` (`javascript.rs`, `python.rs`, `go.rs`, `java.rs`, `php.rs`, `ruby.rs`, `csharp.rs`, `swift.rs`, `kotlin.rs`, `rust_lang.rs`) plus cross-cutting files for taint, config, and manifest rules. They use the `impl_rule!` macro (`src/rules/mod.rs:98`) for boilerplate-free metadata and are exercised by fixture-based tests in `tests/fixtures/`. This is the curated, hardened, byte-identical-output-tested layer. `www/src/data/rules.ts` is generated from this registry by `src/bin/gen_rules_ts.rs` and is enforced by CI to never drift (`CONTRIBUTING.md:16`).

**Bundled YAML rule packs.** `rules/` is embedded into the binary at compile time via `include_dir!` (`src/rules/mod.rs:35`). Each `.yaml` / `.yml` file is parsed through the Semgrep-compat loader and registered alongside the Rust rules at startup — same registry, same scan loop, no flag required. The embedded walker (`src/rules/semgrep_compat.rs:1172-1209`) is invoked from `RuleRegistry::new()` (`src/rules/mod.rs:538-540`) and skips `queries/` subdirs so CodeQL pack metadata doesn't reach the YAML parser. `rules/kernel/dirty-frag-class/` is today's only bundled pack — a maintainer-curated bundle of Semgrep-shaped YAML rules calibrated against a single Linux kernel bug class (ESP/AEAD shared-fragment regressions, scatterwalk store hazards, RxRPC dispatch). Future packs (other kernel classes, vendor compliance) go under `rules/<area>/<class>/` and load the same way.

**External YAML rule packs.** `foxguard --rules <path>` (`src/cli.rs:76-78`) loads additional Semgrep-shaped YAML rules from a user-supplied directory, layered on top of the bundled set in the same `RuleRegistry` (`src/app.rs:688-695`). Used for organization-specific rule libraries or third-party packs. The on-disk loader is `load_semgrep_rules` (`src/rules/semgrep_compat.rs:1133-1162`), which is a thin wrapper over `parse_semgrep_file` / `parse_semgrep_str` (`src/rules/semgrep_compat.rs:1039-1130`) — the same entry points the embedded walker uses.

**`--no-builtins`** (`src/app.rs:682-686`) suppresses both the Rust core and the bundled YAML packs, so the registry contains only what the user passes via `--rules`. There is no separate flag to disable bundled YAML alone. There is no duplication between Rust and YAML rules — they are different layers with different review bars.

The `queries/` subfolder under `dirty-frag-class/` holds CodeQL `.ql` queries and a `qlpack.yml`. The Semgrep loader skips rules with `engine: codeql` (`src/rules/semgrep_compat.rs:1067-1077`); the separate CodeQL driver in `src/engine/codeql.rs` shells out to `codeql`. When `codeql` is on PATH, the driver auto-creates an ephemeral database scoped to the scan target via `codeql database create --language=<lang> --source-root=<target>` and runs the loaded `.ql` queries against it. Explicit `--codeql-db` and `FOXGUARD_CODEQL_DB` still take precedence; they're the right escape hatch for users with a pre-built DB.

## Engine

`src/engine/parser.rs` parses source into tree-sitter trees with per-language grammars (`tree-sitter-python`, `tree-sitter-go`, ...). `src/engine/scanner.rs` is the parallel scanner driver (rayon, `ignore::WalkBuilder`) that batches AST rules by analysis requirement (`SyntaxTree` vs `FileContext`). The taint engine is intraprocedural and flow-insensitive, implemented per-language in `src/rules/python_taint.rs`, `src/rules/javascript_taint.rs`, and `src/rules/go_taint.rs`; design and limits are documented in `docs/taint-tracking.md`. Cross-file taint summaries live in `src/rules/cross_file.rs`.

## Integrations

- **CLI.** The `foxguard` binary, configured from `.foxguard.yml` at repo root for baselines and excludes.
- **GitHub App.** Webhook receiver under `src/github_app/` (`webhook.rs`, `auth.rs`, `review.rs`, `installation_store.rs`), built behind the `github-app` feature flag. Permissions, events, and Phase 2 plan are in `src/github_app/README.md`.
- **Claude Code plugin.** `plugins/claude-code/` adds `/foxguard:*` skills and post-edit hooks. Local plugin loading and hook behavior live in `docs/claude-code-integration.md`; the cross-agent contract is in `docs/agent-editor-integration.md`.
- **VS Code extension.** `vscode-extension/` (TypeScript) scans on save and surfaces findings inline.
- **GitHub Action.** `action/action.yml` plus `action/entrypoint.sh` wrap the CLI for CI, with SARIF upload to GitHub Code Scanning.

## Output formats

`src/report/` produces terminal (`terminal.rs`), JSON (`json.rs`), SARIF (`sarif.rs`), GitHub PR comments (`github_pr.rs`), and CycloneDX 1.6 CBOM for post-quantum crypto inventory (`cbom.rs`).

## Distribution

`npx foxguard@latest`, `cargo install foxguard`, `curl -fsSL https://foxguard.dev/install.sh | sh` for prebuilt binaries, and a reference `Dockerfile.github-app` for the webhook receiver. Homebrew was retired in favor of the install script (commit 6d55755). The npm wrapper under `packages/npm/` downloads the version-matched binary.

## Learning more

- Adding a rule or language: `CONTRIBUTING.md`.
- GitHub App internals: `src/github_app/README.md`.
- Taint engine scope and limits: `docs/taint-tracking.md`.
- False-positive policy: `docs/precision.md`.
- Agent/editor integration contract: `docs/agent-editor-integration.md`.
