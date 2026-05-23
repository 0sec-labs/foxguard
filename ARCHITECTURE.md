# Architecture

foxguard is a Rust-native static analyzer with tree-sitter parsers for 11 programming languages (`src/lib.rs:43-60`) plus five configuration formats (nginx, Apache, HAProxy, Dockerfile, package manifests). It runs at linter speed locally and ships as a CLI, GitHub App, Claude Code plugin, VS Code extension, and GitHub Action.

## Rule model: Rust core + YAML extensions

There are two rule surfaces, and the distinction matters.

**Rust canonical core (188 rules).** Every built-in rule is a Rust struct registered at startup in `RuleRegistry::new()` (`src/rules/mod.rs:305-518`). Rules live in one file per language under `src/rules/` (`javascript.rs`, `python.rs`, `go.rs`, `java.rs`, `php.rs`, `ruby.rs`, `csharp.rs`, `swift.rs`, `kotlin.rs`, `rust_lang.rs`) plus cross-cutting files for taint, config, and manifest rules. They use the `impl_rule!` macro (`src/rules/mod.rs:86`) for boilerplate-free metadata and are exercised by fixture-based tests in `tests/fixtures/`. This is the curated, hardened, byte-identical-output-tested core. `www/src/data/rules.ts` is generated from this registry by `src/bin/gen_rules_ts.rs` and is enforced by CI to never drift (`CONTRIBUTING.md:16`).

**YAML rule packs (opt-in).** External Semgrep-compatible YAML rules are loaded only when the user explicitly passes `--rules <path>` (`src/cli.rs:76-78`). The loader walks the path and parses each file via `load_semgrep_rules` (`src/rules/semgrep_compat.rs:1122-1151`), wiring the resulting rules into the same `RuleRegistry` (`src/app.rs:678-683`). With `--no-builtins`, the registry starts empty and only the YAML pack runs (`src/app.rs:672-676`). No YAML is embedded in the binary.

`rules/kernel/dirty-frag-class/` is the first such pack: a maintainer-curated, domain-specific bundle of Semgrep-shaped YAML rules calibrated against a single Linux kernel bug class (ESP/AEAD shared-fragment regressions, scatterwalk store hazards, RxRPC dispatch). It is versioned alongside the repo but stays out of the default scan. Future packs (other kernel classes, vendor-specific compliance) belong under `rules/<area>/<class>/` and follow the same opt-in load path. There is no duplication between Rust and YAML rules — they are different layers with different review bars.

The `queries/` subfolder under `dirty-frag-class/` holds CodeQL `.ql` queries and a `qlpack.yml`. The Semgrep loader skips rules with `engine: codeql` (`src/rules/semgrep_compat.rs:1057-1066`); these queries are static reference material today, not wired into the default runtime. The separate CodeQL driver in `src/engine/codeql.rs` shells out to `codeql` and requires an explicit `--codeql-db`.

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
