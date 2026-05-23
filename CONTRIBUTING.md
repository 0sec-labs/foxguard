# Contributing to foxguard

## Adding a rule

Each language has its own rule file in `src/rules/`. To add a new rule:

1. Add a struct in the appropriate language file (e.g., `src/rules/javascript.rs`)
2. Use the `impl_rule!` macro to define rule metadata and the check body — see any existing rule for the pattern
3. Register it in `src/rules/mod.rs` inside `RuleRegistry::new()`
4. Add a test case to the corresponding fixture in `tests/fixtures/`
5. Regenerate the website rule inventory: `cargo run --bin gen_rules_ts > www/src/data/rules.ts`
6. Run `cargo test` and `cargo clippy -- -D warnings`

The `impl_rule!` macro (defined in `src/rules/mod.rs`) eliminates boilerplate — each rule is a one-liner for metadata plus the check logic. Look at any existing rule in `src/rules/go.rs` for the pattern.

The Rust registry is the single source of truth for rule metadata. `www/src/data/rules.ts` is generated from it by `src/bin/gen_rules_ts.rs` and must not be hand-edited. The `rule-inventory-check` CI job and the `rule_inventory` cargo test both fail if the committed file drifts from the generator output.

### Rust vs YAML rule packs

Use a YAML rule pack under `rules/<area>/<class>/` if the detection is Semgrep-shaped — `pattern-regex` / `pattern-not-regex` with `paths.include` / `paths.exclude`, scoped to a specific bug class or vendor corpus. Drop the YAML in place and rebuild; `include_dir!` snapshots `rules/` at compile time and `RuleRegistry::new()` registers it alongside the Rust core. See [`rules/README.md`](./rules/README.md) for the layout and calibration-test convention.

YAML rule IDs must use a pack-specific namespace, for example `kernel/dirty-frag/<rule-name>` or `acme/security/<rule-name>`. Do not use reserved built-in namespaces: `py/`, `js/`, `go/`, `java/`, `php/`, `ruby/`, `cs/`, `csharp/`, `swift/`, `kotlin/`, `rs/`, `rust/`, `config/`, or `manifest/`.

Add a Rust rule (per the steps above) when the detection needs cross-file taint, custom Rust types or traits, or non-trivial AST analysis that the Semgrep-compat surface can't express.

## Adding a language

1. Add the tree-sitter grammar to `Cargo.toml`
2. Add a `Language` variant in `src/lib.rs`
3. Update `src/engine/parser.rs` and `src/engine/scanner.rs`
4. Update `src/rules/semgrep_compat.rs` language mapping
5. Create `src/rules/<language>.rs` with rules
6. Register in `src/rules/mod.rs`
7. Add a test fixture in `tests/fixtures/`

## Development

```sh
cargo build              # build
cargo test               # run tests
cargo clippy -- -D warnings  # lint
cargo fmt                # format
```

## Project structure

```
src/              # Rust source
  rules/          # One file per language (javascript.rs, python.rs, etc.)
  engine/         # Scanner, parser
  report/         # Terminal, JSON, SARIF output
  secrets.rs      # Secrets scanning
www/              # foxguard.dev (Astro)
  src/data/       # Rule data for the website
  src/content/    # Blog posts (markdown)
vscode-extension/ # VS Code extension
packages/npm/     # npm wrapper (downloads binary)
action/           # GitHub Action
benchmarks/       # Benchmark suite
```

## Releasing

```sh
./scripts/release.sh 0.6.1
```

This prepares a tag-driven release:

- bumps Cargo, npm, and VS Code extension versions
- refreshes the tracked VS Code lockfile
- runs the verification suite
- commits the release metadata
- pushes `main` and the `v*` tag

The GitHub `Release` workflow then:

- verifies the tag matches all package versions
- builds the release binaries
- creates the GitHub Release
- publishes crates.io, npm, and the VS Code extension

For the full runbook and recovery rules, see [`RELEASING.md`](./RELEASING.md).

Required GitHub repository secrets:

- `CARGO_REGISTRY_TOKEN`
- `NPM_TOKEN`
- `VSCE_PAT`

## Pull requests

- One feature or fix per PR
- Include tests for new rules
- Run `cargo fmt` and `cargo clippy` before submitting
- If you added or modified rules, regenerate `www/src/data/rules.ts` with `cargo run --bin gen_rules_ts > www/src/data/rules.ts` and commit the result
