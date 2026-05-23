# foxguard YAML rule packs

## What this is

A directory of Semgrep-compatible YAML rule packs that **ship inside the `foxguard` binary and load by default**. `rules/` is embedded at compile time via `include_dir!` ([`src/rules/mod.rs:35`](../src/rules/mod.rs)); the Semgrep-compat loader walks the tree recursively, registers every `.yaml` / `.yml` file alongside the 188 Rust rules in the same `RuleRegistry::new()` call ([`src/rules/mod.rs:538`](../src/rules/mod.rs)), and skips `queries/` subdirs so companion CodeQL pack metadata doesn't reach the YAML parser ([`src/rules/semgrep_compat.rs:1198-1208`](../src/rules/semgrep_compat.rs)).

Plain `foxguard <target>` therefore runs the kernel/dirty-frag-class pack today without any flags. The packs are versioned alongside the engine and reviewed at the same bar as Rust rules.

## How to disable

`--no-builtins` ([`src/cli.rs:86-88`](../src/cli.rs), wired in [`src/app.rs:682-686`](../src/app.rs)) suppresses both the Rust core and the bundled YAML packs. There is no separate flag to disable bundled YAML alone — if and when someone needs that, we'll add one.

## Adding external packs on top

`--rules <path>` ([`src/cli.rs:76-78`](../src/cli.rs)) still loads additional Semgrep-shaped YAML rules from a directory or file, layered on top of the bundled set in the same registry ([`src/app.rs:688-695`](../src/app.rs)). Use it for organization-specific rule libraries or third-party packs.

```sh
foxguard --rules /path/to/org-rules ./target/
```

External rule IDs must use a pack-specific namespace, such as `acme/security/no-unsafe-call`. The built-in namespaces are reserved and rejected at load time: `py/`, `js/`, `go/`, `java/`, `php/`, `ruby/`, `cs/`, `csharp/`, `swift/`, `kotlin/`, `rs/`, `rust/`, `config/`, and `manifest/`.

## Layout convention

```
rules/<area>/<class>/
```

- `<area>` is a coarse topic — today: `kernel`. Future areas might be `compliance`, `vendor`, `cloud`.
- `<class>` is a specific bug class or rule grouping inside that area.
- Each `<class>/` contains the Semgrep-compat YAML rules plus an optional `queries/` subdirectory for companion CodeQL queries referenced by `engine: codeql` rules. The embedded walker skips `queries/` subtrees by name.

## What's here today

| Pack | Description |
|------|-------------|
| [`kernel/dirty-frag-class/`](kernel/dirty-frag-class/README.md) | Linux kernel Dirty Frag (SKB shared-fragment in-place decrypt) memory-corruption class — oss-security 2026-05-07. |

## Adding a new pack

1. Pick a path under `rules/<area>/<class>/`. Reuse an existing `<area>` if one fits; otherwise add a new top-level folder.
2. Pick rule IDs under a pack-specific namespace, for example `kernel/dirty-frag/<rule-name>`. Do not use reserved built-in namespaces such as `py/`, `go/`, `rs/`, `config/`, or `manifest/`.
3. Write Semgrep-compat YAML (`pattern-regex`, `pattern-not-regex`, `paths.include` / `paths.exclude`, `languages`, `severity`, `metadata.cwe`, `metadata.references`). Any rule under `kernel/dirty-frag-class/` shows the shape the loader accepts.
4. Add calibration tests in `tests/<area>_<class>.rs` that drive `parse_semgrep_file` against positive and negative fixtures. Use [`tests/kernel_dirty_frag.rs`](../tests/kernel_dirty_frag.rs) as the template — it loads each YAML, parses fixtures with tree-sitter-c, and asserts finding counts.

Files placed under `rules/` are picked up automatically on the next `cargo build` — `include_dir!` re-snapshots the tree at compile time. No edit to `RuleRegistry::new()` is required for new YAML packs.
