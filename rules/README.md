# foxguard YAML rule packs

## What this is

Opt-in, Semgrep-compatible YAML rule packs. **Nothing under `rules/` is loaded by default.** The canonical engine ships 188 Rust rules registered in [`src/rules/mod.rs`](../src/rules/mod.rs) (the `registry.register(...)` block starting at line 309) and compiled into the binary. The YAML packs here are domain extensions you layer on top when scanning a target that warrants them — the Linux kernel today, potentially a compliance or vendor corpus later. Keeping them out-of-binary is deliberate: the broad regex shapes carry recall/precision trade-offs only acceptable when the operator opts in for a known target class.

## How to load

The `--rules` flag points at a file or directory; the loader walks recursively for `*.yaml` / `*.yml`:

```sh
foxguard --rules rules/kernel/dirty-frag-class/ ./linux/
```

The flag is defined in [`src/cli.rs:78`](../src/cli.rs) and dispatched in [`src/app.rs:679`](../src/app.rs), which calls `load_semgrep_rules` ([`src/rules/semgrep_compat.rs:1122`](../src/rules/semgrep_compat.rs)). Built-in Rust rules still run unless you also pass `--no-builtins`.

## Layout convention

```
rules/<area>/<class>/
```

- `<area>` is a coarse topic — today: `kernel`. Future areas might be `compliance`, `vendor`, `cloud`.
- `<class>` is a specific bug class or rule grouping inside that area.
- Each `<class>/` contains the Semgrep-compat YAML rules plus an optional `queries/` subdirectory for companion CodeQL queries referenced by `engine: codeql` rules.

## What's here today

| Pack | Description |
|------|-------------|
| [`kernel/dirty-frag-class/`](kernel/dirty-frag-class/README.md) | Linux kernel Dirty Frag (SKB shared-fragment in-place decrypt) memory-corruption class — oss-security 2026-05-07. |

## Adding a new pack

1. Pick a path under `rules/<area>/<class>/`. Reuse an existing `<area>` if one fits; otherwise add a new top-level folder.
2. Write Semgrep-compat YAML (`pattern-regex`, `pattern-not-regex`, `paths.include` / `paths.exclude`, `languages`, `severity`, `metadata.cwe`, `metadata.references`). Any rule under `kernel/dirty-frag-class/` shows the shape the loader accepts.
3. Add calibration tests in `tests/<area>_<class>.rs` that drive `parse_semgrep_file` against positive and negative fixtures. Use [`tests/kernel_dirty_frag.rs`](../tests/kernel_dirty_frag.rs) as the template — it loads each YAML, parses fixtures with tree-sitter-c, and asserts finding counts.
