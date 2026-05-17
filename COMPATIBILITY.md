# foxguard Compatibility

Fast local security guard for changed files, built-in rules, Semgrep-compatible YAML, and Coccinelle semantic patches.

foxguard supports a focused Semgrep-compatible YAML subset for local rule loading and an additive Coccinelle bridge for C semantic patches.

That supported subset is regression-tested in-repo and parity-checked in CI against the real `semgrep` CLI.

The product default is still built-in rules. Compatibility mode exists to help teams adopt foxguard without throwing away existing rule work on day one.

## Recommended usage

Built-ins first:

```sh
foxguard .
foxguard secrets .
foxguard --rules ./rules .
foxguard --changed .
```

External-rules-only compatibility run:

```sh
foxguard --no-builtins --rules ./rules .
```

Coccinelle-backed C rule:

```sh
foxguard --rules ./kernel-rules .
```

Adoption baseline:

```sh
foxguard baseline --output .foxguard/baseline.json
foxguard --baseline .foxguard/baseline.json .
```

## Supported today

Top-level structure:

- `rules`
- `id`
- `message`
- `severity`
- `languages`
- `metadata.cwe`

Pattern operators:

- `pattern`
- `pattern-regex`
- `pattern-either`
- `pattern-not`
- `pattern-not-regex`
- `pattern-not-inside`
- `pattern-inside`
- `patterns`

Rule scoping:

- `paths.include`
- `paths.exclude`

Metavariable filtering:

- `metavariable-regex`

Taint rules (`mode: taint`):

- `mode: taint` on Python rules only; non-Python taint rules are skipped with a warning
- `pattern-sources`, `pattern-sinks`, `pattern-sanitizers` — each entry must be either a single `pattern:` string or a `pattern-either:` list (nested `pattern-either:` is supported and flattens recursively)
- Supported `pattern:` shapes:
  - bare identifier (`request`) — a source-only shape compiled to a parameter-name match
  - dotted attribute chain (`request.data`, `request.json`) — nested chains flatten to `leftmost root + outermost field` (matches the engine's one-level attribute propagation)
  - call forms with any arguments (`pickle.loads($X)`, `pickle.loads(...)`, `pickle.loads()`, `eval($X)`) — arguments are stripped, the dotted callee path is what matches
- Severity mapping matches the pattern-rule bridge (`ERROR` → Critical, `WARNING` → High, `INFO` → Medium) and `metadata.cwe` is propagated to findings
- Rules that use anything outside this subset (`patterns:` / `pattern-inside:` / `metavariable-pattern:` inside a source/sink/sanitizer block, unsupported pattern shapes, non-Python languages, missing sources or sinks) are skipped with a warning — other rules in the same file still load. Entries with unsupported keys are dropped individually so a single bad entry will not disable sibling entries in the same block.

Language mapping:

- JavaScript / TypeScript
- Python
- Go

Rule loading:

- load a single YAML file
- load a directory recursively
- deduplicate language aliases that map to the same foxguard parser

## Coccinelle bridge

Rules with `engine: coccinelle` are loaded from the same `--rules` YAML files or directories as Semgrep-compatible rules:

```yaml
rules:
  - id: kernel/dirty-frag-inplace-crypto-no-cow
    engine: coccinelle
    severity: high
    languages: [c]
    metadata:
      cwe: CWE-362
    message: In-place crypto on skb data without a preceding copy-on-write gate.
    script_path: dirty-frag-inplace-crypto-no-cow.cocci
```

Supported Coccinelle rule keys:

- `id`
- `engine: coccinelle`
- `message`
- `severity` (`critical`, `high`, `medium`, `low`, plus Semgrep-style `ERROR`, `WARNING`, `INFO`)
- `languages: [c]`
- `metadata.cwe`
- `script` for inline SmPL
- `script_path` for a `.cocci` file relative to the YAML file

Execution model:

- foxguard shells out to upstream `spatch`; whatever SmPL surface your installed `spatch` accepts is the supported SmPL surface.
- Coccinelle currently scans `.c` and `.h` files.
- Findings are normalized into the same `Finding` shape used by built-in and Semgrep-compatible rules, so terminal, JSON, SARIF, CBOM, and baselines work through the existing report path.
- If `spatch` is missing, foxguard emits one warning and skips Coccinelle rules while continuing the rest of the scan.

## Important limitations

foxguard does **not** claim full Semgrep or OpenGrep compatibility.

If a feature is not listed in the supported section above, assume it is either unsupported or only partially supported today.

That includes more advanced Semgrep/OpenGrep capabilities such as:

- the broader rule syntax beyond the subset above
- the full ecosystem of published registry rules
- engine behaviors that depend on features foxguard does not implement yet

## Product stance

The intended model is:

- foxguard built-ins are the default product
- external YAML is the adoption bridge
- Semgrep and OpenGrep remain the reference tools for the broadest rule ecosystems

This keeps the promise clear:

- use foxguard for fast local feedback
- bring in compatible YAML where it helps
- do not assume full drop-in equivalence
