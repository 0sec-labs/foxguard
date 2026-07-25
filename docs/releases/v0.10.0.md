# foxguard v0.10.0 - Haskell support + broader Semgrep compatibility

This release makes Haskell a first-class scanned language, expands the Semgrep/OpenGrep compatibility layer substantially, and tightens the shipped integrations around PR review noise and editor suppressions.

```sh
npx foxguard@latest .
```

## Highlights

### Haskell and Cardano rules

- Added Haskell parser support end-to-end: `.hs`, `.lhs`, and `.hsc` files now scan through tree-sitter Haskell.
- Added Semgrep-compatible `languages: [haskell]` support, including generic/regex fan-out and Haskell comment handling.
- Added built-in Cardano Haskell seed rules for high-signal review leads around unsafe partials, FFI boundaries, and CBOR/VRF-style parsing hazards.
- Added Haskell fixtures and parity tests so Haskell support stays covered in CI.

### Semgrep/OpenGrep compatibility

- Expanded generic mode support for `patterns`, `pattern-either`, `pattern-regex`, named regex captures, metavariable constraints, and PCRE-style lookahead/backreference fallback via `fancy-regex`.
- Added or improved Semgrep taint bridge shapes for parameter-as-source, focus-on-call-argument sinks, call-on-member, field/subscript/receiver-call sources, object/dict-literal values, tainted return values, binary/string-format sinks, and metavariable-regex-bounded callees.
- Added external taint-mode engines/bridges for more languages, including Ruby, PHP, C#, Bash, Solidity, Scala, Apex, and Swift.
- Registry coverage now loads 2,066 of 2,144 tracked registry rules, a 96.4% load rate; the remaining skips are mostly unsupported taint shapes.

### Integrations and workflow fixes

- Reduced GitHub App PR review noise so app comments are less repetitive on repeated scans.
- Routed VS Code config suppressions through the Rust CLI config editor instead of duplicating YAML mutation logic in the extension.
- Added a hidden internal CLI command for editor-owned suppression writes, with duplicate no-rewrite handling and safer JSON/process behavior.
- Isolated MCP scan fixtures from repo baseline discovery so local config no longer hides the fixture finding under test.

### Docs, packaging, and site

- Refreshed README, npm package metadata, VS Code metadata, website copy, architecture docs, and the Claude Code skill for 200+ built-in rules across 12 source languages.
- Updated Foxguard/0sec branding on the site to the current 0sec aperture mark.
- Clarified built-in taint-rule coverage versus Semgrep-compatible external taint engines.
- Kept release provenance instructions pinned and CI-checked: prebuilt binaries publish checksums and GitHub artifact attestations.

### Dependency maintenance

- Updated website dependencies including Astro, js-yaml, Vite, and esbuild to clear current dev-server/package advisories.

## Verification

- `cargo fmt --check`
- `cargo clippy -- -D warnings`
- `cargo test`
- `npm ci && npm run build` in `www`
- `npm ci && npm run compile` in `vscode-extension`
- `npm pack --dry-run` in `packages/npm`
- Main branch CI and GitHub App Image workflows are green before tagging.

## Upgrade

```sh
npx foxguard@latest .
# or
curl -fsSL https://foxguard.dev/install.sh | sh
# or
cargo install foxguard
```

GitHub Action and pre-commit users can now pin `v0.10.0`:

```yaml
- uses: 0sec-labs/foxguard/action@v0.10.0
```

```yaml
repos:
  - repo: https://github.com/0sec-labs/foxguard
    rev: v0.10.0
    hooks:
      - id: foxguard
```
