# foxguard v0.11.0 — deeper Semgrep taint compatibility + a hardened GitHub App

This release pushes the Semgrep/OpenGrep taint-rule compatibility layer substantially higher and hardens the GitHub App that reviews pull requests, informed by production telemetry.

```sh
npx foxguard@latest .
```

## Highlights

### Semgrep/OpenGrep registry compatibility: 96.4% → 98.2%

Against the tracked registry snapshot (2,144 rules), foxguard now loads **2,106 rules (98.2%)**, up from 2,066 (96.4%) in v0.10.0 — **+40 taint rules**, via roughly a dozen new faithfully-matched `mode: taint` primitives. Every primitive fires on a positive fixture and stays silent on a near-miss (proven through the real `parse_taint_rule → compiled() → check()` path); where a rule could only be loaded by dropping a constraint that genuinely bounds the match, it is left skipped — over-matching is worse than skipping.

New taint-rule shapes now recognized include:

- **Typed-metavariable sources** for C# (`(Type $MV)`), plus a signature-first-parameter source and a concat-argument call sink (`xpath-injection`).
- **Focus-argument-of-call source** (`rng.NextBytes($X)` seeds `$X`) — the source-side dual of the focus-call sink.
- **Constructor-argument and property-assignment sinks** with `metavariable-regex` enumeration (`csharp-sqli`: `new SqlCommand($CMD)` / `$cmd.CommandText = $VALUE`).
- **Positional method-argument sink** and a **receiver-provenance call source** for Java (`tainted-session-from-http-request`, `md5-used-as-password`).
- **PHP** comparison-equality (`md5($x) == $y`), tainted class-name (`new $SINK(...)`), and tainted subscript-key (`$_SESSION[$KEY] = ...`) sinks.
- **Go** `[]byte("literal")` secret source (`hardcoded-jwt-key`) and a deep-wildcard method-name-enumerated sink (`gorm-dangerous-method-usage`); taint no longer flows through boolean comparison/logical operators (a `bool` predicate isn't operand data).
- **Ruby** `Digest::MD5` scope-path sources and `metavariable-pattern` alternation → concrete `Call` sinks (`Net::HTTP`).
- **Python** MCP decorated-handler-parameter sources (`@server.tool()`) for `mcp-ssrf` / `mcp-command-injection`.
- **JavaScript** inline `createHash("md5")` provenance source and enumerated DOM property-assignment sinks (`react-unsanitized-property`).

Bounded multi-hop cross-file taint is available for all eight cross-file languages (Python, JavaScript, Go, Java, C#, Ruby, PHP, Kotlin). The remaining skipped rules are diagnosed one-by-one in `docs/parity/` with the specific new primitive each would need.

### GitHub App: diff-scoped PR scanning + operational hardening

Driven by production log analysis (the App reviews PRs across its installations), this release fixes the two issues that mattered most:

- **Diff-scoped scan with fallback.** The App now runs the full-tree scan first (preserving whole-repo cross-file taint context) and, only if it exceeds `FOXGUARD_SCAN_TIMEOUT_SECS`, falls back to a scan of just the PR's changed files (`--changed-files-from`, a new CLI flag that scans a file list with repo root as analysis context). Non-code paths (`tests/fixtures`, `vendor`, `node_modules`, minified/`dist`/`build`) are excluded on both paths. In production this took the scan-timeout rate from ~20% (PRs that got **no review at all**) to 0%.
- **Configurable scan timeout** via `FOXGUARD_SCAN_TIMEOUT_SECS` (default 60), replacing a hardcoded 60s cap applied to both clone and scan.
- **Durable installation store** — install metadata now surfaces persistence errors with the exact path, so a misconfigured (read-only/ephemeral) volume is visible rather than silently dropped.

### Maintenance

- Removed dead code and stale `#[allow]` attributes; corrected accumulated documentation drift across the parity design notes and the GitHub App README.

## Compatibility

- 238 built-in rules across 12 source languages; first-party taint for 14 languages; cross-file taint for 8.
- Output: terminal, JSON, SARIF, CycloneDX 1.6 CBOM, and Semgrep-compatible JSON.
- No breaking changes to the CLI, config, or output formats.
