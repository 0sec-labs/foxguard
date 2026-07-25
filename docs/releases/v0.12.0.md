# foxguard v0.12.0 — stable finding interchange and quieter Python reviews

This release gives Foxguard findings an explicit, tested interchange contract, connects that contract to 0sec's cross-tool ingestion path, hardens GitHub App pull-request admission, and removes false command-injection alerts for provably safe Python subprocess argument vectors.

```sh
npx foxguard@latest .
```

## Highlights

### Versioned native finding contract

- Native JSON now reports `finding_schema_version: "1.0.0"` independently of the report envelope's `schema_version`.
- The v1 finding shape is documented in `docs/finding-contract.md`, provided as `schemas/finding-v1.schema.json`, and pinned by a full-field golden fixture shared by Rust and VS Code tests.
- Native JSON, SARIF, the GitHub App, and the VS Code extension are tested against the same finding semantics. Existing integrations that still return a legacy bare finding array remain supported.
- Breaking changes to required finding fields, types, or meanings now require a new major finding-schema version instead of silently rewriting v1.

### 0sec cross-tool integration

- The 0sec monorepo now pins a healthy Foxguard source commit, adapts native v1 findings into its ingest contract, and exercises release binary → HTTP ingest → tenant-scoped persistence in CI.
- Source and release gates remain intentionally separate: the submodule contract validates the exact source pin and release ancestry, while cross-tool E2E downloads the declared release binary. Unreleased source changes therefore cannot silently redefine released evidence.

### GitHub App hardening

- Pull-request work now enters a bounded queue: 128 pending jobs and four workers by default, configurable with positive `FOXGUARD_PR_QUEUE_CAPACITY` and `FOXGUARD_PR_WORKERS` values.
- Replayed GitHub delivery IDs are deduplicated. Concurrent updates for the same repository and pull request coalesce, and the newest head receives a follow-up scan instead of racing an active scan or being lost.
- Queue overload is acknowledged and logged without blocking webhook handling.
- Release CI smoke-tests GitHub App container startup and its health endpoint before publishing the image; the Rust suite separately pins webhook-signature behavior.

### Python subprocess argv precision

- `py/no-command-injection` now recognizes shell-free `subprocess` calls whose argument-vector provenance is statically proven within the sink's lexical scope and whose executable head is constant.
- Typed method builders are bound to their receiver class, while unsafe mutation, aliasing, unknown calls, dynamic `shell` values, cross-scope collisions, and non-constant executable heads invalidate the proof and remain findings.
- Regression fixtures cover the safe builder shape that caused a false positive in a real 0verse review and 17 unsafe near-misses.

### Packaging and integration reliability

- The npm launcher cache is keyed by target platform, preventing a binary selected for one platform from being reused on another.
- The VS Code extension centralizes and tests supported-file detection.
- The GitHub Action reports terminal finding counts accurately.
- Release automation runs Node tests and verifies that a published VS Code Marketplace version becomes visible after `vsce` publication.

## Compatibility

- The CLI and configuration remain backward compatible.
- Native finding contract: `1.0.0`.
- Legacy bare-array finding consumers remain supported.
- GitHub App queue defaults are suitable for existing deployments; operators can override them through environment variables.

## Verification

- `cargo fmt --check`
- `cargo clippy -- -D warnings`
- `cargo test`
- `npm ci && npm run build` in `www`
- `npm ci && npm run compile` in `vscode-extension`
- `npm pack --dry-run` in `packages/npm`
- Version alignment across Cargo, npm, VS Code extension, VS Code lockfile, and README release pins

## Upgrade

```sh
npx foxguard@latest .
# or
curl -fsSL https://foxguard.dev/install.sh | sh
# or
cargo install foxguard
```

GitHub Action and pre-commit users can pin `v0.12.0`:

```yaml
- uses: 0sec-labs/foxguard/action@v0.12.0
```

```yaml
repos:
  - repo: https://github.com/0sec-labs/foxguard
    rev: v0.12.0
    hooks:
      - id: foxguard
```
