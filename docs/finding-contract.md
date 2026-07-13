# Finding serialization contract

Foxguard native JSON reports expose two independent semantic versions:

- `schema_version` versions the report envelope.
- `finding_schema_version` versions each object in `findings`.

Version 1 is described by [`schemas/finding-v1.schema.json`](../schemas/finding-v1.schema.json).
Consumers should ignore unknown fields so additive metadata remains compatible.
Foxguard continues to accept the legacy bare finding array inside integrations
that predate the native envelope.

## Current consumers

| Consumer | Contract used |
| --- | --- |
| CLI `--format json` | Produces the native versioned envelope and findings |
| CLI `--format sarif` | Maps finding locations, severity, confidence, tags, CWE and dependency metadata into SARIF 2.1.0 |
| GitHub App | Reads native `findings`; retains legacy bare-array compatibility |
| VS Code extension | Reads native `findings`; retains legacy bare-array compatibility |
| GitHub Action | Uses terminal output for the summary and SARIF for code scanning; it does not parse native findings |
| 0sec monorepo | Pins the latest healthy Foxguard `main` commit through an automated pull request, adapts native v1 findings into its ingest contract, and exercises release binary → HTTP ingest → tenant-scoped persistence in CI |

The canonical full-field fixture is
[`tests/contracts/native-report-v1.json`](../tests/contracts/native-report-v1.json).
Rust and VS Code tests consume this fixture. Any breaking change to required
field names, types, or meanings requires a major finding-schema version bump
and a parallel fixture/schema rather than rewriting the v1 files.
