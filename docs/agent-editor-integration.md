# Agent and Editor Integration Contract

foxguard integrations should share the same scanner behavior even when their host
systems use different hook names, payloads, or UI surfaces. The Claude Code plugin
is one implementation of this contract, not the contract itself.

## Goals

- Give agents and editors fast feedback on the file they just changed.
- Keep failures in integration glue from blocking the host tool.
- Preserve foxguard's normal CLI behavior for CI, pre-commit hooks, and humans.
- Keep host-specific packaging, marketplace metadata, and command naming outside
  the shared contract.

## Shared Hook Shape

An edit-time integration needs five inputs:

| Field | Meaning |
| --- | --- |
| `path` | File path the host just wrote, edited, or saved. |
| `workspace_root` | Optional root used to resolve relative paths and discover `.foxguard.yml`. |
| `severity` | Minimum severity surfaced to the host. Default: `medium`. |
| `mode` | Usually `scan-file`; integrations may expose `scan-workspace`, `diff`, `secrets`, and `pqc` as explicit commands. |
| `format` | Machine format the adapter reads. Default: `json`. |

The adapter normalizes the host payload into those fields, then runs:

```sh
foxguard --format json --severity "$severity" "$path"
```

If the host needs config isolation or a fixed working directory, the adapter may
also pass `--config <path>` or set its current directory to `workspace_root`.

## Adapter Protocol

The reusable protocol is JSON over stdin/stdout. Hosts send one request object to
the reference adapter binary and read one response object back:

```sh
jq -n --arg path src/app.py \
  '{command:"scan-file", path:$path, severity:"medium"}' \
  | foxguard-adapter
```

Common request fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `schema_version` | string | Optional. Defaults to `1.0.0`. |
| `request_id` | string | Optional host correlation id echoed in the response. |
| `command` | string | `scan-file`, `scan-workspace`, `diff`, `secrets`, `pqc`, `explain`, or `suppress`. |
| `path` | string | File or workspace path. Required for `scan-file`; optional for workspace commands. |
| `workspace_root` | string | Optional root for resolving relative `path`, `config`, `rules`, and `baseline`. |
| `severity` | string | Optional minimum severity: `low`, `medium`, `high`, or `critical`. |
| `config` | string | Optional `.foxguard.yml` path. |
| `rules` | string | Optional external Semgrep/OpenGrep-compatible rule file or directory. |
| `change_mode` | string | Optional `changed`, `staged`, `unstaged`, or `all-changes`. |
| `exclude` | string[] | Optional scan path prefixes/globs to skip. |
| `baseline` | string | Optional baseline file. |
| `base` | string | Diff base for `diff`; defaults to `main`. |
| `explain` | bool | Include dataflow metadata where available. |
| `max_file_size` | number | Optional byte limit, defaulting to the CLI default. |
| `min_confidence` | number | Optional confidence threshold. |
| `finding` | object | Selector for `explain` filtering and `suppress` suggestions. |
| `suppression` | string | For `suppress`: `inline`, `config`, or `baseline`. |

Response fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `ok` | bool | `false` only when the adapter or scanner failed. Findings are not an adapter failure. |
| `exit_code` | number | CLI-compatible intent: `0` clean, `1` findings, `2` scanner/adapter error. |
| `summary` | object | Finding totals, per-severity counts, files scanned, and duration. |
| `findings` | array | The normal foxguard JSON finding shape. |
| `notices` | array | Scanner warnings and skipped-file summaries. |
| `diff` | object | Diff totals for `diff` responses. |
| `suppression` | object | Suggested inline/config/baseline suppression for `suppress`. |
| `error` | string | Human-readable error when `ok` is `false`. |

The adapter process exits `0` after emitting a valid JSON response, even when
response `exit_code` is `1`. Hosts should use response `exit_code` for policy:
editor loops can fail open, while CI/pre-commit gates can fail closed.

## Exit Behavior

Adapters should distinguish scanner findings from adapter failures:

| Case | Adapter behavior |
| --- | --- |
| Clean scan | Exit success and stay silent. |
| Findings at or above threshold | Surface a compact summary to the host and use the host's actionable-feedback convention. |
| `foxguard` missing | Exit success with a setup hint only when the host has an appropriate setup command. |
| Missing or unreadable edited file | Exit success and stay silent. |
| Invalid host payload | Exit success and stay silent. |
| Scanner execution error | Prefer a concise diagnostic; do not fail closed unless the integration is an explicit CI/pre-commit gate. |

This fail-open rule is for live editor and agent loops. CI and pre-commit
integrations should keep foxguard's normal nonzero exit behavior.

## Output Summary

Live integrations should avoid dumping full JSON. A useful summary includes:

- total finding count at or above the threshold
- file path
- one line per finding: severity, rule id, line, description
- a local rerun command, for example `foxguard --severity medium path/to/file`

Adapters should parse the JSON report instead of relying only on process exit
codes. foxguard exits `1` for findings and `2` for scanner errors, but JSON
contents are the stable way to decide whether a host should receive feedback.

## Command Surface

Host integrations should expose the same conceptual commands even if naming
syntax differs:

| Command | CLI equivalent | Purpose |
| --- | --- | --- |
| `setup` | `foxguard --version` | Verify the scanner is installed and explain hook behavior. |
| `scan` | `foxguard <path>` | Scan a file or workspace. |
| `diff-scan` | `foxguard diff <base> <path>` | Review new findings relative to a base ref. |
| `secrets` | `foxguard secrets <path>` | Run secret detection. |
| `pq-audit` | `foxguard pqc <path>` | Run post-quantum crypto checks. |
| `triage` | `foxguard triage <path>` | Launch the interactive triage UI when the host supports terminals. |

Adapter command mapping:

| Shared command | Adapter request |
| --- | --- |
| Scan current file | `{ "command": "scan-file", "path": "src/app.py", "severity": "medium" }` |
| Scan workspace | `{ "command": "scan-workspace", "workspace_root": ".", "severity": "medium" }` |
| Diff scan | `{ "command": "diff", "base": "main", "workspace_root": "." }` |
| Secrets scan | `{ "command": "secrets", "workspace_root": "." }` |
| PQ audit | `{ "command": "pqc", "workspace_root": ".", "severity": "medium" }` |
| Explain finding | `{ "command": "explain", "path": ".", "finding": { "rule_id": "py/taint-sql-injection" } }` |
| Suggest suppression | `{ "command": "suppress", "finding": { "rule_id": "py/no-eval", "file": "src/app.py", "line": 12 }, "suppression": "inline" }` |

## Reference Adapter

`foxguard-adapter` is the reference adapter binary. It reads a single JSON
request from stdin, calls the same Rust execution layer as the CLI, and writes a
single JSON response to stdout.

Rust integrations can call the same entry point directly:

```rust
use foxguard::adapter::{execute_adapter_request, AdapterCommand, AdapterRequest};

let mut request = AdapterRequest::new(AdapterCommand::ScanFile);
request.path = Some("src/app.py".to_string());
let response = execute_adapter_request(request);
```

Non-Rust integrations should prefer the binary contract until they need deeper
embedding.

## Existing Host Mapping

| Host surface | Current behavior | Shared contract mapping |
| --- | --- | --- |
| VS Code scan-on-save | Runs `foxguard --format json` for the saved document and renders diagnostics. | `scan-file` with `path`, `workspace_root`, `severity`, and optional `config`. |
| VS Code workspace scan | Runs a full workspace scan from a command. | `scan-workspace` with `workspace_root`. |
| VS Code quick fix: inline suppress | Inserts `foxguard: ignore[...]` above the finding. | `suppress` with `suppression: "inline"`. |
| VS Code quick fix: config suppress | Updates `scan.ignore_rules` in `.foxguard.yml`. | `suppress` with `suppression: "config"` for a stable snippet, then host applies the edit. |
| VS Code quick fix: baseline | Writes a baseline fingerprint entry. | `suppress` with `suppression: "baseline"` for the CLI command or host-owned baseline write. |
| Claude Code PostToolUse hook | Reads Claude hook JSON, extracts the edited file, and returns compact stderr feedback. | `scan-file` with fail-open host behavior. |
| Claude `/foxguard:scan` | Runs a full JSON scan. | `scan-workspace` or `scan-file` depending on the argument. |
| Claude `/foxguard:diff-scan` | Runs `foxguard diff <base> . --format json`. | `diff` with `base` and `workspace_root`. |
| Claude `/foxguard:pq-audit` | Runs `foxguard pqc <path> --format json`. | `pqc`. |
| Claude `/foxguard:secrets` | Runs `foxguard secrets <path> --format json`. | `secrets`. |
| Claude `/foxguard:triage` | Tells the user to run the interactive TUI. | Stays CLI/TUI-specific; not part of the JSON adapter. |

## Non-Claude Example: Generic Editor Save Hook

A generic editor or local agent wrapper can call a small adapter on save:

```sh
#!/usr/bin/env sh
set -eu

path="${1:-}"
[ -n "$path" ] && [ -f "$path" ] || exit 0

json="$(jq -n \
  --arg path "$path" \
  --arg severity "${FOXGUARD_HOOK_SEVERITY:-medium}" \
  '{command:"scan-file", path:$path, severity:$severity}' \
  | foxguard-adapter 2>/dev/null || true)"
count="$(printf '%s' "$json" | jq '.summary.findings_total // 0' 2>/dev/null || printf '0')"

[ "$count" -gt 0 ] || exit 0

printf 'foxguard found %s issue(s) in %s\n' "$count" "$path" >&2
printf '%s' "$json" | jq -r '.findings[] | "\(.severity) \(.rule_id) line \(.line): \(.description)"' >&2
exit 2
```

Host mapping:

- Setup: install `foxguard` or use `npx --yes foxguard`.
- Input: editor passes the saved file path as `$1`.
- Output: stderr summary for the editor problem matcher or agent feedback loop.
- Failure behavior: missing file, missing JSON parser, or scanner setup problems do
  not block the save path. CI remains the blocking gate.

## Implementation Boundaries

- Claude Code-specific hook payloads, slash-command names, and marketplace copy
  stay under `plugins/claude-code/`.
- VS Code-specific diagnostics, decorations, and extension packaging stay in the
  VS Code extension surface.
- Shared behavior belongs in docs and small reusable scripts only when two or more
  integrations need the same implementation.
- New target integrations should get separate issues once their host payload,
  setup path, and feedback conventions are known.
