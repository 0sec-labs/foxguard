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

## Non-Claude Example: Generic Editor Save Hook

A generic editor or local agent wrapper can call a small adapter on save:

```sh
#!/usr/bin/env sh
set -eu

path="${1:-}"
[ -n "$path" ] && [ -f "$path" ] || exit 0

json="$(foxguard --format json --severity "${FOXGUARD_HOOK_SEVERITY:-medium}" "$path" 2>/dev/null || true)"
count="$(printf '%s' "$json" | jq '.findings | length' 2>/dev/null || printf '0')"

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
