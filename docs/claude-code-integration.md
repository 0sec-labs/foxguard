# Claude Code Integration

foxguard ships a Claude Code plugin in [`plugins/claude-code`](../plugins/claude-code). It is the recommended Claude Code integration path because it runs automatically during an agent session instead of waiting until commit time.

## What The Plugin Does

- Runs a `PostToolUse` hook after `Write`, `Edit`, `MultiEdit`, and `NotebookEdit` so files Claude changes are scanned immediately.
- Emits medium-and-above findings back to Claude so the agent can fix them before the issue lands in the repo.
- Adds a `SessionStart` secure-coding preamble covering command execution, SQL, SSRF, path traversal, secrets, randomness, crypto, and deserialization.
- Provides namespaced `/foxguard:*` skills for setup, full scans, diff scans, PQ audits, secrets scans, and TUI triage.

## Local Install

Install foxguard first:

```sh
curl -fsSL https://foxguard.dev/install.sh | sh
# or: npm i -g foxguard
# or: cargo install foxguard
```

Then load the plugin from this repo:

```sh
claude --plugin-dir ./plugins/claude-code
```

Inside Claude Code, run:

```text
/foxguard:setup
```

That verifies the `foxguard` binary is available and explains the active hook severity threshold.

## Hook Behavior

The auto-scan hook reads the Claude Code hook JSON from stdin, extracts the
edited path from `tool_input.file_path`, `tool_input.path`,
`tool_input.notebook_path`, `tool_response.filePath`, or
`tool_response.file_path`, and runs:

```sh
foxguard --format json --severity medium <edited-file>
```

If findings are present, the hook exits `2` and prints a compact finding summary to stderr. Missing binaries, unreadable files, invalid hook input, and clean scans exit `0` so plugin machinery does not block Claude by itself.

The hook uses `jq` to parse Claude Code's hook JSON. Run `/foxguard:setup` after
loading the plugin to verify both `jq` and the active `foxguard` binary.

Tune the threshold with:

```sh
export FOXGUARD_HOOK_SEVERITY=high
```

Valid values: `low`, `medium`, `high`, `critical`.

## Commands And Skills

Claude Code plugin skills are namespaced by the plugin name:

- `/foxguard:setup` verifies installation and configuration.
- `/foxguard:scan [path]` runs a full scan and summarizes findings.
- `/foxguard:diff-scan [base]` reports findings introduced by the current branch.
- `/foxguard:pq-audit [path]` runs post-quantum crypto and CNSA 2.0 checks.
- `/foxguard:secrets [path]` scans for leaked credentials and private keys.
- `/foxguard:triage [args]` opens or explains the interactive TUI triage flow.

The plugin also includes a model-invoked `secure-coding` skill so Claude can pull in foxguard-aligned remediation guidance while writing security-sensitive code.

## Pre-commit Still Helps

The plugin is live feedback. A pre-commit hook is still useful as a final gate for human edits, other agents, or terminal changes outside Claude Code:

```sh
foxguard init
```

Or configure your own hook to run:

```sh
npx foxguard --changed --severity high .
```

## Publishing Status

The plugin can be loaded locally today with `--plugin-dir`. Publishing to an official Claude plugin marketplace is an external release step: it requires final marketplace metadata, a release/versioning decision, local plugin smoke testing in Claude Code, and submission through Anthropic's plugin form.

Track the publishing checklist in the GitHub issue linked from the README/PR queue rather than treating it as part of the scanner binary release. Marketplace copy, versioning notes, and local validation commands live in [`plugins/claude-code/MARKETPLACE.md`](../plugins/claude-code/MARKETPLACE.md).

This integration is intentionally Claude Code-specific. Shared behavior for other
agent or editor hook systems is documented in
[`agent-editor-integration.md`](agent-editor-integration.md) so Claude Code
marketplace work can proceed independently. That shared contract now includes
the `foxguard-adapter` JSON protocol; Claude Code's PostToolUse hook maps to
`scan-file`, while its slash commands map to `scan-workspace`, `diff`, `pqc`,
and `secrets`.
