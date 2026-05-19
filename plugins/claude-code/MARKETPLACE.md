# Claude Code Marketplace Release Notes

This package is intentionally scoped to Claude Code. Broader agent or editor
integrations should reuse the scanner behavior where it fits, but they should be
tracked separately from the Claude Code marketplace release.

## Versioning

The initial marketplace version is `0.1.0`, matching
`.claude-plugin/plugin.json`.

Before each marketplace submission:

- Bump the plugin version when any manifest, hook, skill, or bundled prompt
  behavior changes.
- Keep the version in `.claude-plugin/plugin.json` as the source of truth.
- Tag the plugin release only after local smoke testing passes.

## Marketplace Copy

Name:

```text
foxguard
```

Short summary:

```text
Fast local security scanning for Claude Code.
```

Description:

```text
foxguard scans files as Claude Code writes or edits them, then feeds actionable
security findings back into the agent session. It includes slash commands for
full scans, diff scans, post-quantum crypto audits, secrets scans, and TUI
triage, plus secure-coding defaults for common vulnerability classes.
```

Repository:

```text
https://github.com/0sec-labs/foxguard
```

Homepage:

```text
https://foxguard.dev
```

License:

```text
MIT OR Apache-2.0
```

Suggested categories:

```text
security, static-analysis, developer-tools, agent-hooks
```

Suggested demo checklist:

- Start Claude Code with `claude --plugin-dir ./plugins/claude-code`.
- Run `/foxguard:setup`.
- Edit a file with a known command-injection or hardcoded-secret pattern.
- Show the `PostToolUse` stderr finding summary.
- Fix the issue and show the hook staying silent on the clean edit.
- Run `/foxguard:scan .` or `/foxguard:diff-scan main` for an on-demand scan.

## Local Validation

The hook was validated directly with:

```sh
jq --version

printf '{"tool_input":{"file_path":"tests/fixtures/safe.py"}}' \
  | plugins/claude-code/scripts/scan-edited-file.sh

printf '{"tool_input":{"file_path":"tests/fixtures/vulnerable.py"}}' \
  | plugins/claude-code/scripts/scan-edited-file.sh

printf '{"tool_input":{"path":"tests/fixtures/vulnerable.py"}}' \
  | plugins/claude-code/scripts/scan-edited-file.sh

printf '{"tool_input":{"notebook_path":"tests/fixtures/safe.py"}}' \
  | plugins/claude-code/scripts/scan-edited-file.sh

printf '{"tool_response":{"filePath":"tests/fixtures/safe.py"}}' \
  | plugins/claude-code/scripts/scan-edited-file.sh

printf '{"tool_response":{"file_path":"tests/fixtures/safe.py"}}' \
  | plugins/claude-code/scripts/scan-edited-file.sh

printf '{"tool_input":{"file_path":"/does/not/exist.py"}}' \
  | plugins/claude-code/scripts/scan-edited-file.sh
```

Expected results:

- `jq --version` succeeds.
- Clean supported files exit `0` and stay silent.
- Missing files exit `0` and stay silent.
- Finding input exits `2` and emits a compact finding summary to stderr.
- Edited path extraction accepts `tool_input.file_path`, `tool_input.path`,
  `tool_input.notebook_path`, `tool_response.filePath`, and
  `tool_response.file_path`.
- Scanner JSON parsing accepts the current `schema_version` object with a
  `findings` array.

`claude plugin validate plugins/claude-code` passed with Claude Code `2.1.143`.
Older local Claude Code builds have been observed hanging during validation;
`2.1.143` is the known-good version for the current submission notes.

Non-interactive Claude Code smoke tests using `claude -p --plugin-dir
plugins/claude-code` passed with `foxguard 0.8.1` first on `PATH` for:

- `/foxguard:setup`
- `/foxguard:scan tests/fixtures/safe.py`
- `/foxguard:diff-scan main`
- `/foxguard:pq-audit tests/fixtures/safe.py`
- `/foxguard:secrets tests/fixtures/safe.py`
- `/foxguard:triage`

The earlier stale-binary failure mode is covered: `/foxguard:setup` verifies
that `secrets`, `diff`, `tui`, and `pqc` are present before reporting the plugin
ready, and `/foxguard:pq-audit tests/fixtures/safe.py` now exercises the real
`pqc` subcommand successfully when the current binary is first on `PATH`.

## External Submission

Submit through the Anthropic plugin submission flow once the in-session smoke
test has passed. After acceptance, update this file, the plugin README, and the
top-level README with marketplace installation instructions.
