---
description: Run a full foxguard security scan on the repository or a specific path
disable-model-invocation: true
---

Run a full foxguard scan and walk the user through any findings.

1. If the user passed a path as `$ARGUMENTS`, scan that. Otherwise scan `.`.
2. Run via Bash: `foxguard --format json --severity medium "$PATH_OR_DOT"`. Capture stdout — exit 1 just means findings were detected, that's expected.
3. Parse the JSON array. Group findings by `file`, then by `severity` (critical → high → medium). For each finding show: `[SEVERITY] rule_id` at `file:line` with the description and the `snippet`.
4. Summarize at the top: total count, breakdown by severity, top 3 files by finding count.
5. For each critical/high finding, propose a concrete fix the user can accept. Don't apply edits until the user confirms.
6. If the JSON output is large (>50 findings), suggest `/foxguard:triage` for the interactive TUI instead of scrolling text.

If the scan errors (exit 2), report the error verbatim and suggest `/foxguard:setup`.
