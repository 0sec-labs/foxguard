---
description: Scan only changes vs a base branch — surfaces what this branch introduced
disable-model-invocation: true
---

Run a diff scan to show only findings introduced on the current branch.

1. Determine the base branch. If the user passed one as `$ARGUMENTS`, use it. Otherwise default to `main`, falling back to `master` if `main` doesn't exist (`git rev-parse --verify main`).
2. Run via Bash: `foxguard diff "$BASE" . --format json --severity medium`.
3. Parse the JSON output the same way as `/foxguard:scan` — group by file and severity, show rule id, line, description, and snippet.
4. Specifically frame the report as "what this branch adds." If the count is zero, say so plainly — this branch introduces no new findings vs `$BASE`.
5. For critical/high findings, propose fixes. Make clear that pre-existing findings on `$BASE` are not shown — those need a full `/foxguard:scan`.
