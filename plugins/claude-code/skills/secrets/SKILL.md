---
description: Scan for hardcoded secrets, API tokens, and private keys
disable-model-invocation: true
---

Run a secrets-focused scan.

1. Take an optional path from `$ARGUMENTS`, default to `.`.
2. Run via Bash: `foxguard secrets "$PATH_OR_DOT" --format json`.
3. Parse the JSON. Secret values are redacted by foxguard — do not try to reconstruct them.
4. Report each finding: `file:line`, the `rule_id` (e.g., `secret/aws-access-key`, `secret/github-pat`), and the risk class (cloud key, VCS token, payment, generic high-entropy, private key, etc.).
5. For each finding propose the right remediation:
   - Cloud / SaaS tokens: rotate immediately at the issuer, then move to env vars or a secrets manager.
   - Private keys: regenerate, never just delete from history without rotation.
   - High-entropy strings that are NOT secrets: add to a baseline via `foxguard secrets --write-baseline .foxguard-secrets-baseline.json` — explain this is a suppression, not a fix.
6. Remind the user that removing a leaked secret from the working tree does NOT remove it from git history. If the file was ever committed, the secret must be considered compromised.
