---
description: Verify foxguard is installed and ready for the Claude Code plugin
disable-model-invocation: true
---

Walk the user through getting foxguard installed and the plugin working:

1. Run `foxguard --version` via the Bash tool. If it succeeds, also run
   `foxguard --help` and verify the active binary exposes these subcommands:
   `secrets`, `diff`, `tui`, and `pqc`.
2. If `foxguard` is installed but any required subcommand is missing, report
   that the binary is too old for the full Claude Code plugin. Recommend
   upgrading with the install options below before calling the plugin ready.
3. If `foxguard` is not on PATH, offer the install options in this order:
   - **Prebuilt binary (fastest)**: `curl -fsSL https://foxguard.dev/install.sh | sh`
   - **Homebrew** (macOS): `brew install 0sec-labs/foxguard/foxguard`
   - **npm**: `npm i -g foxguard` or zero-install via `npx foxguard`
   - **cargo**: `cargo install foxguard`
   Ask which the user prefers; do NOT install without confirmation.
4. If all required subcommands are present, report the version and tell the
   user the plugin is ready — every Write/Edit will now be auto-scanned.
5. Recommend the user run `foxguard init` inside their repo to add a pre-commit hook so foxguard also catches issues outside Claude Code sessions.
6. Mention the env vars they can tune:
   - `FOXGUARD_HOOK_SEVERITY` — minimum severity for auto-scan (default `medium`; values: `low|medium|high|critical`)

Finish with a one-line confirmation of which version is active, whether the
full command surface is available, and which severity threshold the auto-scan
is using.
