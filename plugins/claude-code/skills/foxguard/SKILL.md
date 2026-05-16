---
description: Run the foxguard security scanner on the user's code. Use proactively when the user asks to find vulnerabilities, scan for secrets, audit cryptography, do a security review, check what a branch introduces, or validate code before merging. Covers SAST, secrets, cross-file taint tracking, post-quantum crypto audit, and diff scans across 10 languages.
---

You are driving [foxguard](https://foxguard.dev), a fast local SAST scanner. This skill is the standalone counterpart to the foxguard Claude Code plugin — you have the scanner binary; you don't have the plugin's slash commands or PostToolUse hook. Behave accordingly: ask before running long scans, surface results inline, propose fixes the user can accept.

## Decide which mode to run

Pick the scan mode from the user's intent. When ambiguous, ask before running.

| User intent | Command | Notes |
|---|---|---|
| "scan / security review / find vulnerabilities" | `foxguard --format json --severity medium "$PATH"` | Default. `$PATH` is `.` unless they specify. |
| "what does this branch add / introduce" | `foxguard diff "$BASE" . --format json --severity medium` | `$BASE` is `main` (fall back to `master` if `main` doesn't exist via `git rev-parse --verify main`). |
| "find secrets / hardcoded keys / leaked tokens" | `foxguard secrets "$PATH" --format json` | Secret values are redacted by foxguard — do not try to reconstruct them. |
| "post-quantum / PQ / CNSA 2.0 / quantum-safe / RSA replacement" | `foxguard pqc "$PATH" --format json --severity medium` | Findings include `cnsa2Deadline`. Surface deadlines prominently. |
| "open the TUI / triage interactively" | Tell the user to run `foxguard tui` in their own terminal | TUI is interactive; **you cannot drive it** through Bash. Do not try. |

Always pass `--format json`. Exit code 1 means findings were detected — that's expected, not an error. Exit code 2 is a real scanner error; report it verbatim.

## Reading the JSON output

Each finding has at minimum: `rule_id`, `severity`, `file`, `line`, `description`, `snippet`. Some include `cwe`, `taint_hops` (cross-file dataflow depth), `confidence`, `cnsa2Deadline` (PQ mode), `crypto_algorithm` (PQ mode).

Group findings by `file`, then by `severity` (critical → high → medium → low). For each finding render: `[SEVERITY] rule_id at file:line` followed by the description, CWE if present, and the snippet.

Lead the report with: total count, severity breakdown, top 3 files by finding count. If output exceeds ~50 findings, suggest the user run `foxguard tui` themselves rather than scrolling text.

## Proposing fixes

For every critical and high finding, propose a concrete patch the user can accept. Match foxguard's rule patterns:

- **Hardcoded secrets** → read from `os.getenv` / `process.env` / equivalent. Remind the user that removing a leaked secret from working tree does NOT remove it from git history; the secret is compromised the moment it was committed and must be rotated at the issuer.
- **Command injection** → argument lists, never shell concatenation. `subprocess.run(["git", "log", branch])` not `shell=True`.
- **SQL injection** → parameterized queries, never f-strings or `+`.
- **Path traversal** → `Path(root).resolve() / Path(name).name`; reject `..`, absolute paths, null bytes before joining.
- **SSRF** → parse the URL, reject private/loopback/link-local ranges and `169.254.169.254` before fetching.
- **Weak crypto** → AES-GCM or ChaCha20-Poly1305 (symmetric), Ed25519 (signatures), X25519 (key agreement), argon2id (passwords). Never DES/3DES/RC4/MD5/SHA-1, never `random.random()` for security tokens.
- **PQ findings** → recommend hybrid suites where the toolchain supports them (X25519+ML-KEM, etc.). Classical primitives may still be fine in non-security paths (signed-binary verification of trusted releases, test fixtures) — ask about context before recommending wholesale rewrites.
- **Deserialization** → never `pickle.load`, `yaml.load` (use `safe_load`), `Marshal.load`, `unserialize` on untrusted input.

Do not apply edits without the user's confirmation. After applying, re-run the original scan command to verify the finding cleared.

## Suppressions

If a finding is a confirmed false positive, a baseline is the right tool:

- General: edit `.foxguard.yml` with a `suppressions:` entry referencing the rule and path.
- Secrets: `foxguard secrets --write-baseline .foxguard-secrets-baseline.json` writes a redacted baseline. Be explicit with the user that a baseline is a *suppression*, not a fix — the entries should be reviewed periodically.

## When foxguard isn't installed

If `foxguard --version` fails, offer the install options in this order, ask which they prefer, and **do not install without confirmation**:

1. **Prebuilt binary**: `curl -fsSL https://foxguard.dev/install.sh | sh`
2. **Homebrew** (macOS): `brew install 0sec-labs/foxguard/foxguard`
3. **npm**: `npm i -g foxguard` (or zero-install: `npx foxguard …`)
4. **cargo**: `cargo install foxguard`

For users who want auto-scan on every Claude edit, point them at the full plugin: `https://github.com/0sec-labs/foxguard/tree/main/plugins/claude-code` — that ships a PostToolUse hook this skill intentionally does not.
