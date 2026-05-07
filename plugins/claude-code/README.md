# foxguard for Claude Code

Live security scanning inside [Claude Code](https://code.claude.com). Every file Claude writes or edits is auto-scanned by [foxguard](https://foxguard.dev) — findings are fed straight back so Claude self-corrects before bad patterns land.

## What you get

- **PostToolUse auto-scan** — every `Write` / `Edit` / `MultiEdit` triggers `foxguard --format json` on the changed file. Medium+ findings are surfaced to Claude on stderr; clean files are silent.
- **SessionStart preamble** — Claude starts each session with foxguard's secure-coding defaults already in context.
- **Slash commands** for on-demand scans:
  - `/foxguard:setup` — verify install, set severity threshold
  - `/foxguard:scan [path]` — full scan, grouped and triaged by severity
  - `/foxguard:diff-scan [base]` — only what this branch introduces vs `main`
  - `/foxguard:pq-audit [path]` — post-quantum readiness with CNSA 2.0 deadlines
  - `/foxguard:secrets [path]` — hardcoded secrets, tokens, private keys
  - `/foxguard:triage [args]` — instructions for the interactive TUI
- **`secure-coding` skill** — model-invoked remediation guidance for command exec, SQL, path traversal, SSRF, secrets, randomness, crypto, and deserialization.
- **`foxguard` skill** — model-invoked router that picks the right scan mode (full / diff / secrets / pq) when the user asks for a security review. Also usable [standalone](#standalone-skill-no-plugin) without the rest of the plugin.

## Install

### 1. Install foxguard

Pick whichever fits:

```sh
# Prebuilt binary — fastest
curl -fsSL https://foxguard.dev/install.sh | sh

# Homebrew
brew install pwnkit-labs/foxguard/foxguard

# npm (global or zero-install)
npm i -g foxguard       # or just: npx foxguard

# cargo
cargo install foxguard
```

Verify with `foxguard --version`.

### 2. Install the plugin

Until the plugin is published to a marketplace, load it directly from this repo:

```sh
claude --plugin-dir /path/to/foxguard/plugins/claude-code
```

Or add to your settings to load it permanently. Once installed, run `/foxguard:setup` to confirm it's wired up.

Marketplace submission copy, versioning notes, and local validation commands are
tracked in [MARKETPLACE.md](MARKETPLACE.md).

## Configuration

Environment variables:

| Var | Default | Purpose |
| :-- | :-- | :-- |
| `FOXGUARD_HOOK_SEVERITY` | `medium` | Minimum severity for the auto-scan. One of `low|medium|high|critical`. |

Set in your shell profile or in Claude Code's environment to tune noise.

## How the auto-scan looks

After Claude edits a file, if foxguard finds an issue, Claude sees something like:

```
foxguard found 1 issue(s) in src/auth.py (severity >= medium):

  [CRITICAL] py/no-command-injection at line 42
    os.system() called with dynamic argument — risk of command injection
    CWE-78
    > os.system("ls " + user_input)

Fix these before continuing. Run `/foxguard:scan` for the full repo or `/foxguard:triage` for the interactive TUI.
```

Claude is expected to fix the finding (or explain why it's a false positive) before moving on.

## Layout

```
plugins/claude-code/
├── .claude-plugin/plugin.json     # manifest
├── hooks/hooks.json               # PostToolUse + SessionStart
├── scripts/
│   ├── scan-edited-file.sh        # the PostToolUse scanner
│   └── secure-defaults.txt        # SessionStart preamble
├── skills/
│   ├── setup/SKILL.md             # /foxguard:setup
│   ├── scan/SKILL.md              # /foxguard:scan
│   ├── diff-scan/SKILL.md         # /foxguard:diff-scan
│   ├── pq-audit/SKILL.md          # /foxguard:pq-audit
│   ├── secrets/SKILL.md           # /foxguard:secrets
│   ├── triage/SKILL.md            # /foxguard:triage
│   ├── secure-coding/SKILL.md     # model-invoked remediation guidance
│   └── foxguard/SKILL.md          # model-invoked scan router (also installable standalone)
└── README.md
```

## Notes

- The hook intentionally never blocks Claude on its own machinery: missing binary, parse errors, or unreadable inputs all exit `0`. Only real findings exit `2`.
- The hook calls `foxguard` from `PATH` first, then falls back to `npx --yes foxguard`. If neither is available it stays silent — run `/foxguard:setup` to fix that.
- `--severity medium` is the default cutoff. Drop to `low` for stricter coverage; raise to `high` for noisier projects.
- foxguard's exit codes: `0` clean, `1` findings, `2` error. The hook checks for findings via the JSON, not the exit code, so a piped error doesn't trigger a false alarm.
- This package is scoped to Claude Code. Broader agent or editor integration
  design should be tracked separately from the Claude Code marketplace release.

## Standalone skill (no plugin)

If you don't want the auto-scan-on-every-edit hook and just want Claude to know how to drive `foxguard` when you ask for a scan, copy a single file:

```sh
mkdir -p ~/.claude/skills/foxguard
curl -fsSL \
  https://raw.githubusercontent.com/PwnKit-Labs/foxguard/main/plugins/claude-code/skills/foxguard/SKILL.md \
  -o ~/.claude/skills/foxguard/SKILL.md
```

That's it. Claude will invoke the skill the next time you ask for a security review, secrets scan, PQ audit, or diff scan. The `foxguard` binary still has to be on `PATH` — the skill walks you through install if it isn't.

The full plugin (this directory) is the right choice if you want the proactive PostToolUse hook. The standalone skill is the right choice if you want pull-based invocation only.

## License

MIT — same as foxguard.
