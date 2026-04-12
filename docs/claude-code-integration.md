# Claude Code Integration

foxguard can run as a [Claude Code hook](https://docs.anthropic.com/en/docs/claude-code/hooks) to scan agent-written code before each commit. When findings are detected, the commit is blocked and Claude sees the output — giving it a chance to fix the issue before retrying.

## Setup

Add the following to `.claude/settings.json` in your project root:

```json
{
  "hooks": {
    "PreCommit": [
      {
        "command": "npx foxguard --changed --severity high .",
        "description": "foxguard security scan"
      }
    ]
  }
}
```

That's it. Claude Code will run foxguard before every commit.

## What happens when findings are detected

1. Claude writes code and attempts to commit.
2. foxguard scans the changed files.
3. If any findings at or above the configured severity are found, foxguard exits non-zero.
4. Claude Code blocks the commit and shows foxguard's output to the agent.
5. The agent sees the finding (rule ID, file, line, description) and can fix it.
6. On the next commit attempt, foxguard runs again.

## Customizing severity threshold

The `--severity` flag controls the minimum severity that causes a non-zero exit:

```json
{ "command": "npx foxguard --changed --severity critical ." }
```

Valid values: `low`, `medium`, `high`, `critical`.

- `critical` — only block on critical findings (SQL injection, command injection, etc.)
- `high` — block on high and critical (recommended default)
- `medium` — block on medium and above
- `low` — block on everything

## Adding secrets scanning

To also catch leaked credentials, add a second hook entry:

```json
{
  "hooks": {
    "PreCommit": [
      {
        "command": "npx foxguard --changed --severity high .",
        "description": "foxguard security scan"
      },
      {
        "command": "npx foxguard secrets --changed .",
        "description": "foxguard secrets scan"
      }
    ]
  }
}
```

## Combining with the VS Code extension

For a full agentic security loop:

1. **VS Code extension** — scans on save, shows findings as inline underlines while the agent is editing.
2. **Claude Code hook** — catches anything missed before commit.

Install the extension from the [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=peaktwilight.foxguard), then add the hook config above. The two complement each other: the extension gives real-time feedback, the hook is the final gate.

## Pinning a version

To avoid network fetches on every commit, pin the version:

```json
{ "command": "npx foxguard@0.4.0 --changed --severity high ." }
```

Or install foxguard globally / via Homebrew and reference the binary directly:

```json
{ "command": "foxguard --changed --severity high ." }
```
