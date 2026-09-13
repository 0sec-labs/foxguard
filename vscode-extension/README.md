# foxguard for VS Code

A security scanner as fast as a linter, written in Rust. Scans your code on every save and shows findings as underlines.

## Features

- Scans on file save and open — instant feedback
- Status bar shows finding count
- Supports JS/TS, Python, Go, Ruby, Java, PHP, Rust, C#, Swift, Kotlin, Haskell
- Critical/High → red underline, Medium → yellow, Low → blue
- Rule IDs link to documentation
- File and workspace scans from the command palette
- Out-of-order completion handled correctly; newer scans supersede older ones

## Scanning behavior

The extension cancels in-flight scans when:

- You edit a file while a scan for it is running (stale results discarded)
- You save again before the previous scan finished
- You close a file that was being scanned
- You change a foxguard configuration setting
- The extension deactivates

A new workspace scan supersedes older document scans inside that workspace;
unrelated workspaces remain independent. A document scan, edit, open, or close
after a workspace scan starts prevents that workspace result from overwriting
the file's diagnostics. Unsaved documents are not scanned as if their current
contents were on disk.

Workspace progress has a **Cancel** button. Cancellation settles progress without
an error, and the status bar reflects remaining active scans. Delayed open scans
and binary discovery are cancelled on configuration changes or deactivation;
configuration changes rescan clean open documents with the new settings.

On POSIX, cancellation stops the scanner's process group and escalates after
500 ms, including wrapper subprocesses that ignore the initial signal. On Windows,
the extension invokes `taskkill /T /F` before terminating the parent. Configuration
mutation commands are not cancelled when a document scan is superseded.

Scanner errors keep existing diagnostics and show an error in the status bar.
Workspace failures also show a notification; details are available in the
**foxguard** output channel. Operational errors, empty output, and invalid JSON
are never shown as "No issues found."
A successful clean workspace report clears old diagnostics only inside its scan
scope, and only for files that have not changed during the scan.

## Requirements

foxguard must be installed:

```sh
curl -fsSL https://foxguard.dev/install.sh | sh
# or
npm install -g foxguard
# or
cargo install foxguard
```

The extension auto-detects foxguard from PATH, or falls back to npx.

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `foxguard.path` | (auto) | Custom path to foxguard binary |
| `foxguard.severity` | `low` | Minimum severity to display |

## Commands

| Command | Shortcut | Description |
|---------|----------|-------------|
| foxguard: Scan Current File | `Cmd+Shift+G` | Scan the active file |
| foxguard: Scan Workspace | | Scan the entire project |

## Links

- [GitHub](https://github.com/0sec-labs/foxguard)
- [foxguard.dev](https://foxguard.dev)
- [Blog](https://foxguard.dev/blog)