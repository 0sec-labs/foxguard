# foxguard for VS Code

A security scanner as fast as a linter, written in Rust. Scans your code on every save and shows findings as underlines.

## Features

- Scans on file save and open — instant feedback
- Status bar shows finding count
- Supports JS/TS, Python, Go, Ruby, Java, PHP, Rust, C#, Swift
- Critical/High → red underline, Medium → yellow, Low → blue
- Rule IDs link to documentation
- Workspace scan via command palette or `Cmd+Shift+G`

## Requirements

foxguard must be installed:

```sh
brew install peaktwilight/tap/foxguard
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

- [GitHub](https://github.com/PwnKit-Labs/foxguard)
- [foxguard.dev](https://foxguard.dev)
- [Blog](https://foxguard.dev/blog)
