# foxguard

A security scanner as fast as a linter, written in Rust.

```sh
npx foxguard .
```

## Why people use it

- Fast enough to run locally instead of waiting for CI
- Useful built-in rules out of the box across 10 languages
- Semgrep-compatible YAML subset when you already have existing rules
- JSON and SARIF output for automation

It scans for SQL injection, XSS, SSRF, hardcoded secrets, command injection, weak crypto, unsafe deserialization, and framework-specific mistakes.

**Languages:** JavaScript, TypeScript, Python, Go, Ruby, Java, PHP, Rust, C#, Swift

## How it works

This is the npm wrapper. It downloads the correct prebuilt Rust binary for your platform from GitHub Releases and caches it locally.

```sh
npx foxguard .                    # scan everything
npx foxguard --changed .          # only modified files
npx foxguard secrets .            # leaked credentials
npx foxguard --format sarif .     # SARIF for GitHub Code Scanning
npx foxguard init                 # install pre-commit hook
```

## Scope

foxguard is built around fast local feedback.

- built-in rules are the default product
- Semgrep/OpenGrep-compatible YAML is the adoption bridge
- full external-rule-engine parity is intentionally out of scope

## Supported platforms

- macOS (x64, arm64)
- Linux (x64, arm64)
- Windows (x64)

## More

- [GitHub](https://github.com/PwnKit-Labs/foxguard)
- [VS Code Extension](https://marketplace.visualstudio.com/items?itemName=peaktwilight.foxguard)
- [foxguard.dev](https://foxguard.dev)
