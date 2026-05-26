# foxguard MCP server

`foxguard-mcp` exposes foxguard scans as Model Context Protocol tools over
line-delimited JSON-RPC on stdio. It is intended for local agent clients that
want structured security feedback while editing code.

## Run

Build from source:

```sh
cargo build --bin foxguard-mcp
```

Use the binary as an MCP stdio server:

```json
{
  "mcpServers": {
    "foxguard": {
      "command": "foxguard-mcp"
    }
  }
}
```

For source checkouts, point the client at `target/debug/foxguard-mcp` after
building.

## Result shape

Every tool returns both MCP text content and structured JSON:

```json
{
  "content": [
    {
      "type": "text",
      "text": "{\"command\":\"scan_file\",\"findings\":[]}"
    }
  ],
  "structuredContent": {
    "command": "scan_file",
    "findings": []
  }
}
```

Older clients can parse `content[0].text` as JSON. Newer clients should prefer
`structuredContent`.

## Tools

| Tool | Purpose | Required inputs |
|------|---------|-----------------|
| `scan_file` | Scan one source file with built-in and optional external rules. | `path` |
| `scan_directory` | Scan a directory tree. | `path` |
| `scan_pqc` | Run only post-quantum crypto audit rules. | `path` |
| `scan_secrets` | Detect leaked credentials and private keys. | `path` |
| `scan_diff` | Return findings newly introduced against a target revision. | `path`, `target` |
| `emit_sarif` | Run a scan and return SARIF 2.1.0 JSON. | `path` |
| `emit_cbom` | Run a PQC scan and return CycloneDX CBOM JSON. | `path` |
| `list_rules` | Return built-in rule IDs and metadata. | none |
| `explain_finding` | Normalize one finding for agent reasoning, including dataflow fields. | `finding` |
| `suggest_suppression` | Return inline and config suppression snippets. | `rule_id` |

Common scan inputs include `config`, `severity`, `min_confidence`,
`max_file_size`, `exclude`, `rules`, `baseline`, `changed`, `staged`,
`unstaged`, `all_changes`, and `explain`. `scan_secrets` also accepts
`exclude_paths`, `exclude_path_file`, and `ignored_rules`. `emit_sarif` accepts
`pqc: true` to emit SARIF from PQC-only findings.

The server honors discovered `.foxguard.yml` configuration, baselines,
severity overrides, rule filters, and suppressions the same way the CLI does.
It validates that requested paths exist before running scans.

## Example call

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "scan_file",
    "arguments": {
      "path": "/repo/app.py",
      "severity": "medium",
      "explain": true
    }
  }
}
```

For diff scans, the target branch or revision must already be available in the
local Git checkout:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "scan_diff",
    "arguments": {
      "path": "/repo",
      "target": "origin/main"
    }
  }
}
```

The MCP server does not apply autofixes or write baselines. It reads the
requested paths and returns findings for the agent or editor to act on.
