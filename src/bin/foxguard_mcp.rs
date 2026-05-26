use foxguard::app::{execute_diff, execute_scan, execute_secrets, DiffExecution, ScanExecution};
use foxguard::cli::{
    ChangeModeArgs, DiffArgs, OutputFormat, ScanArgs, SecretsArgs, SeverityFilter,
};
use foxguard::engine::ScanStats;
use foxguard::report::{cbom::build_cbom, sarif::build_sarif};
use foxguard::rules::RuleRegistry;
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
use std::path::Path;

const DEFAULT_MAX_FILE_SIZE: u64 = 1_048_576;

fn main() {
    let registry = RuleRegistry::new();
    let stdin = io::stdin();
    let stdout = io::stdout();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };

        if line.trim().is_empty() {
            continue;
        }

        let request: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let error_response = json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": {
                        "code": -32700,
                        "message": format!("Parse error: {}", e)
                    }
                });
                let mut out = stdout.lock();
                let _ = writeln!(out, "{}", error_response);
                let _ = out.flush();
                continue;
            }
        };

        let response = handle_request(&request, &registry);

        if let Some(resp) = response {
            let mut out = stdout.lock();
            let _ = writeln!(out, "{}", resp);
            let _ = out.flush();
        }
    }
}

fn handle_request(request: &Value, registry: &RuleRegistry) -> Option<Value> {
    let method = request.get("method")?.as_str()?;
    let id = request.get("id");

    // Notifications (no id) are handled silently
    let id = id?.clone();

    let result = match method {
        "initialize" => handle_initialize(),
        "tools/list" => handle_tools_list(),
        "tools/call" => handle_tools_call(request, registry),
        _ => {
            return Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32601,
                    "message": format!("Method not found: {}", method)
                }
            }));
        }
    };

    match result {
        Ok(value) => Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": value
        })),
        Err(err) => Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": -32602,
                "message": err
            }
        })),
    }
}

fn handle_initialize() -> Result<Value, String> {
    Ok(json!({
        "protocolVersion": "2024-11-05",
        "capabilities": { "tools": {} },
        "serverInfo": {
            "name": "foxguard",
            "version": env!("CARGO_PKG_VERSION")
        }
    }))
}

fn handle_tools_list() -> Result<Value, String> {
    Ok(json!({
        "tools": [
            {
                "name": "scan_file",
                "description": "Run foxguard security scan on a single file",
                "inputSchema": scan_input_schema(["path"], "Absolute path to the file to scan")
            },
            {
                "name": "scan_directory",
                "description": "Run foxguard security scan on a directory",
                "inputSchema": scan_input_schema(["path"], "Absolute path to the directory to scan")
            },
            {
                "name": "scan_pqc",
                "description": "Run foxguard post-quantum crypto audit rules on a file or directory",
                "inputSchema": scan_input_schema(["path"], "Absolute path to the file or directory to scan")
            },
            {
                "name": "scan_secrets",
                "description": "Run foxguard secrets scanning on a file or directory",
                "inputSchema": secrets_input_schema()
            },
            {
                "name": "scan_diff",
                "description": "Run foxguard diff mode and return findings new against a target branch",
                "inputSchema": diff_input_schema()
            },
            {
                "name": "emit_sarif",
                "description": "Run a scan and return SARIF JSON",
                "inputSchema": scan_input_schema(["path"], "Absolute path to the file or directory to scan")
            },
            {
                "name": "emit_cbom",
                "description": "Run a PQC scan and return CycloneDX CBOM JSON",
                "inputSchema": scan_input_schema(["path"], "Absolute path to the file or directory to scan")
            },
            {
                "name": "list_rules",
                "description": "List built-in foxguard rules and rule metadata",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            },
            {
                "name": "explain_finding",
                "description": "Summarize a foxguard finding, including source-to-sink trace metadata when present",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "finding": {
                            "type": "object",
                            "description": "A finding object returned by another foxguard MCP tool"
                        }
                    },
                    "required": ["finding"]
                }
            },
            {
                "name": "suggest_suppression",
                "description": "Return inline and config suppression snippets for an accepted finding",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "rule_id": {
                            "type": "string",
                            "description": "Rule ID to suppress"
                        },
                        "path": {
                            "type": "string",
                            "description": "Optional repository-relative path for config suppression"
                        }
                    },
                    "required": ["rule_id"]
                }
            }
        ]
    }))
}

fn scan_input_schema<const N: usize>(required: [&str; N], path_description: &str) -> Value {
    let required = required.to_vec();

    json!({
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": path_description
            },
            "config": {
                "type": "string",
                "description": "Optional foxguard config path"
            },
            "severity": {
                "type": "string",
                "enum": ["low", "medium", "high", "critical"],
                "description": "Minimum severity to report"
            },
            "min_confidence": {
                "type": "number",
                "minimum": 0.0,
                "maximum": 1.0,
                "description": "Minimum confidence threshold"
            },
            "max_file_size": {
                "type": "integer",
                "minimum": 1,
                "description": "Maximum file size in bytes"
            },
            "exclude": {
                "type": "array",
                "items": { "type": "string" },
                "description": "Scan-relative path prefixes or globs to exclude"
            },
            "rules": {
                "type": "string",
                "description": "Optional external rule file or directory"
            },
            "baseline": {
                "type": "string",
                "description": "Optional baseline file to apply"
            },
            "changed": {
                "type": "boolean",
                "description": "Scan changed files only"
            },
            "staged": {
                "type": "boolean",
                "description": "Scan staged files only"
            },
            "unstaged": {
                "type": "boolean",
                "description": "Scan unstaged and untracked files only"
            },
            "all_changes": {
                "type": "boolean",
                "description": "Scan staged, unstaged, and untracked changes"
            },
            "explain": {
                "type": "boolean",
                "description": "Include dataflow trace fields where available"
            }
        },
        "required": required
    })
}

fn secrets_input_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Absolute path to the file or directory to scan"
            },
            "config": {
                "type": "string",
                "description": "Optional foxguard config path"
            },
            "baseline": {
                "type": "string",
                "description": "Optional secrets baseline file to apply"
            },
            "exclude_paths": {
                "type": "array",
                "items": { "type": "string" },
                "description": "File or directory prefixes to exclude"
            },
            "ignored_rules": {
                "type": "array",
                "items": { "type": "string" },
                "description": "Secret rule IDs to ignore"
            },
            "max_file_size": {
                "type": "integer",
                "minimum": 1,
                "description": "Maximum file size in bytes"
            },
            "changed": { "type": "boolean" },
            "staged": { "type": "boolean" },
            "unstaged": { "type": "boolean" },
            "all_changes": { "type": "boolean" }
        },
        "required": ["path"]
    })
}

fn diff_input_schema() -> Value {
    let mut schema = scan_input_schema(
        ["path", "target"],
        "Absolute path to the repository to scan",
    );
    if let Some(properties) = schema.get_mut("properties").and_then(Value::as_object_mut) {
        properties.insert(
            "target".to_string(),
            json!({
                "type": "string",
                "description": "Target branch or revision to compare against"
            }),
        );
    }
    schema
}

fn handle_tools_call(request: &Value, registry: &RuleRegistry) -> Result<Value, String> {
    let params = request
        .get("params")
        .ok_or_else(|| "Missing params".to_string())?;

    let tool_name = params
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing tool name".to_string())?;

    let empty_arguments = json!({});
    let arguments = params.get("arguments").unwrap_or(&empty_arguments);

    match tool_name {
        "scan_file" => {
            validate_path(arguments, PathExpectation::File)?;
            let execution = execute_scan(&scan_args(arguments, false)?)?;
            Ok(tool_result(scan_execution_value("scan_file", execution)))
        }
        "scan_directory" => {
            validate_path(arguments, PathExpectation::Directory)?;
            let execution = execute_scan(&scan_args(arguments, false)?)?;
            Ok(tool_result(scan_execution_value(
                "scan_directory",
                execution,
            )))
        }
        "scan_pqc" => {
            validate_path(arguments, PathExpectation::Any)?;
            let execution = execute_scan(&scan_args(arguments, true)?)?;
            Ok(tool_result(scan_execution_value("scan_pqc", execution)))
        }
        "scan_secrets" => {
            validate_path(arguments, PathExpectation::Any)?;
            let execution = execute_secrets(&secrets_args(arguments)?)?;
            Ok(tool_result(secrets_execution_value(execution)))
        }
        "scan_diff" => {
            validate_path(arguments, PathExpectation::Directory)?;
            let execution = execute_diff(&diff_args(arguments)?)?;
            Ok(tool_result(diff_execution_value(execution)))
        }
        "emit_sarif" => {
            validate_path(arguments, PathExpectation::Any)?;
            let pq_mode = optional_bool(arguments, "pqc")?;
            let execution = execute_scan(&scan_args(arguments, pq_mode)?)?;
            let sarif = build_sarif(&execution.findings);
            Ok(tool_result(json!({
                "command": "emit_sarif",
                "sarif": sarif,
                "findings_count": execution.findings.len(),
                "files_scanned": execution.files_scanned,
                "duration_ms": execution.duration.as_millis() as u64,
                "notices": execution.notices
            })))
        }
        "emit_cbom" => {
            validate_path(arguments, PathExpectation::Any)?;
            let execution = execute_scan(&scan_args(arguments, true)?)?;
            let (cbom, empty_but_findings_present) = build_cbom(&execution.findings);
            Ok(tool_result(json!({
                "command": "emit_cbom",
                "cbom": cbom,
                "empty_but_findings_present": empty_but_findings_present,
                "findings_count": execution.findings.len(),
                "files_scanned": execution.files_scanned,
                "duration_ms": execution.duration.as_millis() as u64,
                "notices": execution.notices
            })))
        }
        "list_rules" => Ok(tool_result(list_rules(registry))),
        "explain_finding" => Ok(tool_result(explain_finding(arguments)?)),
        "suggest_suppression" => Ok(tool_result(suggest_suppression(arguments)?)),
        _ => Err(format!("Unknown tool: {}", tool_name)),
    }
}

enum PathExpectation {
    File,
    Directory,
    Any,
}

fn validate_path(arguments: &Value, expectation: PathExpectation) -> Result<(), String> {
    let path = required_string(arguments, "path")?;
    // MCP clients pass local filesystem paths by design; validate existence
    // and expected type before dispatching the scanner.
    // foxguard: ignore[rs/no-path-traversal]
    let p = Path::new(&path);
    if !p.exists() {
        return Err(format!("Path does not exist: {}", path));
    }

    match expectation {
        PathExpectation::File if !p.is_file() => Err(format!("Path is not a file: {}", path)),
        PathExpectation::Directory if !p.is_dir() => {
            Err(format!("Path is not a directory: {}", path))
        }
        _ => Ok(()),
    }
}

fn tool_result(output: Value) -> Value {
    let text = match serde_json::to_string(&output) {
        Ok(text) => text,
        Err(error) => json!({
            "serialization_error": error.to_string()
        })
        .to_string(),
    };
    json!({
        "content": [
            {
                "type": "text",
                "text": text
            }
        ],
        "structuredContent": output
    })
}

fn scan_args(arguments: &Value, pq_mode: bool) -> Result<ScanArgs, String> {
    Ok(ScanArgs {
        path: required_string(arguments, "path")?,
        config: optional_string(arguments, "config")?,
        format: OutputFormat::Json,
        severity: optional_severity(arguments, "severity")?,
        rules: optional_string(arguments, "rules")?,
        codeql_db: optional_string(arguments, "codeql_db")?,
        no_builtins: optional_bool(arguments, "no_builtins")?,
        changes: change_mode_args(arguments)?,
        exclude: optional_string_array(arguments, "exclude")?,
        baseline: optional_string(arguments, "baseline")?,
        write_baseline: None,
        explain: optional_bool(arguments, "explain")?,
        fix: false,
        github_pr: None,
        quiet: true,
        output: None,
        max_file_size: optional_u64(arguments, "max_file_size")?.unwrap_or(DEFAULT_MAX_FILE_SIZE),
        show_confidence: false,
        min_confidence: optional_f32(arguments, "min_confidence")?,
        pq_mode,
        cnsa2: pq_mode || optional_bool(arguments, "cnsa2")?,
    })
}

fn secrets_args(arguments: &Value) -> Result<SecretsArgs, String> {
    Ok(SecretsArgs {
        path: required_string(arguments, "path")?,
        config: optional_string(arguments, "config")?,
        format: OutputFormat::Json,
        changes: change_mode_args(arguments)?,
        baseline: optional_string(arguments, "baseline")?,
        write_baseline: None,
        output: None,
        exclude_paths: optional_string_array(arguments, "exclude_paths")?,
        exclude_path_file: optional_string(arguments, "exclude_path_file")?,
        ignored_rules: optional_string_array(arguments, "ignored_rules")?,
        max_file_size: optional_u64(arguments, "max_file_size")?.unwrap_or(DEFAULT_MAX_FILE_SIZE),
    })
}

fn diff_args(arguments: &Value) -> Result<DiffArgs, String> {
    Ok(DiffArgs {
        target: required_string(arguments, "target")?,
        path: required_string(arguments, "path")?,
        config: optional_string(arguments, "config")?,
        format: OutputFormat::Json,
        severity: optional_severity(arguments, "severity")?,
        rules: optional_string(arguments, "rules")?,
        no_builtins: optional_bool(arguments, "no_builtins")?,
        output: None,
        github_pr: None,
        max_file_size: optional_u64(arguments, "max_file_size")?.unwrap_or(DEFAULT_MAX_FILE_SIZE),
    })
}

fn change_mode_args(arguments: &Value) -> Result<ChangeModeArgs, String> {
    let changes = ChangeModeArgs {
        changed: optional_bool(arguments, "changed")?,
        staged: optional_bool(arguments, "staged")?,
        unstaged: optional_bool(arguments, "unstaged")?,
        all_changes: optional_bool(arguments, "all_changes")?,
    };

    let selected = [
        changes.changed,
        changes.staged,
        changes.unstaged,
        changes.all_changes,
    ]
    .into_iter()
    .filter(|selected| *selected)
    .count();
    if selected > 1 {
        return Err(
            "Only one change mode may be set: changed, staged, unstaged, all_changes".to_string(),
        );
    }

    Ok(changes)
}

fn scan_execution_value(command: &str, execution: ScanExecution) -> Value {
    let findings_count = execution.findings.len();
    json!({
        "command": command,
        "findings": execution.findings,
        "findings_count": findings_count,
        "files_scanned": execution.files_scanned,
        "duration_ms": execution.duration.as_millis() as u64,
        "stats": scan_stats_value(&execution.stats),
        "notices": execution.notices
    })
}

fn secrets_execution_value(execution: foxguard::app::SecretsExecution) -> Value {
    let findings_count = execution.findings.len();
    json!({
        "command": "scan_secrets",
        "findings": execution.findings,
        "findings_count": findings_count,
        "files_scanned": execution.files_scanned,
        "duration_ms": execution.duration.as_millis() as u64,
        "notices": execution.notices
    })
}

fn diff_execution_value(execution: DiffExecution) -> Value {
    let findings_count = execution.findings.len();
    json!({
        "command": "scan_diff",
        "findings": execution.findings,
        "findings_count": findings_count,
        "files_scanned": execution.files_scanned,
        "duration_ms": execution.duration.as_millis() as u64,
        "total_current": execution.total_current,
        "existing_count": execution.existing_count,
        "notices": execution.notices
    })
}

fn scan_stats_value(stats: &ScanStats) -> Value {
    json!({
        "files_discovered": stats.files_discovered,
        "files_scanned": stats.files_scanned,
        "files_skipped": stats.files_skipped,
        "files_ignored": stats.files_ignored,
        "unsupported_files": stats.unsupported_files,
        "noise_files": stats.noise_files,
        "too_large_files": stats.too_large_files,
        "metadata_error_files": stats.metadata_error_files,
        "binary_files": stats.binary_files,
        "read_error_files": stats.read_error_files,
        "minified_files": stats.minified_files,
        "parse_error_files": stats.parse_error_files
    })
}

fn list_rules(registry: &RuleRegistry) -> Value {
    let mut rules = registry
        .all_rules()
        .iter()
        .map(|rule| {
            json!({
                "id": rule.id(),
                "severity": rule.severity(),
                "cwe": rule.cwe(),
                "description": rule.description(),
                "language": rule.language().to_string(),
                "cnsa2_deadline": rule.cnsa2_deadline(),
                "taint": rule.id().contains("/taint-")
            })
        })
        .collect::<Vec<_>>();
    rules.sort_by(|a, b| {
        a["id"]
            .as_str()
            .unwrap_or_default()
            .cmp(b["id"].as_str().unwrap_or_default())
    });

    json!({
        "command": "list_rules",
        "rules_count": rules.len(),
        "rules": rules
    })
}

fn explain_finding(arguments: &Value) -> Result<Value, String> {
    let finding = arguments.get("finding").unwrap_or(arguments);
    let rule_id = required_string(finding, "rule_id")?;
    let source_line = optional_usize(finding, "source_line")?;
    let sink_line = optional_usize(finding, "sink_line")?;
    let source_description = optional_string(finding, "source_description")?;
    let sink_description = optional_string(finding, "sink_description")?;
    let has_dataflow = source_line.is_some()
        || sink_line.is_some()
        || source_description.is_some()
        || sink_description.is_some();

    Ok(json!({
        "command": "explain_finding",
        "rule_id": rule_id,
        "severity": optional_string(finding, "severity")?,
        "cwe": optional_string(finding, "cwe")?,
        "description": optional_string(finding, "description")?,
        "location": {
            "file": optional_string(finding, "file")?,
            "line": optional_usize(finding, "line")?,
            "column": optional_usize(finding, "column")?,
            "end_line": optional_usize(finding, "end_line")?,
            "end_column": optional_usize(finding, "end_column")?
        },
        "snippet": optional_string(finding, "snippet")?,
        "dataflow": {
            "available": has_dataflow,
            "source": {
                "line": source_line,
                "description": source_description
            },
            "sink": {
                "line": sink_line,
                "description": sink_description
            },
            "taint_hops": optional_usize(finding, "taint_hops")?
        },
        "fix_suggestion": optional_string(finding, "fix_suggestion")?
    }))
}

fn suggest_suppression(arguments: &Value) -> Result<Value, String> {
    let rule_id = required_string(arguments, "rule_id")?;
    let path = optional_string(arguments, "path")?;
    let comment_prefix = path.as_deref().map(comment_prefix_for_path).unwrap_or("//");
    let path_for_yaml = path.as_deref().unwrap_or("path/to/file");
    let escaped_pattern = regex::escape(path_for_yaml);

    Ok(json!({
        "command": "suggest_suppression",
        "rule_id": rule_id,
        "path": path,
        "inline": {
            "comment": format!("{comment_prefix} foxguard: ignore[{rule_id}]"),
            "note": "Place this on the finding line or the nearest preceding line supported by the file type."
        },
        "config_ignore_rule": {
            "yaml": format!(
                "scan:\n  ignore_rules:\n    - path: {path_for_yaml}\n      rules:\n        - {rule_id}\n"
            )
        },
        "config_pattern_suppression": {
            "yaml": format!(
                "scan:\n  suppressions:\n    - rule_id: {rule_id}\n      path_pattern: \"^{escaped_pattern}$\"\n"
            )
        }
    }))
}

fn comment_prefix_for_path(path: &str) -> &'static str {
    let file_name = match path.rsplit(['/', '\\']).next() {
        Some(file_name) => file_name,
        None => path,
    };
    let extension = match file_name.rsplit_once('.') {
        Some((_, extension)) => extension,
        None => "",
    };

    match extension {
        "py" | "pyw" | "rb" | "rake" | "gemspec" | "yml" | "yaml" | "toml" | "sh" | "bash"
        | "zsh" => "#",
        _ => "//",
    }
}

fn required_string(value: &Value, key: &str) -> Result<String, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("Missing {key} argument"))
}

fn optional_string(value: &Value, key: &str) -> Result<Option<String>, String> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_str()
            .map(|value| Some(value.to_string()))
            .ok_or_else(|| format!("{key} must be a string")),
    }
}

fn optional_string_array(value: &Value, key: &str) -> Result<Vec<String>, String> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(ToOwned::to_owned)
                    .ok_or_else(|| format!("{key} entries must be strings"))
            })
            .collect(),
        Some(_) => Err(format!("{key} must be an array of strings")),
    }
}

fn optional_bool(value: &Value, key: &str) -> Result<bool, String> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(false),
        Some(value) => value
            .as_bool()
            .ok_or_else(|| format!("{key} must be a boolean")),
    }
}

fn optional_u64(value: &Value, key: &str) -> Result<Option<u64>, String> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("{key} must be a positive integer")),
    }
}

fn optional_usize(value: &Value, key: &str) -> Result<Option<usize>, String> {
    optional_u64(value, key).map(|value| value.map(|value| value as usize))
}

fn optional_f32(value: &Value, key: &str) -> Result<Option<f32>, String> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => {
            let raw = value
                .as_f64()
                .ok_or_else(|| format!("{key} must be a number in [0.0, 1.0]"))?;
            if !(0.0..=1.0).contains(&raw) {
                return Err(format!("{key} must be in [0.0, 1.0]"));
            }
            Ok(Some(raw as f32))
        }
    }
}

fn optional_severity(value: &Value, key: &str) -> Result<Option<SeverityFilter>, String> {
    let Some(raw) = optional_string(value, key)? else {
        return Ok(None);
    };

    match raw.as_str() {
        "low" => Ok(Some(SeverityFilter::Low)),
        "medium" => Ok(Some(SeverityFilter::Medium)),
        "high" => Ok(Some(SeverityFilter::High)),
        "critical" => Ok(Some(SeverityFilter::Critical)),
        _ => Err(format!("{key} must be one of: low, medium, high, critical")),
    }
}
