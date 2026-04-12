use foxguard::engine::{scan_directory, ScanResult};
use foxguard::rules::RuleRegistry;
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
use std::path::Path;

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
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Absolute path to the file to scan"
                        }
                    },
                    "required": ["path"]
                }
            },
            {
                "name": "scan_directory",
                "description": "Run foxguard security scan on a directory",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Absolute path to the directory to scan"
                        }
                    },
                    "required": ["path"]
                }
            }
        ]
    }))
}

fn handle_tools_call(request: &Value, registry: &RuleRegistry) -> Result<Value, String> {
    let params = request
        .get("params")
        .ok_or_else(|| "Missing params".to_string())?;

    let tool_name = params
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing tool name".to_string())?;

    let arguments = params
        .get("arguments")
        .ok_or_else(|| "Missing arguments".to_string())?;

    let path = arguments
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing path argument".to_string())?;

    match tool_name {
        "scan_file" => {
            let p = Path::new(path);
            if !p.exists() {
                return Err(format!("Path does not exist: {}", path));
            }
            if !p.is_file() {
                return Err(format!("Path is not a file: {}", path));
            }
            let result = scan_directory(path, registry);
            Ok(format_scan_result(result))
        }
        "scan_directory" => {
            let p = Path::new(path);
            if !p.exists() {
                return Err(format!("Path does not exist: {}", path));
            }
            if !p.is_dir() {
                return Err(format!("Path is not a directory: {}", path));
            }
            let result = scan_directory(path, registry);
            Ok(format_scan_result(result))
        }
        _ => Err(format!("Unknown tool: {}", tool_name)),
    }
}

fn format_scan_result(result: ScanResult) -> Value {
    let output = json!({
        "findings": result.findings,
        "files_scanned": result.files_scanned,
        "duration_ms": result.duration.as_millis() as u64
    });

    json!({
        "content": [
            {
                "type": "text",
                "text": serde_json::to_string(&output).unwrap()
            }
        ]
    })
}
