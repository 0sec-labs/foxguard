use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

fn send_request(stdin: &mut impl Write, stdout: &mut impl BufRead, request: &Value) -> Value {
    let line = serde_json::to_string(request).unwrap();
    writeln!(stdin, "{}", line).unwrap();
    stdin.flush().unwrap();

    let mut response_line = String::new();
    stdout.read_line(&mut response_line).unwrap();
    serde_json::from_str(response_line.trim()).unwrap()
}

fn send_notification(stdin: &mut impl Write, notification: &Value) {
    let line = serde_json::to_string(notification).unwrap();
    writeln!(stdin, "{}", line).unwrap();
    stdin.flush().unwrap();
}

#[test]
fn test_mcp_server_lifecycle() {
    // Build the binary first
    let status = Command::new("cargo")
        .args(["build", "--bin", "foxguard-mcp"])
        .status()
        .expect("failed to build foxguard-mcp");
    assert!(status.success(), "failed to build foxguard-mcp");

    let mut child = Command::new(env!("CARGO_BIN_EXE_foxguard-mcp"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn foxguard-mcp");

    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    // 1. Send initialize request
    let response = send_request(
        &mut stdin,
        &mut stdout,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "test", "version": "1.0" }
            }
        }),
    );

    assert_eq!(response["id"], 1);
    assert_eq!(response["result"]["protocolVersion"], "2024-11-05");
    assert_eq!(response["result"]["serverInfo"]["name"], "foxguard");
    assert!(response["result"]["serverInfo"]["version"]
        .as_str()
        .is_some());

    // 2. Send initialized notification (should be silently ignored)
    send_notification(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }),
    );

    // 3. Send tools/list request
    let response = send_request(
        &mut stdin,
        &mut stdout,
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }),
    );

    assert_eq!(response["id"], 2);
    let tools = response["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 2);

    let tool_names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert!(tool_names.contains(&"scan_file"));
    assert!(tool_names.contains(&"scan_directory"));

    // Verify input schemas
    for tool in tools {
        let schema = &tool["inputSchema"];
        assert_eq!(schema["type"], "object");
        assert!(schema["properties"]["path"].is_object());
        assert_eq!(schema["required"].as_array().unwrap(), &[json!("path")]);
    }

    // 4. Send tools/call with scan_file on a known vulnerable fixture
    let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/vulnerable.py")
        .canonicalize()
        .unwrap();

    let response = send_request(
        &mut stdin,
        &mut stdout,
        &json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "scan_file",
                "arguments": {
                    "path": fixture_path.to_str().unwrap()
                }
            }
        }),
    );

    assert_eq!(response["id"], 3);
    let content = response["result"]["content"].as_array().unwrap();
    assert_eq!(content.len(), 1);
    assert_eq!(content[0]["type"], "text");

    let scan_output: Value = serde_json::from_str(content[0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(scan_output["files_scanned"], 1);
    assert!(scan_output["duration_ms"].as_u64().is_some());

    let findings = scan_output["findings"].as_array().unwrap();
    assert!(
        !findings.is_empty(),
        "Expected findings for vulnerable.py fixture"
    );

    // Verify finding structure
    let first = &findings[0];
    assert!(first["rule_id"].as_str().is_some());
    assert!(first["severity"].as_str().is_some());
    assert!(first["description"].as_str().is_some());
    assert!(first["file"].as_str().is_some());
    assert!(first["line"].as_u64().is_some());
    assert!(first["snippet"].as_str().is_some());

    // 5. Test unknown method
    let response = send_request(
        &mut stdin,
        &mut stdout,
        &json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "unknown/method",
            "params": {}
        }),
    );

    assert_eq!(response["id"], 4);
    assert!(response["error"].is_object());
    assert_eq!(response["error"]["code"], -32601);

    // Clean up
    drop(stdin);
    let _ = child.wait();
}

#[test]
fn test_mcp_scan_directory() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_foxguard-mcp"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn foxguard-mcp");

    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    // Initialize first
    let _ = send_request(
        &mut stdin,
        &mut stdout,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "test", "version": "1.0" }
            }
        }),
    );

    // Scan the fixtures directory
    let fixtures_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .canonicalize()
        .unwrap();

    let response = send_request(
        &mut stdin,
        &mut stdout,
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "scan_directory",
                "arguments": {
                    "path": fixtures_path.to_str().unwrap()
                }
            }
        }),
    );

    assert_eq!(response["id"], 2);
    let content = response["result"]["content"].as_array().unwrap();
    let scan_output: Value = serde_json::from_str(content[0]["text"].as_str().unwrap()).unwrap();
    assert!(scan_output["files_scanned"].as_u64().unwrap() > 1);
    assert!(!scan_output["findings"].as_array().unwrap().is_empty());

    drop(stdin);
    let _ = child.wait();
}

#[test]
fn test_mcp_scan_nonexistent_path() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_foxguard-mcp"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn foxguard-mcp");

    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    // Initialize
    let _ = send_request(
        &mut stdin,
        &mut stdout,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "test", "version": "1.0" }
            }
        }),
    );

    // Try scanning a nonexistent file
    let response = send_request(
        &mut stdin,
        &mut stdout,
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "scan_file",
                "arguments": {
                    "path": "/nonexistent/path/file.py"
                }
            }
        }),
    );

    assert_eq!(response["id"], 2);
    assert!(response["error"].is_object());
    assert!(response["error"]["message"]
        .as_str()
        .unwrap()
        .contains("does not exist"));

    drop(stdin);
    let _ = child.wait();
}
