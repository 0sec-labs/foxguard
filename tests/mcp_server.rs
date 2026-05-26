use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

fn send_request(stdin: &mut impl Write, stdout: &mut impl BufRead, request: &Value) -> Value {
    let line = serde_json::to_string(request)
        .unwrap_or_else(|error| panic!("failed to serialize request: {error}"));
    writeln!(stdin, "{}", line).unwrap_or_else(|error| panic!("failed to write request: {error}"));
    stdin
        .flush()
        .unwrap_or_else(|error| panic!("failed to flush request: {error}"));

    let mut response_line = String::new();
    stdout
        .read_line(&mut response_line)
        .unwrap_or_else(|error| panic!("failed to read response: {error}"));
    serde_json::from_str(response_line.trim())
        .unwrap_or_else(|error| panic!("invalid response JSON: {error}"))
}

fn send_notification(stdin: &mut impl Write, notification: &Value) {
    let line = serde_json::to_string(notification)
        .unwrap_or_else(|error| panic!("failed to serialize notification: {error}"));
    writeln!(stdin, "{}", line)
        .unwrap_or_else(|error| panic!("failed to write notification: {error}"));
    stdin
        .flush()
        .unwrap_or_else(|error| panic!("failed to flush notification: {error}"));
}

fn spawn_mcp_server() -> (Child, ChildStdin, BufReader<ChildStdout>) {
    // Cargo provides this compile-time test binary path; it is not user input.
    // foxguard: ignore[rs/no-command-injection]
    let mut child = Command::new(env!("CARGO_BIN_EXE_foxguard-mcp"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|error| panic!("failed to spawn foxguard-mcp: {error}"));

    let stdin = child
        .stdin
        .take()
        .unwrap_or_else(|| panic!("foxguard-mcp child stdin missing"));
    let stdout = child
        .stdout
        .take()
        .unwrap_or_else(|| panic!("foxguard-mcp child stdout missing"));

    (child, stdin, BufReader::new(stdout))
}

fn json_array<'a>(value: &'a Value, context: &str) -> &'a Vec<Value> {
    value
        .as_array()
        .unwrap_or_else(|| panic!("{context} should be an array"))
}

fn json_str<'a>(value: &'a Value, context: &str) -> &'a str {
    value
        .as_str()
        .unwrap_or_else(|| panic!("{context} should be a string"))
}

fn json_u64(value: &Value, context: &str) -> u64 {
    value
        .as_u64()
        .unwrap_or_else(|| panic!("{context} should be an unsigned integer"))
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[test]
fn test_mcp_server_lifecycle() {
    // Build the binary first
    let status = Command::new("cargo")
        .args(["build", "--bin", "foxguard-mcp"])
        .status()
        .unwrap_or_else(|error| panic!("failed to build foxguard-mcp: {error}"));
    assert!(status.success(), "failed to build foxguard-mcp");

    let (mut child, mut stdin, mut stdout) = spawn_mcp_server();

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
    let tools = json_array(&response["result"]["tools"], "tools");
    assert!(tools.len() >= 10);

    let tool_names: Vec<&str> = tools
        .iter()
        .map(|t| json_str(&t["name"], "tool name"))
        .collect();
    for expected in [
        "scan_file",
        "scan_directory",
        "scan_pqc",
        "scan_secrets",
        "scan_diff",
        "emit_sarif",
        "emit_cbom",
        "list_rules",
        "explain_finding",
        "suggest_suppression",
    ] {
        assert!(
            tool_names.contains(&expected),
            "missing MCP tool {expected}"
        );
    }

    // Verify core scan input schemas retain the stable path contract.
    for tool in tools
        .iter()
        .filter(|tool| matches!(tool["name"].as_str(), Some("scan_file" | "scan_directory")))
    {
        let schema = &tool["inputSchema"];
        assert_eq!(schema["type"], "object");
        assert!(schema["properties"]["path"].is_object());
        assert_eq!(
            json_array(&schema["required"], "schema required"),
            &[json!("path")]
        );
    }

    // 4. Send tools/call with scan_file on a known vulnerable fixture
    let fixture_dir = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("failed to create temporary fixture directory: {error}"));
    let fixture_path = fixture_dir.path().join("vulnerable.py");
    fs::write(&fixture_path, "eval(input())\n")
        .unwrap_or_else(|error| panic!("failed to write vulnerable fixture: {error}"));
    let fixture_path = path_string(&fixture_path);

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
                    "path": fixture_path
                }
            }
        }),
    );

    assert_eq!(response["id"], 3);
    let content = json_array(&response["result"]["content"], "content");
    assert_eq!(content.len(), 1);
    assert_eq!(content[0]["type"], "text");

    let scan_output: Value = serde_json::from_str(json_str(&content[0]["text"], "content text"))
        .unwrap_or_else(|error| panic!("invalid scan output JSON: {error}"));
    assert_eq!(response["result"]["structuredContent"], scan_output);
    assert_eq!(scan_output["files_scanned"], 1);
    assert!(scan_output["duration_ms"].as_u64().is_some());

    let findings = json_array(&scan_output["findings"], "findings");
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
    let (mut child, mut stdin, mut stdout) = spawn_mcp_server();

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
    // Cargo provides this compile-time manifest path for integration tests.
    // foxguard: ignore[rs/no-path-traversal]
    let fixtures_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .canonicalize()
        .unwrap_or_else(|error| panic!("failed to canonicalize fixtures path: {error}"));
    let fixtures_path = path_string(&fixtures_path);

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
                    "path": fixtures_path
                }
            }
        }),
    );

    assert_eq!(response["id"], 2);
    let content = json_array(&response["result"]["content"], "content");
    let scan_output: Value = serde_json::from_str(json_str(&content[0]["text"], "content text"))
        .unwrap_or_else(|error| panic!("invalid scan output JSON: {error}"));
    assert!(json_u64(&scan_output["files_scanned"], "files_scanned") > 1);
    assert!(!json_array(&scan_output["findings"], "findings").is_empty());

    drop(stdin);
    let _ = child.wait();
}

#[test]
fn test_mcp_agent_tools_return_structured_results() {
    let (mut child, mut stdin, mut stdout) = spawn_mcp_server();

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

    let response = send_request(
        &mut stdin,
        &mut stdout,
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "list_rules",
                "arguments": {}
            }
        }),
    );
    let rules = &response["result"]["structuredContent"];
    assert_eq!(rules["command"], "list_rules");
    assert!(json_u64(&rules["rules_count"], "rules_count") > 100);
    assert!(json_array(&rules["rules"], "rules")
        .iter()
        .any(|rule| rule["id"].as_str() == Some("py/no-eval")));

    let fixture_dir = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("failed to create temporary fixture directory: {error}"));
    let fixture_path = fixture_dir.path().join("vulnerable.py");
    fs::write(
        &fixture_path,
        "from cryptography.hazmat.primitives.asymmetric import rsa\n\
         private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n",
    )
    .unwrap_or_else(|error| panic!("failed to write vulnerable fixture: {error}"));
    let fixture_path = path_string(&fixture_path);

    let response = send_request(
        &mut stdin,
        &mut stdout,
        &json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "emit_sarif",
                "arguments": {
                    "path": fixture_path.clone(),
                    "explain": true
                }
            }
        }),
    );
    let sarif = &response["result"]["structuredContent"];
    assert_eq!(sarif["command"], "emit_sarif");
    assert_eq!(sarif["sarif"]["version"], "2.1.0");
    assert!(json_u64(&sarif["findings_count"], "findings_count") > 0);

    let response = send_request(
        &mut stdin,
        &mut stdout,
        &json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "scan_pqc",
                "arguments": {
                    "path": fixture_path
                }
            }
        }),
    );
    let pqc = &response["result"]["structuredContent"];
    assert_eq!(pqc["command"], "scan_pqc");
    assert!(json_array(&pqc["findings"], "pqc findings")
        .iter()
        .any(|finding| finding["rule_id"].as_str() == Some("py/pq-vulnerable-crypto")));

    let dir = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("failed to create temporary directory: {error}"));
    let token = ["ghp_", "abcdefghijklmnopqrstuvwxyz1234567890"].concat();
    fs::write(dir.path().join(".env"), format!("GITHUB_TOKEN={token}\n"))
        .unwrap_or_else(|error| panic!("failed to write secret fixture: {error}"));

    let response = send_request(
        &mut stdin,
        &mut stdout,
        &json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "scan_secrets",
                "arguments": {
                    "path": path_string(dir.path())
                }
            }
        }),
    );
    let secrets = &response["result"]["structuredContent"];
    assert_eq!(secrets["command"], "scan_secrets");
    assert!(json_array(&secrets["findings"], "secret findings")
        .iter()
        .any(|finding| finding["rule_id"].as_str() == Some("secret/github-token")));

    let response = send_request(
        &mut stdin,
        &mut stdout,
        &json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "explain_finding",
                "arguments": {
                    "finding": {
                        "rule_id": "go/taint-sql-injection",
                        "severity": "critical",
                        "description": "Untrusted input reaches SQL sink",
                        "file": "handlers.go",
                        "line": 42,
                        "source_line": 8,
                        "source_description": "HTTP query parameter",
                        "sink_line": 42,
                        "sink_description": "database query"
                    }
                }
            }
        }),
    );
    let explanation = &response["result"]["structuredContent"];
    assert_eq!(explanation["command"], "explain_finding");
    assert_eq!(explanation["rule_id"], "go/taint-sql-injection");
    assert_eq!(explanation["dataflow"]["available"], true);

    let response = send_request(
        &mut stdin,
        &mut stdout,
        &json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "suggest_suppression",
                "arguments": {
                    "rule_id": "py/no-eval",
                    "path": "app.py"
                }
            }
        }),
    );
    let suppression = &response["result"]["structuredContent"];
    assert_eq!(suppression["command"], "suggest_suppression");
    assert_eq!(
        suppression["inline"]["comment"].as_str(),
        Some("# foxguard: ignore[py/no-eval]")
    );
    assert!(suppression["config_ignore_rule"]["yaml"]
        .as_str()
        .unwrap_or_else(|| panic!("suppression YAML should be a string"))
        .contains("py/no-eval"));

    drop(stdin);
    let _ = child.wait();
}

#[test]
fn test_mcp_scan_nonexistent_path() {
    let (mut child, mut stdin, mut stdout) = spawn_mcp_server();

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
        .unwrap_or_else(|| panic!("error message should be a string"))
        .contains("does not exist"));

    drop(stdin);
    let _ = child.wait();
}
