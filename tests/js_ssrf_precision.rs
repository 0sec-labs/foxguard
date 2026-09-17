//! Outbound-origin proofs must survive lexical shadowing and mutable bindings.

use std::process::Command;

fn ssrf_lines(source: &str, filename: &str) -> Vec<u64> {
    let directory = tempfile::tempdir().expect("create source directory");
    let path = directory.path().join(filename);
    std::fs::write(&path, source).expect("write source");
    let output = Command::new(env!("CARGO_BIN_EXE_foxguard"))
        .args(["--config", "/dev/null"])
        .arg(&path)
        .args(["--format", "json"])
        .output()
        .expect("run scanner");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("scanner must return JSON");
    report["findings"].as_array().expect("findings array").iter()
        .filter(|finding| finding["rule_id"] == "js/no-ssrf")
        .map(|finding| finding["line"].as_u64().expect("finding line"))
        .collect()
}

#[test]
fn immutable_origins_allow_dynamic_paths_not_dynamic_authorities() {
    let source = r#"const ORIGIN = "https://provider.example";
const VERSION = "v1internal";
fetch(`${ORIGIN}/oauth/token`);
fetch(`${ORIGIN}/${VERSION}:${method}`);
fetch(`${ORIGIN}/${VERSION}/${operation}`);
fetch(`https://provider.example/path/${input}`);
fetch(`${ORIGIN}?query=${input}`);
fetch(`${ORIGIN}`);
fetch(`${ORIGIN}${input}`);
fetch(`https://${host}/path`);
fetch(`https://${user}@provider.example/path`);
fetch(`https://provider.example:${port}/path`);
fetch(`${scheme}://provider.example/path`);
fetch(`${ORIGIN}.attacker.example/${input}`);
fetch(`${ORIGIN}@attacker.example/${input}`);"#;
    for filename in ["origins.js", "origins.ts"] {
        // Appending a literal suffix still fixes the authority (line 14).
        // Literal userinfo remains deliberately conservative (line 15).
        assert_eq!(ssrf_lines(source, filename), vec![9, 10, 11, 12, 13, 15]);
    }
}

#[test]
fn closest_binding_wins_over_file_global_constant_names() {
    let source = r#"const ORIGIN = "https://provider.example";
function parameter(ORIGIN) { fetch(`${ORIGIN}/path`); }
function destructured({ ORIGIN }) { fetch(`${ORIGIN}/path`); }
function local() { const ORIGIN = request.url; fetch(`${ORIGIN}/path`); }
function hoisted() { fetch(`${ORIGIN}/path`); var ORIGIN = request.url; }
try { work(); } catch (ORIGIN) { fetch(`${ORIGIN}/path`); }
const arrow = ORIGIN => fetch(`${ORIGIN}/path`);
{ let ORIGIN = request.url; fetch(`${ORIGIN}/path`); }
function safeSibling() { fetch(`${ORIGIN}/path`); }
function tdz() { fetch(`${ORIGIN}/path`); const ORIGIN = "https://later.example"; }"#;
    for filename in ["scope.js", "scope.ts"] {
        assert_eq!(ssrf_lines(source, filename), vec![2, 3, 4, 5, 6, 7, 8, 10]);
    }
}

#[test]
fn writes_and_mutable_declarations_do_not_prove_origins() {
    let source = r#"let ORIGIN = "https://provider.example";
ORIGIN = request.url;
fetch(`${ORIGIN}/path`);
fetch(ORIGIN);
const FIXED = "https://provider.example";
FIXED = request.url;
fetch(`${FIXED}/path`);
const FULL = "https://provider.example/path";
fetch(FULL);
fetch(this.buildUrl());
fetch(encodeURIComponent(request.url));"#;
    assert_eq!(ssrf_lines(source, "writes.ts"), vec![3, 4, 7, 10, 11]);
}

#[test]
fn fixed_prefix_requires_a_boundary_before_unknown_text() {
    let source = r#"const ORIGIN = "https://provider.example";
fetch(`https://provider.example${suffix}`);
fetch(`${ORIGIN}:${port}`);
fetch(`${ORIGIN}${suffix}/path`);
fetch(`https://provider.example/${suffix}`);
fetch(`https://provider.example?${suffix}`);
fetch(`https://provider.example#${suffix}`);
fetch(`${ORIGIN}\\${suffix}`);"#;
    assert_eq!(ssrf_lines(source, "boundaries.js"), vec![2, 3, 4, 8]);
}

#[test]
fn typed_parameters_and_loop_bindings_shadow_outer_constants() {
    let source = r#"const ORIGIN = "https://provider.example";
function typed(ORIGIN: string) { fetch(`${ORIGIN}/path`); }
for (const ORIGIN of origins) { fetch(`${ORIGIN}/path`); }
for (let ORIGIN = input; keepGoing(); advance()) { fetch(`${ORIGIN}/path`); }
function hoistedLoop() { for (var ORIGIN of origins) {} fetch(`${ORIGIN}/path`); }
fetch(`${ORIGIN}/path`);"#;
    assert_eq!(ssrf_lines(source, "typed.ts"), vec![2, 3, 4, 5]);
}
