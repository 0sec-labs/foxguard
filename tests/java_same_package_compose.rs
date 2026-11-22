//! Multi-hop compose for many Java files in one package (issue #662).
//!
//! Files are generated in groups of four that form a call chain across files:
//! `Entry{g}` -> `HopA{g}` -> `HopB{g}` -> `Sink{g}` (command execution). Even
//! groups pass request data into the chain (must be reported in the entry
//! file); odd groups pass a constant (must stay silent). All files share one
//! package directory, so the compose phase used to treat every file as a
//! dependency of every other.

use std::fmt::Write as _;
use std::path::Path;
use std::process::Command;
use std::time::Instant;

fn write_group(dir: &Path, g: usize, tainted: bool) {
    let arg = if tainted {
        "request.getParameter(\"cmd\")"
    } else {
        "\"ls\""
    };
    let files = [
        (
            format!("Entry{g}"),
            format!(
                "package bulk;\npublic class Entry{g} {{\n  void run(javax.servlet.http.HttpServletRequest request) throws Exception {{\n    String c = {arg};\n    hopA{g}(c);\n  }}\n}}\n"
            ),
        ),
        (
            format!("HopA{g}"),
            format!(
                "package bulk;\npublic class HopA{g} {{\n  static void hopA{g}(String p) throws Exception {{\n    hopB{g}(p);\n  }}\n}}\n"
            ),
        ),
        (
            format!("HopB{g}"),
            format!(
                "package bulk;\npublic class HopB{g} {{\n  static void hopB{g}(String q) throws Exception {{\n    sink{g}(q);\n  }}\n}}\n"
            ),
        ),
        (
            format!("Sink{g}"),
            format!(
                "package bulk;\npublic class Sink{g} {{\n  static void sink{g}(String r) throws Exception {{\n    Runtime.getRuntime().exec(r);\n  }}\n}}\n"
            ),
        ),
    ];
    for (name, body) in files {
        std::fs::write(dir.join(format!("{name}.java")), body).unwrap();
    }
}

fn generate(n_files: usize) -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("bulk");
    std::fs::create_dir(&dir).unwrap();
    for g in 0..n_files / 4 {
        write_group(&dir, g, g % 2 == 0);
    }
    tmp
}

/// Returns (sorted `file:line:rule` of findings, compose-phase line from timing).
fn scan(root: &Path) -> (Vec<String>, String, f64) {
    let started = Instant::now();
    let out = Command::new(env!("CARGO_BIN_EXE_foxguard"))
        .args(["--config", "/dev/null", "-f", "json", "--file-timeout", "0"])
        .arg(root)
        .env("FOXGUARD_TIMING", "1")
        .output()
        .unwrap();
    let wall = started.elapsed().as_secs_f64();
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    let mut findings: Vec<String> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            let mut s = String::new();
            write!(
                s,
                "{}:{}:{}",
                f["file"].as_str().unwrap_or(""),
                f["line"],
                f["rule_id"].as_str().unwrap_or("")
            )
            .unwrap();
            s
        })
        .collect();
    findings.sort();
    let stderr = String::from_utf8_lossy(&out.stderr);
    let compose = stderr
        .lines()
        .find(|l| l.contains("java multi-hop compose"))
        .unwrap_or("")
        .to_string();
    (findings, compose, wall)
}

#[test]
fn same_package_chain_is_found_across_four_files() {
    let tmp = generate(200);
    let (findings, _, _) = scan(tmp.path());
    let cross: Vec<&String> = findings
        .iter()
        .filter(|f| f.contains("taint-command-injection"))
        .collect();
    // 50 groups, even ones tainted: 25 entry-file findings, one per group,
    // reported in `Entry{even}.java` only (never for odd/constant groups).
    let entry_hits: Vec<&&String> = cross.iter().filter(|f| f.contains("/Entry")).collect();
    assert_eq!(entry_hits.len(), 25, "entry findings: {entry_hits:?}");
    for g in (0..50).step_by(2) {
        assert!(
            entry_hits
                .iter()
                .any(|f| f.contains(&format!("/Entry{g}.java:"))),
            "missing chain finding for group {g}"
        );
    }
    assert!(
        !entry_hits.iter().any(|f| (0..50)
            .skip(1)
            .step_by(2)
            .any(|g| f.contains(&format!("/Entry{g}.java:")))),
        "constant-argument group must not be reported"
    );
}

#[test]
fn findings_independent_of_unrelated_siblings() {
    // Adding many unrelated files to the package must not change findings
    // for the chain files.
    let small = generate(40);
    let big = generate(400);
    let (a, _, _) = scan(small.path());
    let (b, _, _) = scan(big.path());
    let strip = |v: &[String]| -> Vec<String> {
        v.iter()
            .filter(|f| {
                ["Entry", "HopA", "HopB", "Sink"]
                    .iter()
                    .any(|p| (0..10).any(|g| f.contains(&format!("/{p}{g}.java:"))))
            })
            .map(|f| f.rsplit('/').next().unwrap().to_string())
            .collect()
    };
    assert_eq!(strip(&a), strip(&b));
}

#[test]
#[ignore = "benchmark; run with `cargo test --release --test java_same_package_compose -- --ignored --nocapture`"]
fn bench_compose_vs_files_in_one_package() {
    for n in [200usize, 2000] {
        let tmp = generate(n);
        let (findings, compose, wall) = scan(tmp.path());
        eprintln!(
            "same_package_compose files={n} findings={} wall_s={wall:.2} [{}]",
            findings.len(),
            compose.trim()
        );
    }
}
