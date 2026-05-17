use foxguard::engine::parser::parse_file;
use foxguard::rules::semgrep_compat::parse_semgrep_file;
use foxguard::Language;
use std::io::Write;
use std::time::Instant;
use tempfile::NamedTempFile;

#[test]
#[ignore = "benchmark harness; run with `cargo test --test semgrep_compat_bench -- --ignored --nocapture`"]
fn bench_semgrep_ast_rule_pack() {
    let mut rules_yaml = String::from("rules:\n");
    for idx in 0..150 {
        rules_yaml.push_str(&format!(
            "  - id: eval-{idx}\n    pattern: eval(...)\n    message: Avoid eval\n    severity: WARNING\n    languages: [python]\n"
        ));
    }

    let mut rules_file = NamedTempFile::new().expect("temp rules file");
    rules_file
        .write_all(rules_yaml.as_bytes())
        .expect("write rules");

    let mut source = String::new();
    for idx in 0..1_000 {
        source.push_str(&format!("value_{idx} = safe_call({idx})\n"));
    }
    source.push_str("result = eval(user_input)\n");

    let load_start = Instant::now();
    let rules = parse_semgrep_file(rules_file.path()).expect("parse rules");
    let load_elapsed = load_start.elapsed();
    let tree = parse_file(&source, Language::Python).expect("parse fixture");

    let scan_start = Instant::now();
    let findings: usize = rules
        .iter()
        .map(|rule| rule.check(&source, &tree).len())
        .sum();
    let scan_elapsed = scan_start.elapsed();

    eprintln!(
        "semgrep_ast_rule_pack rules={} findings={} load_ms={} scan_ms={}",
        rules.len(),
        findings,
        load_elapsed.as_millis(),
        scan_elapsed.as_millis()
    );
    assert_eq!(findings, rules.len());
}
