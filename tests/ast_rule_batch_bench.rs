use foxguard::engine::parser::parse_file;
use foxguard::rules::semgrep_compat::parse_semgrep_file;
use foxguard::Language;
use std::io::Write;
use std::time::Instant;
use tempfile::NamedTempFile;

#[test]
#[ignore = "benchmark harness; run with `cargo test --test ast_rule_batch_bench -- --ignored --nocapture`"]
fn bench_ast_rule_count_scaling() {
    let mut source = String::new();
    for idx in 0..1_000 {
        source.push_str(&format!("value_{idx} = safe_call({idx})\n"));
    }
    source.push_str("result = eval(user_input)\n");
    let tree = parse_file(&source, Language::Python).expect("parse fixture");

    for rule_count in [1usize, 25, 100, 250] {
        let mut rules_yaml = String::from("rules:\n");
        for idx in 0..rule_count {
            rules_yaml.push_str(&format!(
                "  - id: eval-{idx}\n    pattern: eval(...)\n    message: Avoid eval\n    severity: WARNING\n    languages: [python]\n"
            ));
        }

        let mut rules_file = NamedTempFile::new().expect("temp rules file");
        rules_file
            .write_all(rules_yaml.as_bytes())
            .expect("write rules");
        let rules = parse_semgrep_file(rules_file.path()).expect("parse rules");

        let started = Instant::now();
        let findings: usize = rules
            .iter()
            .map(|rule| rule.check(&source, &tree).len())
            .sum();
        let elapsed = started.elapsed();

        eprintln!(
            "ast_rule_count_scaling rules={} findings={} scan_ms={}",
            rules.len(),
            findings,
            elapsed.as_millis()
        );
        assert_eq!(findings, rule_count);
    }
}
