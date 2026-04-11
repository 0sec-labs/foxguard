//! Parity test: the committed `www/src/data/rules.ts` must be byte-identical
//! to the output of `cargo run --bin gen_rules_ts`.
//!
//! The generator is the source of truth — edit Rust rules, then regenerate.
//! This test (and the matching `rule-inventory-check` CI job) guards against
//! drift between the Rust rule registry and the website rule inventory.

use std::path::Path;
use std::process::Command;

#[test]
fn website_rule_inventory_matches_generator_output() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let inventory_path = Path::new(manifest_dir)
        .join("www")
        .join("src")
        .join("data")
        .join("rules.ts");

    let committed =
        std::fs::read_to_string(&inventory_path).expect("failed to read www/src/data/rules.ts");

    let output = Command::new(env!("CARGO"))
        .args(["run", "--quiet", "--bin", "gen_rules_ts"])
        .current_dir(manifest_dir)
        .output()
        .expect("failed to run gen_rules_ts");

    assert!(
        output.status.success(),
        "gen_rules_ts failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let generated = String::from_utf8(output.stdout).expect("gen_rules_ts output not UTF-8");

    if committed != generated {
        panic!(
            "www/src/data/rules.ts is out of sync with the Rust rule registry.\n\
             Regenerate with:\n\
             \n\
             \tcargo run --bin gen_rules_ts > www/src/data/rules.ts\n"
        );
    }
}
