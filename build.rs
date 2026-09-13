// tree-sitter-bash v0.23.3 (MIT), https://github.com/tree-sitter/tree-sitter-bash.
// Local grammar change: file_redirect accepts the POSIX '<>' operator, also
// absent from upstream v0.25.1. Generated with tree-sitter CLI 0.23.2, ABI 14.
// Keep this bundled so published crates use the same parser as source builds.
fn main() {
    let src_dir = std::path::Path::new("vendor/tree-sitter-bash/src");

    let mut c_config = cc::Build::new();
    c_config
        .std("c11")
        .include(src_dir)
        .include(src_dir.join("tree_sitter"))
        .flag_if_supported("-Wno-unused-value");

    // Namespace the entry point and external scanner so downstream users can
    // also link upstream tree-sitter-bash without selecting the wrong grammar.
    c_config.define("tree_sitter_bash", Some("foxguard_tree_sitter_bash"));
    c_config.define(
        "tree_sitter_bash_external_scanner_create",
        Some("foxguard_tree_sitter_bash_external_scanner_create"),
    );
    c_config.define(
        "tree_sitter_bash_external_scanner_destroy",
        Some("foxguard_tree_sitter_bash_external_scanner_destroy"),
    );
    c_config.define(
        "tree_sitter_bash_external_scanner_scan",
        Some("foxguard_tree_sitter_bash_external_scanner_scan"),
    );
    c_config.define(
        "tree_sitter_bash_external_scanner_serialize",
        Some("foxguard_tree_sitter_bash_external_scanner_serialize"),
    );
    c_config.define(
        "tree_sitter_bash_external_scanner_deserialize",
        Some("foxguard_tree_sitter_bash_external_scanner_deserialize"),
    );

    c_config.flag_if_supported("-utf-8");

    c_config
        .file(src_dir.join("parser.c"))
        .file(src_dir.join("scanner.c"))
        .compile("foxguard-grammar-bash");
    println!("cargo:rerun-if-changed=vendor/tree-sitter-bash/src");
}
