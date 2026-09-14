// Keep grammar sources bundled so published crates and local builds use the
// same parsers. Each vendor directory retains its upstream license and grammar.
fn main() {
    for (grammar, directory) in [
        ("bash", "vendor/tree-sitter-bash/src"),
        ("c", "vendor/tree-sitter-c/src"),
        ("javascript", "vendor/tree-sitter-javascript/src"),
        ("typescript", "vendor/tree-sitter-typescript/typescript/src"),
        ("tsx", "vendor/tree-sitter-typescript/tsx/src"),
    ] {
        let source = std::path::Path::new(directory);
        let upstream = format!("tree_sitter_{grammar}");
        let namespaced = format!("foxguard_{upstream}");
        let mut compiler = cc::Build::new();
        compiler
            .std("c11")
            .include(source)
            .include(source.join("tree_sitter"))
            .flag_if_supported("-Wno-unused-value")
            .flag_if_supported("-utf-8")
            .define(upstream.as_str(), Some(namespaced.as_str()))
            .file(source.join("parser.c"));

        let scanner = source.join("scanner.c");
        if scanner.exists() {
            for hook in ["create", "destroy", "scan", "serialize", "deserialize"] {
                compiler.define(
                    format!("{upstream}_external_scanner_{hook}").as_str(),
                    Some(format!("{namespaced}_external_scanner_{hook}").as_str()),
                );
            }
            compiler.file(scanner);
        }
        compiler.compile(format!("foxguard-grammar-{grammar}").as_str());
    }
    // TypeScript's external scanners include headers outside their src dirs.
    println!("cargo:rerun-if-changed=vendor");
}
