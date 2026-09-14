use foxguard::engine::{detect_language, parse_path};
use std::{fs, path::Path, process::Command};

const CASES: &[(&str, &str, &str, &str)] = &[
    (
        "literals.js",
        concat!(
            "const a = 'a\0b'; const b = \"c\0d\";\n",
            "const template = `a\0${input}b`;\n",
            "const pattern = /[\0-\u{1f}]/; const plain = /x\0y/;\n",
            "const before = 'offset\0check'; eval(input);\n",
        ),
        "js/no-eval",
        "eval(",
    ),
    (
        "imports.ts",
        concat!(
            "interface Context { entries?: import('fs').Dirent[] }\n",
            "let entries: import('fs').Dirent[];\n",
            "const module = await load<typeof import('fs')>();\n",
            "const before = 'offset\0check'; eval(input);\n",
        ),
        "js/no-eval",
        "eval(",
    ),
    (
        "view.tsx",
        concat!(
            "const view = <div title=\"a\0b\" />;\n",
            "const module = load<typeof import('fs')>();\n",
            "const before = /[\0-\u{1f}]/; eval(input);\n",
        ),
        "js/no-eval",
        "eval(",
    ),
    (
        "linkage.h",
        concat!(
            "#ifndef API_H\n#define API_H\n#include <string.h>\n",
            "#ifdef __cplusplus\nextern \"C\" {\n#endif\n",
            "void api(void);\n",
            "#ifdef __cplusplus\n}\n#endif\n#endif\n",
            "int main(int argc, char **argv) {\n",
            "  char buffer[8];\n  strcpy(buffer, argv[1]);\n  return 0;\n}\n",
        ),
        "c/taint-buffer-overflow",
        "strcpy(",
    ),
    (
        "register.c",
        concat!(
            "#include <string.h>\nint main(int argc, char **argv) {\n",
            "  register long result asm(\"rax\") = argc;\n",
            "  char buffer[8];\n  strcpy(buffer, argv[1]);\n  return result;\n}\n",
        ),
        "c/taint-buffer-overflow",
        "strcpy(",
    ),
    (
        "defaults.sh",
        concat!(
            ": \"${URL:=https://example.com/text?tag=report&x=123}\"\n",
            "eval \"$1\"\n",
        ),
        "bash/taint-command-injection",
        "eval ",
    ),
];

#[test]
fn valid_syntax_retains_findings_at_original_source_positions() {
    let directory = tempfile::tempdir().unwrap();
    for &(name, source, _, _) in CASES {
        fs::write(directory.path().join(name), source).unwrap();
    }
    let output = Command::new(env!("CARGO_BIN_EXE_foxguard"))
        .args(["--config", "/dev/null"])
        .arg(directory.path())
        .args(["--format", "json"])
        .output()
        .expect("run scanner");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&output.stderr)));
    assert_eq!(report["target"]["files_scanned"], CASES.len());
    let findings = report["findings"].as_array().unwrap();
    for &(name, source, rule, sink) in CASES {
        let offset = source.rfind(sink).unwrap();
        let prefix = &source[..offset];
        let line = prefix.bytes().filter(|&byte| byte == b'\n').count() + 1;
        let column = prefix.rsplit('\n').next().unwrap().len() + 1;
        assert!(
            findings.iter().any(|finding| {
                Path::new(finding["file"].as_str().unwrap())
                    .file_name()
                    .unwrap()
                    == name
                    && finding["rule_id"] == rule
                    && finding["line"] == line
                    && finding["column"] == column
            }),
            "missing {rule} at {name}:{line}:{column}; findings={findings:?}"
        );
    }
}

#[test]
fn malformed_source_is_not_accepted_as_recovery() {
    for (name, source) in [
        ("outside.js", "const x = 1;\0eval(input);"),
        ("string.js", "const x = \"a\0"),
        ("template.ts", "const x = `a\0"),
        ("regex.tsx", "const x = /[\0/;"),
        ("import.ts", "let x: import(\"broken).Type[];"),
        ("brace.c", "}"),
        ("body.c", "void f(void) { } }"),
        ("guard.h", "#ifdef __cplusplus\n}\n#endif\n"),
        (
            "linkage.h",
            "#ifdef __cplusplus\nextern \"C\" {\n#endif\nvoid f(void);\n}",
        ),
        ("register.c", "register long x asm(\"rax\") = ;"),
        ("default.sh", ": \"${URL:=https://example.com/?a=b&c=d"),
    ] {
        let path = Path::new(name);
        let tree = parse_path(source, detect_language(path).unwrap(), path).unwrap();
        assert!(
            tree.root_node().has_error(),
            "accepted malformed {name}: {source:?}"
        );
    }
}
