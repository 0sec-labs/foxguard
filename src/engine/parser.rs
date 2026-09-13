use crate::Language;
use std::path::Path;

/// Parse source code into a tree-sitter Tree for the given language.
pub fn parse_file(source: &str, language: Language) -> Option<tree_sitter::Tree> {
    parse_source_for_path(source, language, None)
}

/// Parse source code, selecting path-specific grammar variants where needed.
pub fn parse_path(source: &str, language: Language, path: &Path) -> Option<tree_sitter::Tree> {
    parse_source_for_path(source, language, Some(path))
}

fn parse_source_for_path(
    source: &str,
    language: Language,
    path: Option<&Path>,
) -> Option<tree_sitter::Tree> {
    let mut parser = tree_sitter::Parser::new();

    let ts_language = match language {
        Language::JavaScript => javascript_language_for_path(path),
        Language::Python => tree_sitter_python::LANGUAGE.into(),
        Language::Go => tree_sitter_go::LANGUAGE.into(),
        Language::Ruby => tree_sitter_ruby::LANGUAGE.into(),
        Language::Java => tree_sitter_java::LANGUAGE.into(),
        Language::Php => tree_sitter_php::LANGUAGE_PHP.into(),
        Language::Rust => tree_sitter_rust::LANGUAGE.into(),
        Language::CSharp => tree_sitter_c_sharp::LANGUAGE.into(),
        Language::Swift => tree_sitter_swift::LANGUAGE.into(),
        Language::Kotlin => tree_sitter_kotlin_sg::LANGUAGE.into(),
        Language::C => tree_sitter_c::LANGUAGE.into(),
        Language::Hcl => tree_sitter_hcl::LANGUAGE.into(),
        Language::Solidity => tree_sitter_solidity::LANGUAGE.into(),
        Language::Yaml => tree_sitter_yaml::LANGUAGE.into(),
        Language::Dockerfile => tree_sitter_containerfile::LANGUAGE.into(),
        Language::NginxConf | Language::ApacheConf | Language::HAProxyConf | Language::Manifest => {
            super::language::BASH_LANGUAGE.into()
        }
        Language::Bash => super::language::BASH_LANGUAGE.into(),
        Language::Ocaml => tree_sitter_ocaml::LANGUAGE_OCAML.into(),
        Language::Scala => tree_sitter_scala::LANGUAGE.into(),
        Language::Elixir => tree_sitter_elixir::LANGUAGE.into(),
        Language::Json => tree_sitter_json::LANGUAGE.into(),
        Language::Apex => tree_sitter_sfapex::apex::LANGUAGE.into(),
        Language::Clojure => tree_sitter_clojure_orchard::LANGUAGE.into(),
        Language::Html => tree_sitter_html::LANGUAGE.into(),
        Language::Xml => tree_sitter_xml::LANGUAGE_XML.into(),
        Language::Dart => tree_sitter_dart::LANGUAGE.into(),
        Language::Haskell => tree_sitter_haskell::LANGUAGE.into(),
        // Regex-mode rules never use a tree-sitter parser — they match raw text
        // only. Return `None` immediately so the scanner skips the tree build.
        Language::Regex => return None,
    };

    parser.set_language(&ts_language).ok()?;
    parser.parse(source, None)
}

fn javascript_language_for_path(path: Option<&Path>) -> tree_sitter::Language {
    match path
        .and_then(|path| path.extension())
        .and_then(|ext| ext.to_str())
    {
        Some("ts" | "mts" | "cts") => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        Some("tsx") => tree_sitter_typescript::LANGUAGE_TSX.into(),
        _ => tree_sitter_javascript::LANGUAGE.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_typescript_syntax_without_errors() {
        let source = "interface User { id: number }\nconst id = (user: User): number => user.id;\n";
        let tree = parse_path(source, Language::JavaScript, Path::new("src/user.ts"))
            .expect("TypeScript parser should produce a tree");

        assert!(!tree.root_node().has_error());
    }

    #[test]
    fn parses_tsx_syntax_without_errors() {
        let source = "type Props = { title: string };\nexport const Card = ({ title }: Props) => <h1>{title}</h1>;\n";
        let tree = parse_path(source, Language::JavaScript, Path::new("src/Card.tsx"))
            .expect("TSX parser should produce a tree");

        assert!(!tree.root_node().has_error());
    }

    #[test]
    fn parses_terraform_hcl_without_errors() {
        let source = "resource \"aws_s3_bucket\" \"b\" {\n  acl = \"public-read\"\n}\n";
        let tree = parse_path(source, Language::Hcl, Path::new("main.tf"))
            .expect("HCL parser should produce a tree");

        assert!(!tree.root_node().has_error());
        assert_eq!(tree.root_node().kind(), "config_file");
    }

    #[test]
    fn parses_solidity_contract_without_errors() {
        let source = r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Token {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function transfer(address to, uint256 amount) public {
        require(msg.sender == owner, "not owner");
        payable(to).transfer(amount);
    }
}
"#;
        let tree = parse_path(source, Language::Solidity, Path::new("Token.sol"))
            .expect("Solidity parser should produce a tree");

        assert!(!tree.root_node().has_error());
    }

    #[test]
    fn parses_yaml_without_errors() {
        let source = "key: value\nlist:\n  - item1\n  - item2\n";
        let tree = parse_path(source, Language::Yaml, Path::new("config.yaml"))
            .expect("YAML parser should produce a tree");

        assert!(!tree.root_node().has_error());
        assert_eq!(tree.root_node().kind(), "stream");
    }

    #[test]
    fn parses_dockerfile_without_errors() {
        let source = "FROM ubuntu:22.04\nRUN apt-get update && apt-get install -y curl\nCMD [\"/bin/bash\"]\n";
        let tree = parse_path(source, Language::Dockerfile, Path::new("Dockerfile"))
            .expect("Dockerfile parser should produce a tree");

        assert!(!tree.root_node().has_error());
        assert_eq!(tree.root_node().kind(), "source_file");
    }

    #[test]
    fn parses_bash_without_errors() {
        let source = "#!/bin/bash\necho \"Hello, world\"\nif [ -z \"$1\" ]; then\n  exit 1\nfi\n";
        let tree = parse_path(source, Language::Bash, Path::new("script.sh"))
            .expect("Bash parser should produce a tree");

        assert!(!tree.root_node().has_error());
    }

    #[test]
    fn parses_apex_without_errors() {
        let source =
            "public class Hello {\n  public void greet() {\n    String x = 'hi';\n  }\n}\n";
        let tree = parse_path(source, Language::Apex, Path::new("Hello.cls"))
            .expect("Apex parser should produce a tree");

        assert!(!tree.root_node().has_error());
    }

    #[test]
    fn parses_clojure_without_errors() {
        let source = "(defn greet [name]\n  (println \"hello\" name))\n";
        let tree = parse_path(source, Language::Clojure, Path::new("core.clj"))
            .expect("Clojure parser should produce a tree");

        assert!(!tree.root_node().has_error());
    }

    #[test]
    fn parses_html_without_errors() {
        let source = "<html>\n  <body>\n    <a href=\"/x\">link</a>\n  </body>\n</html>\n";
        let tree = parse_path(source, Language::Html, Path::new("index.html"))
            .expect("HTML parser should produce a tree");

        assert!(!tree.root_node().has_error());
    }

    #[test]
    fn parses_xml_without_errors() {
        let source = "<?xml version=\"1.0\"?>\n<root>\n  <child id=\"1\">text</child>\n</root>\n";
        let tree = parse_path(source, Language::Xml, Path::new("data.xml"))
            .expect("XML parser should produce a tree");

        assert!(!tree.root_node().has_error());
    }

    #[test]
    fn parses_dart_without_errors() {
        let source = "void main() {\n  print('hello');\n}\n";
        let tree = parse_path(source, Language::Dart, Path::new("main.dart"))
            .expect("Dart parser should produce a tree");

        assert!(!tree.root_node().has_error());
    }

    #[test]
    fn parses_haskell_without_errors() {
        let source = "module Main where\n\nmain :: IO ()\nmain = putStrLn \"hello\"\n";
        let tree = parse_path(source, Language::Haskell, Path::new("Main.hs"))
            .expect("Haskell parser should produce a tree");

        assert!(!tree.root_node().has_error());
    }

    #[test]
    fn parses_ocaml_without_errors() {
        let source = "let () = print_endline \"Hello, world\"\n";
        let tree = parse_path(source, Language::Ocaml, Path::new("main.ml"))
            .expect("OCaml parser should produce a tree");

        assert!(!tree.root_node().has_error());
    }

    #[test]
    fn parses_scala_without_errors() {
        let source = "object Hello {\n  def main(args: Array[String]): Unit = {\n    println(\"Hello, world\")\n  }\n}\n";
        let tree = parse_path(source, Language::Scala, Path::new("Hello.scala"))
            .expect("Scala parser should produce a tree");

        assert!(!tree.root_node().has_error());
    }

    #[test]
    fn parses_elixir_without_errors() {
        let source = "defmodule Hello do\n  def greet(name) do\n    IO.puts(\"Hello, #{name}\")\n  end\nend\n";
        let tree = parse_path(source, Language::Elixir, Path::new("hello.ex"))
            .expect("Elixir parser should produce a tree");

        assert!(!tree.root_node().has_error());
    }

    #[test]
    fn parses_json_without_errors() {
        let source = "{\"name\": \"foxguard\", \"version\": \"1.0.0\", \"active\": true}\n";
        let tree = parse_path(source, Language::Json, Path::new("config.json"))
            .expect("JSON parser should produce a tree");

        assert!(!tree.root_node().has_error());
    }

    #[test]
    fn parses_bash_read_write_redirect() {
        // regression: tree-sitter-bash 0.23.3 lacked '<>' (LT_GT) token in
        // file_redirect — valid bash read-write redirect produced ERROR nodes.
        let source = "exec 7<> \"$binding_fifo\"\n";
        let tree = parse_path(source, Language::Bash, Path::new("test.sh"))
            .expect("Bash parser should produce a tree");

        assert!(!tree.root_node().has_error());
    }

    #[test]
    fn rejects_malformed_bash() {
        // Genuinely invalid bash must still produce parse errors.
        let source = "if [[ -f /tmp/x ]\n"; // missing closing ']]'
        let tree = parse_path(source, Language::Bash, Path::new("test.sh"))
            .expect("Bash parser should produce a tree");

        assert!(tree.root_node().has_error());
    }
}
