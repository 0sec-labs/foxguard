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
        Language::NginxConf
        | Language::ApacheConf
        | Language::HAProxyConf
        | Language::Dockerfile
        | Language::Manifest => tree_sitter_bash::LANGUAGE.into(),
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
}
