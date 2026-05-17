use crate::Language;

/// Parse source code into a tree-sitter Tree for the given language.
pub fn parse_file(source: &str, language: Language) -> Option<tree_sitter::Tree> {
    let mut parser = tree_sitter::Parser::new();

    let ts_language = match language {
        Language::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        Language::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        Language::Tsx => tree_sitter_typescript::LANGUAGE_TSX.into(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_typescript_without_javascript_recovery_errors() {
        let source = r#"
type RequestLike = { body: { name: string } };

export function render(request: RequestLike): string {
    return request.body.name;
}
"#;
        let tree = parse_file(source, Language::TypeScript).expect("failed to parse TypeScript");
        assert!(!tree.root_node().has_error());
    }

    #[test]
    fn parses_tsx_without_javascript_recovery_errors() {
        let source = r#"
type Props = { title: string };

export function Card({ title }: Props) {
    return <section data-kind="card">{title}</section>;
}
"#;
        let tree = parse_file(source, Language::Tsx).expect("failed to parse TSX");
        assert!(!tree.root_node().has_error());
    }
}
