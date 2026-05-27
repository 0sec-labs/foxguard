//! Intraprocedural, flow-insensitive taint analysis for Java.
//!
//! Java is the next enterprise-heavy language after the existing
//! Python, JavaScript/TypeScript, Go, Kotlin, and C engines. This engine
//! intentionally mirrors the Kotlin implementation shape: grammar-specific
//! source/sink matching stays local, while the public surface reuses the
//! shared `TaintSpec`, `NodeMatcher`, and `TaintFinding` types.
//!
//! Scope:
//! - Per method / constructor / lambda body. Nested lambdas are analyzed
//!   independently and skipped by their parent scope.
//! - Per file. No Java cross-file or type-resolution pass yet.
//! - Flow-insensitive within source order. Clean reassignment clears a name.
//! - String concatenation, method calls on tainted receivers, constructor
//!   wrappers, and direct nested source calls propagate taint.
//! - Sanitizer calls listed on the `TaintSpec` produce clean values.

use crate::rules::common::{walk_tree, AliasTable};
pub use crate::rules::taint_engine::{NodeMatcher, TaintFinding, TaintSpec};
use std::collections::HashMap;
use tree_sitter::Node;

#[derive(Clone, Debug)]
struct TaintInfo {
    description: String,
    line: usize,
    hops: u8,
}

#[derive(Default)]
struct TaintState {
    tainted: HashMap<String, TaintInfo>,
}

impl TaintState {
    fn taint(&mut self, name: String, info: TaintInfo) {
        self.tainted.insert(name, info);
    }

    fn clear(&mut self, name: &str) {
        self.tainted.remove(name);
    }

    fn info(&self, name: &str) -> Option<&TaintInfo> {
        self.tainted.get(name)
    }
}

/// Run the Java taint engine over every method, constructor, and lambda
/// inside `root`.
///
/// The alias table parameter is reserved for future import-aware Java
/// matching. Java source/sink specs today match simple receiver and type
/// names because the built-in rules target common servlet and Spring shapes.
pub fn analyze_tree(
    root: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    _aliases: Option<&AliasTable>,
) -> Vec<TaintFinding> {
    let mut findings = Vec::new();
    walk_tree(root, source, &mut |node, src| {
        if is_scope_node(node.kind()) {
            analyze_scope(node, src, spec, &mut findings);
        }
    });
    findings
}

/// All Java taint rule IDs paired with their specs.
pub fn java_taint_rule_specs() -> Vec<(&'static str, TaintSpec)> {
    vec![
        ("java/taint-sql-injection", sql_injection_spec()),
        ("java/taint-command-injection", command_injection_spec()),
        ("java/taint-ssrf", ssrf_spec()),
        (
            "java/taint-unsafe-deserialization",
            unsafe_deserialization_spec(),
        ),
    ]
}

/// Shared sources for Java taint rules.
///
/// Covers servlet request reads, Spring MVC annotated handler parameters,
/// and environment variables for CLI/service entry points.
pub fn java_taint_sources() -> Vec<NodeMatcher> {
    let mut sources = Vec::new();
    for receiver in ["request", "req"] {
        for method in [
            "getParameter",
            "getParameterMap",
            "getParameterValues",
            "getHeader",
            "getHeaders",
            "getQueryString",
            "getInputStream",
            "getReader",
            "getCookies",
        ] {
            sources.push(NodeMatcher::Call {
                canonical: format!("{receiver}.{method}"),
                description: format!("HttpServletRequest.{method}()"),
            });
        }
    }
    sources.push(NodeMatcher::Call {
        canonical: "System.getenv".into(),
        description: "System.getenv()".into(),
    });
    sources.push(NodeMatcher::ParamName {
        names: vec![
            "@RequestParam".into(),
            "@RequestBody".into(),
            "@PathVariable".into(),
            "@RequestHeader".into(),
            "@CookieValue".into(),
            "@ModelAttribute".into(),
        ],
        description: "Spring MVC annotated parameter".into(),
    });
    sources
}

fn sql_injection_spec() -> TaintSpec {
    TaintSpec {
        sources: java_taint_sources(),
        sinks: vec![
            NodeMatcher::MethodName {
                method: "executeQuery".into(),
                description: "executeQuery() with tainted query".into(),
            },
            NodeMatcher::MethodName {
                method: "execute".into(),
                description: "execute() with tainted query".into(),
            },
            NodeMatcher::MethodName {
                method: "createQuery".into(),
                description: "createQuery() with tainted query".into(),
            },
            NodeMatcher::MethodName {
                method: "createNativeQuery".into(),
                description: "createNativeQuery() with tainted query".into(),
            },
            NodeMatcher::MethodName {
                method: "prepareStatement".into(),
                description: "prepareStatement() with tainted query".into(),
            },
        ],
        sanitizers: vec![],
    }
}

fn command_injection_spec() -> TaintSpec {
    TaintSpec {
        sources: java_taint_sources(),
        sinks: vec![
            NodeMatcher::Call {
                canonical: "Runtime.exec".into(),
                description: "Runtime.exec() with tainted argument".into(),
            },
            NodeMatcher::Call {
                canonical: "ProcessBuilder".into(),
                description: "ProcessBuilder() with tainted argument".into(),
            },
        ],
        sanitizers: vec![],
    }
}

fn ssrf_spec() -> TaintSpec {
    TaintSpec {
        sources: java_taint_sources(),
        sinks: vec![
            NodeMatcher::Call {
                canonical: "URL".into(),
                description: "URL() with tainted target".into(),
            },
            NodeMatcher::Call {
                canonical: "URI".into(),
                description: "URI() with tainted target".into(),
            },
            NodeMatcher::MethodName {
                method: "getForObject".into(),
                description: "RestTemplate.getForObject() with tainted URL".into(),
            },
            NodeMatcher::MethodName {
                method: "getForEntity".into(),
                description: "RestTemplate.getForEntity() with tainted URL".into(),
            },
            NodeMatcher::MethodName {
                method: "postForObject".into(),
                description: "RestTemplate.postForObject() with tainted URL".into(),
            },
            NodeMatcher::MethodName {
                method: "postForEntity".into(),
                description: "RestTemplate.postForEntity() with tainted URL".into(),
            },
            NodeMatcher::MethodName {
                method: "exchange".into(),
                description: "RestTemplate.exchange() with tainted URL".into(),
            },
        ],
        sanitizers: vec![],
    }
}

fn unsafe_deserialization_spec() -> TaintSpec {
    TaintSpec {
        sources: java_taint_sources(),
        sinks: vec![
            NodeMatcher::Call {
                canonical: "ObjectInputStream".into(),
                description: "ObjectInputStream() with tainted stream".into(),
            },
            NodeMatcher::Call {
                canonical: "XMLDecoder".into(),
                description: "XMLDecoder() with tainted stream".into(),
            },
            NodeMatcher::MethodName {
                method: "load".into(),
                description: "Yaml.load() with tainted data".into(),
            },
        ],
        sanitizers: vec![],
    }
}

fn analyze_scope(
    scope_node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    out: &mut Vec<TaintFinding>,
) {
    let body = find_scope_body(scope_node).unwrap_or(scope_node);
    let mut state = TaintState::default();
    collect_param_sources(scope_node, source, spec, &mut state);

    // Three passes cover the common `source -> local -> derived -> sink`
    // chain without adding a fixed-point loop to this deliberately small
    // intraprocedural engine.
    for _ in 0..3 {
        propagate_assignments(body, source, spec, &mut state);
    }
    find_sinks(body, source, spec, &state, out);
}

fn collect_param_sources(
    scope_node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    state: &mut TaintState,
) {
    let mut annotation_names: Vec<&str> = Vec::new();
    let mut bare_names: Vec<&str> = Vec::new();
    for matcher in &spec.sources {
        if let NodeMatcher::ParamName { names, .. } = matcher {
            for name in names {
                if let Some(rest) = name.strip_prefix('@') {
                    annotation_names.push(rest);
                } else {
                    bare_names.push(name.as_str());
                }
            }
        }
    }

    for node in scope_parameter_nodes(scope_node) {
        let Some(name) = formal_parameter_name(node, source) else {
            continue;
        };
        let text = node_text(node, source);
        let matched_annotation = annotation_names
            .iter()
            .find(|annotation| text.contains(&format!("@{annotation}")));

        if let Some(annotation) = matched_annotation {
            state.taint(
                name.to_string(),
                TaintInfo {
                    description: format!("@{annotation} parameter '{name}'"),
                    line: node.start_position().row + 1,
                    hops: 0,
                },
            );
        } else if bare_names.contains(&name) {
            state.taint(
                name.to_string(),
                TaintInfo {
                    description: format!("parameter '{name}'"),
                    line: node.start_position().row + 1,
                    hops: 0,
                },
            );
        }
    }
}

fn propagate_assignments(scope: Node<'_>, source: &str, spec: &TaintSpec, state: &mut TaintState) {
    walk_scope_nodes(scope, source, &mut |node, src| {
        if node.kind() == "variable_declarator" {
            let Some(name_node) = node.child_by_field_name("name") else {
                return;
            };
            let name = node_text(name_node, src).to_string();
            let Some(value) = node.child_by_field_name("value") else {
                return;
            };
            match expression_taint(value, src, spec, state) {
                Some(info) => state.taint(name, bump_hops(info)),
                None => state.clear(&name),
            }
        }

        if node.kind() == "assignment_expression" {
            let Some(left) = node.child_by_field_name("left") else {
                return;
            };
            let Some(name) = assignment_target_name(left, src) else {
                return;
            };
            let Some(right) = node.child_by_field_name("right") else {
                return;
            };
            match expression_taint(right, src, spec, state) {
                Some(info) => state.taint(name.to_string(), bump_hops(info)),
                None => state.clear(name),
            }
        }
    });
}

fn find_sinks(
    scope: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    state: &TaintState,
    out: &mut Vec<TaintFinding>,
) {
    walk_scope_nodes(scope, source, &mut |node, src| {
        if node.kind() != "method_invocation" && node.kind() != "object_creation_expression" {
            return;
        }
        let Some(sink_description) = match_sink(node, src, spec) else {
            return;
        };
        let taint = sink_argument_taint(node, src, spec, state)
            .or_else(|| read_object_receiver_taint(node, src, state));
        if let Some(info) = taint {
            out.push(taint_finding_for_node(node, info, sink_description));
        }
    });
}

fn expression_taint(
    node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    state: &TaintState,
) -> Option<TaintInfo> {
    let text = node_text(node, source);
    if let Some(info) = state.info(text) {
        return Some(info.clone());
    }

    if node.kind() == "identifier" {
        return state.info(text).cloned();
    }

    if is_sanitizer_call(node, source, spec) {
        return None;
    }

    if let Some(description) = classify_source_expr(node, source, spec) {
        return Some(TaintInfo {
            description,
            line: node.start_position().row + 1,
            hops: 0,
        });
    }

    if node.kind() == "method_invocation" {
        if let Some(receiver) = node.child_by_field_name("object") {
            if let Some(info) = expression_taint(receiver, source, spec, state) {
                return Some(bump_hops(info));
            }
        }
    }

    if let Some(args) = call_arguments(node) {
        if let Some(info) = expression_taint(args, source, spec, state) {
            return Some(bump_hops(info));
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(info) = expression_taint(child, source, spec, state) {
            return Some(info);
        }
    }
    None
}

fn classify_source_expr(node: Node<'_>, source: &str, spec: &TaintSpec) -> Option<String> {
    if node.kind() != "method_invocation" {
        return None;
    }
    let method = call_method_name(node, source)?;
    let receiver = call_receiver_text(node, source)?;
    spec.sources.iter().find_map(|matcher| {
        if let NodeMatcher::Call {
            canonical,
            description,
        } = matcher
        {
            if match_java_method_canonical(canonical, receiver, method) {
                return Some(description.clone());
            }
        }
        None
    })
}

fn is_sanitizer_call(node: Node<'_>, source: &str, spec: &TaintSpec) -> bool {
    spec.sanitizers
        .iter()
        .any(|matcher| matcher_matches_call(matcher, node, source))
}

fn match_sink(node: Node<'_>, source: &str, spec: &TaintSpec) -> Option<String> {
    spec.sinks.iter().find_map(|matcher| {
        if matcher_matches_call(matcher, node, source) {
            Some(matcher.description().to_string())
        } else {
            None
        }
    })
}

fn matcher_matches_call(matcher: &NodeMatcher, node: Node<'_>, source: &str) -> bool {
    match matcher {
        NodeMatcher::MethodName { method, .. } => {
            node.kind() == "method_invocation"
                && call_method_name(node, source).is_some_and(|actual| actual == method)
        }
        NodeMatcher::Call { canonical, .. } if node.kind() == "method_invocation" => {
            let Some(method) = call_method_name(node, source) else {
                return false;
            };
            let Some(receiver) = call_receiver_text(node, source) else {
                return false;
            };
            match_java_method_canonical(canonical, receiver, method)
        }
        NodeMatcher::Call { canonical, .. } if node.kind() == "object_creation_expression" => {
            object_creation_type(node, source).is_some_and(|actual| actual == canonical)
        }
        _ => false,
    }
}

fn match_java_method_canonical(canonical: &str, receiver: &str, method: &str) -> bool {
    let Some((expected_receiver, expected_method)) = canonical.rsplit_once('.') else {
        return false;
    };
    if method != expected_method {
        return false;
    }
    let receiver_lower = receiver.to_ascii_lowercase();
    let expected_lower = expected_receiver.to_ascii_lowercase();
    receiver_lower.contains(&expected_lower)
        || (expected_lower == "request" && receiver_lower.contains("request"))
        || (expected_lower == "runtime" && receiver_lower.contains("runtime"))
}

fn sink_argument_taint(
    node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    state: &TaintState,
) -> Option<TaintInfo> {
    call_arguments(node).and_then(|args| expression_taint(args, source, spec, state))
}

fn read_object_receiver_taint(
    node: Node<'_>,
    source: &str,
    state: &TaintState,
) -> Option<TaintInfo> {
    if node.kind() != "method_invocation" {
        return None;
    }
    if call_method_name(node, source) != Some("readObject") {
        return None;
    }
    let receiver = node.child_by_field_name("object")?;
    expression_taint_without_sources(receiver, source, state)
}

fn expression_taint_without_sources(
    node: Node<'_>,
    source: &str,
    state: &TaintState,
) -> Option<TaintInfo> {
    let text = node_text(node, source);
    if let Some(info) = state.info(text) {
        return Some(info.clone());
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(info) = expression_taint_without_sources(child, source, state) {
            return Some(info);
        }
    }
    None
}

fn bump_hops(mut info: TaintInfo) -> TaintInfo {
    info.hops = info.hops.saturating_add(1);
    info
}

fn taint_finding_for_node(
    node: Node<'_>,
    source_info: TaintInfo,
    sink_description: String,
) -> TaintFinding {
    let start = node.start_position();
    let end = node.end_position();
    TaintFinding {
        sink_start_byte: node.start_byte(),
        sink_end_byte: node.end_byte(),
        sink_line: start.row + 1,
        sink_column: start.column + 1,
        sink_end_line: end.row + 1,
        sink_end_column: end.column + 1,
        source_description: source_info.description,
        sink_description,
        source_line: source_info.line,
        rule_id_hint: None,
        hops: source_info.hops.max(1),
    }
}

fn walk_scope_nodes(scope: Node<'_>, source: &str, visitor: &mut impl FnMut(Node<'_>, &str)) {
    let mut cursor = scope.walk();
    for child in scope.children(&mut cursor) {
        walk_scope_node(child, source, visitor);
    }
}

fn walk_scope_node(node: Node<'_>, source: &str, visitor: &mut impl FnMut(Node<'_>, &str)) {
    if is_scope_node(node.kind()) {
        return;
    }
    visitor(node, source);
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_scope_node(child, source, visitor);
    }
}

fn is_scope_node(kind: &str) -> bool {
    matches!(
        kind,
        "method_declaration" | "constructor_declaration" | "lambda_expression"
    )
}

fn scope_parameter_nodes<'a>(scope_node: Node<'a>) -> Vec<Node<'a>> {
    if let Some(parameters) = scope_node.child_by_field_name("parameters") {
        return direct_formal_parameters(parameters);
    }

    let mut params = Vec::new();
    let mut cursor = scope_node.walk();
    for child in scope_node.children(&mut cursor) {
        match child.kind() {
            "formal_parameter" | "spread_parameter" => params.push(child),
            "formal_parameters" | "inferred_parameters" => {
                params.extend(direct_formal_parameters(child));
            }
            _ => {}
        }
    }
    params
}

fn direct_formal_parameters<'a>(parameters: Node<'a>) -> Vec<Node<'a>> {
    let mut params = Vec::new();
    let mut cursor = parameters.walk();
    for child in parameters.children(&mut cursor) {
        match child.kind() {
            "formal_parameter" | "spread_parameter" => params.push(child),
            "formal_parameters" | "inferred_parameters" => {
                params.extend(direct_formal_parameters(child));
            }
            _ => {}
        }
    }
    params
}

fn find_scope_body(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("body").or_else(|| {
        let mut cursor = node.walk();
        let body = node
            .children(&mut cursor)
            .find(|child| child.kind() == "block");
        body
    })
}

fn call_method_name<'a>(node: Node<'a>, source: &'a str) -> Option<&'a str> {
    if node.kind() != "method_invocation" {
        return None;
    }
    node.child_by_field_name("name")
        .map(|name| node_text(name, source))
}

fn call_receiver_text<'a>(node: Node<'a>, source: &'a str) -> Option<&'a str> {
    if node.kind() != "method_invocation" {
        return None;
    }
    node.child_by_field_name("object")
        .map(|object| node_text(object, source))
}

fn object_creation_type<'a>(node: Node<'a>, source: &'a str) -> Option<&'a str> {
    if node.kind() != "object_creation_expression" {
        return None;
    }
    node.child_by_field_name("type")
        .map(|ty| node_text(ty, source))
}

fn call_arguments(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() != "method_invocation" && node.kind() != "object_creation_expression" {
        return None;
    }
    node.child_by_field_name("arguments")
}

fn assignment_target_name<'a>(node: Node<'a>, source: &'a str) -> Option<&'a str> {
    match node.kind() {
        "identifier" | "field_access" => Some(node_text(node, source)),
        _ => None,
    }
}

fn formal_parameter_name<'a>(node: Node<'a>, source: &'a str) -> Option<&'a str> {
    if let Some(name) = node.child_by_field_name("name") {
        return Some(node_text(name, source));
    }
    let mut last_identifier = None;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "identifier" {
            last_identifier = Some(node_text(child, source));
        }
    }
    last_identifier
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    &source[node.byte_range()]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::parser::parse_file;
    use crate::Language;

    fn analyze(src: &str, spec: &TaintSpec) -> Vec<TaintFinding> {
        let Some(tree) = parse_file(src, Language::Java) else {
            panic!("Java fixture should parse");
        };
        analyze_tree(tree.root_node(), src, spec, None)
    }

    #[test]
    fn sql_injection_via_spring_request_param() {
        let src = r#"
class Controller {
    void find(@RequestParam String name, Statement stmt) throws Exception {
        String query = "SELECT * FROM users WHERE name = '" + name + "'";
        stmt.executeQuery(query);
    }
}
"#;
        let findings = analyze(src, &sql_injection_spec());
        assert!(
            !findings.is_empty(),
            "should detect Spring param into SQL: {findings:?}"
        );
    }

    #[test]
    fn command_injection_via_servlet_request() {
        let src = r#"
class Controller {
    void run(HttpServletRequest request) throws Exception {
        String cmd = request.getParameter("cmd");
        Runtime.getRuntime().exec(cmd);
    }
}
"#;
        let findings = analyze(src, &command_injection_spec());
        assert!(
            !findings.is_empty(),
            "should detect servlet request into Runtime.exec: {findings:?}"
        );
    }

    #[test]
    fn ssrf_transitive_flow() {
        let src = r#"
class Controller {
    void fetch(HttpServletRequest req) throws Exception {
        String raw = req.getParameter("url");
        String target = "https://internal/" + raw;
        new URL(target);
    }
}
"#;
        let findings = analyze(src, &ssrf_spec());
        assert!(
            !findings.is_empty(),
            "should detect transitive servlet SSRF: {findings:?}"
        );
    }

    #[test]
    fn unsafe_deserialization_constructor_sink() {
        let src = r#"
class Controller {
    void load(HttpServletRequest request) throws Exception {
        InputStream input = request.getInputStream();
        ObjectInputStream ois = new ObjectInputStream(input);
        ois.readObject();
    }
}
"#;
        let findings = analyze(src, &unsafe_deserialization_spec());
        assert!(
            findings
                .iter()
                .any(|finding| finding.sink_description.contains("ObjectInputStream")),
            "should detect tainted ObjectInputStream constructor: {findings:?}"
        );
    }

    #[test]
    fn clean_literal_no_command_finding() {
        let src = r#"
class Controller {
    void run(HttpServletRequest request) throws Exception {
        String cmd = request.getParameter("cmd");
        Runtime.getRuntime().exec("id");
    }
}
"#;
        let findings = analyze(src, &command_injection_spec());
        assert!(
            findings.is_empty(),
            "literal command should not trigger taint: {findings:?}"
        );
    }

    #[test]
    fn nested_lambda_parameter_does_not_taint_parent_scope() {
        let src = r#"
class Controller {
    private String name = "https://example.com";

    void fetch() throws Exception {
        Function<String, String> normalize = (@RequestParam String name) -> name.trim();
        new URL(name);
    }
}
"#;
        let findings = analyze(src, &ssrf_spec());
        assert!(
            findings.is_empty(),
            "nested lambda parameter should not taint parent scope: {findings:?}"
        );
    }
}
