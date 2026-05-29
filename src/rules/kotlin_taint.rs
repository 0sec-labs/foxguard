//! Intraprocedural, flow-insensitive taint analysis for Kotlin.
//!
//! This is the fourth sibling to `python_taint`, `javascript_taint`,
//! and `go_taint`. It exposes the same public surface — `TaintSpec`,
//! `NodeMatcher`, `TaintFinding`, `analyze_tree` — so callers can write
//! declarative `(sources, sinks, sanitizers)` specs the same way they
//! do for the other languages.
//!
//! The internals are Kotlin-grammar-aware (`call_expression`,
//! `navigation_expression`, `property_declaration`, `simple_identifier`,
//! `function_value_parameters`, …). Like the other engines, the file
//! deliberately keeps grammar quirks local rather than trying to share
//! a polymorphic walker.
//!
//! # Scope (mirrors the other engines)
//!
//! - **Per function / lambda.** Each `function_declaration` and
//!   `lambda_literal` body is analyzed independently. Lambdas matter
//!   because Ktor routes use `routing { get("/path") { … } }` blocks.
//! - **Per file.** No cross-file analysis (v1).
//! - **Flow-insensitive.** Two propagation passes; sources seed a name
//!   set, the analyzer transitively taints any `property_declaration` or
//!   `assignment` whose initializer/RHS references a tainted name or a
//!   tainted source expression.
//! - **String-template interpolation** (`"…${x}…"`) propagates taint.
//! - **No sanitizers.** Kotlin's spec carries an empty sanitizer list;
//!   the engine threads the field through for forward compatibility.
//!
//! # NodeMatcher interpretation
//!
//! Kotlin's grammar means a couple of `NodeMatcher` variants need a
//! Kotlin-flavoured reading. The interpretation is chosen to preserve
//! the exact behaviour the bespoke `run_kt_taint()` harness had before
//! the unified-engine refactor — see `kotlin_taint_rule_specs()` for
//! the rule specs that drive it.
//!
//! - **`Call { canonical }`**
//!   - If `canonical` has no `.`, matches a constructor-style call
//!     `Foo(args)` (a `call_expression` whose callee is a bare
//!     `simple_identifier` equal to `canonical`).
//!   - If `canonical` is `Receiver.method`, matches a method call where
//!     the call's receiver text *contains* `Receiver` and the method
//!     name equals `method`. The receiver-substring rule (rather than
//!     exact-equals) is required to recognise both `Runtime.getRuntime()`
//!     and `getRuntime()` style chains, and `call.request.queryParameters`
//!     style nested navigation — same fuzz the bespoke harness used.
//! - **`MethodName { method }`** — matches any `call_expression` whose
//!   method name (last segment of the navigation chain) equals `method`,
//!   regardless of receiver. Used for sinks like `executeQuery` that
//!   live on many receiver bindings (`db`, `conn`, `tx`, `stmt`…).
//! - **`ParamName { names }`** — matches function parameters by name.
//!   For Kotlin, the `names` list may contain bare identifiers
//!   (`request`, `req`) which behave like Python/JS, OR Spring-style
//!   annotation strings (`@RequestParam`, `@RequestBody`, …). When a
//!   parameter carries one of the annotation strings in its
//!   `parameter_modifiers`, that parameter is treated as a source.
//! - **`Attribute { root, field }`** — not currently used by any
//!   Kotlin rule; reserved for forward compatibility.
//! - **`MemberAssign { … }`** — JS-specific; ignored.

use crate::rules::common::{walk_tree, AliasTable};
pub use crate::rules::taint_engine::{NodeMatcher, TaintFinding, TaintSpec};
use std::collections::HashSet;
use tree_sitter::Node;

// ─── Public API ────────────────────────────────────────────────────────────

/// Run the Kotlin taint engine over every function declaration and
/// lambda body inside `root` and return one [`TaintFinding`] per
/// source→sink flow discovered.
///
/// The `aliases` argument is currently unused — Kotlin imports use
/// fully qualified names at sink sites (`Runtime.getRuntime()`,
/// `javax.script.ScriptEngineManager()`), so a per-file alias table
/// would not change matching today. The parameter is kept for shape
/// parity with the other engines.
pub fn analyze_tree(
    root: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    _aliases: Option<&AliasTable>,
) -> Vec<TaintFinding> {
    let mut findings = Vec::new();
    walk_tree(root, source, &mut |node, src| {
        if node.kind() == "function_declaration" || node.kind() == "lambda_literal" {
            analyze_scope(node, src, spec, &mut findings);
        }
    });
    findings
}

/// All Kotlin taint rule IDs paired with their specs.
///
/// Mirrors `go_taint_rule_specs()` / `python_taint_rule_specs()`.
/// Consumed by [`crate::rules::builtin_taint_specs_for_language`] so
/// taint rules show up as `RegistryTaintSpec` entries the same way the
/// other languages do.
pub fn kotlin_taint_rule_specs() -> Vec<(&'static str, TaintSpec)> {
    vec![
        ("kt/taint-sql-injection", sql_injection_spec()),
        ("kt/taint-command-injection", command_injection_spec()),
        ("kt/taint-ssrf", ssrf_spec()),
    ]
}

/// Shared sources for every Kotlin taint rule. Recognises:
///
/// - Ktor `call.receiveText()`, `call.receive<T>()`
/// - Ktor `request.queryParameters[...]`, `call.request.queryParameters[...]`
/// - Ktor `request.header(...)`, `call.request.header(...)`,
///   `request.queryParameter(...)`
/// - Spring annotations `@RequestParam`, `@RequestBody`, `@PathVariable`,
///   `@RequestHeader` on a function parameter
///
/// The annotation entries use `ParamName` with the `@`-prefixed names
/// the engine recognises specially (see module-level docs).
pub fn kotlin_taint_sources() -> Vec<NodeMatcher> {
    vec![
        NodeMatcher::Call {
            canonical: "call.receiveText".into(),
            description: "call.receiveText()".into(),
        },
        NodeMatcher::Call {
            canonical: "call.receive".into(),
            description: "call.receive()".into(),
        },
        NodeMatcher::Call {
            canonical: "request.header".into(),
            description: "request.header()".into(),
        },
        NodeMatcher::Call {
            canonical: "request.queryParameter".into(),
            description: "request.queryParameter()".into(),
        },
        // Indexing sources (request.queryParameters["x"]) are matched by
        // `is_indexing_source` directly — they have no NodeMatcher form
        // today but are baked into the engine for behaviour preservation.
        NodeMatcher::ParamName {
            names: vec![
                "@RequestParam".into(),
                "@RequestBody".into(),
                "@PathVariable".into(),
                "@RequestHeader".into(),
            ],
            description: "Spring annotation parameter".into(),
        },
    ]
}

// ─── Rule specs ────────────────────────────────────────────────────────────

fn sql_injection_spec() -> TaintSpec {
    TaintSpec {
        sources: kotlin_taint_sources(),
        sinks: vec![
            NodeMatcher::MethodName {
                method: "executeQuery".into(),
                description: "executeQuery() with tainted argument".into(),
            },
            NodeMatcher::MethodName {
                method: "execute".into(),
                description: "execute() with tainted argument".into(),
            },
            NodeMatcher::MethodName {
                method: "createQuery".into(),
                description: "createQuery() with tainted argument".into(),
            },
            NodeMatcher::MethodName {
                method: "createNativeQuery".into(),
                description: "createNativeQuery() with tainted argument".into(),
            },
            NodeMatcher::MethodName {
                method: "rawQuery".into(),
                description: "rawQuery() with tainted argument".into(),
            },
            NodeMatcher::MethodName {
                method: "execSQL".into(),
                description: "execSQL() with tainted argument".into(),
            },
            NodeMatcher::MethodName {
                method: "prepareStatement".into(),
                description: "prepareStatement() with tainted argument".into(),
            },
        ],
        sanitizers: vec![],
    }
}

fn command_injection_spec() -> TaintSpec {
    TaintSpec {
        sources: kotlin_taint_sources(),
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
        sources: kotlin_taint_sources(),
        sinks: vec![
            // URL/URI constructor-style calls.
            NodeMatcher::Call {
                canonical: "URL".into(),
                description: "URL() with tainted argument".into(),
            },
            NodeMatcher::Call {
                canonical: "URI".into(),
                description: "URI() with tainted argument".into(),
            },
            // RestTemplate convenience methods — match by method name on
            // any receiver. The bespoke harness matched these regardless
            // of receiver, so `MethodName` is the right shape.
            NodeMatcher::MethodName {
                method: "getForObject".into(),
                description: "getForObject() with tainted URL".into(),
            },
            NodeMatcher::MethodName {
                method: "getForEntity".into(),
                description: "getForEntity() with tainted URL".into(),
            },
            NodeMatcher::MethodName {
                method: "postForObject".into(),
                description: "postForObject() with tainted URL".into(),
            },
            NodeMatcher::MethodName {
                method: "postForEntity".into(),
                description: "postForEntity() with tainted URL".into(),
            },
            NodeMatcher::MethodName {
                method: "exchange".into(),
                description: "exchange() with tainted URL".into(),
            },
        ],
        sanitizers: vec![],
    }
}

// ─── Internals ─────────────────────────────────────────────────────────────

/// Describes a taint source matched inside a function body.
struct TaintSource {
    var_name: Option<String>,
    description: String,
    line: usize,
}

/// Describes a taint sink match.
struct TaintSink {
    start_byte: usize,
    end_byte: usize,
    description: String,
}

fn analyze_scope(
    scope_node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    out: &mut Vec<TaintFinding>,
) {
    let body = find_function_body(scope_node).unwrap_or(scope_node);

    // Collect sources from the body (Ktor `call.*`, indexing) and from
    // the function's own parameter list (Spring annotations / param
    // names). For lambda_literal nodes there is no parameter list to
    // scan separately.
    let mut sources = collect_body_sources(body, source, spec);
    if matches!(scope_node.kind(), "function_declaration") {
        collect_param_sources(scope_node, source, spec, &mut sources);
    }
    if sources.is_empty() {
        return;
    }

    let tainted = build_tainted_set(body, source, &sources);
    if tainted.is_empty() {
        return;
    }

    let sinks = find_sinks(body, source, spec, &tainted);
    if sinks.is_empty() {
        return;
    }

    // Pick a representative source for the finding's source_description.
    // Mirrors the bespoke harness's "first source wins" rule.
    let (source_desc, source_line) = sources
        .first()
        .map(|s| (s.description.clone(), s.line))
        .unwrap_or_else(|| ("user input".to_string(), 0));

    for sink in sinks {
        let start = byte_to_position(source, sink.start_byte);
        let end = byte_to_position(source, sink.end_byte);
        out.push(TaintFinding {
            sink_start_byte: sink.start_byte,
            sink_end_byte: sink.end_byte,
            sink_line: start.0,
            sink_column: start.1,
            sink_end_line: end.0,
            sink_end_column: end.1,
            source_description: source_desc.clone(),
            sink_description: sink.description,
            source_line,
            rule_id_hint: None,
            // The Kotlin engine does not yet track hops; report 0 so the
            // reporting layer leaves confidence at the engine-default and
            // does not emit a `taint_hops` field, matching the bespoke
            // harness's prior output.
            hops: 0,
        });
    }
}

/// Walk a function or lambda body and collect taint sources expressed
/// as Ktor request reads (call.receiveText(), request.queryParameters[…])
/// captured inside `property_declaration` or `assignment` initialisers.
fn collect_body_sources(scope: Node<'_>, source: &str, spec: &TaintSpec) -> Vec<TaintSource> {
    let mut sources = Vec::new();
    walk_tree(scope, source, &mut |n, s| {
        if n.kind() == "property_declaration" {
            let var = extract_property_var_name(n, s);
            let initializer = extract_property_initializer(n);
            if let (Some(var_name), Some(init)) = (var, initializer) {
                if let Some(desc) = classify_source_expr(init, s, spec) {
                    sources.push(TaintSource {
                        var_name: Some(var_name),
                        description: desc,
                        line: n.start_position().row + 1,
                    });
                }
            }
        }
        if n.kind() == "assignment" {
            if let (Some(left), Some(right)) =
                (n.child(0), n.child(n.child_count().saturating_sub(1)))
            {
                if left.kind() == "simple_identifier" {
                    let left_text = &s[left.byte_range()];
                    if let Some(desc) = classify_source_expr(right, s, spec) {
                        sources.push(TaintSource {
                            var_name: Some(left_text.to_string()),
                            description: desc,
                            line: n.start_position().row + 1,
                        });
                    }
                }
            }
        }
    });
    sources
}

/// Return a source description if `node` is a taint source expression
/// recognised by `spec`. Implements the Kotlin-specific interpretation
/// of `NodeMatcher::Call` (receiver-substring + method) and the baked-in
/// `request.queryParameters[…]` indexing pattern.
fn classify_source_expr(node: Node<'_>, src: &str, spec: &TaintSpec) -> Option<String> {
    // Try every spec source that is a Call matcher.
    if node.kind() == "call_expression" {
        if let Some(method) = call_method_name(node, src) {
            if let Some(receiver) = call_receiver_text(node, src) {
                for matcher in &spec.sources {
                    if let NodeMatcher::Call { canonical, .. } = matcher {
                        if let Some(desc) = match_kotlin_call_canonical(canonical, receiver, method)
                        {
                            return Some(desc);
                        }
                    }
                }
            }
        }
    }

    // Indexing pattern: `request.queryParameters["x"]`, baked in for
    // parity with the bespoke harness.
    if is_indexing_source(node, src) {
        return Some(src[node.byte_range()].to_string());
    }

    None
}

/// Check whether a node looks like a Ktor request-indexing source.
fn is_indexing_source(node: Node<'_>, src: &str) -> bool {
    let text = &src[node.byte_range()];
    (node.kind() == "indexing_expression"
        || text.contains("queryParameters[")
        || text.contains("parameters["))
        && (text.contains("request") || text.contains("call"))
        && (text.contains("queryParameters")
            || text.contains("parameters[")
            || text.contains("header"))
}

/// Apply the Kotlin-flavoured interpretation of `NodeMatcher::Call`.
/// See the module-level docs for the rules.
fn match_kotlin_call_canonical(canonical: &str, receiver: &str, method: &str) -> Option<String> {
    if let Some((expected_recv, expected_method)) = canonical.split_once('.') {
        if method == expected_method && receiver.contains(expected_recv) {
            return Some(format!("{}.{}()", receiver, method));
        }
    }
    None
}

/// Apply the Kotlin-flavoured interpretation of `NodeMatcher::Call` to
/// sink call sites. Returns `true` if the call matches the canonical
/// shape (constructor or `Receiver.method`).
fn match_kotlin_sink_call(
    canonical: &str,
    receiver: Option<&str>,
    method: Option<&str>,
    ctor_name: Option<&str>,
) -> bool {
    if let Some((expected_recv, expected_method)) = canonical.split_once('.') {
        // Method-on-receiver form: `Runtime.exec`.
        if let (Some(recv), Some(m)) = (receiver, method) {
            return m == expected_method && recv.contains(expected_recv);
        }
        return false;
    }
    // Constructor-style: `ProcessBuilder`, `URL`, …
    if let Some(ctor) = ctor_name {
        return ctor == canonical;
    }
    false
}

/// Collect Spring annotation-based parameter sources plus bare
/// `ParamName` matches from a function declaration. Pushes into the
/// caller's source list.
fn collect_param_sources(
    func_node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    out: &mut Vec<TaintSource>,
) {
    // Collect annotation strings and bare names from the spec once.
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

    let mut cursor = func_node.walk();
    for child in func_node.children(&mut cursor) {
        if child.kind() != "function_value_parameters" {
            continue;
        }
        let mut c2 = child.walk();
        let children: Vec<_> = child.children(&mut c2).collect();
        let mut pending_annotation: Option<&str> = None;

        for ch in &children {
            if ch.kind() == "parameter_modifiers" {
                let mod_text = &source[ch.byte_range()];
                for ann in &annotation_names {
                    if mod_text.contains(ann) {
                        pending_annotation = Some(ann);
                        break;
                    }
                }
            } else if ch.kind() == "parameter" {
                // Extract the parameter name (first simple_identifier).
                let mut c3 = ch.walk();
                let mut param_name: Option<&str> = None;
                for pc in ch.children(&mut c3) {
                    if pc.kind() == "simple_identifier" {
                        param_name = Some(&source[pc.byte_range()]);
                        break;
                    }
                }
                if let Some(name) = param_name {
                    if let Some(ann) = pending_annotation.take() {
                        out.push(TaintSource {
                            var_name: Some(name.to_string()),
                            description: format!("@{} parameter '{}'", ann, name),
                            line: ch.start_position().row + 1,
                        });
                    } else if bare_names.contains(&name) {
                        out.push(TaintSource {
                            var_name: Some(name.to_string()),
                            description: format!("parameter '{}'", name),
                            line: ch.start_position().row + 1,
                        });
                    }
                }
                pending_annotation = None;
            } else if ch.kind() != "," && ch.kind() != "(" && ch.kind() != ")" {
                pending_annotation = None;
            }
        }
    }
}

/// Seed the tainted-name set with source variables and transitively
/// taint locals through simple assignment and string concatenation /
/// interpolation. Two passes to handle a single level of chained
/// assignment (`val a = source; val b = a; val c = b + …`).
fn build_tainted_set(scope: Node<'_>, source: &str, sources: &[TaintSource]) -> HashSet<String> {
    let mut tainted: HashSet<String> = HashSet::new();
    for s in sources {
        if let Some(ref name) = s.var_name {
            tainted.insert(name.clone());
        }
    }
    if tainted.is_empty() {
        return tainted;
    }

    for _ in 0..2 {
        walk_tree(scope, source, &mut |n, s| {
            if n.kind() == "property_declaration" {
                let var = extract_property_var_name(n, s);
                let init = extract_property_initializer(n);
                if let (Some(var_name), Some(init_node)) = (var, init) {
                    if !tainted.contains(&var_name) && expr_uses_tainted(init_node, s, &tainted) {
                        tainted.insert(var_name);
                    }
                }
            }
            if n.kind() == "assignment" {
                if let (Some(left), Some(right)) =
                    (n.child(0), n.child(n.child_count().saturating_sub(1)))
                {
                    if left.kind() == "simple_identifier" {
                        let left_text = s[left.byte_range()].to_string();
                        if !tainted.contains(&left_text) && expr_uses_tainted(right, s, &tainted) {
                            tainted.insert(left_text);
                        }
                    }
                }
            }
        });
    }
    tainted
}

/// Recursively check whether `node` references any tainted variable.
/// Picks up `simple_identifier` references and `"…${tainted}…"`
/// string-template interpolations.
fn expr_uses_tainted(node: Node<'_>, src: &str, tainted: &HashSet<String>) -> bool {
    if node.kind() == "simple_identifier" {
        let name = &src[node.byte_range()];
        return tainted.contains(name);
    }
    if node.kind() == "string_literal" {
        let text = &src[node.byte_range()];
        for t in tainted {
            if text.contains(&format!("${{{}}}", t)) || text.contains(&format!("${}", t)) {
                return true;
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if expr_uses_tainted(child, src, tainted) {
            return true;
        }
    }
    false
}

/// Walk `scope` and emit a sink for every call expression whose callee
/// matches the spec's sink list AND whose arguments reference a tainted
/// variable.
fn find_sinks(
    scope: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    tainted: &HashSet<String>,
) -> Vec<TaintSink> {
    let mut sinks = Vec::new();
    walk_tree(scope, source, &mut |n, s| {
        if n.kind() != "call_expression" {
            return;
        }
        let method = call_method_name(n, s);
        let receiver = call_receiver_text(n, s);
        let ctor = call_constructor_name(n, s);

        let Some(args) = call_arguments(n) else {
            return;
        };

        // Parameterized-binding setters bind their value to a placeholder
        // (`?`) in an already-prepared statement; they are NOT injection
        // sinks. Treat them as taint-stopping no-ops so a tainted value
        // passed to e.g. `setString(1, tainted)` does not flag.
        if matches!(method, Some("setString" | "setInt" | "setObject")) {
            return;
        }

        // `prepareStatement(sql, ...)` only executes its FIRST (SQL)
        // argument; trailing arguments (e.g. result-set type flags) are
        // not part of the query. Only treat it as a sink when the SQL
        // string itself is tainted.
        if method == Some("prepareStatement") {
            let first_tainted = first_argument(args)
                .map(|first| expr_uses_tainted(first, s, tainted))
                .unwrap_or(false);
            if first_tainted {
                sinks.push(TaintSink {
                    start_byte: n.start_byte(),
                    end_byte: n.end_byte(),
                    description: "prepareStatement() with tainted argument".into(),
                });
            }
            return;
        }

        if !expr_uses_tainted(args, s, tainted) {
            return;
        }

        for matcher in &spec.sinks {
            match matcher {
                NodeMatcher::MethodName {
                    method: expected,
                    description,
                } if method == Some(expected.as_str()) => {
                    sinks.push(TaintSink {
                        start_byte: n.start_byte(),
                        end_byte: n.end_byte(),
                        description: description.clone(),
                    });
                    return;
                }
                NodeMatcher::Call {
                    canonical,
                    description,
                } if match_kotlin_sink_call(canonical, receiver, method, ctor) => {
                    sinks.push(TaintSink {
                        start_byte: n.start_byte(),
                        end_byte: n.end_byte(),
                        description: description.clone(),
                    });
                    return;
                }
                _ => {}
            }
        }
    });
    sinks
}

// ─── Kotlin AST helpers ────────────────────────────────────────────────────

/// Extract the method name from a `call_expression` whose callee is a
/// `navigation_expression`. Returns the last `simple_identifier` inside
/// the trailing `navigation_suffix`.
fn call_method_name<'a>(node: Node<'a>, src: &'a str) -> Option<&'a str> {
    if node.kind() != "call_expression" {
        return None;
    }
    let callee = node.child(0)?;
    if callee.kind() == "navigation_expression" {
        let nav_suffix = callee.child(callee.child_count().checked_sub(1)?)?;
        if nav_suffix.kind() == "navigation_suffix" {
            let mut cursor = nav_suffix.walk();
            for child in nav_suffix.children(&mut cursor) {
                if child.kind() == "simple_identifier" {
                    return Some(&src[child.byte_range()]);
                }
            }
        }
    }
    None
}

/// Receiver text for a `call_expression` whose callee is a
/// `navigation_expression`: everything before the trailing `.method`.
fn call_receiver_text<'a>(node: Node<'a>, src: &'a str) -> Option<&'a str> {
    if node.kind() != "call_expression" {
        return None;
    }
    let callee = node.child(0)?;
    if callee.kind() == "navigation_expression" {
        let receiver = callee.child(0)?;
        return Some(&src[receiver.byte_range()]);
    }
    None
}

/// Constructor-style callee: for `Foo(args)` returns `Foo`.
fn call_constructor_name<'a>(node: Node<'a>, src: &'a str) -> Option<&'a str> {
    if node.kind() != "call_expression" {
        return None;
    }
    let callee = node.child(0)?;
    if callee.kind() == "simple_identifier" {
        return Some(&src[callee.byte_range()]);
    }
    None
}

/// Locate the `value_arguments` node inside a `call_expression`.
fn call_arguments(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() != "call_expression" {
        return None;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "call_suffix" {
            let mut c2 = child.walk();
            for grandchild in child.children(&mut c2) {
                if grandchild.kind() == "value_arguments" {
                    return Some(grandchild);
                }
            }
        }
    }
    None
}

/// First actual argument expression from a `value_arguments` node.
fn first_argument(args_node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = args_node.walk();
    for child in args_node.children(&mut cursor) {
        if child.kind() == "value_argument" {
            return child.child(0);
        }
    }
    None
}

/// Variable name of a `property_declaration` (`val x = …`).
fn extract_property_var_name(node: Node<'_>, src: &str) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "variable_declaration" {
            let mut c2 = child.walk();
            for gc in child.children(&mut c2) {
                if gc.kind() == "simple_identifier" {
                    return Some(src[gc.byte_range()].to_string());
                }
            }
        }
    }
    None
}

/// Initializer expression of a `property_declaration` (after the `=`).
fn extract_property_initializer(node: Node<'_>) -> Option<Node<'_>> {
    if node.child_count() < 3 {
        return None;
    }
    let mut found_eq = false;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if found_eq && child.kind() != "=" {
            return Some(child);
        }
        if child.kind() == "=" {
            found_eq = true;
        }
    }
    None
}

/// Body node of a `function_declaration` / `lambda_literal`, if any.
fn find_function_body(func_node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = func_node.walk();
    let body = func_node
        .children(&mut cursor)
        .find(|child| child.kind() == "function_body");
    body
}

/// Convert a byte offset into the source to a `(line, column)` pair,
/// matching the conventions used by `make_finding_from_offsets`.
fn byte_to_position(source: &str, byte: usize) -> (usize, usize) {
    let byte = byte.min(source.len());
    let line = source[..byte].bytes().filter(|b| *b == b'\n').count() + 1;
    let line_start = source[..byte].rfind('\n').map_or(0, |idx| idx + 1);
    let column = source[line_start..byte].chars().count() + 1;
    (line, column)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::parser::parse_file;
    use crate::Language;

    fn analyze(src: &str, spec: &TaintSpec) -> Vec<TaintFinding> {
        let tree = parse_file(src, Language::Kotlin).expect("parse");
        analyze_tree(tree.root_node(), src, spec, None)
    }

    #[test]
    fn sql_injection_via_ktor_receive() {
        let src = r#"
fun Application.module() {
    routing {
        post("/users") {
            val body = call.receiveText()
            val query = "SELECT * FROM users WHERE name = '" + body + "'"
            db.executeQuery(query)
        }
    }
}
"#;
        let findings = analyze(src, &sql_injection_spec());
        assert!(
            !findings.is_empty(),
            "should detect tainted SQL via call.receiveText(): {:?}",
            findings
        );
    }

    #[test]
    fn command_injection_via_request_param() {
        let src = r#"
@PostMapping("/exec")
fun execute(@RequestBody input: String) {
    val args = input.split(" ")
    ProcessBuilder(args).start()
}
"#;
        let findings = analyze(src, &command_injection_spec());
        assert!(
            !findings.is_empty(),
            "should detect tainted ProcessBuilder via @RequestBody: {:?}",
            findings
        );
    }

    #[test]
    fn ssrf_transitive_flow() {
        let src = r#"
fun Application.module() {
    routing {
        post("/fetch") {
            val body = call.receiveText()
            val target = body
            val endpoint = "https://internal/" + target
            val url = URL(endpoint)
        }
    }
}
"#;
        let findings = analyze(src, &ssrf_spec());
        assert!(
            !findings.is_empty(),
            "should detect SSRF via transitive flow: {:?}",
            findings
        );
    }

    #[test]
    fn clean_literal_no_finding() {
        let src = r#"
fun handler(call: ApplicationCall) {
    val data = call.receiveText()
    Runtime.getRuntime().exec("ls -la")
}
"#;
        let findings = analyze(src, &command_injection_spec());
        assert!(
            findings.is_empty(),
            "literal command should not trigger taint: {:?}",
            findings
        );
    }

    #[test]
    fn prepared_statement_with_binding_is_clean() {
        // Tainted value bound via setString to a placeholder is safe; the
        // prepareStatement SQL string itself is a constant literal.
        let src = r#"
fun handler(call: ApplicationCall, conn: Connection) {
    val id = call.request.queryParameters["id"]
    val stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?")
    stmt.setString(1, id)
}
"#;
        let findings = analyze(src, &sql_injection_spec());
        assert!(
            findings.is_empty(),
            "parameterized prepared statement should not flag: {:?}",
            findings
        );
    }

    #[test]
    fn prepared_statement_with_tainted_sql_flags() {
        // Tainted value concatenated directly into the SQL string passed to
        // prepareStatement must still flag.
        let src = r#"
fun handler(call: ApplicationCall, conn: Connection) {
    val id = call.request.queryParameters["id"]
    val stmt = conn.prepareStatement("SELECT * FROM users WHERE id = " + id)
}
"#;
        let findings = analyze(src, &sql_injection_spec());
        assert!(
            !findings.is_empty(),
            "tainted SQL in prepareStatement should flag: {:?}",
            findings
        );
    }
}
