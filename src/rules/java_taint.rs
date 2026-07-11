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
use crate::rules::cross_file::{CrossFileSummaryMap, FunctionTaintSummary, ParamSinkFlow};
use crate::rules::taint_engine::{
    cross_file_taint_finding, walk_scope_nodes as walk_taint_scope_nodes,
};
pub use crate::rules::taint_engine::{
    LabelPolicy, NodeMatcher, Propagator, TaintFinding, TaintSpec,
};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::PathBuf;
use tree_sitter::Node;

#[derive(Clone, Debug)]
struct TaintInfo {
    description: String,
    line: usize,
    hops: u8,
    /// Optional taint-**labels** set carried by this value (Semgrep advanced
    /// taint mode). `None` = the historical unlabeled/boolean behavior (every
    /// existing engine path and rule is unchanged). `Some(set)` is populated
    /// only when a [`LabelPolicy`] is active for the rule under analysis; the
    /// sink then fires only when the set satisfies the policy's boolean
    /// `requires:` (a single positive label like `CONCAT`, or a negation like
    /// `INPUT and not CLEAN`).
    labels: Option<BTreeSet<String>>,
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
    aliases: Option<&AliasTable>,
) -> Vec<TaintFinding> {
    analyze_tree_with_propagators(root, source, spec, aliases, &[])
}

/// Like [`analyze_tree`] but also applies a list of taint [`Propagator`]s
/// during each function's walk. Used by the Semgrep YAML bridge to honor
/// `pattern-propagators` (e.g. `(StringBuilder $SB).append($X)`); the built-in
/// Java rules call [`analyze_tree`] with no propagators.
pub fn analyze_tree_with_propagators(
    root: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    aliases: Option<&AliasTable>,
    propagators: &[Propagator],
) -> Vec<TaintFinding> {
    analyze_tree_labeled(root, source, spec, aliases, propagators, None)
}

/// Like [`analyze_tree_with_propagators`] but also honors a taint-**labels**
/// [`LabelPolicy`] (Semgrep advanced taint mode, `CONCAT`-family slice). With
/// `policy = None` this is byte-for-byte the historical unlabeled behavior, so
/// every existing built-in and Semgrep rule is unaffected. With `policy =
/// Some(..)` primary sources emit the policy's source label, values passing
/// through string-building nodes are conditionally relabeled, and a sink fires
/// only when the reaching value carries the policy's required label.
pub fn analyze_tree_labeled(
    root: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    _aliases: Option<&AliasTable>,
    propagators: &[Propagator],
    policy: Option<&LabelPolicy>,
) -> Vec<TaintFinding> {
    let mut findings = Vec::new();
    walk_tree(root, source, &mut |node, src| {
        if is_scope_node(node.kind()) {
            analyze_scope(node, src, spec, propagators, policy, &mut findings);
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

// ─── Cross-file (interprocedural across files) taint ─────────────────────
//
// Scope of the Java cross-file pass (deliberately narrow; see
// `docs/taint-tracking.md`):
//
// * **Resolution is NAME-based, not type-based.** A method declaration is
//   summarized by its bare method name. A call site resolves to a summary
//   whenever the invoked method name matches a summarized method in a
//   sibling file of the same directory (used as a same-package proxy, the
//   way the Go engine treats same-directory `.go` files). This intentionally
//   over-approximates: `helper.process(x)`, `Helper.process(x)`, and a bare
//   `process(x)` all resolve to *any* same-package `process` summary,
//   regardless of the receiver's declared type.
// * **Bounded multi-hop IS modeled.** A helper `f` that forwards its parameter
//   into another same-directory helper `g` which sinks it (`A → f → g → sink`)
//   is captured by [`compose_cross_file_summaries`], the per-file step of the
//   scanner's bounded multi-hop fixpoint (see `docs/taint-tracking.md`).
// * **What is NOT modeled:** instance-method dispatch through interfaces or
//   subclasses, method overloads (same name, different arity/types — only
//   arity is checked via the argument count), `import`-based class resolution
//   across packages/directories, and cross-file chains deeper than the hop cap.
//   These need a Java type/symbol table the engine does not build.

/// Extract cross-file taint summaries for every method declaration in `root`.
///
/// Pass 1 of the two-pass scanner. For each method, every parameter is
/// treated as a synthetic taint source; a parameter that reaches a sink
/// records a [`ParamSinkFlow`], and a parameter that flows to a `return`
/// records a `params_to_return` index. Summaries are keyed by the bare
/// method name (last-write-wins on name collisions, mirroring Go).
pub fn extract_cross_file_summaries(
    root: Node<'_>,
    source: &str,
    _aliases: Option<&AliasTable>,
    rule_specs: &[(&str, TaintSpec)],
) -> Vec<FunctionTaintSummary> {
    let mut summaries = Vec::new();
    walk_tree(root, source, &mut |node, src| {
        if node.kind() != "method_declaration" {
            return;
        }
        let Some(method_name) = node
            .child_by_field_name("name")
            .map(|n| node_text(n, src).to_string())
        else {
            return;
        };
        let param_names = method_param_names(node, src);
        if let Some(summary) =
            summarize_java_method(node, &method_name, &param_names, src, rule_specs)
        {
            summaries.push(summary);
        }
    });
    summaries
}

/// The parameter names of a method/constructor/lambda scope, in order.
fn method_param_names(scope_node: Node<'_>, source: &str) -> Vec<String> {
    scope_parameter_nodes(scope_node)
        .into_iter()
        .filter_map(|node| formal_parameter_name(node, source).map(|s| s.to_string()))
        .collect()
}

/// Build a [`FunctionTaintSummary`] for a single method, or `None` if no
/// parameter reaches a sink or a return value.
fn summarize_java_method(
    method_node: Node<'_>,
    method_name: &str,
    param_names: &[String],
    source: &str,
    rule_specs: &[(&str, TaintSpec)],
) -> Option<FunctionTaintSummary> {
    if param_names.is_empty() {
        return None;
    }

    let mut params_to_sink: Vec<ParamSinkFlow> = Vec::new();
    let mut params_to_return: Vec<usize> = Vec::new();

    for (param_idx, param_name) in param_names.iter().enumerate() {
        if java_param_flows_to_return(method_node, param_name, source) {
            params_to_return.push(param_idx);
        }

        for (rule_id, rule_spec) in rule_specs {
            let synthetic = TaintSpec {
                sources: vec![NodeMatcher::ParamName {
                    names: vec![param_name.clone()],
                    description: format!("parameter '{param_name}'"),
                }],
                sinks: rule_spec.sinks.clone(),
                sanitizers: rule_spec.sanitizers.clone(),
            };
            let mut findings = Vec::new();
            analyze_scope(method_node, source, &synthetic, &[], None, &mut findings);
            if let Some(finding) = findings.first() {
                params_to_sink.push(ParamSinkFlow {
                    param_index: param_idx,
                    sink_rule_id: rule_id.to_string(),
                    sink_description: finding.sink_description.clone(),
                });
            }
        }
    }

    if params_to_sink.is_empty() && params_to_return.is_empty() {
        return None;
    }

    Some(FunctionTaintSummary {
        name: method_name.to_string(),
        params_to_return,
        params_to_sink,
    })
}

/// Does `param_name`, treated as a taint source, reach a `return` statement?
fn java_param_flows_to_return(method_node: Node<'_>, param_name: &str, source: &str) -> bool {
    let synthetic = TaintSpec {
        sources: vec![NodeMatcher::ParamName {
            names: vec![param_name.to_string()],
            description: format!("parameter '{param_name}'"),
        }],
        sinks: vec![],
        sanitizers: vec![],
    };
    let body = find_scope_body(method_node).unwrap_or(method_node);
    let mut state = TaintState::default();
    collect_param_sources(method_node, source, &synthetic, None, &mut state);
    for _ in 0..3 {
        propagate_assignments(body, source, &synthetic, None, &mut state);
    }

    let mut flows = false;
    walk_scope_nodes(body, source, &mut |node, src| {
        if flows || node.kind() != "return_statement" {
            return;
        }
        if let Some(expr) = node.named_child(0) {
            if expression_taint(expr, src, &synthetic, None, &state).is_some() {
                flows = true;
            }
        }
    });
    flows
}

/// Cross-file resolution info for the Java engine.
///
/// `same_package_paths` are the canonical paths of sibling Java files in the
/// same directory (the same-package proxy); `summaries` is the pass-1 map
/// keyed by canonical path; `allowed_rule_ids` gates which rules may emit
/// cross-file findings in the current run.
pub struct CrossFileInfo<'a> {
    pub same_package_paths: &'a [PathBuf],
    pub summaries: &'a CrossFileSummaryMap,
    pub allowed_rule_ids: &'a HashSet<String>,
}

/// Pass 2 cross-file resolution: walk every scope, compute its intra-file
/// taint state, and for each helper-method call that resolves to a sibling
/// summary, emit a finding when a tainted argument lands on a parameter with
/// a recorded sink flow.
///
/// Returns findings whose `rule_id_hint` carries the attributed rule id.
pub fn extract_cross_file_findings(
    root: Node<'_>,
    source: &str,
    rule_specs: &[(&str, TaintSpec)],
    cross_file: &CrossFileInfo<'_>,
) -> Vec<TaintFinding> {
    // The caller-side taint state is driven by the real sources (shared
    // across the built-in Java rules); union them so an inline source
    // argument like `helper(request.getParameter("x"))` is recognized.
    let mut source_spec = TaintSpec::default();
    for (_, spec) in rule_specs {
        source_spec.sources.extend(spec.sources.iter().cloned());
        source_spec
            .sanitizers
            .extend(spec.sanitizers.iter().cloned());
    }

    let mut out = Vec::new();
    walk_tree(root, source, &mut |node, src| {
        if is_scope_node(node.kind()) {
            resolve_cross_file_scope(node, src, &source_spec, cross_file, &mut out);
        }
    });
    out
}

fn resolve_cross_file_scope(
    scope_node: Node<'_>,
    source: &str,
    source_spec: &TaintSpec,
    cross_file: &CrossFileInfo<'_>,
    out: &mut Vec<TaintFinding>,
) {
    let body = find_scope_body(scope_node).unwrap_or(scope_node);
    let mut state = TaintState::default();
    collect_param_sources(scope_node, source, source_spec, None, &mut state);
    for _ in 0..3 {
        propagate_assignments(body, source, source_spec, None, &mut state);
    }

    walk_scope_nodes(body, source, &mut |node, src| {
        if node.kind() != "method_invocation" {
            return;
        }
        let Some(method_name) = call_method_name(node, src) else {
            return;
        };
        let Some(summary) = lookup_cross_file_summary(cross_file, method_name) else {
            return;
        };
        let Some(args) = node.child_by_field_name("arguments") else {
            return;
        };
        let mut cursor = args.walk();
        let arg_nodes: Vec<Node<'_>> = args.named_children(&mut cursor).collect();

        for flow in &summary.params_to_sink {
            if !cross_file.allowed_rule_ids.contains(&flow.sink_rule_id) {
                continue;
            }
            if flow.param_index >= arg_nodes.len() {
                continue;
            }
            let arg = arg_nodes[flow.param_index];
            if let Some(info) = expression_taint(arg, src, source_spec, None, &state) {
                out.push(cross_file_taint_finding(
                    node,
                    info.description,
                    info.line,
                    &flow.sink_description,
                    method_name,
                    &flow.sink_rule_id,
                ));
            }
        }
    });
}

fn lookup_cross_file_summary<'a>(
    cross_file: &'a CrossFileInfo<'_>,
    method_name: &str,
) -> Option<&'a FunctionTaintSummary> {
    for path in cross_file.same_package_paths {
        if let Some(file_summaries) = cross_file.summaries.get(path) {
            if let Some(summary) = file_summaries.iter().find(|s| s.name == method_name) {
                return Some(summary);
            }
        }
    }
    None
}

/// Re-derive a file's cross-file summaries with same-package call resolution
/// enabled, composing the current summary map one hop deeper.
///
/// This is the Java counterpart of [`go_taint::compose_cross_file_summaries`]
/// and the per-file step of the scanner's **bounded multi-hop** fixpoint.
///
/// Java uses its OWN name-based, same-directory summary machinery (not the
/// shared `TaintLanguageAdapter` path Python/Go/JS use), so composition is
/// implemented directly here. For each method we seed one parameter at a time
/// as a synthetic source and propagate intra-file taint (the base summary
/// already over-approximates return/propagation *through* calls, so
/// `params_to_return` needs no cross-file step). We then resolve every
/// helper-method call that lands in a sibling summary: when a tainted argument
/// hits a param the sibling records in `params_to_sink`, THIS parameter reaches
/// that sink one hop deeper — e.g. `f(p)` whose body is `return g(p)` where the
/// sibling `g` sinks its argument gains `f`'s `params_to_sink` entry.
///
/// The scanner unions the returned flows into the existing summaries via
/// [`FunctionTaintSummary::merge_from`] and repeats until a fixpoint (no
/// change) or the hop bound is reached. `summaries` is a read-only snapshot
/// from the previous round, so each round adds exactly one hop; monotone growth
/// over a finite lattice guarantees termination, and the scanner's round cap is
/// a hard backstop against mutually-recursive helpers.
pub fn compose_cross_file_summaries(
    root: Node<'_>,
    source: &str,
    _aliases: Option<&AliasTable>,
    rule_specs: &[(&str, TaintSpec)],
    same_package_paths: &[PathBuf],
    summaries: &CrossFileSummaryMap,
    allowed_rule_ids: &HashSet<String>,
) -> Vec<FunctionTaintSummary> {
    let cross_file = CrossFileInfo {
        same_package_paths,
        summaries,
        allowed_rule_ids,
    };

    let mut out = Vec::new();
    walk_tree(root, source, &mut |node, src| {
        if node.kind() != "method_declaration" {
            return;
        }
        let Some(method_name) = node
            .child_by_field_name("name")
            .map(|n| node_text(n, src).to_string())
        else {
            return;
        };
        let param_names = method_param_names(node, src);
        if let Some(summary) = compose_java_method(
            node,
            &method_name,
            &param_names,
            src,
            rule_specs,
            &cross_file,
        ) {
            out.push(summary);
        }
    });
    out
}

/// Compose one method's cross-file `params_to_sink` flows: seed each parameter
/// as a source, propagate intra-file taint, and record a flow whenever a
/// tainted argument reaches a sibling helper's recorded sink. Returns `None`
/// when no parameter reaches a cross-file sink (the base summary already owns
/// the direct-sink and `params_to_return` facts).
fn compose_java_method(
    method_node: Node<'_>,
    method_name: &str,
    param_names: &[String],
    source: &str,
    rule_specs: &[(&str, TaintSpec)],
    cross_file: &CrossFileInfo<'_>,
) -> Option<FunctionTaintSummary> {
    if param_names.is_empty() {
        return None;
    }
    let body = find_scope_body(method_node).unwrap_or(method_node);

    // Sanitizers from every rule are unioned so a value cleaned before it
    // reaches the helper is not treated as tainted. Java's built-in rules ship
    // none today, but this keeps the composition sanitizer-aware for custom
    // rules and mirrors the shared-machinery languages.
    let mut sanitizers = Vec::new();
    for (_, rule_spec) in rule_specs {
        sanitizers.extend(rule_spec.sanitizers.iter().cloned());
    }

    let mut params_to_sink: Vec<ParamSinkFlow> = Vec::new();
    for (param_idx, param_name) in param_names.iter().enumerate() {
        let synthetic = TaintSpec {
            sources: vec![NodeMatcher::ParamName {
                names: vec![param_name.clone()],
                description: format!("parameter '{param_name}'"),
            }],
            sinks: vec![],
            sanitizers: sanitizers.clone(),
        };

        let mut state = TaintState::default();
        collect_param_sources(method_node, source, &synthetic, None, &mut state);
        for _ in 0..3 {
            propagate_assignments(body, source, &synthetic, None, &mut state);
        }

        walk_scope_nodes(body, source, &mut |node, src| {
            if node.kind() != "method_invocation" {
                return;
            }
            let Some(callee) = call_method_name(node, src) else {
                return;
            };
            let Some(summary) = lookup_cross_file_summary(cross_file, callee) else {
                return;
            };
            let Some(args) = node.child_by_field_name("arguments") else {
                return;
            };
            let mut cursor = args.walk();
            let arg_nodes: Vec<Node<'_>> = args.named_children(&mut cursor).collect();

            for flow in &summary.params_to_sink {
                if !cross_file.allowed_rule_ids.contains(&flow.sink_rule_id) {
                    continue;
                }
                if flow.param_index >= arg_nodes.len() {
                    continue;
                }
                let arg = arg_nodes[flow.param_index];
                if expression_taint(arg, src, &synthetic, None, &state).is_none() {
                    continue;
                }
                let dup = params_to_sink
                    .iter()
                    .any(|f| f.param_index == param_idx && f.sink_rule_id == flow.sink_rule_id);
                if !dup {
                    params_to_sink.push(ParamSinkFlow {
                        param_index: param_idx,
                        sink_rule_id: flow.sink_rule_id.clone(),
                        sink_description: flow.sink_description.clone(),
                    });
                }
            }
        });
    }

    if params_to_sink.is_empty() {
        return None;
    }
    Some(FunctionTaintSummary {
        name: method_name.to_string(),
        params_to_return: Vec::new(),
        params_to_sink,
    })
}

fn analyze_scope(
    scope_node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    propagators: &[Propagator],
    policy: Option<&LabelPolicy>,
    out: &mut Vec<TaintFinding>,
) {
    let body = find_scope_body(scope_node).unwrap_or(scope_node);
    let mut state = TaintState::default();
    collect_param_sources(scope_node, source, spec, policy, &mut state);

    // Three passes cover the common `source -> local -> derived -> sink`
    // chain without adding a fixed-point loop to this deliberately small
    // intraprocedural engine. Propagators run inside the loop so a chain like
    // `source -> local -> sb.append(local) -> stmt.execute(sb.toString())`
    // resolves as taint flows through the body.
    for _ in 0..3 {
        propagate_assignments(body, source, spec, policy, &mut state);
        apply_propagators(body, source, spec, propagators, policy, &mut state);
    }
    find_sinks(body, source, spec, policy, &state, out);
}

/// Apply "argument taints receiver" [`Propagator`]s: for each
/// `receiver.method(args)` call whose method matches a propagator and one of
/// whose arguments is tainted, mark the receiver variable tainted.
///
/// Confined to the tractable subset: the receiver must be a plain identifier
/// (`sb.append(x)`), not a nested member/index expression, so we never
/// over-taint a whole receiver chain. New taint is collected during the walk
/// and applied afterward to keep the read/write phases separate.
fn apply_propagators(
    scope: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    propagators: &[Propagator],
    policy: Option<&LabelPolicy>,
    state: &mut TaintState,
) {
    if propagators.is_empty() {
        return;
    }
    let mut pending: Vec<(String, TaintInfo)> = Vec::new();
    walk_scope_nodes(scope, source, &mut |node, src| {
        if node.kind() != "method_invocation" {
            return;
        }
        let Some(recv) = node.child_by_field_name("object") else {
            return;
        };
        if recv.kind() != "identifier" {
            return;
        }
        let Some(method) = call_method_name(node, src) else {
            return;
        };
        let method_matches = propagators
            .iter()
            .any(|p| p.method.as_deref().is_none_or(|m| m == method));
        if !method_matches {
            return;
        }
        let recv_name = node_text(recv, src);
        // Already tainted — keep the existing (earlier/better) taint info.
        if state.info(recv_name).is_some() {
            return;
        }
        if let Some(info) = sink_argument_taint(node, src, spec, policy, state) {
            // A relabel propagator such as `(StringBuilder $SB).append($INPUT)`
            // with `label: CONCAT, requires: INPUT` builds a string on the
            // receiver: apply the string-building relabel so the receiver picks
            // up the emitted label (e.g. `CONCAT`).
            let info = relabel_through(node, src, info, policy);
            pending.push((recv_name.to_string(), bump_hops(info)));
        }
    });
    for (name, info) in pending {
        state.taint(name, info);
    }
}

fn collect_param_sources(
    scope_node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    policy: Option<&LabelPolicy>,
    state: &mut TaintState,
) {
    let mut annotation_names: Vec<&str> = Vec::new();
    let mut bare_names: Vec<&str> = Vec::new();
    // `$`-prefixed name (`$PARAM`) is the any-parameter wildcard compiled from a
    // Semgrep `pattern-inside: function(...,$ARG,...) + focus-metavariable: $ARG`
    // source block: seed *every* parameter of the enclosing scope.
    let mut wildcard = false;
    for matcher in &spec.sources {
        if let NodeMatcher::ParamName { names, .. } = matcher {
            for name in names {
                if let Some(rest) = name.strip_prefix('@') {
                    annotation_names.push(rest);
                } else if name == crate::rules::taint_engine::ANY_PARAM_WILDCARD {
                    wildcard = true;
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

        // Typed-metavariable source `(HttpServletRequest $REQ)`: seed the
        // parameter when its DECLARED TYPE matches, regardless of name.
        let typed_desc = formal_parameter_type(node, source)
            .and_then(|ty| typed_source_description(spec, ty).map(|d| (d, name)));

        if let Some(annotation) = matched_annotation {
            state.taint(
                name.to_string(),
                TaintInfo {
                    description: format!("@{annotation} parameter '{name}'"),
                    line: node.start_position().row + 1,
                    hops: 0,
                    labels: source_labels(policy),
                },
            );
        } else if let Some((description, name)) = typed_desc {
            state.taint(
                name.to_string(),
                TaintInfo {
                    description,
                    line: node.start_position().row + 1,
                    hops: 0,
                    labels: source_labels(policy),
                },
            );
        } else if bare_names.contains(&name) || wildcard {
            state.taint(
                name.to_string(),
                TaintInfo {
                    description: format!("parameter '{name}'"),
                    line: node.start_position().row + 1,
                    hops: 0,
                    labels: source_labels(policy),
                },
            );
        }
    }
}

fn propagate_assignments(
    scope: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    policy: Option<&LabelPolicy>,
    state: &mut TaintState,
) {
    walk_scope_nodes(scope, source, &mut |node, src| {
        if node.kind() == "variable_declarator" {
            let Some(name_node) = node.child_by_field_name("name") else {
                return;
            };
            let name = node_text(name_node, src).to_string();
            let Some(value) = node.child_by_field_name("value") else {
                return;
            };
            match expression_taint(value, src, spec, policy, state) {
                Some(info) => state.taint(name, bump_hops(info)),
                None => {
                    // Typed-metavariable source `(HttpServletRequest $REQ)`
                    // applied to a local: `HttpServletRequest req = ...;`
                    // seeds `req` by its DECLARED TYPE even when the
                    // initializer is not itself tainted. Re-applied every
                    // propagation pass, so it survives the clean-reassignment
                    // clear above.
                    match local_declarator_type(node, src)
                        .and_then(|ty| typed_source_description(spec, ty))
                    {
                        Some(description) => state.taint(
                            name,
                            TaintInfo {
                                description,
                                line: node.start_position().row + 1,
                                hops: 0,
                                labels: source_labels(policy),
                            },
                        ),
                        None => state.clear(&name),
                    }
                }
            }
        }

        // Enhanced-for `for (Type v : collection)`: iterating a tainted
        // collection yields tainted elements, so seed the loop variable when the
        // iterated expression carries taint. This carries taint through the
        // cookie loop `for (Cookie c : request.getCookies())` in the
        // `tainted-session-from-http-request` fixture.
        if node.kind() == "enhanced_for_statement" {
            if let (Some(name_node), Some(iterable)) = (
                node.child_by_field_name("name"),
                node.child_by_field_name("value"),
            ) {
                let name = node_text(name_node, src).to_string();
                match expression_taint(iterable, src, spec, policy, state) {
                    Some(info) => state.taint(name, bump_hops(info)),
                    None => state.clear(&name),
                }
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
            match expression_taint(right, src, spec, policy, state) {
                Some(info) => {
                    // A `$X += $INPUT` compound assignment builds a string on
                    // `$X`; treat it as a string-building relabel node so the
                    // target acquires the emitted label (e.g. `CONCAT`).
                    let info = if assignment_is_concat(node, src) {
                        apply_relabel(info, policy)
                    } else {
                        info
                    };
                    state.taint(name.to_string(), bump_hops(info));
                }
                None => state.clear(name),
            }
        }
    });
}

fn find_sinks(
    scope: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    policy: Option<&LabelPolicy>,
    state: &TaintState,
    out: &mut Vec<TaintFinding>,
) {
    // Typed-assignment sinks (`(java.io.File $FILE) = ...`) are cheap to skip
    // when the rule has none: only build the local-variable declared-type map
    // (needed to resolve a bare `assignment_expression` LHS to its declared
    // type) when at least one such sink is present.
    let has_typed_assign = spec
        .sinks
        .iter()
        .any(|m| matches!(m, NodeMatcher::TypedAssignTarget { .. }));
    let local_types = if has_typed_assign {
        collect_local_var_types(scope, source)
    } else {
        HashMap::new()
    };
    let has_method_arg_sink = spec
        .sinks
        .iter()
        .any(|m| matches!(m, NodeMatcher::MethodArgSink { .. }));

    walk_scope_nodes(scope, source, &mut |node, src| {
        // Typed-assignment / declaration sinks fire on declaration and
        // assignment nodes, which the call-only walk below never inspects.
        if has_typed_assign {
            check_typed_assign_sink(node, src, spec, policy, state, &local_types, out);
        }

        // Positional-argument sinks (`setAttribute($NAME, $VALUE)` focus
        // `$VALUE`) fire only when the argument at the focused index is tainted,
        // which the any-argument sink path below cannot express.
        if has_method_arg_sink {
            check_method_arg_sinks(node, src, spec, policy, state, out);
        }

        if node.kind() != "method_invocation" && node.kind() != "object_creation_expression" {
            return;
        }
        let Some(sink_description) = match_sink(node, src, spec) else {
            return;
        };
        let taint = sink_argument_taint(node, src, spec, policy, state)
            .or_else(|| read_object_receiver_taint(node, src, state));
        if let Some(info) = taint {
            // Taint-labels gating: when a `LabelPolicy` is active the sink fires
            // ONLY if the reaching value carries the required label (e.g.
            // `requires: CONCAT`). A value that reached the sink WITHOUT going
            // through a string-building relabel carries only the source label
            // and is correctly rejected — the precision that taint-labels exist
            // for (see `docs/parity/taint-labels-design.md`).
            if let Some(p) = policy {
                let labels = info.labels.clone().unwrap_or_default();
                if !p.sink_requires.eval(&labels) {
                    return;
                }
            }
            out.push(taint_finding_for_node(node, info, sink_description));
        }
    });
}

/// Fire a [`NodeMatcher::TypedAssignTarget`] sink (`(java.io.File $FILE) = ...`)
/// when `node` is a declaration or assignment whose LHS is a variable of the
/// required declared type AND whose RHS carries taint.
///
/// Two node shapes are handled:
/// - `variable_declarator` (`File f = <rhs>`): the declared type is read off
///   the owning `local_variable_declaration`.
/// - `assignment_expression` (`f = <rhs>`): the LHS is a bare identifier, so
///   its declared type is resolved through `local_types` (built once per scope
///   from the local declarations). A target with no known declared type is
///   skipped (no over-match).
///
/// Faithful by construction: the sink requires BOTH the type match AND a
/// tainted RHS, so a literal RHS or a wrong-type LHS is silent.
fn check_typed_assign_sink(
    node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    policy: Option<&LabelPolicy>,
    state: &TaintState,
    local_types: &HashMap<String, String>,
    out: &mut Vec<TaintFinding>,
) {
    let (decl_type, rhs) = match node.kind() {
        "variable_declarator" => {
            let Some(value) = node.child_by_field_name("value") else {
                return;
            };
            let Some(ty) = local_declarator_type(node, source) else {
                return;
            };
            (ty.to_string(), value)
        }
        "assignment_expression" => {
            let Some(left) = node.child_by_field_name("left") else {
                return;
            };
            let Some(name) = assignment_target_name(left, source) else {
                return;
            };
            let Some(ty) = local_types.get(name) else {
                return;
            };
            let Some(right) = node.child_by_field_name("right") else {
                return;
            };
            (ty.clone(), right)
        }
        _ => return,
    };

    let Some(sink_description) = typed_assign_sink_description(spec, &decl_type) else {
        return;
    };
    // The RHS must carry taint — this is what keeps the sink from firing on
    // every `File f = <literal>` / `x = y`.
    let Some(info) = expression_taint(rhs, source, spec, policy, state) else {
        return;
    };
    if let Some(p) = policy {
        let labels = info.labels.clone().unwrap_or_default();
        if !p.sink_requires.eval(&labels) {
            return;
        }
    }
    out.push(taint_finding_for_node(node, info, sink_description));
}

/// Fire a [`NodeMatcher::MethodArgSink`] sink when `node` is a call to one of
/// the matcher's `methods` AND the argument at the focused `arg_index` carries
/// taint — the positional-`focus-metavariable` sink
/// `request.getSession().setAttribute($NAME, $VALUE)` (focus `$VALUE`).
///
/// Faithful by construction: only the argument at `arg_index` is checked, so a
/// tainted argument at any OTHER position (e.g. a tainted session KEY at index
/// 0) does NOT fire. The receiver context is a droppable narrowing (see the
/// matcher docs), so the sink is bounded by the method-name set and the focused
/// argument position.
fn check_method_arg_sinks(
    node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    policy: Option<&LabelPolicy>,
    state: &TaintState,
    out: &mut Vec<TaintFinding>,
) {
    if node.kind() != "method_invocation" {
        return;
    }
    let Some(method) = call_method_name(node, source) else {
        return;
    };
    let Some(args) = node.child_by_field_name("arguments") else {
        return;
    };
    let mut cursor = args.walk();
    let arg_nodes: Vec<Node<'_>> = args.named_children(&mut cursor).collect();

    for matcher in &spec.sinks {
        let NodeMatcher::MethodArgSink {
            methods,
            arg_index,
            description,
        } = matcher
        else {
            continue;
        };
        if !methods.iter().any(|m| m == method) {
            continue;
        }
        let Some(arg) = arg_nodes.get(*arg_index) else {
            continue;
        };
        let Some(info) = expression_taint(*arg, source, spec, policy, state) else {
            continue;
        };
        if let Some(p) = policy {
            let labels = info.labels.clone().unwrap_or_default();
            if !p.sink_requires.eval(&labels) {
                continue;
            }
        }
        out.push(taint_finding_for_node(node, info, description.clone()));
    }
}

/// Build a map from local-variable name to its declared type text for every
/// `local_variable_declaration` inside `scope`. Used to resolve the declared
/// type of a bare `assignment_expression` LHS (`f = ...`) against a
/// [`NodeMatcher::TypedAssignTarget`] sink.
fn collect_local_var_types(scope: Node<'_>, source: &str) -> HashMap<String, String> {
    let mut types = HashMap::new();
    walk_scope_nodes(scope, source, &mut |node, src| {
        if node.kind() != "local_variable_declaration" {
            return;
        }
        let Some(ty) = node.child_by_field_name("type").map(|t| node_text(t, src)) else {
            return;
        };
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() != "variable_declarator" {
                continue;
            }
            if let Some(name) = child.child_by_field_name("name") {
                types.insert(node_text(name, src).to_string(), ty.to_string());
            }
        }
    });
    types
}

/// If `decl_type` matches a [`NodeMatcher::TypedAssignTarget`] sink in `spec`
/// (by final `.`-segment, so both `File` and `java.io.File` match `File`),
/// return that sink's description.
fn typed_assign_sink_description(spec: &TaintSpec, decl_type: &str) -> Option<String> {
    let seg = type_final_segment(decl_type);
    spec.sinks.iter().find_map(|matcher| match matcher {
        NodeMatcher::TypedAssignTarget {
            type_name,
            description,
        } if type_name == seg => Some(description.clone()),
        _ => None,
    })
}

fn expression_taint(
    node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    policy: Option<&LabelPolicy>,
    state: &TaintState,
) -> Option<TaintInfo> {
    let info = expression_taint_core(node, source, spec, policy, state)?;
    // Conditional relabel: for each policy `Relabel`, a value that carries its
    // `from` label and flows through a string-building node (`+`,
    // `String.format`, `.concat`, `.append`, `new StringBuilder(...)`)
    // additionally acquires the `to` label (e.g. `INPUT → CONCAT`). With no
    // policy it is a no-op.
    Some(relabel_through(node, source, info, policy))
}

fn expression_taint_core(
    node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    policy: Option<&LabelPolicy>,
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
            labels: source_labels(policy),
        });
    }

    if node.kind() == "method_invocation" {
        if let Some(receiver) = node.child_by_field_name("object") {
            if let Some(info) = expression_taint(receiver, source, spec, policy, state) {
                return Some(bump_hops(info));
            }
        }
    }

    if let Some(args) = call_arguments(node) {
        if let Some(info) = expression_taint(args, source, spec, policy, state) {
            return Some(bump_hops(info));
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(info) = expression_taint(child, source, spec, policy, state) {
            return Some(info);
        }
    }
    None
}

// ─── Taint-labels helpers (Semgrep advanced taint, `CONCAT`-family slice) ──

/// The label set a freshly-seeded primary source carries under `policy`:
/// `Some({source_label})` when a policy is active, else `None` (the historical
/// unlabeled behavior).
fn source_labels(policy: Option<&LabelPolicy>) -> Option<BTreeSet<String>> {
    policy.map(|p| {
        let mut set = BTreeSet::new();
        set.insert(p.source_label.clone());
        set
    })
}

/// For each of the policy's [`Relabel`](crate::rules::taint_engine::Relabel)s,
/// add its `to` label to `info` when `info` already carries the `from` label.
/// No-op without a policy or without a matching trigger label.
fn apply_relabel(mut info: TaintInfo, policy: Option<&LabelPolicy>) -> TaintInfo {
    if let Some(p) = policy {
        let additions: Vec<String> = p
            .relabels
            .iter()
            .filter(|r| info.labels.as_ref().is_some_and(|ls| ls.contains(&r.from)))
            .map(|r| r.to.clone())
            .collect();
        if !additions.is_empty() {
            let set = info.labels.get_or_insert_with(BTreeSet::new);
            for a in additions {
                set.insert(a);
            }
        }
    }
    info
}

/// Apply the string-building relabel to `info` when `node` is a string-building
/// node (`+` binary, `String.format`/`String.join`/`.concat`/`.append` call, or
/// a `new StringBuilder(...)`/`new StringBuffer(...)` construction).
fn relabel_through(
    node: Node<'_>,
    source: &str,
    info: TaintInfo,
    policy: Option<&LabelPolicy>,
) -> TaintInfo {
    if policy.is_some() && is_string_building_node(node, source) {
        apply_relabel(info, policy)
    } else {
        info
    }
}

/// True when `node` is a Java string-building expression: a `+` concatenation,
/// a `String.format`/`String.join`/`.concat`/`.append` call, or a
/// `new StringBuilder(...)` / `new StringBuffer(...)` construction. These are
/// exactly the shapes the `CONCAT`-family relabel source/propagator enumerates.
fn is_string_building_node(node: Node<'_>, source: &str) -> bool {
    match node.kind() {
        "binary_expression" => {
            node.child_by_field_name("operator")
                .map(|op| node_text(op, source))
                == Some("+")
        }
        "method_invocation" => matches!(
            call_method_name(node, source),
            Some("format" | "join" | "concat" | "append")
        ),
        "object_creation_expression" => object_creation_type(node, source)
            .map(type_final_segment)
            .is_some_and(|ty| ty == "StringBuilder" || ty == "StringBuffer"),
        _ => false,
    }
}

/// True when `node` is a `$X += ...` compound-assignment (string-building on
/// the target).
fn assignment_is_concat(node: Node<'_>, source: &str) -> bool {
    node.child_by_field_name("operator")
        .map(|op| node_text(op, source))
        == Some("+=")
}

fn classify_source_expr(node: Node<'_>, source: &str, spec: &TaintSpec) -> Option<String> {
    if node.kind() != "method_invocation" {
        return None;
    }
    let method = call_method_name(node, source)?;
    let receiver = call_receiver_text(node, source)?;

    // Receiver-provenance source `$MD.digest(...)` where `$MD` was initialized by
    // `MessageDigest.getInstance("MD5")` (the `md5-used-as-password` rule). The
    // `.digest()` call on an MD5-provenance receiver is the taint origin; a
    // receiver initialized with a strong algorithm (`"SHA-256"`) does NOT match,
    // so the digest bytes stay clean.
    for matcher in &spec.sources {
        if let NodeMatcher::ReceiverProvenanceCall {
            init_receiver,
            init_method,
            init_arg,
            method: call_method,
            description,
        } = matcher
        {
            if method == call_method
                && receiver_has_init_provenance(
                    node,
                    receiver,
                    init_receiver,
                    init_method,
                    init_arg,
                    source,
                )
            {
                return Some(description.clone());
            }
        }
    }

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

/// The nearest enclosing method/constructor/lambda scope of `node`, found by
/// climbing the parent chain. `None` when `node` has no scope ancestor.
fn enclosing_scope(node: Node<'_>) -> Option<Node<'_>> {
    let mut current = node.parent();
    while let Some(n) = current {
        if is_scope_node(n.kind()) {
            return Some(n);
        }
        current = n.parent();
    }
    None
}

/// True when the plain-identifier `receiver` variable is declared in `node`'s
/// enclosing scope with an initializer call
/// `init_receiver.init_method("init_arg")` — the provenance link the
/// `ReceiverProvenanceCall` source requires. The `init_arg` string literal is
/// the discriminator (MD5 vs a strong algorithm), and both the init receiver
/// (matched by final `.`-segment) and the first string-literal argument must
/// match exactly.
fn receiver_has_init_provenance(
    node: Node<'_>,
    receiver: &str,
    init_receiver: &str,
    init_method: &str,
    init_arg: &str,
    source: &str,
) -> bool {
    // A dotted or expression receiver (`a.b.digest()`) is not a plain local
    // variable and cannot carry a tracked initializer.
    if !is_plain_identifier(receiver) {
        return false;
    }
    let Some(scope) = enclosing_scope(node) else {
        return false;
    };
    let body = find_scope_body(scope).unwrap_or(scope);
    let mut found = false;
    walk_scope_nodes(body, source, &mut |n, src| {
        if found || n.kind() != "variable_declarator" {
            return;
        }
        let Some(name_node) = n.child_by_field_name("name") else {
            return;
        };
        if node_text(name_node, src) != receiver {
            return;
        }
        let Some(value) = n.child_by_field_name("value") else {
            return;
        };
        if init_call_matches(value, init_receiver, init_method, init_arg, src) {
            found = true;
        }
    });
    found
}

/// True when `node` is a call `init_receiver.init_method(...)` whose first
/// string-literal argument (quotes stripped) equals `init_arg`. The receiver is
/// matched by its final `.`-segment so both `MessageDigest.getInstance(...)` and
/// `java.security.MessageDigest.getInstance(...)` match `MessageDigest`.
fn init_call_matches(
    node: Node<'_>,
    init_receiver: &str,
    init_method: &str,
    init_arg: &str,
    source: &str,
) -> bool {
    if node.kind() != "method_invocation" {
        return false;
    }
    if call_method_name(node, source) != Some(init_method) {
        return false;
    }
    let Some(receiver) = call_receiver_text(node, source) else {
        return false;
    };
    if type_final_segment(receiver) != init_receiver {
        return false;
    }
    let Some(args) = node.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = args.walk();
    for arg in args.named_children(&mut cursor) {
        if arg.kind() == "string_literal" {
            let text = node_text(arg, source);
            let inner = text
                .strip_prefix('"')
                .and_then(|t| t.strip_suffix('"'))
                .unwrap_or(text);
            return inner == init_arg;
        }
    }
    false
}

/// True when `s` is a single plain Java identifier (no dots, no call/index
/// punctuation) — a local variable name that can carry a tracked initializer.
fn is_plain_identifier(s: &str) -> bool {
    !s.is_empty()
        && !s.contains('.')
        && !s.contains('(')
        && !s.contains('[')
        && s.chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '$')
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
        // Any-receiver method-name regex sink `$OBJ.$M(...)` + `metavariable-regex`
        // pinning `$M` (e.g. the `formatted-sql-string` SQL-exec methods). The
        // receiver type (`Statement`, `PreparedStatement`, …) is a droppable
        // narrowing; the method-name regex is what bounds the match.
        NodeMatcher::MethodNameRegex { regex, .. } => {
            node.kind() == "method_invocation"
                && call_method_name(node, source).is_some_and(|m| regex.is_match(m))
        }
        // Bare-metavar callee regex sink `$F(...)` + `metavariable-regex` pinning
        // `$F` — matched against the full callee text.
        NodeMatcher::CallRegex { regex, .. } if node.kind() == "method_invocation" => {
            call_full_callee_text(node, source).is_some_and(|c| regex.is_match(&c))
        }
        // Any-method call on a concrete root receiver `recv.$M(...)`.
        NodeMatcher::ReceiverCall { receiver, .. } if node.kind() == "method_invocation" => {
            call_receiver_text(node, source)
                .is_some_and(|r| r.split('.').next().unwrap_or(r) == receiver)
        }
        _ => false,
    }
}

/// The full callee text of a method invocation (`receiver.method` or bare
/// `method`), used to test a `CallRegex` sink against the whole callee.
fn call_full_callee_text(node: Node<'_>, source: &str) -> Option<String> {
    let method = call_method_name(node, source)?;
    match call_receiver_text(node, source) {
        Some(recv) => Some(format!("{recv}.{method}")),
        None => Some(method.to_string()),
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
    policy: Option<&LabelPolicy>,
    state: &TaintState,
) -> Option<TaintInfo> {
    call_arguments(node).and_then(|args| expression_taint(args, source, spec, policy, state))
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
        source_range: None,
        rule_id_hint: None,
        hops: source_info.hops.max(1),
    }
}

fn walk_scope_nodes(scope: Node<'_>, source: &str, visitor: &mut impl FnMut(Node<'_>, &str)) {
    walk_taint_scope_nodes(scope, source, is_scope_node, visitor);
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

/// The declared type text of a `formal_parameter` / `spread_parameter`, e.g.
/// `HttpServletRequest`, `javax.servlet.http.HttpServletRequest`, `String[]`.
fn formal_parameter_type<'a>(node: Node<'a>, source: &'a str) -> Option<&'a str> {
    node.child_by_field_name("type")
        .map(|ty| node_text(ty, source))
}

/// The declared type text of the `local_variable_declaration` that owns a
/// `variable_declarator`, or `None` when the declarator is not a local (e.g.
/// a field). Used to seed typed-metavariable sources on locals.
fn local_declarator_type<'a>(declarator: Node<'a>, source: &'a str) -> Option<&'a str> {
    let parent = declarator.parent()?;
    if parent.kind() != "local_variable_declaration" {
        return None;
    }
    parent
        .child_by_field_name("type")
        .map(|ty| node_text(ty, source))
}

/// If `decl_type` matches a `TypedName` source in `spec` (by final `.`-segment,
/// so both `HttpServletRequest` and `javax.servlet.http.HttpServletRequest`
/// match `HttpServletRequest`), return that source's description.
fn typed_source_description(spec: &TaintSpec, decl_type: &str) -> Option<String> {
    let seg = type_final_segment(decl_type);
    spec.sources.iter().find_map(|matcher| match matcher {
        NodeMatcher::TypedName {
            type_name,
            description,
        } if type_name == seg => Some(description.clone()),
        _ => None,
    })
}

/// The final `.`-segment of a declared type, with array/generic suffixes
/// stripped: `javax.servlet.http.HttpServletRequest` and `HttpServletRequest`
/// both yield `HttpServletRequest`; `Cookie[]` yields `Cookie`.
fn type_final_segment(type_text: &str) -> &str {
    let mut base = type_text.trim();
    if base.ends_with('>') {
        if let Some(lt) = base.find('<') {
            base = base[..lt].trim_end();
        }
    }
    while let Some(stripped) = base.strip_suffix("[]") {
        base = stripped.trim_end();
    }
    base.rsplit('.').next().unwrap_or(base).trim()
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

    fn summaries(src: &str) -> Vec<FunctionTaintSummary> {
        let Some(tree) = parse_file(src, Language::Java) else {
            panic!("Java fixture should parse");
        };
        let specs = java_taint_rule_specs();
        extract_cross_file_summaries(tree.root_node(), src, None, &specs)
    }

    #[test]
    fn cross_file_summary_records_param_to_sink() {
        let src = r#"
class QueryHelper {
    static Statement stmt;
    public static void runQuery(String term) throws Exception {
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + term + "'");
    }
}
"#;
        let found = summaries(src);
        let helper = found
            .iter()
            .find(|s| s.name == "runQuery")
            .expect("runQuery should be summarized");
        let flow = helper
            .params_to_sink
            .iter()
            .find(|f| f.param_index == 0)
            .expect("param 0 should reach a sink");
        assert_eq!(flow.sink_rule_id, "java/taint-sql-injection");
    }

    #[test]
    fn cross_file_summary_records_param_to_return() {
        let src = r#"
class Passthrough {
    public static String clean(String value) {
        return value.trim();
    }
}
"#;
        let found = summaries(src);
        let helper = found
            .iter()
            .find(|s| s.name == "clean")
            .expect("clean should be summarized");
        assert!(
            helper.params_to_return.contains(&0),
            "param 0 should flow to the return value: {helper:?}"
        );
    }

    #[test]
    fn cross_file_summary_skips_methods_with_no_flow() {
        // `log` neither sinks nor returns its parameter, so it must not be
        // summarized at all.
        let src = r#"
class Plain {
    public static void log(String message) {
        System.out.println("constant");
    }
}
"#;
        let found = summaries(src);
        assert!(
            found.iter().all(|s| s.name != "log"),
            "method with no param flow should not be summarized: {found:?}"
        );
    }

    #[test]
    fn compose_lifts_forwarded_param_to_cross_file_sink() {
        // Middle helper `process` forwards its parameter into a same-package
        // helper `runQuery` that sinks it. Its base summary records nothing;
        // composing it against `runQuery`'s summary must lift the cross-file
        // sink into `process`'s own params_to_sink (the A->f->g->sink hop).
        let sink_src = r#"
class QueryHelper {
    static Statement stmt;
    static void runQuery(String term) throws Exception {
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + term + "'");
    }
}
"#;
        let middle_src = r#"
class Service {
    static void process(String term) throws Exception {
        QueryHelper.runQuery(term);
    }
}
"#;
        let sink_path = PathBuf::from("QueryHelper.java");
        let mut map = CrossFileSummaryMap::new();
        map.insert(sink_path.clone(), summaries(sink_src));

        // Sanity: the base summary of `process` records no sink flow.
        assert!(
            summaries(middle_src)
                .iter()
                .find(|s| s.name == "process")
                .is_none_or(|s| s.params_to_sink.is_empty()),
            "base summary of process must not record a sink flow"
        );

        let tree = parse_file(middle_src, Language::Java).expect("parse middle");
        let specs = java_taint_rule_specs();
        let allowed: HashSet<String> = specs.iter().map(|(id, _)| id.to_string()).collect();
        let composed = compose_cross_file_summaries(
            tree.root_node(),
            middle_src,
            None,
            &specs,
            std::slice::from_ref(&sink_path),
            &map,
            &allowed,
        );
        let process = composed
            .iter()
            .find(|s| s.name == "process")
            .expect("process should gain a composed summary");
        let flow = process
            .params_to_sink
            .iter()
            .find(|f| f.param_index == 0)
            .expect("param 0 should reach the cross-file sink");
        assert_eq!(flow.sink_rule_id, "java/taint-sql-injection");
    }

    #[test]
    fn compose_is_taint_sensitive_across_the_hop() {
        // The middle helper replaces its parameter with a constant before the
        // cross-file call, so the composed summary must NOT record a sink flow
        // (the negative multi-hop shape — no configured Java sanitizer needed).
        let sink_src = r#"
class QueryHelper {
    static Statement stmt;
    static void runQuery(String term) throws Exception {
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + term + "'");
    }
}
"#;
        let middle_src = r#"
class Service {
    static void process(String term) throws Exception {
        String safe = "constant";
        QueryHelper.runQuery(safe);
    }
}
"#;
        let sink_path = PathBuf::from("QueryHelper.java");
        let mut map = CrossFileSummaryMap::new();
        map.insert(sink_path.clone(), summaries(sink_src));

        let tree = parse_file(middle_src, Language::Java).expect("parse middle");
        let specs = java_taint_rule_specs();
        let allowed: HashSet<String> = specs.iter().map(|(id, _)| id.to_string()).collect();
        let composed = compose_cross_file_summaries(
            tree.root_node(),
            middle_src,
            None,
            &specs,
            std::slice::from_ref(&sink_path),
            &map,
            &allowed,
        );
        assert!(
            composed.iter().all(|s| s.params_to_sink.is_empty()),
            "a clean (constant) argument must not compose a sink flow: {composed:?}"
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
