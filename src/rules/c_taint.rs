//! Intraprocedural, flow-insensitive taint analysis for C.
//!
//! Fifth sibling to `python_taint`, `javascript_taint`, `go_taint`,
//! and `kotlin_taint`. Exposes the same public surface -- `TaintSpec`,
//! `NodeMatcher`, `TaintFinding`, `analyze_tree` -- so callers can write
//! declarative `(sources, sinks, sanitizers)` specs the same way they
//! do for the other languages.
//!
//! # Scope (mirrors the other engines)
//!
//! - **Per function.** Each `function_definition` body is analyzed
//!   independently.
//! - **Per file.** No cross-file analysis (v1).
//! - **Flow-insensitive.** Two propagation passes; sources seed a name
//!   set, the analyzer transitively taints any declaration or assignment
//!   whose initializer/RHS references a tainted name or a tainted
//!   source expression.
//! - **String concat propagation** -- binary `+` or function calls
//!   that wrap tainted arguments propagate taint.
//! - **No alias table.** C has no import system; `#include` is textual.
//!   All callee names are matched as-is.
//!
//! # Target vulnerability classes
//!
//! - **Format string** -- `printf(user_input)` where the format argument
//!   is tainted.
//! - **Command injection** -- `system()`, `popen()`, `exec*()` family.
//! - **Buffer overflow** -- `strcpy()`, `strcat()`, `memcpy()` with
//!   tainted source or tainted length.
//! - **SQL injection** -- string-building that flows into `sqlite3_exec`
//!   or `mysql_query`.
//!
//! # Sources
//!
//! `read()`, `recv()`, `fgets()`, `scanf()`, `getenv()`, `fread()`,
//! `recvfrom()`, `recvmsg()`, `fgetc()`, `getchar()`, `gets()`.
//! The `argv` parameter name is also treated as a source.
//!
//! # Sanitizers
//!
//! Bounds-checking patterns (`snprintf`, `strlcpy`, `strlcat`,
//! `strncpy`, `strncat`) collapse taint to clean.

use crate::rules::common::{walk_tree, AliasTable};
pub use crate::rules::taint_engine::{NodeMatcher, TaintFinding, TaintSpec};
use std::collections::HashSet;
use tree_sitter::Node;

// -- Public API --------------------------------------------------------------

/// Run the C taint engine over every function body inside `root` and
/// return one [`TaintFinding`] per source->sink flow.
///
/// The `aliases` argument is unused for C (no import system) but kept
/// for shape parity with the other engines.
pub fn analyze_tree(
    root: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    _aliases: Option<&AliasTable>,
) -> Vec<TaintFinding> {
    let mut findings = Vec::new();
    walk_tree(root, source, &mut |node, src| {
        if node.kind() == "function_definition" {
            analyze_scope(node, src, spec, &mut findings);
        }
    });
    findings
}

/// All C taint rule IDs paired with their specs.
///
/// Consumed by [`crate::rules::builtin_taint_specs_for_language`].
pub fn c_taint_rule_specs() -> Vec<(&'static str, TaintSpec)> {
    vec![
        ("c/taint-format-string", format_string_spec()),
        ("c/taint-command-injection", command_injection_spec()),
        ("c/taint-buffer-overflow", buffer_overflow_spec()),
        ("c/taint-sql-injection", sql_injection_spec()),
    ]
}

/// Shared sources for every C taint rule.
pub fn c_taint_sources() -> Vec<NodeMatcher> {
    vec![
        // POSIX / libc input functions
        NodeMatcher::Call {
            canonical: "read".into(),
            description: "read() — POSIX file/socket read".into(),
        },
        NodeMatcher::Call {
            canonical: "recv".into(),
            description: "recv() — socket receive".into(),
        },
        NodeMatcher::Call {
            canonical: "recvfrom".into(),
            description: "recvfrom() — socket receive with address".into(),
        },
        NodeMatcher::Call {
            canonical: "recvmsg".into(),
            description: "recvmsg() — socket message receive".into(),
        },
        NodeMatcher::Call {
            canonical: "fgets".into(),
            description: "fgets() — buffered input".into(),
        },
        NodeMatcher::Call {
            canonical: "fread".into(),
            description: "fread() — binary file read".into(),
        },
        NodeMatcher::Call {
            canonical: "fgetc".into(),
            description: "fgetc() — single character read".into(),
        },
        NodeMatcher::Call {
            canonical: "getchar".into(),
            description: "getchar() — stdin character read".into(),
        },
        NodeMatcher::Call {
            canonical: "gets".into(),
            description: "gets() — unsafe stdin read".into(),
        },
        NodeMatcher::Call {
            canonical: "scanf".into(),
            description: "scanf() — formatted stdin input".into(),
        },
        NodeMatcher::Call {
            canonical: "fscanf".into(),
            description: "fscanf() — formatted file input".into(),
        },
        NodeMatcher::Call {
            canonical: "getenv".into(),
            description: "getenv() — environment variable".into(),
        },
        // `argv` parameter -- main(int argc, char **argv)
        NodeMatcher::ParamName {
            names: vec!["argv".into()],
            description: "argv — command-line arguments".into(),
        },
    ]
}

// -- Rule specs --------------------------------------------------------------

fn format_string_spec() -> TaintSpec {
    TaintSpec {
        sources: c_taint_sources(),
        sinks: vec![
            NodeMatcher::Call {
                canonical: "printf".into(),
                description: "printf() with tainted format string".into(),
            },
            NodeMatcher::Call {
                canonical: "fprintf".into(),
                description: "fprintf() with tainted format string".into(),
            },
            NodeMatcher::Call {
                canonical: "sprintf".into(),
                description: "sprintf() with tainted format string".into(),
            },
            NodeMatcher::Call {
                canonical: "snprintf".into(),
                description: "snprintf() with tainted format string".into(),
            },
            NodeMatcher::Call {
                canonical: "syslog".into(),
                description: "syslog() with tainted format string".into(),
            },
        ],
        sanitizers: vec![],
    }
}

fn command_injection_spec() -> TaintSpec {
    TaintSpec {
        sources: c_taint_sources(),
        sinks: vec![
            NodeMatcher::Call {
                canonical: "system".into(),
                description: "system() with tainted argument".into(),
            },
            NodeMatcher::Call {
                canonical: "popen".into(),
                description: "popen() with tainted argument".into(),
            },
            NodeMatcher::Call {
                canonical: "execl".into(),
                description: "execl() with tainted argument".into(),
            },
            NodeMatcher::Call {
                canonical: "execlp".into(),
                description: "execlp() with tainted argument".into(),
            },
            NodeMatcher::Call {
                canonical: "execle".into(),
                description: "execle() with tainted argument".into(),
            },
            NodeMatcher::Call {
                canonical: "execv".into(),
                description: "execv() with tainted argument".into(),
            },
            NodeMatcher::Call {
                canonical: "execvp".into(),
                description: "execvp() with tainted argument".into(),
            },
            NodeMatcher::Call {
                canonical: "execve".into(),
                description: "execve() with tainted argument".into(),
            },
        ],
        sanitizers: vec![],
    }
}

fn buffer_overflow_spec() -> TaintSpec {
    TaintSpec {
        sources: c_taint_sources(),
        sinks: vec![
            NodeMatcher::Call {
                canonical: "strcpy".into(),
                description: "strcpy() with tainted source — use strlcpy or strncpy".into(),
            },
            NodeMatcher::Call {
                canonical: "strcat".into(),
                description: "strcat() with tainted source — use strlcat or strncat".into(),
            },
            NodeMatcher::Call {
                canonical: "memcpy".into(),
                description: "memcpy() with tainted argument".into(),
            },
            NodeMatcher::Call {
                canonical: "memmove".into(),
                description: "memmove() with tainted argument".into(),
            },
            NodeMatcher::Call {
                canonical: "gets".into(),
                description: "gets() — always a buffer overflow risk".into(),
            },
        ],
        sanitizers: vec![
            NodeMatcher::Call {
                canonical: "strlcpy".into(),
                description: "strlcpy() — bounds-checked copy".into(),
            },
            NodeMatcher::Call {
                canonical: "strlcat".into(),
                description: "strlcat() — bounds-checked concatenation".into(),
            },
            NodeMatcher::Call {
                canonical: "strncpy".into(),
                description: "strncpy() — length-limited copy".into(),
            },
            NodeMatcher::Call {
                canonical: "strncat".into(),
                description: "strncat() — length-limited concatenation".into(),
            },
            NodeMatcher::Call {
                canonical: "snprintf".into(),
                description: "snprintf() — bounds-checked format".into(),
            },
        ],
    }
}

fn sql_injection_spec() -> TaintSpec {
    TaintSpec {
        sources: c_taint_sources(),
        sinks: vec![
            NodeMatcher::Call {
                canonical: "sqlite3_exec".into(),
                description: "sqlite3_exec() with tainted query".into(),
            },
            NodeMatcher::Call {
                canonical: "mysql_query".into(),
                description: "mysql_query() with tainted query".into(),
            },
            NodeMatcher::Call {
                canonical: "mysql_real_query".into(),
                description: "mysql_real_query() with tainted query".into(),
            },
            NodeMatcher::Call {
                canonical: "PQexec".into(),
                description: "PQexec() with tainted query".into(),
            },
        ],
        sanitizers: vec![
            // Parameterized query APIs act as sanitizers for the SQL
            // injection rule because they separate data from query
            // structure.
            NodeMatcher::Call {
                canonical: "sqlite3_prepare_v2".into(),
                description: "sqlite3_prepare_v2() — parameterized query".into(),
            },
            NodeMatcher::Call {
                canonical: "mysql_stmt_prepare".into(),
                description: "mysql_stmt_prepare() — parameterized query".into(),
            },
            NodeMatcher::Call {
                canonical: "PQexecParams".into(),
                description: "PQexecParams() — parameterized query".into(),
            },
        ],
    }
}

// -- Internals ---------------------------------------------------------------

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
    let body = scope_node
        .child_by_field_name("body")
        .unwrap_or(scope_node);

    // Collect sources from the body (call expressions that are sources)
    // and from the function's parameter list (argv).
    let mut sources = collect_body_sources(body, source, spec);
    collect_param_sources(scope_node, source, spec, &mut sources);

    if sources.is_empty() {
        return;
    }

    let tainted = build_tainted_set(body, source, &sources, spec);
    if tainted.is_empty() {
        return;
    }

    let sinks = find_sinks(body, source, spec, &tainted);
    if sinks.is_empty() {
        return;
    }

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
            hops: 0,
        });
    }
}

/// Walk the function body and collect taint sources: call expressions
/// whose callee matches one of the spec's `Call` sources, where the
/// result is assigned to a variable.
fn collect_body_sources(scope: Node<'_>, source: &str, spec: &TaintSpec) -> Vec<TaintSource> {
    let mut sources = Vec::new();
    walk_tree(scope, source, &mut |n, s| {
        // `type var = source_call(...);` -- declaration
        if n.kind() == "declaration" {
            if let Some((var_name, init_node)) = extract_declarator_init(n, s) {
                if let Some(desc) = classify_source_expr(init_node, s, spec) {
                    sources.push(TaintSource {
                        var_name: Some(var_name),
                        description: desc,
                        line: n.start_position().row + 1,
                    });
                }
            }
        }
        // `var = source_call(...);` -- expression_statement with assignment
        if n.kind() == "expression_statement" {
            if let Some(expr) = n.child(0) {
                if expr.kind() == "assignment_expression" {
                    if let (Some(left), Some(right)) = (
                        expr.child_by_field_name("left"),
                        expr.child_by_field_name("right"),
                    ) {
                        if left.kind() == "identifier" {
                            let var_name = &s[left.byte_range()];
                            if let Some(desc) = classify_source_expr(right, s, spec) {
                                sources.push(TaintSource {
                                    var_name: Some(var_name.to_string()),
                                    description: desc,
                                    line: n.start_position().row + 1,
                                });
                            }
                        }
                    }
                }
            }
        }
        // Bare call as a statement: `read(fd, buf, sizeof(buf));`
        // Here, for read/recv/fgets/scanf, the *buffer* parameter is the tainted one.
        if n.kind() == "call_expression" {
            if let Some(callee) = call_function_name(n, s) {
                let buf_param_callee = matches!(
                    callee,
                    "read" | "recv" | "recvfrom" | "recvmsg" | "fgets" | "fread"
                );
                let scan_callee = matches!(callee, "scanf" | "fscanf");
                if buf_param_callee || scan_callee {
                    if let Some(args) = n.child_by_field_name("arguments") {
                        let arg_names = collect_arg_identifiers(args, s);
                        // For read/recv: second argument is the buffer
                        // For fgets: first argument is the buffer
                        // For scanf/fscanf: arguments after the format string
                        let target_args = if matches!(callee, "fgets") {
                            arg_names.first().cloned().into_iter().collect::<Vec<_>>()
                        } else if matches!(callee, "read" | "recv" | "recvfrom" | "recvmsg") {
                            arg_names.get(1).cloned().into_iter().collect::<Vec<_>>()
                        } else if matches!(callee, "fread") {
                            arg_names.first().cloned().into_iter().collect::<Vec<_>>()
                        } else if scan_callee {
                            // All args after the format string
                            let start = if callee == "fscanf" { 2 } else { 1 };
                            arg_names.get(start..).unwrap_or_default().to_vec()
                        } else {
                            vec![]
                        };
                        let desc_text = spec
                            .sources
                            .iter()
                            .find_map(|m| {
                                if let NodeMatcher::Call {
                                    canonical,
                                    description,
                                } = m
                                {
                                    if canonical == callee {
                                        return Some(description.clone());
                                    }
                                }
                                None
                            })
                            .unwrap_or_else(|| format!("{}()", callee));
                        for arg_name in target_args {
                            sources.push(TaintSource {
                                var_name: Some(arg_name),
                                description: desc_text.clone(),
                                line: n.start_position().row + 1,
                            });
                        }
                    }
                }
            }
        }
    });
    sources
}

/// Classify an expression node as a taint source if it matches a
/// `Call` source in the spec. Returns the source description.
fn classify_source_expr(node: Node<'_>, src: &str, spec: &TaintSpec) -> Option<String> {
    if node.kind() == "call_expression" {
        let callee = call_function_name(node, src)?;
        for matcher in &spec.sources {
            if let NodeMatcher::Call {
                canonical,
                description,
            } = matcher
            {
                if callee == canonical.as_str() {
                    return Some(description.clone());
                }
            }
        }
    }
    // Subscript on argv: `argv[1]`
    if node.kind() == "subscript_expression" {
        if let Some(arg) = node.child_by_field_name("argument") {
            let text = &src[arg.byte_range()];
            if text == "argv" {
                return Some("argv — command-line arguments".to_string());
            }
        }
    }
    None
}

/// Collect parameter taint sources. Matches `argv` parameter names and
/// any other `ParamName` matchers in the spec.
fn collect_param_sources(
    func_node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    out: &mut Vec<TaintSource>,
) {
    let Some(declarator) = func_node.child_by_field_name("declarator") else {
        return;
    };
    // The declarator is a `function_declarator` containing a `parameter_list`.
    let Some(params) = declarator.child_by_field_name("parameters") else {
        return;
    };

    let mut cursor = params.walk();
    for child in params.children(&mut cursor) {
        if child.kind() != "parameter_declaration" {
            continue;
        }
        // The parameter declarator may be an identifier or a pointer_declarator.
        let param_name = extract_param_name(child, source);
        if let Some(name) = param_name {
            for matcher in &spec.sources {
                if let NodeMatcher::ParamName { names, description } = matcher {
                    if names.iter().any(|n| n == &name) {
                        out.push(TaintSource {
                            var_name: Some(name.clone()),
                            description: description.clone(),
                            line: child.start_position().row + 1,
                        });
                        break;
                    }
                }
            }
        }
    }
}

/// Extract the parameter name from a `parameter_declaration`.
/// Handles both `int x` and `char **argv` (pointer declarator chains).
fn extract_param_name(param: Node<'_>, source: &str) -> Option<String> {
    let decl = param.child_by_field_name("declarator")?;
    Some(innermost_identifier(decl, source)?.to_string())
}

/// Drill into pointer_declarator / array_declarator chains to find the
/// innermost identifier.
fn innermost_identifier<'a>(mut node: Node<'_>, source: &'a str) -> Option<&'a str> {
    loop {
        match node.kind() {
            "identifier" => return Some(&source[node.byte_range()]),
            "pointer_declarator" | "array_declarator" | "parenthesized_declarator" => {
                node = node.child_by_field_name("declarator")?;
            }
            _ => return None,
        }
    }
}

/// Build the tainted set by transitively propagating taint through
/// declarations and assignments. Two passes to handle chained
/// assignments like `char *a = source; char *b = a; f(b);`.
fn build_tainted_set(
    scope: Node<'_>,
    source: &str,
    sources: &[TaintSource],
    spec: &TaintSpec,
) -> HashSet<String> {
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
            // Declaration: `type var = expr;`
            if n.kind() == "declaration" {
                if let Some((var_name, init_node)) = extract_declarator_init(n, s) {
                    if !tainted.contains(&var_name)
                        && expr_uses_tainted(init_node, s, &tainted, spec)
                    {
                        tainted.insert(var_name);
                    }
                }
            }
            // Assignment expression: `var = expr;`
            if n.kind() == "expression_statement" {
                if let Some(expr) = n.child(0) {
                    if expr.kind() == "assignment_expression" {
                        if let (Some(left), Some(right)) = (
                            expr.child_by_field_name("left"),
                            expr.child_by_field_name("right"),
                        ) {
                            if left.kind() == "identifier" {
                                let left_text = s[left.byte_range()].to_string();
                                if !tainted.contains(&left_text)
                                    && expr_uses_tainted(right, s, &tainted, spec)
                                {
                                    tainted.insert(left_text);
                                }
                            }
                        }
                    }
                }
            }
            // Buffer-writing calls: `sprintf(dest, fmt, tainted)`,
            // `strcpy(dest, tainted)`, `memcpy(dest, tainted, n)`, etc.
            // If any non-destination argument is tainted, the destination
            // buffer name becomes tainted. Sanitizer calls are excluded:
            // `strncpy`/`strlcpy`/etc. are safe-copy functions that
            // collapse taint rather than propagating it.
            if n.kind() == "call_expression" {
                if let Some(callee) = call_function_name(n, s) {
                    let is_sanitizer = spec.sanitizers.iter().any(|san| {
                        if let NodeMatcher::Call { canonical, .. } = san {
                            callee == canonical.as_str()
                        } else {
                            false
                        }
                    });
                    if is_buffer_writing_call(callee) && !is_sanitizer {
                        if let Some(args) = n.child_by_field_name("arguments") {
                            let arg_names = collect_arg_identifiers(args, s);
                            // The first argument is the destination buffer.
                            if let Some(dest_name) = arg_names.first() {
                                if !dest_name.is_empty() && !tainted.contains(dest_name) {
                                    // Check if any argument after the destination is tainted.
                                    let non_dest_tainted = arg_names.iter().skip(1).any(|name| {
                                        !name.is_empty() && tainted.contains(name)
                                    });
                                    if non_dest_tainted {
                                        tainted.insert(dest_name.clone());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
    }
    tainted
}

/// Recursively check whether `node` references any tainted variable
/// or is itself a taint source expression. Also handles string concat
/// via `strcat`/`sprintf` wrapping patterns, and passes through
/// non-sanitizer call wrappers.
fn expr_uses_tainted(
    node: Node<'_>,
    src: &str,
    tainted: &HashSet<String>,
    spec: &TaintSpec,
) -> bool {
    if node.kind() == "identifier" {
        let name = &src[node.byte_range()];
        return tainted.contains(name);
    }
    // `argv[N]` subscript
    if node.kind() == "subscript_expression" {
        if let Some(arg) = node.child_by_field_name("argument") {
            let text = &src[arg.byte_range()];
            if tainted.contains(text) {
                return true;
            }
        }
    }
    // String literal with embedded tainted variable (rare in C, but
    // handle concatenation operators).
    if node.kind() == "concatenated_string" {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if expr_uses_tainted(child, src, tainted, spec) {
                return true;
            }
        }
        return false;
    }
    // Call expression: if it's a sanitizer, stop propagation.
    if node.kind() == "call_expression" {
        if let Some(callee) = call_function_name(node, src) {
            for san in &spec.sanitizers {
                if let NodeMatcher::Call { canonical, .. } = san {
                    if callee == canonical.as_str() {
                        return false;
                    }
                }
            }
        }
        // Non-sanitizer call: if any argument is tainted, the result is.
        if let Some(args) = node.child_by_field_name("arguments") {
            let mut cursor = args.walk();
            for child in args.named_children(&mut cursor) {
                if expr_uses_tainted(child, src, tainted, spec) {
                    return true;
                }
            }
        }
        return false;
    }
    // Binary expression (e.g., pointer arithmetic, though string concat
    // in C usually happens through function calls).
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if expr_uses_tainted(child, src, tainted, spec) {
            return true;
        }
    }
    false
}

/// Walk `scope` and emit a sink for every call expression whose callee
/// matches the spec's sink list AND whose arguments reference a tainted
/// variable.
///
/// For format-string sinks (`printf`, `fprintf`, `sprintf`, `snprintf`,
/// `syslog`), only the *format argument* is checked (the first
/// non-file-descriptor argument). If the format argument is a string
/// literal, the call is safe even if later arguments are tainted.
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
        let Some(callee) = call_function_name(n, s) else {
            return;
        };
        let Some(args) = n.child_by_field_name("arguments") else {
            return;
        };

        for matcher in &spec.sinks {
            if let NodeMatcher::Call {
                canonical,
                description,
            } = matcher
            {
                if callee != canonical.as_str() {
                    continue;
                }

                // Format-string sinks: only flag when the FORMAT arg is tainted
                if is_format_string_sink(callee) {
                    let fmt_idx = format_arg_index(callee);
                    let mut cursor = args.walk();
                    let arg_nodes: Vec<Node<'_>> = args.named_children(&mut cursor).collect();
                    if let Some(fmt_arg) = arg_nodes.get(fmt_idx) {
                        // If the format argument is a string literal, it's safe.
                        if fmt_arg.kind() == "string_literal" {
                            continue;
                        }
                        if expr_uses_tainted_simple(*fmt_arg, s, tainted) {
                            sinks.push(TaintSink {
                                start_byte: n.start_byte(),
                                end_byte: n.end_byte(),
                                description: description.clone(),
                            });
                        }
                    }
                } else {
                    // General sinks: any tainted argument triggers.
                    if expr_uses_tainted_simple(args, s, tainted) {
                        sinks.push(TaintSink {
                            start_byte: n.start_byte(),
                            end_byte: n.end_byte(),
                            description: description.clone(),
                        });
                    }
                }
                return;
            }
        }
    });
    sinks
}

/// Simplified taint check that only looks at identifier references
/// (no sanitizer awareness). Used in sink detection where we've
/// already propagated taint with sanitizer handling.
fn expr_uses_tainted_simple(node: Node<'_>, src: &str, tainted: &HashSet<String>) -> bool {
    if node.kind() == "identifier" {
        let name = &src[node.byte_range()];
        return tainted.contains(name);
    }
    if node.kind() == "subscript_expression" {
        if let Some(arg) = node.child_by_field_name("argument") {
            let text = &src[arg.byte_range()];
            if tainted.contains(text) {
                return true;
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if expr_uses_tainted_simple(child, src, tainted) {
            return true;
        }
    }
    false
}

/// Whether a callee is a format-string function where only the format
/// argument should be checked (not arbitrary arguments).
fn is_format_string_sink(callee: &str) -> bool {
    matches!(
        callee,
        "printf" | "fprintf" | "sprintf" | "snprintf" | "syslog"
    )
}

/// Index of the format argument for format-string sinks.
/// - `printf(fmt, ...)` -> 0
/// - `fprintf(stream, fmt, ...)` -> 1
/// - `sprintf(buf, fmt, ...)` -> 1
/// - `snprintf(buf, size, fmt, ...)` -> 2
/// - `syslog(priority, fmt, ...)` -> 1
fn format_arg_index(callee: &str) -> usize {
    match callee {
        "printf" => 0,
        "fprintf" | "sprintf" | "syslog" => 1,
        "snprintf" => 2,
        _ => 0,
    }
}

/// Whether a call writes into its first argument (destination buffer).
/// Used by `build_tainted_set` to propagate taint through calls like
/// `sprintf(dest, fmt, tainted)`.
fn is_buffer_writing_call(callee: &str) -> bool {
    matches!(
        callee,
        "sprintf"
            | "snprintf"
            | "strcpy"
            | "strncpy"
            | "strcat"
            | "strncat"
            | "strlcpy"
            | "strlcat"
            | "memcpy"
            | "memmove"
    )
}

// -- C AST helpers -----------------------------------------------------------

/// Extract the callee name from a `call_expression`. Only handles bare
/// identifier callees (no function pointers or member access).
fn call_function_name<'a>(node: Node<'a>, src: &'a str) -> Option<&'a str> {
    if node.kind() != "call_expression" {
        return None;
    }
    let func = node.child_by_field_name("function")?;
    if func.kind() == "identifier" {
        return Some(&src[func.byte_range()]);
    }
    None
}

/// Collect identifier names from an argument list.
fn collect_arg_identifiers(args: Node<'_>, src: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut cursor = args.walk();
    for child in args.named_children(&mut cursor) {
        if child.kind() == "identifier" {
            names.push(src[child.byte_range()].to_string());
        } else if child.kind() == "pointer_expression" || child.kind() == "cast_expression" {
            // `&buf` or `(char *)buf` — drill into the operand
            if let Some(inner) = find_innermost_identifier(child, src) {
                names.push(inner.to_string());
            }
        } else {
            // Push an empty placeholder to keep positional indexing correct.
            names.push(String::new());
        }
    }
    names
}

/// Find the innermost identifier in a unary/cast expression chain.
fn find_innermost_identifier<'a>(node: Node<'_>, src: &'a str) -> Option<&'a str> {
    if node.kind() == "identifier" {
        return Some(&src[node.byte_range()]);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(id) = find_innermost_identifier(child, src) {
            return Some(id);
        }
    }
    None
}

/// Extract `(var_name, init_expression_node)` from a `declaration` node.
/// Handles `type *var = expr;` patterns.
fn extract_declarator_init<'a>(
    decl: Node<'a>,
    src: &'a str,
) -> Option<(String, Node<'a>)> {
    let mut cursor = decl.walk();
    for child in decl.children(&mut cursor) {
        if child.kind() == "init_declarator" {
            let declarator = child.child_by_field_name("declarator")?;
            let value = child.child_by_field_name("value")?;
            let name = innermost_identifier(declarator, src)?;
            return Some((name.to_string(), value));
        }
    }
    None
}

/// Convert a byte offset into the source to a `(line, column)` pair.
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
        let tree = parse_file(src, Language::C).expect("parse");
        analyze_tree(tree.root_node(), src, spec, None)
    }

    #[test]
    fn format_string_via_getenv() {
        let src = r#"
#include <stdio.h>
#include <stdlib.h>

void handler() {
    char *input = getenv("USER_INPUT");
    printf(input);
}
"#;
        let findings = analyze(src, &format_string_spec());
        assert!(
            !findings.is_empty(),
            "should detect printf with tainted format string: {:?}",
            findings
        );
    }

    #[test]
    fn format_string_safe_literal() {
        let src = r#"
#include <stdio.h>
#include <stdlib.h>

void handler() {
    char *input = getenv("USER_INPUT");
    printf("%s", input);
}
"#;
        let findings = analyze(src, &format_string_spec());
        assert!(
            findings.is_empty(),
            "printf with literal format string should be safe: {:?}",
            findings
        );
    }

    #[test]
    fn command_injection_via_system() {
        let src = r#"
#include <stdlib.h>

void handler() {
    char *cmd = getenv("CMD");
    system(cmd);
}
"#;
        let findings = analyze(src, &command_injection_spec());
        assert!(
            !findings.is_empty(),
            "should detect system() with tainted argument: {:?}",
            findings
        );
    }

    #[test]
    fn buffer_overflow_via_strcpy() {
        let src = r#"
#include <string.h>
#include <stdio.h>

void handler() {
    char buf[256];
    char dest[64];
    fgets(buf, sizeof(buf), stdin);
    strcpy(dest, buf);
}
"#;
        let findings = analyze(src, &buffer_overflow_spec());
        assert!(
            !findings.is_empty(),
            "should detect strcpy with tainted source: {:?}",
            findings
        );
    }

    #[test]
    fn buffer_overflow_sanitized_by_strncpy() {
        let src = r#"
#include <string.h>
#include <stdio.h>

void handler() {
    char buf[256];
    char dest[64];
    fgets(buf, sizeof(buf), stdin);
    char *safe = strncpy(dest, buf, sizeof(dest) - 1);
    strcpy(dest, safe);
}
"#;
        let findings = analyze(src, &buffer_overflow_spec());
        assert!(
            findings.is_empty(),
            "strncpy should sanitize the taint: {:?}",
            findings
        );
    }

    #[test]
    fn sql_injection_via_sprintf() {
        let src = r#"
#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>

void handler(sqlite3 *db) {
    char *input = getenv("QUERY");
    char query[512];
    sprintf(query, "SELECT * FROM users WHERE name = '%s'", input);
    sqlite3_exec(db, query, NULL, NULL, NULL);
}
"#;
        let findings = analyze(src, &sql_injection_spec());
        assert!(
            !findings.is_empty(),
            "should detect sqlite3_exec with tainted query: {:?}",
            findings
        );
    }

    #[test]
    fn argv_to_system() {
        let src = r#"
#include <stdlib.h>

int main(int argc, char **argv) {
    system(argv[1]);
}
"#;
        let findings = analyze(src, &command_injection_spec());
        assert!(
            !findings.is_empty(),
            "should detect system() with argv: {:?}",
            findings
        );
    }

    #[test]
    fn recv_to_execv() {
        let src = r#"
#include <unistd.h>
#include <sys/socket.h>

void handler(int sockfd) {
    char buf[1024];
    recv(sockfd, buf, sizeof(buf), 0);
    execv(buf, NULL);
}
"#;
        let findings = analyze(src, &command_injection_spec());
        assert!(
            !findings.is_empty(),
            "should detect execv() with socket data: {:?}",
            findings
        );
    }

    #[test]
    fn clean_literal_no_finding() {
        let src = r#"
#include <stdlib.h>

void handler() {
    system("ls -la");
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
    fn transitive_taint_through_assignment() {
        let src = r#"
#include <stdlib.h>

void handler() {
    char *input = getenv("CMD");
    char *cmd = input;
    system(cmd);
}
"#;
        let findings = analyze(src, &command_injection_spec());
        assert!(
            !findings.is_empty(),
            "should detect transitive taint: {:?}",
            findings
        );
    }

    #[test]
    fn scanf_to_system() {
        let src = r#"
#include <stdio.h>
#include <stdlib.h>

void handler() {
    char buf[256];
    scanf("%s", buf);
    system(buf);
}
"#;
        let findings = analyze(src, &command_injection_spec());
        assert!(
            !findings.is_empty(),
            "should detect scanf input flowing to system(): {:?}",
            findings
        );
    }
}
