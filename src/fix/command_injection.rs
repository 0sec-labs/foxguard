use super::{find_node_at_byte, node_text, CodeEdit};

/// Fix Python command injection: rewrite `os.system(cmd)` / `subprocess.call(cmd, shell=True)`
/// to `subprocess.run([...])`.
///
/// Handles:
/// - `os.system("cmd " + var)` -> `subprocess.run(["cmd", var])`
/// - `os.popen("cmd " + var)` -> `subprocess.run(["cmd", var])`
pub fn fix_python(
    source: &str,
    tree: &tree_sitter::Tree,
    sink_start: usize,
    sink_end: usize,
) -> Option<Vec<CodeEdit>> {
    let root = tree.root_node();
    let call_node = find_call_at(root, sink_start, sink_end)?;

    let args = call_node.child_by_field_name("arguments")?;
    let first_arg = first_positional_arg(args)?;

    // Extract command parts from string concatenation
    let parts = extract_command_parts(first_arg, source)?;

    if parts.is_empty() {
        return None;
    }

    // Build subprocess.run([...]) call
    let list_items: Vec<String> = parts
        .iter()
        .map(|p| match p {
            CommandPart::Literal(s) => format!("\"{}\"", s),
            CommandPart::Variable(v) => v.clone(),
        })
        .collect();

    // Keep a `subprocess.*` callee and its other arguments; only drop `shell=`
    // (a list argv combined with shell=True would run just its first element).
    let func_text = call_func_text(call_node, source)?;
    let callee = if func_text.starts_with("subprocess.") {
        func_text
    } else {
        "subprocess.run"
    };
    let mut call_args = vec![format!("[{}]", list_items.join(", "))];
    if func_text.starts_with("subprocess.") {
        let mut cursor = args.walk();
        for arg in args.named_children(&mut cursor) {
            if arg.id() == first_arg.id() {
                continue;
            }
            if arg.kind() == "keyword_argument"
                && arg
                    .child_by_field_name("name")
                    .is_some_and(|name| node_text(name, source) == "shell")
            {
                continue;
            }
            call_args.push(node_text(arg, source).to_string());
        }
    }
    let replacement = format!("{}({})", callee, call_args.join(", "));

    let mut edits = vec![CodeEdit {
        start_byte: call_node.start_byte(),
        end_byte: call_node.end_byte(),
        replacement,
    }];
    let mut imported = false;
    let mut cursor = root.walk();
    for statement in root.named_children(&mut cursor) {
        if statement.kind() == "import_statement" {
            let mut imports = statement.walk();
            if statement
                .named_children(&mut imports)
                .any(|name| name.kind() == "dotted_name" && node_text(name, source) == "subprocess")
            {
                imported = true;
                break;
            }
        }
    }
    if !imported {
        // Keep shebangs, encoding comments, module docstrings and future imports first.
        let mut cursor = root.walk();
        let insertion = root
            .named_children(&mut cursor)
            .find(|node| match node.kind() {
                "comment" | "future_import_statement" => false,
                "expression_statement" => !node
                    .named_child(0)
                    .is_some_and(|child| matches!(child.kind(), "string" | "concatenated_string")),
                _ => true,
            })
            .map_or(0, |node| node.start_byte());
        edits.push(CodeEdit {
            start_byte: insertion,
            end_byte: insertion,
            replacement: "import subprocess\n".to_string(),
        });
    }
    Some(edits)
}

/// Fix JavaScript command injection: rewrite `exec(cmd)` to `execFile(name, [args])`.
///
/// Handles:
/// - `exec("cmd " + var)` -> `execFile("cmd", [var])`
pub fn fix_javascript(
    source: &str,
    tree: &tree_sitter::Tree,
    sink_start: usize,
    sink_end: usize,
) -> Option<Vec<CodeEdit>> {
    let root = tree.root_node();
    let call_node = find_call_at(root, sink_start, sink_end)?;

    let func = call_node.child_by_field_name("function")?;
    let func_text = node_text(func, source);

    let args = call_node.child_by_field_name("arguments")?;
    let first_arg = first_positional_arg(args)?;

    let parts = extract_command_parts(first_arg, source)?;
    if parts.is_empty() {
        return None;
    }

    // Rewrite exec -> execFile with separate args
    let new_func = if let Some(prefix) = func_text.strip_suffix("execSync") {
        format!("{prefix}execFileSync")
    } else {
        let prefix = func_text.strip_suffix("exec")?;
        format!("{prefix}execFile")
    };

    let (cmd, cmd_args) = split_command_parts(&parts)?;

    let args_list: Vec<String> = cmd_args
        .iter()
        .map(|p| match p {
            CommandPart::Literal(s) => format!("\"{}\"", s),
            CommandPart::Variable(v) => v.clone(),
        })
        .collect();

    let cmd_str = match &cmd {
        CommandPart::Literal(s) => format!("\"{}\"", s),
        CommandPart::Variable(v) => v.clone(),
    };

    let replacement = format!("{}({}, [{}])", new_func, cmd_str, args_list.join(", "));

    let mut edits = vec![CodeEdit {
        start_byte: call_node.start_byte(),
        end_byte: call_node.end_byte(),
        replacement,
    }];
    // A bare `exec(...)` was imported by name; `execFile` must be imported too.
    let (old_name, new_name) = if func_text == "execSync" {
        ("execSync", "execFileSync")
    } else {
        ("exec", "execFile")
    };
    if func_text == old_name {
        edits.extend(import_edit_for_js(root, source, old_name, new_name));
    }
    Some(edits)
}

/// If `old` is imported from `child_process` (CommonJS destructuring or ESM named
/// import) and `new` is not, return an edit that adds `new` next to it.
fn import_edit_for_js(
    root: tree_sitter::Node,
    source: &str,
    old: &str,
    new: &str,
) -> Option<CodeEdit> {
    fn is_child_process(text: &str) -> bool {
        let text = text.trim_matches(|c| c == '"' || c == '\'' || c == '`');
        text == "child_process" || text == "node:child_process"
    }
    // Collect (specifier node of `old`, already_has_new) per matching import.
    fn visit(
        node: tree_sitter::Node,
        source: &str,
        old: &str,
        new: &str,
    ) -> Option<Option<CodeEdit>> {
        let from_child_process = match node.kind() {
            "import_statement" => node
                .child_by_field_name("source")
                .is_some_and(|s| is_child_process(node_text(s, source))),
            "variable_declarator" => node.child_by_field_name("value").is_some_and(|v| {
                v.kind() == "call_expression"
                    && v.child_by_field_name("function")
                        .is_some_and(|f| node_text(f, source) == "require")
                    && v.child_by_field_name("arguments").is_some_and(|a| {
                        is_child_process(
                            node_text(a, source).trim_matches(|c| c == '(' || c == ')'),
                        )
                    })
            }),
            _ => false,
        };
        if from_child_process {
            let mut found = None;
            let mut has_new = false;
            let mut stack = vec![node];
            while let Some(current) = stack.pop() {
                if matches!(
                    current.kind(),
                    "import_specifier" | "shorthand_property_identifier_pattern"
                ) {
                    let name = node_text(current, source);
                    if name == old {
                        found = Some(current);
                    } else if name == new {
                        has_new = true;
                    }
                    continue;
                }
                let mut cursor = current.walk();
                stack.extend(current.named_children(&mut cursor));
            }
            if has_new {
                return Some(None);
            }
            if let Some(spec) = found {
                return Some(Some(CodeEdit {
                    start_byte: spec.end_byte(),
                    end_byte: spec.end_byte(),
                    replacement: format!(", {new}"),
                }));
            }
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if let Some(result) = visit(child, source, old, new) {
                return Some(result);
            }
        }
        None
    }
    visit(root, source, old, new).flatten()
}

/// Fix Go command injection: rewrite `exec.Command("sh", "-c", cmd + var)`
/// to `exec.Command("cmd", var)`.
///
/// Handles:
/// - `exec.Command("sh", "-c", "cmd " + var)` -> `exec.Command("cmd", var)`
pub fn fix_go(
    source: &str,
    tree: &tree_sitter::Tree,
    sink_start: usize,
    sink_end: usize,
) -> Option<Vec<CodeEdit>> {
    let root = tree.root_node();
    let call_node = find_call_at(root, sink_start, sink_end)?;

    let args = call_node.child_by_field_name("arguments")?;

    // Collect all positional arguments
    let mut arg_nodes = Vec::new();
    let mut cursor = args.walk();
    for child in args.named_children(&mut cursor) {
        arg_nodes.push(child);
    }

    // Check if this is the exec.Command("sh", "-c", ...) pattern
    if arg_nodes.len() >= 3 {
        let first = node_text(arg_nodes[0], source);
        let second = node_text(arg_nodes[1], source);
        if (first == "\"sh\""
            || first == "\"bash\""
            || first == "\"/bin/sh\""
            || first == "\"/bin/bash\"")
            && second == "\"-c\""
        {
            // The third argument is the shell command string
            let cmd_arg = arg_nodes[2];
            let parts = extract_command_parts(cmd_arg, source)?;
            if parts.is_empty() {
                return None;
            }

            let items: Vec<String> = parts
                .iter()
                .map(|p| match p {
                    CommandPart::Literal(s) => format!("\"{}\"", s),
                    CommandPart::Variable(v) => v.clone(),
                })
                .collect();

            let func_text = call_func_text(call_node, source)?;
            let replacement = format!("{}({})", func_text, items.join(", "));

            return Some(vec![CodeEdit {
                start_byte: call_node.start_byte(),
                end_byte: call_node.end_byte(),
                replacement,
            }]);
        }
    }

    // For other patterns, try to extract concat from first arg
    if let Some(first_arg) = arg_nodes.first() {
        let parts = extract_command_parts(*first_arg, source)?;
        if parts.is_empty() {
            return None;
        }

        let items: Vec<String> = parts
            .iter()
            .map(|p| match p {
                CommandPart::Literal(s) => format!("\"{}\"", s),
                CommandPart::Variable(v) => v.clone(),
            })
            .collect();

        let func_text = call_func_text(call_node, source)?;
        let replacement = format!("{}({})", func_text, items.join(", "));

        return Some(vec![CodeEdit {
            start_byte: call_node.start_byte(),
            end_byte: call_node.end_byte(),
            replacement,
        }]);
    }

    None
}

// ─── Shared helpers ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum CommandPart {
    Literal(String),
    Variable(String),
}

/// Extract command parts from a string concatenation expression.
/// Splits string literals at spaces to separate command name from arguments.
fn extract_command_parts(node: tree_sitter::Node, source: &str) -> Option<Vec<CommandPart>> {
    let mut leaves = Vec::new();
    collect_leaves(node, source, &mut leaves);

    if leaves.is_empty() {
        return None;
    }

    // Split string literals at whitespace boundaries to extract command + args
    let mut parts = Vec::new();
    for leaf in leaves {
        match leaf {
            CommandPart::Literal(s) => {
                let trimmed = s.trim();
                if !trimmed.is_empty() {
                    for word in trimmed.split_whitespace() {
                        parts.push(CommandPart::Literal(word.to_string()));
                    }
                }
            }
            CommandPart::Variable(v) => {
                parts.push(CommandPart::Variable(v));
            }
        }
    }

    // A command that starts with a variable cannot be split safely: the value
    // may itself contain arguments, so an argv rewrite would change behaviour.
    if parts.is_empty() || matches!(parts[0], CommandPart::Variable(_)) {
        None
    } else {
        Some(parts)
    }
}

fn collect_leaves(node: tree_sitter::Node, source: &str, out: &mut Vec<CommandPart>) {
    match node.kind() {
        "binary_operator" | "binary_expression" => {
            let left = node.child_by_field_name("left");
            let right = node.child_by_field_name("right");
            if let Some(l) = left {
                collect_leaves(l, source, out);
            }
            if let Some(r) = right {
                collect_leaves(r, source, out);
            }
        }
        "string" | "interpreted_string_literal" | "raw_string_literal" => {
            let text = node_text(node, source);
            let inner = strip_quotes(text);
            out.push(CommandPart::Literal(inner.to_string()));
        }
        _ => {
            out.push(CommandPart::Variable(node_text(node, source).to_string()));
        }
    }
}

fn strip_quotes(s: &str) -> &str {
    if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')) {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

/// Split parts into (command, arguments)
fn split_command_parts(parts: &[CommandPart]) -> Option<(CommandPart, Vec<CommandPart>)> {
    if parts.is_empty() {
        return None;
    }
    Some((parts[0].clone(), parts[1..].to_vec()))
}

/// Find the call expression node at the given byte range.
fn find_call_at(root: tree_sitter::Node, start: usize, end: usize) -> Option<tree_sitter::Node> {
    let node = find_node_at_byte(root, start)?;
    let mut current = node;
    loop {
        if (current.kind() == "call" || current.kind() == "call_expression")
            && current.start_byte() <= start
            && current.end_byte() >= end
        {
            return Some(current);
        }
        current = current.parent()?;
    }
}

fn call_func_text<'a>(call_node: tree_sitter::Node, source: &'a str) -> Option<&'a str> {
    let func = call_node
        .child_by_field_name("function")
        .or_else(|| call_node.child_by_field_name("callee"))?;
    Some(node_text(func, source))
}

fn first_positional_arg(args: tree_sitter::Node) -> Option<tree_sitter::Node> {
    let mut cursor = args.walk();
    let result = args
        .named_children(&mut cursor)
        .find(|child| child.kind() != "keyword_argument" && child.kind() != "spread_element");
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::parse_file;
    use crate::Language;

    #[test]
    fn test_fix_python_os_system() {
        let source = r#"os.system("ls " + user_input)"#;
        let tree = parse_file(source, Language::Python).unwrap();
        let mut edits = fix_python(source, &tree, 0, source.len()).unwrap();
        assert_eq!(
            crate::fix::apply_edits(source, &mut edits),
            "import subprocess\nsubprocess.run([\"ls\", user_input])"
        );
    }

    #[test]
    fn python_command_fixes_preserve_preamble_and_share_import() {
        let preamble = "#!/usr/bin/env python3\n\"\"\"Module documentation.\"\"\"\nfrom __future__ import annotations\n";
        let source = format!("{preamble}os.system(\"ls \" + first)\nos.system(\"ls \" + second)\n");
        let tree = parse_file(&source, Language::Python).unwrap();
        let mut edits = Vec::new();
        for name in ["first", "second"] {
            let end = source.find(&format!("{name})")).unwrap() + name.len() + 1;
            let start = source[..end].rfind("os.system(").unwrap();
            edits.extend(fix_python(&source, &tree, start, end).unwrap());
        }
        assert_eq!(
            crate::fix::apply_edits(&source, &mut edits),
            format!(
                "{preamble}import subprocess\nsubprocess.run([\"ls\", first])\nsubprocess.run([\"ls\", second])\n"
            )
        );
    }

    #[test]
    fn test_fix_js_exec() {
        let source = r#"exec("cmd " + input)"#;
        let tree = parse_file(source, Language::JavaScript).unwrap();
        let edits = fix_javascript(source, &tree, 0, source.len()).unwrap();
        assert_eq!(edits.len(), 1);
        assert_eq!(edits[0].replacement, r#"execFile("cmd", [input])"#);
    }
}

#[cfg(test)]
mod defect_tests {
    use super::*;
    use crate::engine::parse_file;
    use crate::Language;

    fn run(language: Language, source: &str, needle: &str) -> Option<String> {
        let tree = parse_file(source, language).unwrap();
        let start = source.find(needle).unwrap();
        let end = start + source[start..].find(')').unwrap() + 1;
        let mut edits = match language {
            Language::Python => fix_python(source, &tree, start, end),
            _ => fix_javascript(source, &tree, start, end),
        }?;
        let out = crate::fix::apply_edits(source, &mut edits);
        let reparsed = parse_file(&out, language).unwrap();
        assert!(
            !reparsed.root_node().has_error(),
            "fixed output must parse: {out}"
        );
        Some(out)
    }

    #[test]
    fn shell_true_is_dropped_and_other_arguments_kept() {
        let out = run(
            Language::Python,
            "import subprocess\nsubprocess.check_output(\"ls \" + x, shell=True, cwd=d)\n",
            "subprocess.check_output",
        )
        .unwrap();
        assert_eq!(
            out,
            "import subprocess\nsubprocess.check_output([\"ls\", x], cwd=d)\n"
        );
        assert!(!out.contains("shell"));
    }

    #[test]
    fn variable_only_command_is_not_rewritten() {
        assert!(run(
            Language::Python,
            "subprocess.run(cmd, shell=True)\n",
            "subprocess.run"
        )
        .is_none());
        assert!(run(Language::Python, "os.system(cmd)\n", "os.system").is_none());
    }

    #[test]
    fn js_destructured_exec_import_gains_exec_file() {
        let out = run(
            Language::JavaScript,
            "const { exec } = require('child_process');\nexec(\"ls \" + x);\n",
            "exec(\"",
        )
        .unwrap();
        assert_eq!(
            out,
            "const { exec, execFile } = require('child_process');\nexecFile(\"ls\", [x]);\n"
        );
    }

    #[test]
    fn js_esm_exec_import_gains_exec_file() {
        let out = run(
            Language::JavaScript,
            "import { exec } from 'child_process';\nexec(\"ls \" + x);\n",
            "exec(\"",
        )
        .unwrap();
        assert!(
            out.starts_with("import { exec, execFile } from 'child_process';"),
            "{out}"
        );
    }
}
