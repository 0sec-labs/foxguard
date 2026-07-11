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

    let replacement = format!("subprocess.run([{}])", list_items.join(", "));

    Some(vec![CodeEdit {
        start_byte: call_node.start_byte(),
        end_byte: call_node.end_byte(),
        replacement,
    }])
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

    Some(vec![CodeEdit {
        start_byte: call_node.start_byte(),
        end_byte: call_node.end_byte(),
        replacement,
    }])
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

    if parts.is_empty() {
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
        let edits = fix_python(source, &tree, 0, source.len()).unwrap();
        assert_eq!(edits.len(), 1);
        assert_eq!(
            edits[0].replacement,
            r#"subprocess.run(["ls", user_input])"#
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
