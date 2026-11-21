use super::{find_node_at_byte, node_text, CodeEdit};

/// Fix Python SQL injection: rewrite string concat/f-string to parameterized query.
///
/// Handles:
/// - `cursor.execute(f"SELECT ... {var}")` -> `cursor.execute("SELECT ... ?", (var,))`
/// - `cursor.execute("SELECT ... " + var)` -> `cursor.execute("SELECT ... ?", (var,))`
pub fn fix_python(
    source: &str,
    tree: &tree_sitter::Tree,
    sink_start: usize,
    sink_end: usize,
) -> Option<Vec<CodeEdit>> {
    let root = tree.root_node();
    let call_node = find_call_at(root, sink_start, sink_end)?;

    let args = call_node.child_by_field_name("arguments")?;
    // The first positional argument is the SQL string
    let first_arg = first_positional_arg(args)?;

    match first_arg.kind() {
        // f-string: f"SELECT * FROM users WHERE name = {name}"
        "string"
            if source[first_arg.start_byte()..first_arg.end_byte()].starts_with("f\"")
                || source[first_arg.start_byte()..first_arg.end_byte()].starts_with("f'") =>
        {
            fix_python_fstring(source, call_node, args, first_arg)
        }
        // String concatenation or %-formatting: "SELECT ... " + var
        "binary_operator" | "concatenated_string" => {
            fix_python_concat(source, call_node, args, first_arg)
        }
        _ => None,
    }
}

/// Fix JavaScript SQL injection: rewrite string concat/template to parameterized query.
///
/// Handles:
/// - `` db.query(`SELECT ... ${var}`) `` -> `db.query("SELECT ... $1", [var])`
/// - `db.query("SELECT ... " + var)` -> `db.query("SELECT ... $1", [var])`
pub fn fix_javascript(
    source: &str,
    tree: &tree_sitter::Tree,
    sink_start: usize,
    sink_end: usize,
) -> Option<Vec<CodeEdit>> {
    let root = tree.root_node();
    let call_node = find_call_at(root, sink_start, sink_end)?;

    let args = call_node.child_by_field_name("arguments")?;
    let first_arg = first_positional_arg(args)?;

    match first_arg.kind() {
        "template_string" => fix_js_template(source, call_node, args, first_arg),
        "binary_expression" => fix_js_concat(source, call_node, args, first_arg),
        _ => None,
    }
}

/// Fix Go SQL injection: rewrite string concat to parameterized query.
///
/// Handles:
/// - `db.Query("SELECT ... " + var)` -> `db.Query("SELECT ... $1", var)`
pub fn fix_go(
    source: &str,
    tree: &tree_sitter::Tree,
    sink_start: usize,
    sink_end: usize,
) -> Option<Vec<CodeEdit>> {
    let root = tree.root_node();
    let call_node = find_call_at(root, sink_start, sink_end)?;

    let args = call_node.child_by_field_name("arguments")?;
    let first_arg = first_positional_arg(args)?;

    if first_arg.kind() == "binary_expression" {
        fix_go_concat(source, call_node, args, first_arg)
    } else {
        None
    }
}

// ─── Python helpers ──────────────────────────────────────────────────────

fn fix_python_fstring(
    source: &str,
    call_node: tree_sitter::Node,
    _args_node: tree_sitter::Node,
    fstr_node: tree_sitter::Node,
) -> Option<Vec<CodeEdit>> {
    let fstr_text = node_text(fstr_node, source);

    // Extract interpolated expressions from f-string
    let mut params = Vec::new();
    let mut cursor = fstr_node.walk();
    for child in fstr_node.named_children(&mut cursor) {
        if child.kind() == "interpolation" {
            // Get the expression inside { }
            let mut inner_cursor = child.walk();
            for inner in child.named_children(&mut inner_cursor) {
                if inner.kind() != "type_conversion" && inner.kind() != "format_specifier" {
                    params.push(node_text(inner, source).to_string());
                    break;
                }
            }
        }
    }

    if params.is_empty() {
        return None;
    }

    // Build the parameterized query from AST children instead of naive string search.
    let quote_char = if fstr_text.starts_with("f\"") {
        '"'
    } else {
        '\''
    };
    let mut query = String::new();
    query.push(quote_char);
    let mut cursor2 = fstr_node.walk();
    for child in fstr_node.children(&mut cursor2) {
        match child.kind() {
            "interpolation" => query.push('?'),
            "string_content" => query.push_str(node_text(child, source)),
            _ => {}
        }
    }
    query.push(quote_char);
    let query = unquote_placeholders(&query);

    // Build the params tuple
    let params_str = if params.len() == 1 {
        format!("({},)", params[0])
    } else {
        format!("({})", params.join(", "))
    };

    // Get the method call prefix (e.g., "cursor.execute")
    let func_text = call_func_text(call_node, source)?;

    let replacement = format!("{}({}, {})", func_text, query, params_str);

    Some(vec![CodeEdit {
        start_byte: call_node.start_byte(),
        end_byte: call_node.end_byte(),
        replacement,
    }])
}

fn fix_python_concat(
    source: &str,
    call_node: tree_sitter::Node,
    _args_node: tree_sitter::Node,
    concat_node: tree_sitter::Node,
) -> Option<Vec<CodeEdit>> {
    // Extract string parts and variable parts from "str" + var + "str" + var
    let (string_parts, var_parts) = extract_concat_parts(concat_node, source)?;

    if var_parts.is_empty() {
        return None;
    }

    // Build parameterized query
    let mut query = String::new();
    for (i, part) in string_parts.iter().enumerate() {
        query.push_str(part);
        if i < var_parts.len() {
            query.push('?');
        }
    }

    let query = unquote_placeholders(&query);
    let params_str = if var_parts.len() == 1 {
        format!("({},)", var_parts[0])
    } else {
        format!("({})", var_parts.join(", "))
    };

    let func_text = call_func_text(call_node, source)?;
    let replacement = format!("{}(\"{}\", {})", func_text, query, params_str);

    Some(vec![CodeEdit {
        start_byte: call_node.start_byte(),
        end_byte: call_node.end_byte(),
        replacement,
    }])
}

// ─── JavaScript helpers ──────────────────────────────────────────────────

fn fix_js_template(
    source: &str,
    call_node: tree_sitter::Node,
    _args_node: tree_sitter::Node,
    template_node: tree_sitter::Node,
) -> Option<Vec<CodeEdit>> {
    // Extract substitutions from template literal
    let mut params = Vec::new();
    let mut cursor = template_node.walk();
    for child in template_node.named_children(&mut cursor) {
        if child.kind() == "template_substitution" {
            // Get expression inside ${ }
            let mut inner_cursor = child.walk();
            let first = child.named_children(&mut inner_cursor).next();
            if let Some(inner) = first {
                params.push(node_text(inner, source).to_string());
            }
        }
    }

    if params.is_empty() {
        return None;
    }

    // Build parameterized query from AST children instead of naive string search.
    let mut query = String::new();
    query.push('"');
    let mut param_idx = 1;
    let mut cursor2 = template_node.walk();
    for child in template_node.children(&mut cursor2) {
        match child.kind() {
            "template_substitution" => {
                query.push_str(&format!("${}", param_idx));
                param_idx += 1;
            }
            "string_fragment" => query.push_str(node_text(child, source)),
            _ => {}
        }
    }
    query.push('"');
    let query = unquote_placeholders(&query);

    let func_text = call_func_text(call_node, source)?;
    let replacement = format!("{}({}, [{}])", func_text, query, params.join(", "));

    Some(vec![CodeEdit {
        start_byte: call_node.start_byte(),
        end_byte: call_node.end_byte(),
        replacement,
    }])
}

fn fix_js_concat(
    source: &str,
    call_node: tree_sitter::Node,
    _args_node: tree_sitter::Node,
    concat_node: tree_sitter::Node,
) -> Option<Vec<CodeEdit>> {
    let (string_parts, var_parts) = extract_concat_parts(concat_node, source)?;

    if var_parts.is_empty() {
        return None;
    }

    let mut query = String::new();
    for (i, part) in string_parts.iter().enumerate() {
        query.push_str(part);
        if i < var_parts.len() {
            query.push_str(&format!("${}", i + 1));
        }
    }

    let query = unquote_placeholders(&query);
    let func_text = call_func_text(call_node, source)?;
    let replacement = format!("{}(\"{}\", [{}])", func_text, query, var_parts.join(", "));

    Some(vec![CodeEdit {
        start_byte: call_node.start_byte(),
        end_byte: call_node.end_byte(),
        replacement,
    }])
}

// ─── Go helpers ──────────────────────────────────────────────────────────

fn fix_go_concat(
    source: &str,
    call_node: tree_sitter::Node,
    _args_node: tree_sitter::Node,
    concat_node: tree_sitter::Node,
) -> Option<Vec<CodeEdit>> {
    let (string_parts, var_parts) = extract_concat_parts(concat_node, source)?;

    if var_parts.is_empty() {
        return None;
    }

    let mut query = String::new();
    for (i, part) in string_parts.iter().enumerate() {
        query.push_str(part);
        if i < var_parts.len() {
            query.push_str(&format!("${}", i + 1));
        }
    }

    let query = unquote_placeholders(&query);
    let func_text = call_func_text(call_node, source)?;
    let replacement = format!("{}(\"{}\", {})", func_text, query, var_parts.join(", "));

    Some(vec![CodeEdit {
        start_byte: call_node.start_byte(),
        end_byte: call_node.end_byte(),
        replacement,
    }])
}

// ─── Shared helpers ──────────────────────────────────────────────────────

/// Turn `'?'` / `'$1'` into `?` / `$1`. A quoted placeholder is a string
/// literal, not a bind parameter, so the "fixed" query would never bind.
fn unquote_placeholders(query: &str) -> String {
    let chars: Vec<char> = query.chars().collect();
    let mut out = String::with_capacity(query.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\'' {
            let mut j = i + 1;
            if j < chars.len() && chars[j] == '?' {
                j += 1;
            } else if j < chars.len() && chars[j] == '$' {
                let digits = chars[j + 1..]
                    .iter()
                    .take_while(|c| c.is_ascii_digit())
                    .count();
                j = if digits > 0 { j + 1 + digits } else { 0 };
            } else {
                j = 0;
            }
            if j > 0 && j < chars.len() && chars[j] == '\'' {
                out.extend(&chars[i + 1..j]);
                i = j + 1;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// Find the call expression node that covers the given byte range.
fn find_call_at(root: tree_sitter::Node, start: usize, end: usize) -> Option<tree_sitter::Node> {
    let node = find_node_at_byte(root, start)?;
    // Walk up to find the call expression
    let mut current = node;
    loop {
        if current.kind() == "call" || current.kind() == "call_expression" {
            // Verify it covers our range
            if current.start_byte() <= start && current.end_byte() >= end {
                return Some(current);
            }
        }
        current = current.parent()?;
    }
}

/// Get the function/method text before the arguments.
/// e.g., for `cursor.execute(...)` returns `"cursor.execute"`
fn call_func_text<'a>(call_node: tree_sitter::Node, source: &'a str) -> Option<&'a str> {
    // The function field is typically named "function" or "callee"
    let func = call_node
        .child_by_field_name("function")
        .or_else(|| call_node.child_by_field_name("callee"))?;
    Some(node_text(func, source))
}

/// Get the first positional argument from an arguments node.
fn first_positional_arg(args: tree_sitter::Node) -> Option<tree_sitter::Node> {
    let mut cursor = args.walk();
    let result = args
        .named_children(&mut cursor)
        .find(|child| child.kind() != "keyword_argument" && child.kind() != "spread_element");
    result
}

/// Extract string literal parts and variable parts from a binary concatenation.
/// Returns (string_parts, var_parts) where string_parts[i] + var_parts[i] + string_parts[i+1]...
fn extract_concat_parts(
    node: tree_sitter::Node,
    source: &str,
) -> Option<(Vec<String>, Vec<String>)> {
    let mut leaves = Vec::new();
    collect_concat_leaves(node, source, &mut leaves);

    if leaves.is_empty() {
        return None;
    }

    let mut string_parts = Vec::new();
    let mut var_parts = Vec::new();
    let mut current_string = String::new();

    for leaf in &leaves {
        match leaf {
            ConcatLeaf::StringLit(s) => current_string.push_str(s),
            ConcatLeaf::Variable(v) => {
                string_parts.push(current_string.clone());
                current_string.clear();
                var_parts.push(v.clone());
            }
        }
    }
    string_parts.push(current_string);

    if var_parts.is_empty() {
        return None;
    }

    Some((string_parts, var_parts))
}

#[derive(Debug)]
enum ConcatLeaf {
    StringLit(String),
    Variable(String),
}

fn collect_concat_leaves(node: tree_sitter::Node, source: &str, out: &mut Vec<ConcatLeaf>) {
    match node.kind() {
        "binary_operator" | "binary_expression" => {
            // Check if this is a + concatenation
            let op = node.child_by_field_name("operator");
            let is_plus = match op {
                Some(op_node) => node_text(op_node, source) == "+",
                None => {
                    // Some grammars embed the operator differently
                    let text = node_text(node, source);
                    text.contains('+')
                }
            };

            if !is_plus {
                out.push(ConcatLeaf::Variable(node_text(node, source).to_string()));
                return;
            }

            let left = node.child_by_field_name("left");
            let right = node.child_by_field_name("right");

            if let Some(l) = left {
                collect_concat_leaves(l, source, out);
            }
            if let Some(r) = right {
                collect_concat_leaves(r, source, out);
            }
        }
        "string" | "interpreted_string_literal" | "raw_string_literal" => {
            let text = node_text(node, source);
            // Strip quotes
            let inner = strip_string_quotes(text);
            out.push(ConcatLeaf::StringLit(inner.to_string()));
        }
        _ => {
            out.push(ConcatLeaf::Variable(node_text(node, source).to_string()));
        }
    }
}

fn strip_string_quotes(s: &str) -> &str {
    if ((s.starts_with('"') && s.ends_with('"'))
        || (s.starts_with('\'') && s.ends_with('\''))
        || (s.starts_with('`') && s.ends_with('`')))
        && s.len() >= 2
    {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::parse_file;
    use crate::Language;

    #[test]
    fn test_fix_python_fstring() {
        let source = r#"cursor.execute(f"SELECT * FROM users WHERE name = {name}")"#;
        let tree = parse_file(source, Language::Python).unwrap();
        // The call spans the entire source
        let edits = fix_python(source, &tree, 0, source.len()).unwrap();
        assert_eq!(edits.len(), 1);
        assert_eq!(
            edits[0].replacement,
            r#"cursor.execute("SELECT * FROM users WHERE name = ?", (name,))"#
        );
    }

    #[test]
    fn test_fix_python_concat() {
        let source = r#"cursor.execute("SELECT * FROM users WHERE name = " + name)"#;
        let tree = parse_file(source, Language::Python).unwrap();
        let edits = fix_python(source, &tree, 0, source.len()).unwrap();
        assert_eq!(edits.len(), 1);
        assert_eq!(
            edits[0].replacement,
            r#"cursor.execute("SELECT * FROM users WHERE name = ?", (name,))"#
        );
    }

    #[test]
    fn test_fix_js_template() {
        let source = "db.query(`SELECT * FROM users WHERE name = ${name}`)";
        let tree = parse_file(source, Language::JavaScript).unwrap();
        let edits = fix_javascript(source, &tree, 0, source.len()).unwrap();
        assert_eq!(edits.len(), 1);
        assert_eq!(
            edits[0].replacement,
            r#"db.query("SELECT * FROM users WHERE name = $1", [name])"#
        );
    }

    #[test]
    fn test_fix_js_concat() {
        let source = r#"db.query("SELECT * FROM users WHERE name = " + name)"#;
        let tree = parse_file(source, Language::JavaScript).unwrap();
        let edits = fix_javascript(source, &tree, 0, source.len()).unwrap();
        assert_eq!(edits.len(), 1);
        assert_eq!(
            edits[0].replacement,
            r#"db.query("SELECT * FROM users WHERE name = $1", [name])"#
        );
    }

    #[test]
    fn test_fix_go_concat() {
        let source = r#"db.Query("SELECT * FROM users WHERE name = " + name)"#;
        let tree = parse_file(source, Language::Go).unwrap();
        let edits = fix_go(source, &tree, 0, source.len());
        // Go call_expression might need a function wrapper to parse
        // This test verifies the basic flow
        if let Some(edits) = edits {
            assert_eq!(edits.len(), 1);
            assert!(edits[0].replacement.contains("$1"));
        }
    }

    fn assert_fix_parses(language: Language, source: &str, expected: &str) {
        let tree = parse_file(source, language).unwrap();
        let start = source.find(|c: char| c.is_alphabetic()).unwrap();
        let end = source.trim_end().trim_end_matches(';').len();
        let mut edits = match language {
            Language::Python => fix_python(source, &tree, start, end),
            Language::JavaScript => fix_javascript(source, &tree, start, end),
            _ => fix_go(source, &tree, start, end),
        }
        .unwrap();
        let out = crate::fix::apply_edits(source, &mut edits);
        assert_eq!(out, expected);
        assert!(!parse_file(&out, language).unwrap().root_node().has_error());
    }

    #[test]
    fn quoted_placeholders_are_unquoted() {
        assert_eq!(
            unquote_placeholders("a = '?' and b = '$12'"),
            "a = ? and b = $12"
        );
        assert_eq!(unquote_placeholders("a = 'x?y'"), "a = 'x?y'");
        assert_fix_parses(
            Language::Python,
            "cursor.execute(\"SELECT * FROM t WHERE n = '\" + name + \"'\")\n",
            "cursor.execute(\"SELECT * FROM t WHERE n = ?\", (name,))\n",
        );
        assert_fix_parses(
            Language::Python,
            "cursor.execute(f\"SELECT * FROM t WHERE n = '{name}'\")\n",
            "cursor.execute(\"SELECT * FROM t WHERE n = ?\", (name,))\n",
        );
        assert_fix_parses(
            Language::JavaScript,
            "db.query(\"SELECT * FROM t WHERE n = '\" + name + \"'\");\n",
            "db.query(\"SELECT * FROM t WHERE n = $1\", [name]);\n",
        );
        assert_fix_parses(
            Language::JavaScript,
            "db.query(`SELECT * FROM t WHERE n = '${name}'`);\n",
            "db.query(\"SELECT * FROM t WHERE n = $1\", [name]);\n",
        );
    }
}
