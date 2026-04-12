use std::borrow::Cow;
use std::collections::HashMap;

use crate::{Finding, Severity};

/// Shared per-file import alias table.
///
/// Maps a local identifier (as it appears in source) to its canonical
/// dotted/qualified path. Each language populates the table with its own
/// tree-walking logic, but the resolution algorithm is identical.
#[derive(Debug, Default, Clone)]
pub struct AliasTable {
    pub(crate) map: HashMap<String, String>,
}

impl AliasTable {
    /// Create a new empty alias table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert an alias mapping.
    pub fn insert(&mut self, local: String, canonical: String) {
        self.map.insert(local, canonical);
    }

    /// Insert only if the key is not already present.
    pub fn entry_or_insert(&mut self, local: String, canonical: String) {
        self.map.entry(local).or_insert(canonical);
    }

    /// Resolve a call-site callee text (as it appears in the source) back to
    /// its canonical dotted path. Returns the input unchanged when no alias
    /// matches. For example, with `import pickle as p`:
    ///   `p.loads`        → `pickle.loads`
    ///   `pickle.loads`   → `pickle.loads`
    ///   `eval`           → `eval`
    pub fn resolve<'a>(&'a self, callee: &'a str) -> Cow<'a, str> {
        if let Some((head, tail)) = callee.split_once('.') {
            if let Some(canonical_root) = self.map.get(head) {
                if canonical_root == head {
                    return Cow::Borrowed(callee);
                }
                return Cow::Owned(format!("{}.{}", canonical_root, tail));
            }
            return Cow::Borrowed(callee);
        }
        if let Some(canonical) = self.map.get(callee) {
            return Cow::Borrowed(canonical.as_str());
        }
        Cow::Borrowed(callee)
    }

    #[cfg(test)]
    pub fn get(&self, local: &str) -> Option<&str> {
        self.map.get(local).map(String::as_str)
    }
}

/// Extract the full source line containing the given byte offset.
///
/// Returns an empty string when `byte_offset` is out of range for `source`.
pub fn get_source_line(source: &str, byte_offset: usize) -> String {
    if byte_offset > source.len() {
        return String::new();
    }
    // Clamp to len so we never slice past the end.
    let byte_offset = byte_offset.min(source.len());
    let start = source[..byte_offset].rfind('\n').map_or(0, |p| p + 1);
    let end = source[byte_offset..]
        .find('\n')
        .map_or(source.len(), |p| byte_offset + p);
    source[start..end].to_string()
}

/// Recursively walk every node in a tree-sitter tree, calling `callback` on
/// each node.
pub fn walk_tree(
    node: tree_sitter::Node,
    source: &str,
    callback: &mut dyn FnMut(tree_sitter::Node, &str),
) {
    callback(node, source);
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_tree(child, source, callback);
    }
}

/// Create a [`Finding`] from a tree-sitter `Node`.
pub fn make_finding(
    rule_id: &str,
    severity: Severity,
    cwe: Option<&str>,
    description: &str,
    node: tree_sitter::Node,
    source: &str,
) -> Finding {
    let start = node.start_position();
    let end = node.end_position();
    Finding {
        rule_id: rule_id.to_string(),
        severity,
        cwe: cwe.map(|s| s.to_string()),
        description: description.to_string(),
        file: String::new(),
        line: start.row + 1,
        column: start.column + 1,
        end_line: end.row + 1,
        end_column: end.column + 1,
        snippet: get_source_line(source, node.start_byte()),
        source_line: None,
        source_description: None,
        sink_line: None,
        sink_description: None,
        fix_suggestion: None,
    }
}

/// Create a [`Finding`] from raw byte offsets (start and end) rather than a
/// tree-sitter node.
pub fn make_finding_from_offsets(
    rule_id: &str,
    severity: Severity,
    cwe: Option<&str>,
    description: &str,
    source: &str,
    start_byte: usize,
    end_byte: usize,
) -> Finding {
    let start_byte = start_byte.min(source.len());
    let end_byte = end_byte.min(source.len());

    let line = source[..start_byte].bytes().filter(|b| *b == b'\n').count() + 1;
    let line_start = source[..start_byte].rfind('\n').map_or(0, |idx| idx + 1);
    let column = source[line_start..start_byte].chars().count() + 1;

    let end_line = source[..end_byte].bytes().filter(|b| *b == b'\n').count() + 1;
    let end_line_start = source[..end_byte].rfind('\n').map_or(0, |idx| idx + 1);
    let end_column = source[end_line_start..end_byte].chars().count() + 1;

    Finding {
        rule_id: rule_id.to_string(),
        severity,
        cwe: cwe.map(|s| s.to_string()),
        description: description.to_string(),
        file: String::new(),
        line,
        column,
        end_line,
        end_column,
        snippet: get_source_line(source, start_byte),
        source_line: None,
        source_description: None,
        sink_line: None,
        sink_description: None,
        fix_suggestion: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_source_line_basic() {
        let src = "line one\nline two\nline three";
        assert_eq!(get_source_line(src, 0), "line one");
        assert_eq!(get_source_line(src, 9), "line two");
        assert_eq!(get_source_line(src, 18), "line three");
    }

    #[test]
    fn get_source_line_empty_source() {
        assert_eq!(get_source_line("", 0), "");
    }

    #[test]
    fn get_source_line_out_of_bounds() {
        assert_eq!(get_source_line("hello", 100), "");
    }
}
