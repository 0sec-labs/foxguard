use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::{Finding, Severity};

/// Default minimum length for strings flagged as a hardcoded secret.
///
/// Historically this was hardcoded as `>= 4` across every language-specific
/// `no-hardcoded-secret` rule. It is now exposed as `scan.secrets.min_length`
/// in `.foxguard.yml` (refs #210) while defaulting to the same value so
/// behavior is unchanged out of the box.
pub const DEFAULT_HARDCODED_SECRET_MIN_LENGTH: usize = 4;

/// Process-wide override for the hardcoded-secret minimum length threshold.
///
/// Stored as an atomic so rule checks (which run in a rayon thread pool)
/// can read it without locking. `0` means "no override, use the default".
/// Callers set this from the loaded `FoxguardConfig` before scanning.
static HARDCODED_SECRET_MIN_LENGTH_OVERRIDE: AtomicUsize = AtomicUsize::new(0);

/// Install a process-wide `scan.secrets.min_length` override. Pass `None` to
/// clear (reverting to [`DEFAULT_HARDCODED_SECRET_MIN_LENGTH`]).
///
/// Intentionally process-scoped rather than per-scan because rule structs
/// are zero-sized and the rule-trait `check` method does not take a config
/// parameter. Keeping the override in an atomic avoids a wide-reaching
/// refactor of the `Rule` trait while still giving users a single config
/// knob. A per-rule `configure()` hook (see issue #210) would subsume this.
pub fn set_hardcoded_secret_min_length_override(value: Option<usize>) {
    HARDCODED_SECRET_MIN_LENGTH_OVERRIDE.store(value.unwrap_or(0), Ordering::Relaxed);
}

/// Minimum length (in bytes) a string must have before a `*-hardcoded-secret`
/// rule will fire. Returns the configured override, falling back to
/// [`DEFAULT_HARDCODED_SECRET_MIN_LENGTH`].
pub fn hardcoded_secret_min_length() -> usize {
    let override_value = HARDCODED_SECRET_MIN_LENGTH_OVERRIDE.load(Ordering::Relaxed);
    if override_value == 0 {
        DEFAULT_HARDCODED_SECRET_MIN_LENGTH
    } else {
        override_value
    }
}

/// True when `inner` (the unquoted content of a string literal) is long
/// enough to be reported by a `*-hardcoded-secret` rule, per the
/// `scan.secrets.min_length` threshold.
pub fn is_secret_value_long_enough(inner: &str) -> bool {
    inner.len() >= hardcoded_secret_min_length()
}

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

/// Iteratively walk every node in a tree-sitter tree (DFS pre-order), calling
/// `callback` on each node.
pub fn walk_tree(
    node: tree_sitter::Node,
    source: &str,
    callback: &mut dyn FnMut(tree_sitter::Node, &str),
) {
    let mut stack: Vec<tree_sitter::Node> = vec![node];
    while let Some(current) = stack.pop() {
        callback(current, source);
        let start = stack.len();
        let mut cursor = current.walk();
        if cursor.goto_first_child() {
            loop {
                stack.push(cursor.node());
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
            stack[start..].reverse();
        }
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
        sink_start_byte: None,
        sink_end_byte: None,
        confidence: crate::default_confidence(),
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
        sink_start_byte: None,
        sink_end_byte: None,
        confidence: crate::default_confidence(),
    }
}

/// Map a taint hop count to a confidence score.
///
/// The curve is intentionally coarse:
/// - 1 hop (direct source→sink in the same function) → 1.0
/// - 2 hops (one level of interprocedural propagation, typically a
///   cross-file summary hit) → 0.8
/// - 3+ hops → 0.6
///
/// Tuned for the v1 taint engine which only tracks a small number of
/// hops in practice. Update this when deeper analysis lands.
pub fn confidence_for_hops(hops: u8) -> f32 {
    match hops {
        0 | 1 => 1.0,
        2 => 0.8,
        _ => 0.6,
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

    #[test]
    fn confidence_for_hops_curve_matches_documented_values() {
        // Documented curve from issue #207: 1 hop → 1.0, 2 hops → 0.8,
        // 3+ hops → 0.6. A zero hop value is treated as "no info" and
        // maps to 1.0 so a TaintFinding built without an explicit hops
        // value doesn't accidentally get downgraded.
        assert_eq!(confidence_for_hops(0), 1.0);
        assert_eq!(confidence_for_hops(1), 1.0);
        assert_eq!(confidence_for_hops(2), 0.8);
        assert_eq!(confidence_for_hops(3), 0.6);
        assert_eq!(confidence_for_hops(10), 0.6);
    }
}
