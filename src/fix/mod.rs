pub mod command_injection;
pub mod sql_injection;
pub mod xss;

use crate::engine::{detect_language, parse_path};
use crate::Finding;
use colored::Colorize;
use std::collections::HashMap;
use std::path::Path;

/// A single byte-range replacement within a file.
#[derive(Debug, Clone)]
pub struct CodeEdit {
    pub start_byte: usize,
    pub end_byte: usize,
    pub replacement: String,
}

/// All edits for a single file.
#[derive(Debug)]
pub struct FileFix {
    pub file_path: String,
    pub edits: Vec<CodeEdit>,
}

/// Try to generate edits for a single finding.
/// Returns `None` if the rule_id is unsupported or the AST shape is unrecognized.
fn generate_fix(
    finding: &Finding,
    source: &str,
    tree: &tree_sitter::Tree,
) -> Option<Vec<CodeEdit>> {
    let start = finding.sink_start_byte?;
    let end = finding.sink_end_byte?;

    match finding.rule_id.as_str() {
        "py/taint-sql-injection" => sql_injection::fix_python(source, tree, start, end),
        "js/taint-sql-injection" => sql_injection::fix_javascript(source, tree, start, end),
        "go/taint-sql-injection" => sql_injection::fix_go(source, tree, start, end),
        "py/taint-command-injection" => command_injection::fix_python(source, tree, start, end),
        "js/taint-command-injection" => command_injection::fix_javascript(source, tree, start, end),
        "go/taint-command-injection" => command_injection::fix_go(source, tree, start, end),
        "js/taint-xss-innerhtml" => xss::fix_javascript(source, tree, start, end),
        _ => None,
    }
}

/// Apply byte-range edits to source, processing in reverse order so offsets stay valid.
pub fn apply_edits(source: &str, edits: &mut [CodeEdit]) -> String {
    edits.sort_by_key(|e| std::cmp::Reverse(e.start_byte));

    let mut result = source.to_string();
    let mut last_start = usize::MAX;

    for edit in edits.iter() {
        // Skip overlapping edits
        if edit.end_byte > last_start {
            continue;
        }
        let start = edit.start_byte.min(result.len());
        let end = edit.end_byte.min(result.len());
        result.replace_range(start..end, &edit.replacement);
        last_start = edit.start_byte;
    }

    result
}

/// Generate and apply fixes for all fixable findings. Returns the number of files modified.
pub fn apply_all_fixes(findings: &[Finding], scan_root: &str) -> usize {
    let root = Path::new(scan_root);

    // Group findings by file
    let mut by_file: HashMap<&str, Vec<&Finding>> = HashMap::new();
    for f in findings {
        if f.sink_start_byte.is_some() && f.sink_end_byte.is_some() {
            by_file.entry(&f.file).or_default().push(f);
        }
    }

    let mut files_fixed = 0;

    for (file, file_findings) in &by_file {
        let file_path = root.join(file);
        let source = match std::fs::read_to_string(&file_path) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let language = match detect_language(&file_path) {
            Some(l) => l,
            None => continue,
        };

        let tree = match parse_path(&source, language, &file_path) {
            Some(t) => t,
            None => continue,
        };

        let mut all_edits: Vec<CodeEdit> = Vec::new();
        for finding in file_findings {
            if let Some(edits) = generate_fix(finding, &source, &tree) {
                all_edits.extend(edits);
            }
        }

        if all_edits.is_empty() {
            continue;
        }

        let modified = apply_edits(&source, &mut all_edits);
        if modified == source {
            continue;
        }

        print_diff(file, &source, &modified);

        if let Err(e) = std::fs::write(&file_path, &modified) {
            eprintln!("Error writing {}: {}", file, e);
            continue;
        }

        files_fixed += 1;
    }

    files_fixed
}

/// Print a simple colorized unified diff to stderr.
pub fn print_diff(file_path: &str, original: &str, modified: &str) {
    let orig_lines: Vec<&str> = original.lines().collect();
    let mod_lines: Vec<&str> = modified.lines().collect();

    eprintln!(
        "\n{} {}",
        "---".dimmed(),
        format!("a/{}", file_path).dimmed()
    );
    eprintln!("{} {}", "+++".dimmed(), format!("b/{}", file_path).dimmed());

    // Simple line-by-line diff using longest common subsequence
    let mut i = 0;
    let mut j = 0;
    let mut in_hunk = false;

    while i < orig_lines.len() || j < mod_lines.len() {
        if i < orig_lines.len() && j < mod_lines.len() && orig_lines[i] == mod_lines[j] {
            if in_hunk {
                eprintln!(" {}", orig_lines[i]);
            }
            i += 1;
            j += 1;
            in_hunk = false;
        } else {
            if !in_hunk {
                eprintln!(
                    "{}",
                    format!(
                        "@@ -{},{} +{},{} @@",
                        i + 1,
                        orig_lines.len() - i,
                        j + 1,
                        mod_lines.len() - j
                    )
                    .cyan()
                );
                in_hunk = true;
            }
            // Find the next matching line
            let next_match = find_next_match(&orig_lines, &mod_lines, i, j);
            match next_match {
                Some((ni, nj)) => {
                    for line in &orig_lines[i..ni] {
                        eprintln!("{}", format!("-{}", line).red());
                    }
                    for line in &mod_lines[j..nj] {
                        eprintln!("{}", format!("+{}", line).green());
                    }
                    i = ni;
                    j = nj;
                }
                None => {
                    for line in &orig_lines[i..] {
                        eprintln!("{}", format!("-{}", line).red());
                    }
                    for line in &mod_lines[j..] {
                        eprintln!("{}", format!("+{}", line).green());
                    }
                    break;
                }
            }
        }
    }
}

fn find_next_match(
    orig: &[&str],
    modified: &[&str],
    start_i: usize,
    start_j: usize,
) -> Option<(usize, usize)> {
    // Look for the next line that matches in both sequences
    let window = 50;
    for di in 0..window.min(orig.len() - start_i) {
        for dj in 0..window.min(modified.len() - start_j) {
            if di == 0 && dj == 0 {
                continue;
            }
            if orig[start_i + di] == modified[start_j + dj] {
                return Some((start_i + di, start_j + dj));
            }
        }
    }
    None
}

/// Helper: find the tree-sitter node at a specific byte offset.
pub fn find_node_at_byte(root: tree_sitter::Node, byte: usize) -> Option<tree_sitter::Node> {
    let node = root.descendant_for_byte_range(byte, byte)?;
    Some(node)
}

/// Helper: get node text from source.
pub fn node_text<'a>(node: tree_sitter::Node, source: &'a str) -> &'a str {
    &source[node.start_byte()..node.end_byte()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apply_edits_single() {
        let source = "hello world";
        let mut edits = vec![CodeEdit {
            start_byte: 6,
            end_byte: 11,
            replacement: "rust".to_string(),
        }];
        assert_eq!(apply_edits(source, &mut edits), "hello rust");
    }

    #[test]
    fn test_apply_edits_multiple_reverse_order() {
        let source = "aaa bbb ccc";
        let mut edits = vec![
            CodeEdit {
                start_byte: 0,
                end_byte: 3,
                replacement: "xxx".to_string(),
            },
            CodeEdit {
                start_byte: 8,
                end_byte: 11,
                replacement: "zzz".to_string(),
            },
        ];
        assert_eq!(apply_edits(source, &mut edits), "xxx bbb zzz");
    }

    #[test]
    fn test_apply_edits_overlapping_skipped() {
        let source = "abcdefgh";
        let mut edits = vec![
            CodeEdit {
                start_byte: 2,
                end_byte: 6,
                replacement: "XX".to_string(),
            },
            CodeEdit {
                start_byte: 4,
                end_byte: 8,
                replacement: "YY".to_string(),
            },
        ];
        // The second edit (bytes 4..8) overlaps with the first (2..6) after sorting by reverse start.
        // The 4..8 edit is applied first (higher start), then 2..6 is skipped because end_byte(6) > last_start(4).
        let result = apply_edits(source, &mut edits);
        assert_eq!(result, "abcdYY");
    }
}
