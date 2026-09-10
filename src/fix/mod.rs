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

/// Apply edits in reverse byte order, skipping overlaps and duplicate edits.
pub fn apply_edits(source: &str, edits: &mut [CodeEdit]) -> String {
    edits.sort_by_key(|e| std::cmp::Reverse(e.start_byte));

    let mut result = source.to_string();
    let mut last_start = usize::MAX;
    let mut last_edit: Option<&CodeEdit> = None;

    for edit in edits.iter() {
        if last_edit.is_some_and(|previous| {
            previous.start_byte == edit.start_byte
                && previous.end_byte == edit.end_byte
                && previous.replacement == edit.replacement
        }) {
            continue;
        }
        // Skip overlapping edits
        if edit.end_byte > last_start {
            continue;
        }
        let start = edit.start_byte.min(result.len());
        let end = edit.end_byte.min(result.len());
        result.replace_range(start..end, &edit.replacement);
        last_start = edit.start_byte;
        last_edit = Some(edit);
    }

    result
}

/// Generate and apply fixes for all fixable findings. Returns the number of files modified.
pub fn apply_all_fixes(findings: &[Finding], scan_root: &str) -> usize {
    let root = match Path::new(scan_root).canonicalize() {
        Ok(root) => root,
        Err(error) => {
            eprintln!("Error resolving scan root {}: {}", scan_root, error);
            return 0;
        }
    };
    let single_file = root.is_file();

    // Group findings by file
    let mut by_file: HashMap<&str, Vec<&Finding>> = HashMap::new();
    for f in findings {
        if f.sink_start_byte.is_some() && f.sink_end_byte.is_some() {
            by_file.entry(&f.file).or_default().push(f);
        }
    }

    let mut files_fixed = 0;

    for (file, file_findings) in &by_file {
        // Scanner finding paths are relative to the process directory, not the
        // scan root. Resolve once and use the same target for reading and writing.
        let file_path = match Path::new(file).canonicalize() {
            Ok(path) => path,
            Err(_) => continue,
        };
        let in_scope = if single_file {
            file_path == root
        } else {
            file_path.starts_with(&root)
        };
        if !in_scope {
            eprintln!(
                "Warning: skipping fix for {} — path escapes scan root {}",
                file,
                root.display()
            );
            continue;
        }

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

    const FIXABLE_SOURCE: &str = "from flask import request\nimport os\n\ndef handler():\n    user_input = request.args.get(\"name\")\n    os.system(\"ls \" + user_input)\n";

    fn scan_fixable_file(path: &Path) -> Vec<Finding> {
        crate::engine::scan_directory(
            &path.to_string_lossy(),
            &crate::rules::RuleRegistry::new(),
            1024 * 1024,
            None,
        )
        .findings
    }

    #[test]
    fn autofix_handles_cwd_relative_directory_and_file_targets() {
        let workspace = tempfile::tempdir_in(".").expect("temporary workspace");
        let file = workspace.path().join("app.py");
        for scan_root in [workspace.path(), file.as_path()] {
            std::fs::write(&file, FIXABLE_SOURCE).expect("write source");
            let findings = scan_fixable_file(&file);
            assert_eq!(apply_all_fixes(&findings, &scan_root.to_string_lossy()), 1);
            let modified = std::fs::read_to_string(&file).expect("read fixed source");
            assert!(!modified.contains("os.system("));
            assert!(modified.contains("subprocess.run("));
        }
    }

    #[test]
    fn autofix_rejects_targets_outside_scan_root() {
        let workspace = tempfile::tempdir().expect("temporary workspace");
        let root = workspace.path().join("repo");
        std::fs::create_dir(&root).expect("create scan root");
        let victim = workspace.path().join("victim.py");
        std::fs::write(&victim, FIXABLE_SOURCE).expect("write victim");
        let mut findings = scan_fixable_file(&victim);

        // Establish that these are real fixable findings, not unsupported rules.
        assert_eq!(apply_all_fixes(&findings, &victim.to_string_lossy()), 1);
        for path in [victim.clone(), root.join("../victim.py")] {
            std::fs::write(&victim, FIXABLE_SOURCE).expect("restore victim");
            for finding in &mut findings {
                finding.file = path.to_string_lossy().into_owned();
            }
            assert_eq!(apply_all_fixes(&findings, &root.to_string_lossy()), 0);
            assert_eq!(std::fs::read_to_string(&victim).unwrap(), FIXABLE_SOURCE);
        }
    }

    #[cfg(unix)]
    #[test]
    fn autofix_rejects_symlinks_outside_scan_root() {
        let workspace = tempfile::tempdir().expect("temporary workspace");
        let root = workspace.path().join("repo");
        std::fs::create_dir(&root).expect("create scan root");
        let victim = workspace.path().join("victim.py");
        std::fs::write(&victim, FIXABLE_SOURCE).expect("write victim");
        let link = root.join("app.py");
        std::os::unix::fs::symlink(&victim, &link).expect("create escaping symlink");
        let mut findings = scan_fixable_file(&victim);
        for finding in &mut findings {
            finding.file = link.to_string_lossy().into_owned();
        }
        assert_eq!(apply_all_fixes(&findings, &root.to_string_lossy()), 0);
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), FIXABLE_SOURCE);
    }
}
