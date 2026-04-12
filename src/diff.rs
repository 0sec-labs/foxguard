use crate::engine::{scan_directory, scan_paths_with_root, ScanResult};
use crate::rules::RuleRegistry;
use crate::Finding;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Result of a diff scan: new findings plus summary counts.
pub struct DiffResult {
    pub new_findings: Vec<Finding>,
    pub total_current: usize,
    pub existing_count: usize,
}

/// Run git in a specific repo directory.
fn run_git(repo_root: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(args)
        .output()
        .map_err(|e| format!("Failed to run git: {}", e))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Get the repo root for the given path.
fn repo_root(path: &Path) -> Result<PathBuf, String> {
    let dir = if path.is_dir() {
        path
    } else {
        path.parent().unwrap_or(Path::new("."))
    };
    let root = run_git(dir, &["rev-parse", "--show-toplevel"])?;
    Ok(PathBuf::from(root.trim()))
}

/// Get files changed between the target branch and HEAD.
fn changed_files_vs_target(repo_root: &Path, target: &str) -> Result<Vec<PathBuf>, String> {
    // Get the merge base to find only truly changed files
    let merge_base =
        run_git(repo_root, &["merge-base", target, "HEAD"]).unwrap_or_else(|_| target.to_string());
    let merge_base = merge_base.trim();

    let stdout = run_git(
        repo_root,
        &["diff", "--name-only", "--diff-filter=ACMR", merge_base],
    )?;

    let mut files = Vec::new();
    for line in stdout.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let path = repo_root.join(line);
        if path.exists() {
            files.push(path);
        }
    }

    Ok(files)
}

/// Read a file's contents from a specific git ref.
fn read_file_at_ref(repo_root: &Path, git_ref: &str, rel_path: &str) -> Result<String, String> {
    let spec = format!("{}:{}", git_ref, rel_path);
    run_git(repo_root, &["show", &spec])
}

/// Scan the target branch's version of specific files by writing them to temp files.
fn scan_target_branch_files(
    repo_root: &Path,
    target: &str,
    changed_files: &[PathBuf],
    registry: &RuleRegistry,
    max_file_size: u64,
) -> Result<ScanResult, String> {
    let temp_dir =
        tempfile::tempdir().map_err(|e| format!("Failed to create temp directory: {}", e))?;

    let mut temp_paths = Vec::new();

    for file in changed_files {
        let rel_path = file
            .strip_prefix(repo_root)
            .map_err(|e| format!("Failed to get relative path: {}", e))?;
        let rel_str = rel_path.to_string_lossy().to_string();

        // Try to read from the target branch; skip files that don't exist there (new files)
        let content = match read_file_at_ref(repo_root, target, &rel_str) {
            Ok(c) => c,
            Err(_) => continue, // file doesn't exist on target branch
        };

        let temp_path = temp_dir.path().join(rel_path);
        if let Some(parent) = temp_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create temp dir: {}", e))?;
        }
        std::fs::write(&temp_path, &content)
            .map_err(|e| format!("Failed to write temp file: {}", e))?;

        temp_paths.push(temp_path);
    }

    if temp_paths.is_empty() {
        return Ok(ScanResult {
            findings: Vec::new(),
            files_scanned: 0,
            duration: std::time::Duration::ZERO,
        });
    }

    Ok(scan_paths_with_root(
        temp_dir.path(),
        &temp_paths,
        registry,
        max_file_size,
    ))
}

/// Two findings are "the same" if they share the same rule_id and snippet content.
/// We deliberately ignore line numbers since they shift with edits.
fn finding_key(finding: &Finding) -> (String, String, String) {
    (
        finding.rule_id.clone(),
        finding.file.clone(),
        finding.snippet.trim().to_string(),
    )
}

/// Compute new findings: those in current but not in base.
/// Matching is by (rule_id, relative_file_path, snippet_content).
pub fn diff_findings(current: Vec<Finding>, base: Vec<Finding>) -> DiffResult {
    let total_current = current.len();

    let base_keys: HashSet<(String, String, String)> = base.iter().map(finding_key).collect();

    let new_findings: Vec<Finding> = current
        .into_iter()
        .filter(|f| !base_keys.contains(&finding_key(f)))
        .collect();

    let existing_count = total_current - new_findings.len();

    DiffResult {
        new_findings,
        total_current,
        existing_count,
    }
}

/// Run a full diff scan: scan current tree, scan target branch files, return new findings.
pub fn run_diff(
    scan_path: &str,
    target: &str,
    registry: &RuleRegistry,
    max_file_size: u64,
) -> Result<(ScanResult, DiffResult), String> {
    let scan_root = Path::new(scan_path);
    let repo = repo_root(scan_root)?;

    // Verify the target ref exists
    run_git(&repo, &["rev-parse", "--verify", target])
        .map_err(|_| format!("Target ref '{}' does not exist", target))?;

    // Scan current working tree
    let current_result = scan_directory(scan_path, registry, max_file_size);

    // Get changed files between target and HEAD
    let changed = changed_files_vs_target(&repo, target)?;

    if changed.is_empty() {
        // No changed files — everything is existing
        let total = current_result.findings.len();
        return Ok((
            ScanResult {
                findings: Vec::new(),
                files_scanned: current_result.files_scanned,
                duration: current_result.duration,
            },
            DiffResult {
                new_findings: Vec::new(),
                total_current: total,
                existing_count: total,
            },
        ));
    }

    // Scan the target branch versions of changed files
    let base_result = scan_target_branch_files(&repo, target, &changed, registry, max_file_size)?;

    // Only diff findings from changed files (current side)
    let changed_rel: HashSet<String> = changed
        .iter()
        .filter_map(|p| {
            p.strip_prefix(&repo)
                .ok()
                .map(|r| r.to_string_lossy().to_string())
        })
        .collect();

    let (changed_findings, unchanged_findings): (Vec<Finding>, Vec<Finding>) =
        current_result.findings.into_iter().partition(|f| {
            // The file field in findings is relative to scan root
            changed_rel
                .iter()
                .any(|rel| f.file.ends_with(rel) || rel.ends_with(&f.file))
        });

    let diff = diff_findings(changed_findings, base_result.findings);
    let total_current = diff.total_current + unchanged_findings.len();
    let existing_count = diff.existing_count + unchanged_findings.len();

    Ok((
        ScanResult {
            findings: Vec::new(), // not used; diff_result has everything
            files_scanned: current_result.files_scanned,
            duration: current_result.duration,
        },
        DiffResult {
            new_findings: diff.new_findings,
            total_current,
            existing_count,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Severity;

    fn make_finding(rule_id: &str, file: &str, line: usize, snippet: &str) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            severity: Severity::High,
            cwe: None,
            description: "test".to_string(),
            file: file.to_string(),
            line,
            column: 1,
            end_line: line,
            end_column: 10,
            snippet: snippet.to_string(),
            source_line: None,
            source_description: None,
            sink_line: None,
            sink_description: None,
            fix_suggestion: None,
        }
    }

    #[test]
    fn test_diff_findings_new_only() {
        let current = vec![
            make_finding("rule-1", "app.js", 10, "eval(input)"),
            make_finding("rule-2", "app.js", 20, "exec(cmd)"),
        ];
        let base = vec![
            make_finding("rule-1", "app.js", 8, "eval(input)"), // same rule+snippet, different line
        ];

        let result = diff_findings(current, base);
        assert_eq!(result.new_findings.len(), 1);
        assert_eq!(result.new_findings[0].rule_id, "rule-2");
        assert_eq!(result.total_current, 2);
        assert_eq!(result.existing_count, 1);
    }

    #[test]
    fn test_diff_findings_all_new() {
        let current = vec![make_finding("rule-1", "app.js", 10, "eval(input)")];
        let base = vec![];

        let result = diff_findings(current, base);
        assert_eq!(result.new_findings.len(), 1);
        assert_eq!(result.existing_count, 0);
    }

    #[test]
    fn test_diff_findings_none_new() {
        let current = vec![make_finding("rule-1", "app.js", 10, "eval(input)")];
        let base = vec![make_finding("rule-1", "app.js", 10, "eval(input)")];

        let result = diff_findings(current, base);
        assert_eq!(result.new_findings.len(), 0);
        assert_eq!(result.existing_count, 1);
    }

    #[test]
    fn test_diff_findings_snippet_whitespace_tolerance() {
        let current = vec![make_finding("rule-1", "app.js", 10, "  eval(input)  ")];
        let base = vec![make_finding("rule-1", "app.js", 5, "eval(input)")];

        let result = diff_findings(current, base);
        assert_eq!(
            result.new_findings.len(),
            0,
            "whitespace-trimmed snippets should match"
        );
    }
}
