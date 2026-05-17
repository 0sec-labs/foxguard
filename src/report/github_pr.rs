use crate::{Finding, Severity};
use std::collections::{HashMap, HashSet};
use std::path::Path;

pub const COMMENT_MARKER: &str = "<!-- foxguard:pr-review -->";

/// Format the severity as an uppercase label for the PR comment.
fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Low => "LOW",
        Severity::Medium => "MEDIUM",
        Severity::High => "HIGH",
        Severity::Critical => "CRITICAL",
    }
}

/// Build the markdown body for a single inline review comment.
pub fn format_comment_body(finding: &Finding) -> String {
    let cwe_suffix = finding
        .cwe
        .as_ref()
        .map(|c| format!(" ({c})"))
        .unwrap_or_default();

    let mut body = format!(
        "{COMMENT_MARKER}\n\n**foxguard** \u{00b7} `{}` \u{00b7} `{}`{}\n\n{}",
        severity_label(finding.severity),
        finding.rule_id,
        cwe_suffix,
        finding.description,
    );

    if let Some(ref fix) = finding.fix_suggestion {
        body.push_str(&format!("\n\n**Fix:** {fix}"));
    }

    body
}

fn existing_foxguard_comment_ids(stdout: &[u8]) -> Result<Vec<u64>, String> {
    let value: serde_json::Value = serde_json::from_slice(stdout)
        .map_err(|e| format!("Failed to parse existing PR comments: {e}"))?;
    let comments: Vec<&serde_json::Value> = match value.as_array() {
        Some(values) if values.iter().all(|value| value.is_array()) => values
            .iter()
            .flat_map(|page| page.as_array().into_iter().flatten())
            .collect(),
        Some(values) => values.iter().collect(),
        None => Vec::new(),
    };

    Ok(comments
        .into_iter()
        .filter(|comment| {
            comment["body"]
                .as_str()
                .is_some_and(|body| body.contains(COMMENT_MARKER))
        })
        .filter_map(|comment| comment["id"].as_u64())
        .collect())
}

fn delete_existing_foxguard_comments(repo: &str, pr_number: u64) -> Result<usize, String> {
    let endpoint = format!("repos/{repo}/pulls/{pr_number}/comments");
    let output = std::process::Command::new("gh")
        .args(["api", &endpoint, "--paginate", "--slurp"])
        .output()
        .map_err(|e| format!("Failed to list existing PR comments: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("gh api returned {}: {}", output.status, stderr));
    }

    let ids = existing_foxguard_comment_ids(&output.stdout)?;
    for id in &ids {
        let endpoint = format!("repos/{repo}/pulls/comments/{id}");
        let output = std::process::Command::new("gh")
            .args(["api", &endpoint, "--method", "DELETE"])
            .output()
            .map_err(|e| format!("Failed to delete prior PR comment {id}: {e}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!(
                "gh api failed to delete prior PR comment {id}: {}: {}",
                output.status, stderr
            ));
        }
    }

    Ok(ids.len())
}

/// Make a file path relative to the repository root.
///
/// If `scan_root` is provided, the finding's file path is stripped of that
/// prefix so the resulting path is relative (as required by the GitHub API).
pub fn relative_path(file: &str, scan_root: Option<&Path>) -> String {
    if let Some(root) = scan_root {
        if let Ok(canonical_root) = std::fs::canonicalize(root) {
            // `file` comes from scanner findings and is canonicalized below
            // before it is stripped against the trusted scan root.
            let file_path = Path::new(file); // foxguard: ignore[rs/no-path-traversal]
            let canonical_file =
                std::fs::canonicalize(file_path).unwrap_or(file_path.to_path_buf());
            if let Ok(stripped) = canonical_file.strip_prefix(&canonical_root) {
                return stripped.to_string_lossy().into_owned();
            }
        }
    }
    // Fallback: strip leading "./" or "/" if present
    let trimmed = file.strip_prefix("./").unwrap_or(file);
    trimmed.strip_prefix('/').unwrap_or(trimmed).to_string()
}

pub fn review_comments_for_findings(
    findings: &[Finding],
    pr_files: &HashSet<String>,
    scan_root: Option<&Path>,
) -> Vec<serde_json::Value> {
    findings
        .iter()
        .filter_map(|f| {
            let path = relative_path(&f.file, scan_root);
            if !pr_files.contains(&path) {
                return None;
            }
            Some(serde_json::json!({
                "path": path,
                "line": f.line,
                "side": "RIGHT",
                "body": format_comment_body(f),
            }))
        })
        .collect()
}

pub fn review_comments_for_commentable_lines(
    findings: &[Finding],
    commentable_lines: &HashMap<String, HashSet<usize>>,
    scan_root: Option<&Path>,
) -> Vec<serde_json::Value> {
    findings
        .iter()
        .filter_map(|f| {
            let path = relative_path(&f.file, scan_root);
            if !commentable_lines
                .get(&path)
                .is_some_and(|lines| lines.contains(&f.line))
            {
                return None;
            }
            Some(serde_json::json!({
                "path": path,
                "line": f.line,
                "side": "RIGHT",
                "body": format_comment_body(f),
            }))
        })
        .collect()
}

pub fn review_body_for_comments(comments: Vec<serde_json::Value>) -> serde_json::Value {
    serde_json::json!({
        "event": "COMMENT",
        "body": format!("{COMMENT_MARKER}\n\n**foxguard** found {} issue(s) in this PR", comments.len()),
        "comments": comments,
    })
}

/// Post findings as inline review comments on a GitHub pull request.
///
/// Uses `gh api` to create a single PR review containing all comments.
/// Returns `Ok(())` on success, or an error message on failure.
/// This is best-effort: callers should not abort on failure.
pub fn post_pr_review(
    findings: &[Finding],
    pr_number: u64,
    scan_root: Option<&Path>,
) -> Result<(), String> {
    let token = std::env::var("GITHUB_TOKEN").ok();
    if token.is_none() {
        eprintln!("Warning: GITHUB_TOKEN not set, skipping PR review comments");
        return Ok(());
    }

    let repo = std::env::var("GITHUB_REPOSITORY").map_err(|_| {
        "GITHUB_REPOSITORY environment variable not set; cannot post PR review".to_string()
    })?;

    let deleted = delete_existing_foxguard_comments(&repo, pr_number)?;
    if deleted > 0 {
        eprintln!(
            "Removed {} prior foxguard PR comment(s) on PR #{}",
            deleted, pr_number
        );
    }

    if findings.is_empty() {
        return Ok(());
    }

    // Get the PR diff to know which lines are commentable
    let diff_output = std::process::Command::new("gh")
        .args([
            "api",
            &format!("repos/{repo}/pulls/{pr_number}/files"),
            "--jq",
            ".[].filename",
        ])
        .output()
        .map_err(|e| format!("Failed to get PR files: {e}"))?;

    let pr_files: HashSet<String> = String::from_utf8_lossy(&diff_output.stdout)
        .lines()
        .map(|l| l.trim().to_string())
        .collect();

    // Build the comments array — only for files that are in the PR diff
    let comments = review_comments_for_findings(findings, &pr_files, scan_root);

    if comments.is_empty() {
        eprintln!("No findings in PR-changed files, skipping review");
        return Ok(());
    }

    let comment_count = comments.len();
    let review_body = review_body_for_comments(comments);

    let json_str = serde_json::to_string(&review_body)
        .map_err(|e| format!("Failed to serialize review body: {e}"))?;

    let endpoint = format!("repos/{repo}/pulls/{pr_number}/reviews");

    let output = std::process::Command::new("gh")
        .args(["api", &endpoint, "--method", "POST", "--input", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(ref mut stdin) = child.stdin {
                stdin.write_all(json_str.as_bytes())?;
            }
            child.wait_with_output()
        })
        .map_err(|e| format!("Failed to run `gh api`: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("gh api returned {}: {}", output.status, stderr));
    }

    eprintln!(
        "Posted {} inline comment(s) on PR #{}",
        comment_count, pr_number
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_finding() -> Finding {
        Finding {
            rule_id: "py/taint-sql-injection".to_string(),
            severity: Severity::Critical,
            cwe: Some("CWE-89".to_string()),
            description: "Untrusted input reaches cursor.execute".to_string(),
            file: "./src/app.py".to_string(),
            line: 42,
            column: 5,
            end_line: 42,
            end_column: 40,
            snippet: "cursor.execute(query)".to_string(),
            source_line: None,
            source_description: None,
            sink_line: None,
            sink_description: None,
            fix_suggestion: Some(
                "Use parameterized queries: `cur.execute(\"SELECT * FROM users WHERE name = ?\", (name,))`"
                    .to_string(),
            ),
            sink_start_byte: None,
            sink_end_byte: None,
            confidence: crate::default_confidence(),
            taint_hops: None,
            tags: vec![],
            crypto_algorithm: None,
            cnsa2_deadline: None,
            dep_name: None,
        }
    }

    #[test]
    fn test_format_comment_body_includes_severity_and_rule() {
        let f = sample_finding();
        let body = format_comment_body(&f);
        assert!(body.contains(COMMENT_MARKER));
        assert!(body.contains("**foxguard**"));
        assert!(body.contains("`CRITICAL`"));
        assert!(body.contains("`py/taint-sql-injection`"));
        assert!(body.contains("CWE-89"));
        assert!(body.contains("**Fix:**"));
    }

    #[test]
    fn test_format_comment_body_no_cwe() {
        let mut f = sample_finding();
        f.cwe = None;
        let body = format_comment_body(&f);
        assert!(!body.contains("CWE"));
    }

    #[test]
    fn test_format_comment_body_no_fix() {
        let mut f = sample_finding();
        f.fix_suggestion = None;
        let body = format_comment_body(&f);
        assert!(!body.contains("**Fix:**"));
    }

    #[test]
    fn test_relative_path_strips_dot_slash() {
        assert_eq!(relative_path("./src/app.py", None), "src/app.py");
    }

    #[test]
    fn test_relative_path_strips_leading_slash() {
        assert_eq!(relative_path("/src/app.py", None), "src/app.py");
    }

    #[test]
    fn test_relative_path_already_relative() {
        assert_eq!(relative_path("src/app.py", None), "src/app.py");
    }

    #[test]
    fn test_severity_labels() {
        assert_eq!(severity_label(Severity::Low), "LOW");
        assert_eq!(severity_label(Severity::Medium), "MEDIUM");
        assert_eq!(severity_label(Severity::High), "HIGH");
        assert_eq!(severity_label(Severity::Critical), "CRITICAL");
    }

    #[test]
    fn test_post_pr_review_skips_when_no_token() {
        // Ensure GITHUB_TOKEN is not set for this test
        std::env::remove_var("GITHUB_TOKEN");
        let result = post_pr_review(&[sample_finding()], 1, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_post_pr_review_skips_empty_findings() {
        std::env::remove_var("GITHUB_TOKEN");
        std::env::remove_var("GITHUB_REPOSITORY");
        let result = post_pr_review(&[], 1, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_existing_foxguard_comment_ids_reads_plain_comment_array() {
        let stdout = br#"[
            {"id": 11, "body": "<!-- foxguard:pr-review -->\nold"},
            {"id": 12, "body": "human comment"},
            {"id": 13, "body": "<!-- foxguard:pr-review -->\nolder"}
        ]"#;

        let ids = match existing_foxguard_comment_ids(stdout) {
            Ok(ids) => ids,
            Err(error) => panic!("failed to parse comments: {error}"),
        };

        assert_eq!(ids, vec![11, 13]);
    }

    #[test]
    fn test_existing_foxguard_comment_ids_reads_slurped_pages() {
        let stdout = br#"[
            [{"id": 21, "body": "<!-- foxguard:pr-review -->\nold"}],
            [{"id": 22, "body": "human comment"}],
            [{"id": 23, "body": "<!-- foxguard:pr-review -->\nolder"}]
        ]"#;

        let ids = match existing_foxguard_comment_ids(stdout) {
            Ok(ids) => ids,
            Err(error) => panic!("failed to parse comments: {error}"),
        };

        assert_eq!(ids, vec![21, 23]);
    }
}
