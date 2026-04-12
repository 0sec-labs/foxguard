use crate::{Finding, Severity};
use std::path::Path;

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
fn format_comment_body(finding: &Finding) -> String {
    let cwe_suffix = finding
        .cwe
        .as_ref()
        .map(|c| format!(" ({c})"))
        .unwrap_or_default();

    let mut body = format!(
        "**foxguard** \u{00b7} `{}` \u{00b7} `{}`{}\n\n{}",
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

/// Make a file path relative to the repository root.
///
/// If `scan_root` is provided, the finding's file path is stripped of that
/// prefix so the resulting path is relative (as required by the GitHub API).
fn relative_path(file: &str, scan_root: Option<&Path>) -> String {
    if let Some(root) = scan_root {
        if let Ok(canonical_root) = std::fs::canonicalize(root) {
            let file_path = Path::new(file);
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

    if findings.is_empty() {
        return Ok(());
    }

    // Build the comments array for the review
    let comments: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            let path = relative_path(&f.file, scan_root);
            serde_json::json!({
                "path": path,
                "line": f.line,
                "body": format_comment_body(f),
            })
        })
        .collect();

    let review_body = serde_json::json!({
        "event": "COMMENT",
        "body": format!("foxguard found {} finding(s)", findings.len()),
        "comments": comments,
    });

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
        findings.len(),
        pr_number
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
        }
    }

    #[test]
    fn test_format_comment_body_includes_severity_and_rule() {
        let f = sample_finding();
        let body = format_comment_body(&f);
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
        std::env::set_var("GITHUB_TOKEN", "test");
        std::env::set_var("GITHUB_REPOSITORY", "owner/repo");
        let result = post_pr_review(&[], 1, None);
        assert!(result.is_ok());
        std::env::remove_var("GITHUB_TOKEN");
        std::env::remove_var("GITHUB_REPOSITORY");
    }
}
