use crate::{Finding, Severity};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;

pub const COMMENT_MARKER: &str = "<!-- foxguard:pr-review -->";

#[derive(Debug, serde::Deserialize)]
struct PullRequestFile {
    filename: String,
    patch: Option<String>,
}

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

/// Findings that land on an added line of the PR diff.
pub fn findings_on_commentable_lines(
    findings: &[Finding],
    commentable_lines: &HashMap<String, HashSet<usize>>,
    scan_root: Option<&Path>,
) -> Vec<Finding> {
    findings
        .iter()
        .filter(|f| {
            commentable_lines
                .get(&relative_path(&f.file, scan_root))
                .is_some_and(|lines| lines.contains(&f.line))
        })
        .cloned()
        .collect()
}

pub fn review_body_for_findings(
    findings: &[Finding],
    comments: Vec<serde_json::Value>,
) -> serde_json::Value {
    serde_json::json!({
        "event": "COMMENT",
        "body": review_summary_body(findings),
        "comments": comments,
    })
}

fn review_summary_body(findings: &[Finding]) -> String {
    let mut low = 0;
    let mut medium = 0;
    let mut high = 0;
    let mut critical = 0;
    let mut class_counts: BTreeMap<String, (usize, BTreeSet<String>)> = BTreeMap::new();

    for finding in findings {
        match finding.severity {
            Severity::Low => low += 1,
            Severity::Medium => medium += 1,
            Severity::High => high += 1,
            Severity::Critical => critical += 1,
        }

        let class = finding_class_label(&finding.rule_id);
        let entry = class_counts
            .entry(class)
            .or_insert_with(|| (0, BTreeSet::new()));
        entry.0 += 1;
        entry.1.insert(finding.rule_id.clone());
    }

    let mut classes: Vec<(String, usize, BTreeSet<String>)> = class_counts
        .into_iter()
        .map(|(class, (count, rule_ids))| (class, count, rule_ids))
        .collect();
    classes.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let mut body = format!(
        "{COMMENT_MARKER}\n\n**foxguard** found {} issue(s) in this PR",
        findings.len()
    );
    body.push_str(&format!(
        "\n\n**By severity**\n- `CRITICAL`: {critical}\n- `HIGH`: {high}\n- `MEDIUM`: {medium}\n- `LOW`: {low}"
    ));

    if !classes.is_empty() {
        body.push_str("\n\n**By class**");
        for (class, count, rule_ids) in classes {
            let rules = rule_ids.into_iter().collect::<Vec<_>>().join("`, `");
            body.push_str(&format!("\n- `{class}`: {count} (`{rules}`)"));
        }
    }

    body
}

fn finding_class_label(rule_id: &str) -> String {
    let family = rule_id
        .split_once('/')
        .map(|(_, suffix)| suffix)
        .unwrap_or(rule_id);
    let mut parts: Vec<&str> = family.split('-').collect();
    while parts
        .first()
        .is_some_and(|part| matches!(*part, "no" | "taint" | "detect"))
    {
        parts.remove(0);
    }
    if parts.is_empty() {
        parts = family.split('-').collect();
    }
    parts
        .into_iter()
        .map(display_class_token)
        .collect::<Vec<_>>()
        .join(" ")
}

fn display_class_token(token: &str) -> String {
    match token {
        "api" => "API".to_string(),
        "cbom" => "CBOM".to_string(),
        "cli" => "CLI".to_string(),
        "cors" => "CORS".to_string(),
        "csrf" => "CSRF".to_string(),
        "dos" => "DoS".to_string(),
        "html" => "HTML".to_string(),
        "http" => "HTTP".to_string(),
        "https" => "HTTPS".to_string(),
        "jwt" => "JWT".to_string(),
        "osv" => "OSV".to_string(),
        "pq" => "PQ".to_string(),
        "pqc" => "PQC".to_string(),
        "sarif" => "SARIF".to_string(),
        "sql" => "SQL".to_string(),
        "ssrf" => "SSRF".to_string(),
        "tls" => "TLS".to_string(),
        "xss" => "XSS".to_string(),
        "xxe" => "XXE".to_string(),
        _ => {
            let mut chars = token.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        }
    }
}

fn gh_pull_request_files(stdout: &[u8]) -> Result<Vec<PullRequestFile>, String> {
    let value: serde_json::Value = serde_json::from_slice(stdout)
        .map_err(|e| format!("Failed to parse PR files response: {e}"))?;
    let file_values: Vec<serde_json::Value> = match value.as_array() {
        Some(values) if values.iter().all(|value| value.is_array()) => values
            .iter()
            .flat_map(|page| page.as_array().into_iter().flatten().cloned())
            .collect(),
        Some(values) => values.clone(),
        None => Vec::new(),
    };

    file_values
        .into_iter()
        .map(|value| {
            serde_json::from_value(value).map_err(|e| format!("Failed to decode PR file: {e}"))
        })
        .collect()
}

fn hunk_new_start(line: &str) -> Option<usize> {
    let hunk = line.strip_prefix("@@ ")?;
    let plus = hunk.split_whitespace().find(|part| part.starts_with('+'))?;
    let start = plus.trim_start_matches('+').split(',').next()?;
    start.parse().ok()
}

fn commentable_lines_from_patch(patch: Option<&str>) -> Option<HashSet<usize>> {
    let patch = patch?;
    let mut lines = HashSet::new();
    let mut new_line = None;
    for line in patch.lines() {
        if let Some(start) = hunk_new_start(line) {
            new_line = Some(start);
            continue;
        }

        let Some(current_line) = new_line.as_mut() else {
            continue;
        };
        if line.starts_with('+') {
            lines.insert(*current_line);
            *current_line += 1;
        } else if line.starts_with(' ') {
            *current_line += 1;
        }
    }
    Some(lines)
}

fn commentable_lines_by_file(stdout: &[u8]) -> Result<HashMap<String, HashSet<usize>>, String> {
    Ok(gh_pull_request_files(stdout)?
        .into_iter()
        .filter_map(|file| {
            let lines = commentable_lines_from_patch(file.patch.as_deref())?;
            Some((file.filename, lines))
        })
        .collect())
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
        let deleted = delete_existing_foxguard_comments(&repo, pr_number)?;
        if deleted > 0 {
            eprintln!(
                "Removed {} prior foxguard PR comment(s) on PR #{}",
                deleted, pr_number
            );
        }
        return Ok(());
    }

    // Get the PR diff to know which lines are commentable.
    let diff_output = std::process::Command::new("gh")
        .args([
            "api",
            &format!("repos/{repo}/pulls/{pr_number}/files"),
            "--paginate",
            "--slurp",
        ])
        .output()
        .map_err(|e| format!("Failed to get PR files: {e}"))?;

    if !diff_output.status.success() {
        let stderr = String::from_utf8_lossy(&diff_output.stderr);
        return Err(format!(
            "gh api returned {} while listing PR files: {}",
            diff_output.status, stderr
        ));
    }

    let commentable_lines = commentable_lines_by_file(&diff_output.stdout)?;
    let commentable_findings =
        findings_on_commentable_lines(findings, &commentable_lines, scan_root);
    let comments =
        review_comments_for_commentable_lines(&commentable_findings, &commentable_lines, scan_root);

    if comments.is_empty() {
        let deleted = delete_existing_foxguard_comments(&repo, pr_number)?;
        if deleted > 0 {
            eprintln!(
                "Removed {} prior foxguard PR comment(s) on PR #{}",
                deleted, pr_number
            );
        }
        eprintln!("No findings on commentable PR lines, skipping review");
        return Ok(());
    }

    let deleted = delete_existing_foxguard_comments(&repo, pr_number)?;
    if deleted > 0 {
        eprintln!(
            "Removed {} prior foxguard PR comment(s) on PR #{}",
            deleted, pr_number
        );
    }

    let comment_count = comments.len();
    let review_body = review_body_for_findings(&commentable_findings, comments);

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
            dep_version: None,
            dep_ecosystem: None,
            dep_purl: None,
            dep_vulnerability_id: None,
            dep_fixed_version: None,
            dep_source: None,
            dep_vulnerability_severity: None,
            dep_path: vec![],
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

    #[test]
    fn test_commentable_lines_from_patch_includes_added_lines_only() {
        let lines = commentable_lines_from_patch(Some(
            "@@ -10,4 +20,5 @@ fn demo() {\n context\n-old\n+new\n keep\n+added",
        ))
        .unwrap_or_else(|| panic!("patch should parse"));

        assert!(lines.contains(&21));
        assert!(lines.contains(&23));
        assert!(!lines.contains(&20));
        assert!(!lines.contains(&22));
        assert!(!lines.contains(&24));
    }

    #[test]
    fn test_commentable_lines_by_file_reads_slurped_pages() {
        let stdout = br#"[
            [{"filename":"src/app.py","patch":"@@ -1 +1,2 @@\n context\n+added"}],
            [{"filename":"src/other.py","patch":"@@ -5 +8,2 @@\n keep\n+new"}]
        ]"#;

        let lines = commentable_lines_by_file(stdout)
            .unwrap_or_else(|error| panic!("failed to parse PR files: {error}"));

        assert_eq!(lines["src/app.py"], HashSet::from([2]));
        assert_eq!(lines["src/other.py"], HashSet::from([9]));
    }

    #[test]
    fn test_review_comments_for_commentable_lines_skips_non_diff_lines() {
        let mut off_hunk = sample_finding();
        off_hunk.line = 99;
        let findings = vec![sample_finding(), off_hunk];
        let commentable_lines =
            HashMap::from([(String::from("src/app.py"), HashSet::from([42usize]))]);

        let comments = review_comments_for_commentable_lines(&findings, &commentable_lines, None);

        assert_eq!(comments.len(), 1);
        assert_eq!(comments[0]["path"], "src/app.py");
        assert_eq!(comments[0]["line"], 42);
    }

    #[test]
    fn test_review_body_for_findings_groups_by_class_and_severity() {
        let mut secret = sample_finding();
        secret.rule_id = "js/no-hardcoded-secret".to_string();
        secret.severity = Severity::High;
        secret.description = "Hardcoded secret".to_string();

        let mut taint = sample_finding();
        taint.rule_id = "py/taint-sql-injection".to_string();
        taint.description = "Tainted SQL".to_string();

        let mut direct = sample_finding();
        direct.rule_id = "py/no-sql-injection".to_string();
        direct.description = "Direct SQL".to_string();
        direct.severity = Severity::Medium;

        let comments =
            vec![serde_json::json!({"path":"src/app.py","line":1,"side":"RIGHT","body":"x"})];
        let review = review_body_for_findings(&[secret, taint, direct], comments);
        let body = review["body"]
            .as_str()
            .unwrap_or_else(|| panic!("review body should be a string"));

        assert!(body.contains("**foxguard** found 3 issue(s)"));
        assert!(body.contains("**By severity**"));
        assert!(body.contains("`CRITICAL`: 1"));
        assert!(body.contains("`HIGH`: 1"));
        assert!(body.contains("`MEDIUM`: 1"));
        assert!(body.contains("**By class**"));
        assert!(body.contains("`SQL Injection`: 2"));
        assert!(body.contains("`py/no-sql-injection`"));
        assert!(body.contains("`py/taint-sql-injection`"));
        assert!(body.contains("`Hardcoded Secret`: 1"));
    }
}
