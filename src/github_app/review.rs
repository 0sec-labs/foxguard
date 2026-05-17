//! Pull request review posting for the GitHub App receiver.

use crate::report::github_pr::{review_comments_for_commentable_lines, COMMENT_MARKER};
use crate::{Finding, Severity};
use reqwest::Url;
use serde::Deserialize;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::Path;
use std::time::Duration;

const GITHUB_API_VERSION: &str = "2026-03-10";
const PAGE_SIZE: usize = 100;

#[derive(Debug)]
pub enum ReviewError {
    InvalidApiBaseUrl(String),
    InvalidRepository(String),
    InvalidEndpoint(String),
    Http(reqwest::Error),
}

impl fmt::Display for ReviewError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidApiBaseUrl(error) => write!(f, "invalid GitHub API base URL: {error}"),
            Self::InvalidRepository(error) => write!(f, "invalid GitHub repository: {error}"),
            Self::InvalidEndpoint(error) => write!(f, "invalid GitHub API endpoint: {error}"),
            Self::Http(error) => write!(f, "GitHub review request failed: {error}"),
        }
    }
}

impl std::error::Error for ReviewError {}

impl From<reqwest::Error> for ReviewError {
    fn from(error: reqwest::Error) -> Self {
        Self::Http(error)
    }
}

#[derive(Clone)]
pub struct GitHubReviewClient {
    http: reqwest::Client,
    api_base_url: Url,
}

impl GitHubReviewClient {
    pub fn new(api_base_url: &str) -> Result<Self, ReviewError> {
        let api_base_url = Url::parse(api_base_url)
            .map_err(|error| ReviewError::InvalidApiBaseUrl(error.to_string()))?;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent("foxguard-github-app")
            .build()?;
        Ok(Self { http, api_base_url })
    }

    pub async fn post_pull_request_review(
        &self,
        repo_full_name: &str,
        pr_number: u64,
        head_sha: &str,
        findings: &[Finding],
        scan_root: Option<&Path>,
        installation_token: &str,
    ) -> Result<PostReviewOutcome, ReviewError> {
        let repo = RepositoryPath::parse(repo_full_name)?;
        let existing_comment_ids = self
            .existing_foxguard_comment_ids(&repo, pr_number, installation_token)
            .await?;
        if findings.is_empty() {
            let deleted_comments = self
                .delete_foxguard_comment_ids(&repo, &existing_comment_ids, installation_token)
                .await?;
            return Ok(PostReviewOutcome {
                deleted_comments,
                posted_comments: 0,
            });
        }

        let commentable_lines = self
            .pull_request_commentable_lines(&repo, pr_number, installation_token)
            .await?;
        let comments =
            review_comments_for_commentable_lines(findings, &commentable_lines, scan_root);
        if comments.is_empty() {
            let deleted_comments = self
                .delete_foxguard_comment_ids(&repo, &existing_comment_ids, installation_token)
                .await?;
            return Ok(PostReviewOutcome {
                deleted_comments,
                posted_comments: 0,
            });
        }

        let posted_comments = comments.len();
        for comment in comments {
            self.post_inline_comment(&repo, pr_number, head_sha, comment, installation_token)
                .await?;
        }

        let deleted_comments = self
            .delete_foxguard_comment_ids(&repo, &existing_comment_ids, installation_token)
            .await?;

        Ok(PostReviewOutcome {
            deleted_comments,
            posted_comments,
        })
    }

    pub async fn post_check_run(
        &self,
        repo_full_name: &str,
        head_sha: &str,
        findings: &[Finding],
        installation_token: &str,
    ) -> Result<PostCheckRunOutcome, ReviewError> {
        let repo = RepositoryPath::parse(repo_full_name)?;
        let annotations = check_run_annotations(findings);
        let annotation_count = annotations.len();
        let url = self.endpoint(&format!("repos/{}/{}/check-runs", repo.owner, repo.name))?;
        let body = serde_json::json!({
            "name": "foxguard",
            "head_sha": head_sha,
            "status": "completed",
            "conclusion": check_run_conclusion(findings),
            "output": {
                "title": check_run_title(findings),
                "summary": check_run_summary(findings, annotation_count),
                "annotations": annotations,
            },
        });
        // URL construction is restricted to a validated GitHub API base URL plus
        // repository path segments parsed by `RepositoryPath::parse`.
        let request = self.http.post(url); // foxguard: ignore[rs/no-ssrf]
        request
            .bearer_auth(installation_token)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", GITHUB_API_VERSION)
            .json(&body)
            .send()
            .await?
            .error_for_status()?;

        Ok(PostCheckRunOutcome {
            posted_annotations: annotation_count,
        })
    }

    async fn delete_foxguard_comment_ids(
        &self,
        repo: &RepositoryPath,
        ids: &[u64],
        installation_token: &str,
    ) -> Result<usize, ReviewError> {
        for id in ids {
            let url = self.endpoint(&format!(
                "repos/{}/{}/pulls/comments/{id}",
                repo.owner, repo.name
            ))?;
            // URL construction is restricted to validated path segments and ids
            // returned by GitHub's PR comments API.
            let request = self.http.delete(url); // foxguard: ignore[rs/no-ssrf]
            request
                .bearer_auth(installation_token)
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", GITHUB_API_VERSION)
                .send()
                .await?
                .error_for_status()?;
        }
        Ok(ids.len())
    }

    async fn existing_foxguard_comment_ids(
        &self,
        repo: &RepositoryPath,
        pr_number: u64,
        installation_token: &str,
    ) -> Result<Vec<u64>, ReviewError> {
        let comments = self
            .paginated_get::<PullRequestComment>(
                &format!(
                    "repos/{}/{}/pulls/{pr_number}/comments",
                    repo.owner, repo.name
                ),
                installation_token,
            )
            .await?;

        Ok(comments
            .into_iter()
            .filter(|comment| {
                comment
                    .body
                    .as_deref()
                    .is_some_and(|body| body.contains(COMMENT_MARKER))
            })
            .map(|comment| comment.id)
            .collect())
    }

    async fn pull_request_commentable_lines(
        &self,
        repo: &RepositoryPath,
        pr_number: u64,
        installation_token: &str,
    ) -> Result<HashMap<String, HashSet<usize>>, ReviewError> {
        let files = self
            .paginated_get::<PullRequestFile>(
                &format!("repos/{}/{}/pulls/{pr_number}/files", repo.owner, repo.name),
                installation_token,
            )
            .await?;
        Ok(files
            .into_iter()
            .filter_map(|file| {
                let lines = commentable_lines_from_patch(file.patch.as_deref())?;
                Some((file.filename, lines))
            })
            .collect())
    }

    async fn post_inline_comment(
        &self,
        repo: &RepositoryPath,
        pr_number: u64,
        head_sha: &str,
        comment: Value,
        installation_token: &str,
    ) -> Result<(), ReviewError> {
        let url = self.endpoint(&format!(
            "repos/{}/{}/pulls/{pr_number}/comments",
            repo.owner, repo.name
        ))?;
        let body = serde_json::json!({
            "body": comment["body"],
            "commit_id": head_sha,
            "path": comment["path"],
            "line": comment["line"],
            "side": comment["side"],
        });
        // URL construction is restricted to a validated GitHub API base URL plus
        // repository path segments parsed by `RepositoryPath::parse`.
        let request = self.http.post(url); // foxguard: ignore[rs/no-ssrf]
        request
            .bearer_auth(installation_token)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", GITHUB_API_VERSION)
            .json(&body)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    async fn paginated_get<T>(
        &self,
        endpoint: &str,
        installation_token: &str,
    ) -> Result<Vec<T>, ReviewError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let mut page = 1;
        let mut items = Vec::new();
        loop {
            let mut url = self.endpoint(endpoint)?;
            url.query_pairs_mut()
                .append_pair("per_page", &PAGE_SIZE.to_string())
                .append_pair("page", &page.to_string());
            // URL construction is restricted to a validated GitHub API base URL
            // plus endpoints built from validated repository path segments.
            let request = self.http.get(url); // foxguard: ignore[rs/no-ssrf]
            let mut page_items = request
                .bearer_auth(installation_token)
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", GITHUB_API_VERSION)
                .send()
                .await?
                .error_for_status()?
                .json::<Vec<T>>()
                .await?;
            let is_last_page = page_items.len() < PAGE_SIZE;
            items.append(&mut page_items);
            if is_last_page {
                return Ok(items);
            }
            page += 1;
        }
    }

    fn endpoint(&self, endpoint: &str) -> Result<Url, ReviewError> {
        self.api_base_url
            .join(&format!(
                "{}/",
                self.api_base_url.path().trim_end_matches('/')
            ))
            .and_then(|base| base.join(endpoint))
            .map_err(|error| ReviewError::InvalidEndpoint(error.to_string()))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct PostReviewOutcome {
    pub deleted_comments: usize,
    pub posted_comments: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub struct PostCheckRunOutcome {
    pub posted_annotations: usize,
}

#[derive(Debug)]
struct RepositoryPath {
    owner: String,
    name: String,
}

impl RepositoryPath {
    fn parse(full_name: &str) -> Result<Self, ReviewError> {
        let mut parts = full_name.split('/');
        let owner = parts
            .next()
            .ok_or_else(|| ReviewError::InvalidRepository("owner is required".to_string()))?;
        let name = parts
            .next()
            .ok_or_else(|| ReviewError::InvalidRepository("name is required".to_string()))?;
        if parts.next().is_some() {
            return Err(ReviewError::InvalidRepository(
                "repository must be owner/name".to_string(),
            ));
        }
        if !valid_repo_segment(owner) || !valid_repo_segment(name) {
            return Err(ReviewError::InvalidRepository(
                "repository path contains invalid characters".to_string(),
            ));
        }

        Ok(Self {
            owner: owner.to_string(),
            name: name.to_string(),
        })
    }
}

fn valid_repo_segment(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[derive(Debug, Deserialize)]
struct PullRequestComment {
    id: u64,
    body: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PullRequestFile {
    filename: String,
    patch: Option<String>,
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
        if line.starts_with('+') || line.starts_with(' ') {
            lines.insert(*current_line);
            *current_line += 1;
        }
    }
    Some(lines)
}

fn hunk_new_start(line: &str) -> Option<usize> {
    let hunk = line.strip_prefix("@@ ")?;
    let plus = hunk.split_whitespace().find(|part| part.starts_with('+'))?;
    let start = plus.trim_start_matches('+').split(',').next()?;
    start.parse().ok()
}

fn check_run_conclusion(findings: &[Finding]) -> &'static str {
    if findings.is_empty() {
        return "success";
    }
    if findings
        .iter()
        .any(|finding| matches!(finding.severity, Severity::High | Severity::Critical))
    {
        return "failure";
    }
    "neutral"
}

fn check_run_title(findings: &[Finding]) -> &'static str {
    if findings.is_empty() {
        "foxguard found no issues"
    } else {
        "foxguard found issues"
    }
}

fn check_run_summary(findings: &[Finding], annotation_count: usize) -> String {
    if findings.is_empty() {
        return "foxguard scan completed with no findings.".to_string();
    }

    let mut low = 0;
    let mut medium = 0;
    let mut high = 0;
    let mut critical = 0;
    for finding in findings {
        match finding.severity {
            Severity::Low => low += 1,
            Severity::Medium => medium += 1,
            Severity::High => high += 1,
            Severity::Critical => critical += 1,
        }
    }

    let mut summary = format!(
        "foxguard found {} issue(s): {critical} critical, {high} high, {medium} medium, {low} low.",
        findings.len()
    );
    if annotation_count < findings.len() {
        summary.push_str(&format!(
            " Showing the first {annotation_count} as check annotations."
        ));
    }
    summary
}

fn check_run_annotations(findings: &[Finding]) -> Vec<Value> {
    findings
        .iter()
        .filter(|finding| finding.line > 0)
        .take(50)
        .map(|finding| {
            let end_line = finding.end_line.max(finding.line);
            serde_json::json!({
                "path": finding.file,
                "start_line": finding.line,
                "end_line": end_line,
                "annotation_level": annotation_level(finding.severity),
                "title": truncate(&format!("{} ({})", finding.rule_id, finding.severity), 255),
                "message": truncate(&finding.description, 64_000),
                "raw_details": truncate(&finding.snippet, 64_000),
            })
        })
        .collect()
}

fn annotation_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Low => "notice",
        Severity::Medium => "warning",
        Severity::High | Severity::Critical => "failure",
    }
}

fn truncate(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    if max_chars <= 3 {
        return ".".repeat(max_chars);
    }
    let mut truncated: String = value.chars().take(max_chars - 3).collect();
    truncated.push_str("...");
    truncated
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repository_path_accepts_owner_repo() {
        let parsed = match RepositoryPath::parse("0sec-labs/foxguard") {
            Ok(parsed) => parsed,
            Err(error) => panic!("repository should parse: {error}"),
        };
        assert_eq!(parsed.owner, "0sec-labs");
        assert_eq!(parsed.name, "foxguard");
    }

    #[test]
    fn repository_path_rejects_path_injection() {
        assert!(RepositoryPath::parse("0sec-labs/foxguard/issues").is_err());
        assert!(RepositoryPath::parse("0sec-labs/../foxguard").is_err());
        assert!(RepositoryPath::parse("0sec-labs/foxguard?x=1").is_err());
    }

    #[test]
    fn endpoint_preserves_enterprise_api_path() {
        let client = match GitHubReviewClient::new("https://github.example.com/api/v3") {
            Ok(client) => client,
            Err(error) => panic!("client should build: {error}"),
        };
        let url = match client.endpoint("repos/owner/repo/pulls/1/files") {
            Ok(url) => url,
            Err(error) => panic!("endpoint should build: {error}"),
        };

        assert_eq!(
            url.as_str(),
            "https://github.example.com/api/v3/repos/owner/repo/pulls/1/files"
        );
    }

    #[test]
    fn valid_repo_segment_rejects_empty_and_traversal() {
        assert!(!valid_repo_segment(""));
        assert!(!valid_repo_segment("."));
        assert!(!valid_repo_segment(".."));
        assert!(valid_repo_segment("repo.name_1-2"));
    }

    #[test]
    fn commentable_lines_include_added_and_context_lines() {
        let lines = match commentable_lines_from_patch(Some(
            "@@ -10,4 +20,5 @@ fn demo() {\n context\n-old\n+new\n keep\n+added",
        )) {
            Some(lines) => lines,
            None => panic!("patch should parse"),
        };

        assert!(lines.contains(&20));
        assert!(lines.contains(&21));
        assert!(lines.contains(&22));
        assert!(lines.contains(&23));
        assert!(!lines.contains(&24));
    }

    #[test]
    fn commentable_lines_returns_none_without_patch() {
        assert!(commentable_lines_from_patch(None).is_none());
    }

    fn finding(severity: Severity, line: usize) -> Finding {
        Finding {
            rule_id: "test/rule".to_string(),
            severity,
            cwe: Some("CWE-79".to_string()),
            description: "finding description".to_string(),
            file: "src/app.js".to_string(),
            line,
            column: 1,
            end_line: line,
            end_column: 2,
            snippet: "bad()".to_string(),
            source_line: None,
            source_description: None,
            sink_line: None,
            sink_description: None,
            fix_suggestion: None,
            sink_start_byte: None,
            sink_end_byte: None,
            confidence: 1.0,
            taint_hops: None,
            tags: Vec::new(),
            crypto_algorithm: None,
            cnsa2_deadline: None,
            dep_name: None,
        }
    }

    #[test]
    fn check_run_conclusion_matches_severity() {
        assert_eq!(check_run_conclusion(&[]), "success");
        assert_eq!(
            check_run_conclusion(&[finding(Severity::Low, 1)]),
            "neutral"
        );
        assert_eq!(
            check_run_conclusion(&[finding(Severity::High, 1)]),
            "failure"
        );
    }

    #[test]
    fn check_run_annotations_cap_at_github_limit() {
        let findings: Vec<_> = (1..=60)
            .map(|line| finding(Severity::Critical, line))
            .collect();
        let annotations = check_run_annotations(&findings);

        assert_eq!(annotations.len(), 50);
        assert_eq!(annotations[0]["path"], "src/app.js");
        assert_eq!(annotations[0]["start_line"], 1);
        assert_eq!(annotations[0]["annotation_level"], "failure");
    }

    #[test]
    fn check_run_summary_mentions_truncated_annotations() {
        let findings: Vec<_> = (1..=60)
            .map(|line| finding(Severity::Medium, line))
            .collect();
        let summary = check_run_summary(&findings, 50);

        assert!(summary.contains("60 issue(s)"));
        assert!(summary.contains("Showing the first 50"));
    }
}
