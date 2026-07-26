//! Pull request review posting for the GitHub App receiver.

use crate::pr_policy::{PrPolicyEvaluation, PrPolicyNotEvaluated, PrPolicyReport};
use crate::report::github_pr::{format_comment_body, COMMENT_MARKER};
use crate::{Finding, Severity};
use reqwest::Url;
use serde::Deserialize;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::time::Duration;

const GITHUB_API_VERSION: &str = "2026-03-10";
const PAGE_SIZE: usize = 100;

#[derive(Debug)]
pub enum ReviewError {
    InvalidApiBaseUrl(String),
    InvalidRepository(String),
    InvalidRepositoryWebUrl(String),
    InvalidEndpoint(String),
    Http(reqwest::Error),
}

impl fmt::Display for ReviewError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidApiBaseUrl(error) => write!(f, "invalid GitHub API base URL: {error}"),
            Self::InvalidRepository(error) => write!(f, "invalid GitHub repository: {error}"),
            Self::InvalidRepositoryWebUrl(error) => {
                write!(f, "invalid GitHub repository web URL: {error}")
            }
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

/// The policy result represented by a GitHub check run.
pub enum CheckRunPolicy<'a> {
    Evaluated(&'a PrPolicyEvaluation),
    NotEvaluated {
        findings: &'a [Finding],
        policy: &'a PrPolicyNotEvaluated,
    },
}

#[derive(Clone)]
pub struct GitHubReviewClient {
    http: reqwest::Client,
    api_base_url: Url,
    app_id: u64,
}

impl GitHubReviewClient {
    pub fn new(api_base_url: &str, app_id: u64) -> Result<Self, ReviewError> {
        let api_base_url = Url::parse(api_base_url)
            .map_err(|error| ReviewError::InvalidApiBaseUrl(error.to_string()))?;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent("foxguard-github-app")
            .build()?;
        Ok(Self {
            http,
            api_base_url,
            app_id,
        })
    }

    /// Fetch added lines for each changed file in a pull request. Files without
    /// a patch remain in the map with an empty line set so file-only findings
    /// can still be scoped to changed files.
    pub async fn pull_request_changed_lines(
        &self,
        repo_full_name: &str,
        pr_number: u64,
        installation_token: &str,
    ) -> Result<HashMap<String, HashSet<usize>>, ReviewError> {
        let repo = RepositoryPath::parse(repo_full_name)?;
        self.pull_request_commentable_lines(&repo, pr_number, installation_token)
            .await
    }

    pub async fn post_pull_request_review(
        &self,
        repo_full_name: &str,
        pr_number: u64,
        findings: &[Finding],
        source_revision: &SourceRevision,
        installation_token: &str,
        changed_lines: Option<&HashMap<String, HashSet<usize>>>,
    ) -> Result<PostReviewOutcome, ReviewError> {
        let repo = RepositoryPath::parse(repo_full_name)?;
        let existing_comment_ids = self
            .existing_foxguard_comment_ids(&repo, pr_number, installation_token)
            .await?;
        let mut owned_summary_comment_ids = self
            .existing_foxguard_summary_comment_ids(&repo, pr_number, installation_token)
            .await?;
        let canonical_summary_comment_id = owned_summary_comment_ids.pop();

        let review_findings = if findings.is_empty() {
            Vec::new()
        } else {
            let owned_lines;
            let changed_lines = match changed_lines {
                Some(lines) => lines,
                None => {
                    owned_lines = self
                        .pull_request_commentable_lines(&repo, pr_number, installation_token)
                        .await?;
                    &owned_lines
                }
            };
            filter_findings_to_changed_lines(findings, changed_lines)
        };

        let review_messages = if review_findings.is_empty() {
            if let Some(comment_id) = canonical_summary_comment_id {
                self.update_summary_comment(
                    &repo,
                    comment_id,
                    &review_findings,
                    source_revision,
                    installation_token,
                )
                .await?;
                1
            } else {
                0
            }
        } else {
            self.create_or_update_summary_comment(
                &repo,
                pr_number,
                &review_findings,
                source_revision,
                canonical_summary_comment_id,
                installation_token,
            )
            .await?;
            1
        };

        self.delete_summary_comment_ids(&repo, &owned_summary_comment_ids, installation_token)
            .await?;
        let deleted_comments = self
            .delete_foxguard_comment_ids(&repo, &existing_comment_ids, installation_token)
            .await?;

        Ok(PostReviewOutcome {
            deleted_comments,
            review_messages,
        })
    }

    pub async fn post_check_run(
        &self,
        repo_full_name: &str,
        head_sha: &str,
        policy: CheckRunPolicy<'_>,
        installation_token: &str,
        changed_lines: Option<&HashMap<String, HashSet<usize>>>,
    ) -> Result<PostCheckRunOutcome, ReviewError> {
        let repo = RepositoryPath::parse(repo_full_name)?;
        let (body, annotation_count) = check_run_payload(head_sha, policy, changed_lines);
        let url = self.endpoint(&format!("repos/{}/{}/check-runs", repo.owner, repo.name))?;
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
    async fn delete_summary_comment_ids(
        &self,
        repo: &RepositoryPath,
        ids: &[u64],
        installation_token: &str,
    ) -> Result<(), ReviewError> {
        for id in ids {
            let url = self.endpoint(&format!(
                "repos/{}/{}/issues/comments/{id}",
                repo.owner, repo.name
            ))?;
            // URL construction is restricted to validated path segments and ids
            // returned by GitHub's issue-comments API.
            let request = self.http.delete(url); // foxguard: ignore[rs/no-ssrf]
            request
                .bearer_auth(installation_token)
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", GITHUB_API_VERSION)
                .send()
                .await?
                .error_for_status()?;
        }
        Ok(())
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
                is_owned_marker_comment(
                    comment.body.as_deref(),
                    comment.performed_via_github_app.as_ref(),
                    self.app_id,
                )
            })
            .map(|comment| comment.id)
            .collect())
    }

    async fn existing_foxguard_summary_comment_ids(
        &self,
        repo: &RepositoryPath,
        pr_number: u64,
        installation_token: &str,
    ) -> Result<Vec<u64>, ReviewError> {
        let comments = self
            .paginated_get::<IssueComment>(
                &format!(
                    "repos/{}/{}/issues/{pr_number}/comments",
                    repo.owner, repo.name
                ),
                installation_token,
            )
            .await?;

        Ok(owned_foxguard_summary_comment_ids(comments, self.app_id))
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
            .map(|file| {
                let lines = added_lines_from_patch(file.patch.as_deref()).unwrap_or_default();
                (file.filename, lines)
            })
            .collect())
    }

    async fn create_or_update_summary_comment(
        &self,
        repo: &RepositoryPath,
        pr_number: u64,
        findings: &[Finding],
        source_revision: &SourceRevision,
        existing_comment_id: Option<u64>,
        installation_token: &str,
    ) -> Result<(), ReviewError> {
        if let Some(comment_id) = existing_comment_id {
            self.update_summary_comment(
                repo,
                comment_id,
                findings,
                source_revision,
                installation_token,
            )
            .await
        } else {
            self.create_summary_comment(
                repo,
                pr_number,
                findings,
                source_revision,
                installation_token,
            )
            .await
        }
    }

    async fn create_summary_comment(
        &self,
        repo: &RepositoryPath,
        pr_number: u64,
        findings: &[Finding],
        source_revision: &SourceRevision,
        installation_token: &str,
    ) -> Result<(), ReviewError> {
        let url = self.endpoint(&format!(
            "repos/{}/{}/issues/{pr_number}/comments",
            repo.owner, repo.name
        ))?;
        // URL construction is restricted to a validated GitHub API base URL plus
        // repository path segments parsed by `RepositoryPath::parse`.
        let request = self.http.post(url); // foxguard: ignore[rs/no-ssrf]
        request
            .bearer_auth(installation_token)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", GITHUB_API_VERSION)
            .json(&summary_comment_request_body(findings, source_revision))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    async fn update_summary_comment(
        &self,
        repo: &RepositoryPath,
        comment_id: u64,
        findings: &[Finding],
        source_revision: &SourceRevision,
        installation_token: &str,
    ) -> Result<(), ReviewError> {
        let url = self.endpoint(&format!(
            "repos/{}/{}/issues/comments/{comment_id}",
            repo.owner, repo.name
        ))?;
        let body = summary_comment_request_body(findings, source_revision);
        // URL construction is restricted to validated path segments and a
        // comment id returned by GitHub's issue-comments API.
        let request = self.http.patch(url); // foxguard: ignore[rs/no-ssrf]
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
            let response = request
                .bearer_auth(installation_token)
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", GITHUB_API_VERSION)
                .send()
                .await?
                .error_for_status()?;
            // GitHub uses RFC 5988 link-header pagination; the absence of a
            // `rel="next"` link is the only reliable terminator. Page size
            // can be smaller than PAGE_SIZE while another page still exists
            // (e.g. comments deleted mid-pagination, or GitHub trimming a
            // page near a rate-limit boundary), so we MUST NOT rely on item
            // count to detect the last page — that would silently drop
            // data.
            // Reading a response header by a constant name; no outbound request is made here.
            // foxguard: ignore[rs/no-ssrf]
            let has_next_page = response
                .headers()
                .get(reqwest::header::LINK)
                .and_then(|value| value.to_str().ok())
                .is_some_and(link_header_has_next);
            let mut page_items = response.json::<Vec<T>>().await?;
            items.append(&mut page_items);
            if !has_next_page {
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
    pub review_messages: usize,
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

#[derive(Debug)]
pub struct SourceRevision {
    repo_web_url: Url,
    head_sha: String,
}

impl SourceRevision {
    pub fn new(repo_web_url: &str, head_sha: &str) -> Result<Self, ReviewError> {
        let repo_web_url = Url::parse(repo_web_url)
            .map_err(|error| ReviewError::InvalidRepositoryWebUrl(error.to_string()))?;
        if repo_web_url.scheme() != "https" {
            return Err(ReviewError::InvalidRepositoryWebUrl(
                "scheme must be https".to_string(),
            ));
        }
        if repo_web_url.username() != "" || repo_web_url.password().is_some() {
            return Err(ReviewError::InvalidRepositoryWebUrl(
                "credentials are not allowed".to_string(),
            ));
        }
        if repo_web_url.query().is_some() || repo_web_url.fragment().is_some() {
            return Err(ReviewError::InvalidRepositoryWebUrl(
                "query and fragment are not allowed".to_string(),
            ));
        }
        if repo_web_url.host_str().is_none() {
            return Err(ReviewError::InvalidRepositoryWebUrl(
                "host is required".to_string(),
            ));
        }
        let path_segments = repo_web_url.path_segments().ok_or_else(|| {
            ReviewError::InvalidRepositoryWebUrl("repository path is required".to_string())
        })?;
        let mut path_segment_count = 0;
        for segment in path_segments {
            if segment.is_empty() {
                continue;
            }
            if matches!(segment, "." | "..") {
                return Err(ReviewError::InvalidRepositoryWebUrl(
                    "path traversal segments are not allowed".to_string(),
                ));
            }
            path_segment_count += 1;
        }
        if path_segment_count < 2 {
            return Err(ReviewError::InvalidRepositoryWebUrl(
                "repository owner/name path is required".to_string(),
            ));
        }

        Ok(Self {
            repo_web_url,
            head_sha: head_sha.to_string(),
        })
    }

    fn permalink(&self, file: &str, line: usize, end_line: usize) -> Option<String> {
        if !valid_repo_relative_path(file) {
            return None;
        }

        let mut permalink = self.repo_web_url.as_str().trim_end_matches('/').to_string();
        permalink.push_str("/blob/");
        push_percent_encoded_path_segment(&mut permalink, &self.head_sha);
        for segment in file.split('/') {
            permalink.push('/');
            push_percent_encoded_path_segment(&mut permalink, segment);
        }
        if line > 0 {
            if end_line > line {
                permalink.push_str(&format!("#L{line}-L{end_line}"));
            } else {
                permalink.push_str(&format!("#L{line}"));
            }
        }
        Some(permalink)
    }
}

fn valid_repo_relative_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && path
            .split('/')
            .all(|segment| !segment.is_empty() && !matches!(segment, "." | ".."))
}

fn push_percent_encoded_path_segment(url: &mut String, segment: &str) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";

    for byte in segment.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            url.push(char::from(byte));
        } else {
            url.push('%');
            url.push(char::from(HEX[usize::from(byte >> 4)]));
            url.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
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
    performed_via_github_app: Option<PerformedViaGitHubApp>,
}

#[derive(Debug, Deserialize)]
struct IssueComment {
    id: u64,
    body: Option<String>,
    performed_via_github_app: Option<PerformedViaGitHubApp>,
}

#[derive(Debug, Deserialize)]
struct PerformedViaGitHubApp {
    id: u64,
}

fn is_owned_marker_comment(
    body: Option<&str>,
    performed_via_github_app: Option<&PerformedViaGitHubApp>,
    app_id: u64,
) -> bool {
    body.is_some_and(|body| body.contains(COMMENT_MARKER))
        && performed_via_github_app.is_some_and(|app| app.id == app_id)
}

fn owned_foxguard_summary_comment_ids(comments: Vec<IssueComment>, app_id: u64) -> Vec<u64> {
    comments
        .into_iter()
        .filter(|comment| {
            is_owned_marker_comment(
                comment.body.as_deref(),
                comment.performed_via_github_app.as_ref(),
                app_id,
            )
        })
        .map(|comment| comment.id)
        .collect()
}

#[derive(Debug, Deserialize)]
struct PullRequestFile {
    filename: String,
    patch: Option<String>,
}

/// Parse an RFC 5988 `Link` header and return `true` if any link entry
/// is tagged `rel="next"`.
///
/// GitHub returns pagination as a comma-separated list of links, each
/// of the form `<URL>; rel="next"` (other rels include `prev`, `first`,
/// `last`). Quotes around the rel value are optional per the RFC, so
/// both `rel="next"` and `rel=next` must be accepted. The URL itself
/// is ignored — the caller already knows what page number to ask for.
///
/// This is intentionally a tolerant string-based parser rather than a
/// full RFC 5988 implementation: GitHub's emitted form is stable and we
/// only need to answer "is there a next page?".
fn link_header_has_next(header_value: &str) -> bool {
    for entry in header_value.split(',') {
        let mut parts = entry.split(';').map(str::trim);
        // Skip the URL part; we only care about parameters.
        if parts.next().is_none() {
            continue;
        }
        for parameter in parts {
            let Some((name, value)) = parameter.split_once('=') else {
                continue;
            };
            if !name.trim().eq_ignore_ascii_case("rel") {
                continue;
            }
            let rel = value.trim().trim_matches('"');
            // GitHub may emit a space-separated list of rel values per
            // RFC 5988 (e.g. `rel="next prev"`), so check each token.
            if rel.split_ascii_whitespace().any(|token| token == "next") {
                return true;
            }
        }
    }
    false
}

fn added_lines_from_patch(patch: Option<&str>) -> Option<HashSet<usize>> {
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

fn hunk_new_start(line: &str) -> Option<usize> {
    let hunk = line.strip_prefix("@@ ")?;
    let plus = hunk.split_whitespace().find(|part| part.starts_with('+'))?;
    let start = plus.trim_start_matches('+').split(',').next()?;
    start.parse().ok()
}

/// Filter line-bearing findings to changed lines and file-only findings to
/// changed files. This GitHub review transport constraint is separate from a
/// repository policy decision.
fn filter_findings_to_changed_lines(
    findings: &[Finding],
    changed_lines: &HashMap<String, HashSet<usize>>,
) -> Vec<Finding> {
    findings
        .iter()
        .filter(|finding| {
            // HashMap::get on the local changed-lines map; not a network call.
            // foxguard: ignore[rs/no-ssrf]
            changed_lines
                .get(&finding.file)
                .is_some_and(|lines| finding.line == 0 || lines.contains(&finding.line))
        })
        .cloned()
        .collect()
}

fn check_run_payload(
    head_sha: &str,
    policy: CheckRunPolicy<'_>,
    changed_lines: Option<&HashMap<String, HashSet<usize>>>,
) -> (Value, usize) {
    let findings = match &policy {
        CheckRunPolicy::Evaluated(evaluation) => evaluation.findings.as_slice(),
        CheckRunPolicy::NotEvaluated { findings, .. } => *findings,
    };
    let annotation_findings = match changed_lines {
        Some(lines) => filter_findings_to_changed_lines(findings, lines),
        None => findings.to_vec(),
    };
    let annotation_findings: Vec<Finding> = annotation_findings
        .into_iter()
        .filter(|finding| !is_summary_only_finding(finding))
        .collect();
    let annotations = check_run_annotations(&annotation_findings);
    let annotation_count = annotations.len();
    let (conclusion, title, summary) = match policy {
        CheckRunPolicy::Evaluated(evaluation) => (
            evaluation.report().decision.github_check_conclusion(),
            check_run_title(evaluation),
            check_run_summary(findings, annotation_count, evaluation.report()),
        ),
        CheckRunPolicy::NotEvaluated { policy, .. } => (
            "neutral",
            "foxguard policy not evaluated",
            check_run_not_evaluated_summary(findings, annotation_count, policy),
        ),
    };
    (
        serde_json::json!({
            "name": "foxguard",
            "head_sha": head_sha,
            "status": "completed",
            "conclusion": conclusion,
            "output": {
                "title": title,
                "summary": summary,
                "annotations": annotations,
            },
        }),
        annotation_count,
    )
}

fn check_run_not_evaluated_summary(
    findings: &[Finding],
    annotation_count: usize,
    policy: &PrPolicyNotEvaluated,
) -> String {
    let mut summary = format!(
        "foxguard found {} issue(s) in a partial scan. {policy}",
        findings.len()
    );
    if annotation_count > 0 {
        summary.push_str(&format!(
            " Showing {annotation_count} partial-scan finding(s) as check annotations."
        ));
    }
    summary.push_str("\n\nThis neutral check is not a v1 repository-scope policy decision.");
    summary
}

fn check_run_title(evaluation: &PrPolicyEvaluation) -> &'static str {
    match evaluation.report().decision {
        crate::pr_policy::PrPolicyDecision::Pass => "foxguard policy passed",
        crate::pr_policy::PrPolicyDecision::Neutral => "foxguard policy reported issues",
        crate::pr_policy::PrPolicyDecision::Fail => "foxguard policy failed",
    }
}

fn check_run_summary(
    findings: &[Finding],
    annotation_count: usize,
    policy: &PrPolicyReport,
) -> String {
    let policy_summary = format!(
        "PR security policy {} (scope {}, report >= {}, block >= {}): {} \
         ({} included, {} blocking).",
        policy.version,
        policy.scope,
        policy.reporting_threshold,
        policy.blocking_threshold,
        policy.decision,
        policy.included_findings,
        policy.blocking_findings
    );
    if findings.is_empty() {
        return format!("foxguard scan completed with no reportable findings.\n\n{policy_summary}");
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
        "foxguard found {} reportable issue(s): {critical} critical, {high} high, {medium} medium, {low} low.",
        findings.len()
    );
    let annotation_eligible_count = findings
        .iter()
        .filter(|finding| !is_summary_only_finding(finding) && finding.line > 0)
        .count();
    if annotation_count < annotation_eligible_count {
        summary.push_str(&format!(
            " Showing the first {annotation_count} as check annotations."
        ));
    }
    let summary_only_findings: Vec<&Finding> = findings
        .iter()
        .filter(|finding| is_summary_only_finding(finding))
        .collect();
    if !summary_only_findings.is_empty() {
        summary.push_str(&format!(
            " {} dependency finding(s) are summarized below without check annotations.",
            summary_only_findings.len()
        ));
        summary.push_str("\n\nDependency findings (summary only):");
        for finding in summary_only_findings.iter().take(10) {
            summary.push_str(&format!("\n- {}", dependency_summary_line(finding)));
        }
        if summary_only_findings.len() > 10 {
            summary.push_str(&format!(
                "\n- ... {} more dependency finding(s)",
                summary_only_findings.len() - 10
            ));
        }
    }
    summary.push_str(&format!("\n\n{policy_summary}"));
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

fn summary_comment_request_body(findings: &[Finding], source_revision: &SourceRevision) -> Value {
    serde_json::json!({
        "body": review_summary_body(findings, source_revision),
    })
}

fn review_summary_body(findings: &[Finding], source_revision: &SourceRevision) -> String {
    if findings.is_empty() {
        return format!("{COMMENT_MARKER}\n\n**foxguard** found no issues in this PR revision.");
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

    let mut body = format!(
        "{COMMENT_MARKER}\n\n**foxguard** found {} issue(s) in this PR",
        findings.len()
    );
    body.push_str(&format!(
        "\n\n**By severity**\n- `CRITICAL`: {critical}\n- `HIGH`: {high}\n- `MEDIUM`: {medium}\n- `LOW`: {low}"
    ));
    body.push_str("\n\n**Findings**");
    for finding in findings {
        body.push_str(&format_review_finding(finding, source_revision));
    }
    body
}

fn format_review_finding(finding: &Finding, source_revision: &SourceRevision) -> String {
    let cwe_suffix = finding
        .cwe
        .as_deref()
        .map(|cwe| format!(" ({cwe})"))
        .unwrap_or_default();
    let advisory_suffix = finding
        .dep_vulnerability_id
        .as_deref()
        .map(|advisory| format!(" ({advisory})"))
        .unwrap_or_default();
    let location = format_review_location(finding, source_revision);
    let mut entry = format!(
        "\n- **{}** `{}`{}{} at {} — {}",
        severity_label(finding.severity),
        finding.rule_id,
        cwe_suffix,
        advisory_suffix,
        location,
        finding.description,
    );
    if let Some(fix) = &finding.fix_suggestion {
        entry.push_str(&format!("\n  - **Fix:** {fix}"));
    }
    entry
}

fn format_review_location(finding: &Finding, source_revision: &SourceRevision) -> String {
    let line_range = if finding.line > 0 {
        if finding.end_line > finding.line {
            format!(":{}-{}", finding.line, finding.end_line)
        } else {
            format!(":{}", finding.line)
        }
    } else {
        String::new()
    };
    let label = format!(
        "{}{}",
        percent_encoded_display_path(&finding.file),
        line_range
    );
    source_revision
        .permalink(&finding.file, finding.line, finding.end_line)
        .map(|url| format!("[`{label}`](<{url}>)"))
        .unwrap_or_else(|| format!("`{label}`"))
}

fn percent_encoded_display_path(path: &str) -> String {
    let mut encoded = String::with_capacity(path.len());
    for (index, segment) in path.split('/').enumerate() {
        if index > 0 {
            encoded.push('/');
        }
        push_percent_encoded_path_segment(&mut encoded, segment);
    }
    encoded
}

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Low => "LOW",
        Severity::Medium => "MEDIUM",
        Severity::High => "HIGH",
        Severity::Critical => "CRITICAL",
    }
}

fn is_summary_only_finding(finding: &Finding) -> bool {
    finding.dep_name.is_some()
}

fn dependency_summary_line(finding: &Finding) -> String {
    let package = match (finding.dep_name.as_deref(), finding.dep_version.as_deref()) {
        (Some(name), Some(version)) => format!("`{name}@{version}`"),
        (Some(name), None) => format!("`{name}`"),
        _ => format!("`{}`", finding.rule_id),
    };
    let location = format!("in `{}`", percent_encoded_display_path(&finding.file));
    let advisory = finding
        .dep_vulnerability_id
        .as_deref()
        .map(|id| format!(" affected by `{id}`"))
        .unwrap_or_default();
    let fix = finding
        .dep_fixed_version
        .as_deref()
        .map(|version| format!("; upgrade to `{version}` or later"))
        .unwrap_or_default();
    format!("{package} {location}{advisory}{fix}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pr_policy::evaluate;

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
        let client = match GitHubReviewClient::new("https://github.example.com/api/v3", 42) {
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
    fn added_lines_include_added_lines_only() {
        let lines = match added_lines_from_patch(Some(
            "@@ -10,4 +20,5 @@ fn demo() {\n context\n-old\n+new\n keep\n+added",
        )) {
            Some(lines) => lines,
            None => panic!("patch should parse"),
        };

        assert!(lines.contains(&21));
        assert!(lines.contains(&23));
        assert!(!lines.contains(&20));
        assert!(!lines.contains(&22));
        assert!(!lines.contains(&24));
    }

    #[test]
    fn added_lines_returns_none_without_patch() {
        assert!(added_lines_from_patch(None).is_none());
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
            dep_version: None,
            dep_ecosystem: None,
            dep_purl: None,
            dep_vulnerability_id: None,
            dep_fixed_version: None,
            dep_source: None,
            dep_vulnerability_severity: None,
            dep_path: vec![],
            crypto_material: None,
        }
    }

    fn finding_in_file(severity: Severity, file: &str, line: usize) -> Finding {
        Finding {
            file: file.to_string(),
            ..finding(severity, line)
        }
    }

    fn dependency_finding(line: usize) -> Finding {
        let mut finding = finding(Severity::High, line);
        finding.rule_id = "manifest/osv-vulnerable-dep".to_string();
        finding.file = "package-lock.json".to_string();
        finding.dep_name = Some("elliptic".to_string());
        finding.dep_version = Some("6.5.4".to_string());
        finding.dep_vulnerability_id = Some("GHSA-r9p9-mrjm-926w".to_string());
        finding.dep_fixed_version = Some("6.6.0".to_string());
        finding
    }

    fn scanned_revision(repo_web_url: &str, head_sha: &str) -> SourceRevision {
        SourceRevision::new(repo_web_url, head_sha)
            .unwrap_or_else(|error| panic!("source revision should parse: {error}"))
    }

    #[test]
    fn check_run_conclusion_comes_from_shared_policy() {
        let pass = evaluate(crate::pr_policy::PrSecurityPolicy::default(), vec![]);
        assert_eq!(
            pass.report().decision,
            crate::pr_policy::PrPolicyDecision::Pass
        );

        let neutral = evaluate(
            crate::pr_policy::PrSecurityPolicy::default(),
            vec![finding(Severity::Medium, 1)],
        );
        assert_eq!(
            neutral.report().decision,
            crate::pr_policy::PrPolicyDecision::Neutral
        );

        let fail = evaluate(
            crate::pr_policy::PrSecurityPolicy::default(),
            vec![finding(Severity::High, 1)],
        );
        assert_eq!(
            fail.report().decision,
            crate::pr_policy::PrPolicyDecision::Fail
        );
        assert_eq!(check_run_title(&fail), "foxguard policy failed");
    }

    #[test]
    fn check_run_payload_matches_shared_mixed_policy_contract() {
        let (policy, findings, expected) = crate::pr_policy::contract_fixture::mixed_v1();
        let evaluation = evaluate(policy, findings);
        let (payload, annotation_count) =
            check_run_payload("head-sha", CheckRunPolicy::Evaluated(&evaluation), None);

        assert_eq!(evaluation.report(), &expected);
        assert_eq!(annotation_count, expected.included_findings);
        assert_eq!(payload["conclusion"].as_str(), Some("failure"));
        assert_eq!(
            payload["output"]["title"].as_str(),
            Some("foxguard policy failed")
        );
        let summary = payload["output"]["summary"]
            .as_str()
            .expect("check-run summary");
        assert!(summary.contains("scope repository"));
        assert!(summary.contains("report >= medium, block >= high"));
        assert!(summary.contains("fail (3 included, 2 blocking)"));
    }

    #[test]
    fn partial_check_run_is_not_labeled_as_repository_policy() {
        let (policy, findings, _) = crate::pr_policy::contract_fixture::mixed_v1();
        let partial = PrPolicyNotEvaluated::new(
            policy,
            crate::pr_policy::PrPolicyNotEvaluatedReason::ChangedFilesFallback,
        );
        let (payload, _) = check_run_payload(
            "head-sha",
            CheckRunPolicy::NotEvaluated {
                findings: &findings,
                policy: &partial,
            },
            None,
        );

        assert_eq!(payload["conclusion"].as_str(), Some("neutral"));
        assert_eq!(
            payload["output"]["title"].as_str(),
            Some("foxguard policy not evaluated")
        );
        let summary = payload["output"]["summary"]
            .as_str()
            .expect("check-run summary");
        assert!(summary.contains("was not evaluated"));
        assert!(summary.contains("not a v1 repository-scope policy decision"));
        assert!(!summary.contains("scope repository"));
    }

    #[test]
    fn partial_check_annotations_stay_within_changed_lines() {
        let policy = crate::pr_policy::PrSecurityPolicy::default();
        let partial = PrPolicyNotEvaluated::new(
            policy,
            crate::pr_policy::PrPolicyNotEvaluatedReason::ChangedFilesFallback,
        );
        let findings = vec![finding(Severity::High, 3), finding(Severity::High, 9)];
        let changed_lines = HashMap::from([("src/app.js".to_string(), HashSet::from([3]))]);

        let (payload, annotation_count) = check_run_payload(
            "head-sha",
            CheckRunPolicy::NotEvaluated {
                findings: &findings,
                policy: &partial,
            },
            Some(&changed_lines),
        );

        assert_eq!(annotation_count, 1);
        assert_eq!(payload["output"]["annotations"][0]["start_line"], 3);
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
    fn summary_comment_request_body_puts_all_findings_in_one_message() {
        let findings = vec![finding(Severity::High, 10), dependency_finding(11)];
        let source = scanned_revision(
            "https://github.com/fork-owner/fork-repo",
            "0123456789abcdef",
        );

        let body = summary_comment_request_body(&findings, &source);
        assert!(body.get("event").is_none());
        assert!(body.get("commit_id").is_none());
        assert!(body.get("comments").is_none());
        let summary = body["body"]
            .as_str()
            .unwrap_or_else(|| panic!("summary body should be a string"));
        assert!(summary.contains("**Findings**"));
        assert!(summary.contains(
            "[`src/app.js:10`](<https://github.com/fork-owner/fork-repo/blob/0123456789abcdef/src/app.js#L10>)"
        ));
        assert!(summary.contains(
            "[`package-lock.json:11`](<https://github.com/fork-owner/fork-repo/blob/0123456789abcdef/package-lock.json#L11>)"
        ));
        assert!(summary.contains("`manifest/osv-vulnerable-dep`"));
        assert!(summary.contains("GHSA-r9p9-mrjm-926w"));
    }

    #[test]
    fn summary_links_single_lines_and_ranges_to_scanned_ghe_fork_revision() {
        let mut range = finding(Severity::High, 20);
        range.end_line = 24;
        let source = scanned_revision(
            "https://github.example.com/fork-owner/fork-repo",
            "feedface0123456789abcdef",
        );

        let summary = review_summary_body(&[finding(Severity::Medium, 10), range], &source);

        assert!(summary.contains(
            "[`src/app.js:10`](<https://github.example.com/fork-owner/fork-repo/blob/feedface0123456789abcdef/src/app.js#L10>)"
        ));
        assert!(summary.contains(
            "[`src/app.js:20-24`](<https://github.example.com/fork-owner/fork-repo/blob/feedface0123456789abcdef/src/app.js#L20-L24>)"
        ));
    }

    #[test]
    fn summary_encodes_special_path_segments_in_permalinks() {
        let source = scanned_revision(
            "https://github.com/fork-owner/fork-repo",
            "0123456789abcdef",
        );
        let finding = finding_in_file(Severity::High, "src/space #?/[brackets].rs", 7);

        let summary = review_summary_body(&[finding], &source);

        assert!(summary.contains(
            "https://github.com/fork-owner/fork-repo/blob/0123456789abcdef/src/space%20%23%3F/%5Bbrackets%5D.rs#L7"
        ));
    }

    #[test]
    fn summary_encodes_untrusted_and_malformed_paths_before_markdown_rendering() {
        let source = scanned_revision(
            "https://github.com/fork-owner/fork-repo",
            "0123456789abcdef",
        );
        let unsafe_path = "src/unsafe`](<https:attacker.invalid>)\n[trick].rs";
        let malformed_path = "/../unsafe`](<https://attacker.invalid>)\n[trick].rs";
        let safe_finding = finding_in_file(Severity::High, unsafe_path, 9);
        let malformed_finding = finding_in_file(Severity::High, malformed_path, 10);

        let summary = review_summary_body(&[safe_finding, malformed_finding], &source);

        assert!(summary.contains(
            "[`src/unsafe%60%5D%28%3Chttps%3Aattacker.invalid%3E%29%0A%5Btrick%5D.rs:9`](<https://github.com/fork-owner/fork-repo/blob/0123456789abcdef/src/unsafe%60%5D%28%3Chttps%3Aattacker.invalid%3E%29%0A%5Btrick%5D.rs#L9>)"
        ));
        assert!(summary.contains(
            "`/../unsafe%60%5D%28%3Chttps%3A//attacker.invalid%3E%29%0A%5Btrick%5D.rs:10`"
        ));
        assert_eq!(summary.matches("](<https://").count(), 1);
        assert!(!summary.contains("https://attacker.invalid"));
        assert!(!summary.contains("`](<https:attacker.invalid>)"));
        assert!(!summary.contains("\n[trick]"));
    }

    #[test]
    fn summary_links_file_only_dependency_findings_without_line_zero_anchor() {
        let source = scanned_revision(
            "https://github.com/fork-owner/fork-repo",
            "0123456789abcdef",
        );

        let summary = review_summary_body(&[dependency_finding(0)], &source);

        assert!(summary.contains(
            "[`package-lock.json`](<https://github.com/fork-owner/fork-repo/blob/0123456789abcdef/package-lock.json>)"
        ));
        assert!(summary.contains("GHSA-r9p9-mrjm-926w"));
        assert!(!summary.contains("#L0"));
    }

    #[test]
    fn source_revision_rejects_invalid_web_urls() {
        assert!(SourceRevision::new("http://github.com/fork-owner/fork-repo", "deadbeef").is_err());
        assert!(SourceRevision::new(
            "https://github.com/fork-owner/fork-repo?ref=main",
            "deadbeef"
        )
        .is_err());
        assert!(SourceRevision::new("https://github.com/fork-owner", "deadbeef").is_err());
    }

    #[test]
    fn owned_foxguard_summary_comment_ids_retain_all_owned_markers() {
        let comments = vec![
            IssueComment {
                id: 3,
                body: Some("human comment".to_string()),
                performed_via_github_app: None,
            },
            IssueComment {
                id: 7,
                body: Some(format!("{COMMENT_MARKER}\nold foxguard summary")),
                performed_via_github_app: Some(PerformedViaGitHubApp { id: 42 }),
            },
            IssueComment {
                id: 11,
                body: Some(format!("{COMMENT_MARKER}\nother app summary")),
                performed_via_github_app: Some(PerformedViaGitHubApp { id: 99 }),
            },
            IssueComment {
                id: 13,
                body: Some(format!("{COMMENT_MARKER}\nnew foxguard summary")),
                performed_via_github_app: Some(PerformedViaGitHubApp { id: 42 }),
            },
        ];

        assert_eq!(
            owned_foxguard_summary_comment_ids(comments, 42),
            vec![7, 13]
        );
    }

    #[test]
    fn check_run_summary_mentions_truncated_annotations() {
        let findings: Vec<_> = (1..=60)
            .map(|line| finding(Severity::Medium, line))
            .collect();
        let policy = evaluate(
            crate::pr_policy::PrSecurityPolicy::default(),
            findings.clone(),
        );
        let summary = check_run_summary(&findings, 50, policy.report());

        assert!(summary.contains("60 reportable issue(s)"));
        assert!(summary.contains("Showing the first 50"));
    }

    #[test]
    fn check_run_summary_mentions_dependency_findings_without_annotations() {
        let findings = vec![dependency_finding(12)];
        let policy = evaluate(
            crate::pr_policy::PrSecurityPolicy::default(),
            findings.clone(),
        );
        let summary = check_run_summary(&findings, 0, policy.report());

        assert!(summary.contains("1 dependency finding(s)"));
        assert!(summary.contains("GHSA-r9p9-mrjm-926w"));
        assert!(summary.contains("`elliptic@6.5.4`"));
    }

    #[test]
    fn check_run_dependency_summary_encodes_untrusted_file_path() {
        let mut finding = dependency_finding(0);
        finding.file = "package`](<https://attacker.invalid>)\n[trick].json".to_string();

        let summary = check_run_summary(&[finding], 0);

        assert!(summary.contains(
            "in `package%60%5D%28%3Chttps%3A//attacker.invalid%3E%29%0A%5Btrick%5D.json`"
        ));
        assert!(!summary.contains("https://attacker.invalid"));
        assert!(!summary.contains("`](<https://attacker.invalid>)"));
        assert!(!summary.contains("\n[trick]"));
    }

    #[test]
    fn filter_findings_to_changed_lines_excludes_pre_existing() {
        let mut changed_lines: HashMap<String, HashSet<usize>> = HashMap::new();
        changed_lines.insert("src/app.js".to_string(), HashSet::from([10, 11, 12]));
        changed_lines.insert("src/utils.js".to_string(), HashSet::from([5, 6]));

        let findings = vec![
            // In changed file + changed line -> included
            finding_in_file(Severity::Critical, "src/app.js", 10),
            // In changed file but NOT a changed line -> excluded (pre-existing)
            finding_in_file(Severity::High, "src/app.js", 50),
            // In an entirely different file not in the PR -> excluded
            finding_in_file(Severity::High, "src/legacy.js", 1),
            // In changed file + changed line -> included
            finding_in_file(Severity::Low, "src/utils.js", 5),
        ];

        let filtered = filter_findings_to_changed_lines(&findings, &changed_lines);
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].file, "src/app.js");
        assert_eq!(filtered[0].line, 10);
        assert_eq!(filtered[1].file, "src/utils.js");
        assert_eq!(filtered[1].line, 5);
    }

    #[test]
    fn check_run_policy_is_not_limited_to_changed_lines() {
        let mut changed_lines: HashMap<String, HashSet<usize>> = HashMap::new();
        changed_lines.insert("src/app.js".to_string(), HashSet::from([10, 11, 12]));

        let all_findings = vec![
            finding_in_file(Severity::High, "src/app.js", 50),
            finding_in_file(Severity::Critical, "src/legacy.js", 1),
            finding_in_file(Severity::Low, "src/app.js", 10),
        ];
        let policy = evaluate(
            crate::pr_policy::PrSecurityPolicy::default(),
            all_findings.clone(),
        );
        assert_eq!(
            policy.report().decision,
            crate::pr_policy::PrPolicyDecision::Fail
        );

        let comment_findings = filter_findings_to_changed_lines(&all_findings, &changed_lines);
        assert_eq!(comment_findings.len(), 1);
        let annotations = check_run_annotations(&comment_findings);
        assert_eq!(annotations.len(), 1);
        assert_eq!(annotations[0]["annotation_level"], "notice");
    }

    #[test]
    fn check_run_policy_fails_on_reported_high_severity() {
        let policy = evaluate(
            crate::pr_policy::PrSecurityPolicy::default(),
            vec![
                finding_in_file(Severity::Critical, "src/legacy.js", 1),
                finding_in_file(Severity::High, "src/app.js", 10),
                finding_in_file(Severity::Low, "src/app.js", 11),
            ],
        );

        assert_eq!(
            policy.report().decision,
            crate::pr_policy::PrPolicyDecision::Fail
        );
    }

    #[test]
    fn check_run_policy_passes_without_reportable_findings() {
        let policy = evaluate(crate::pr_policy::PrSecurityPolicy::default(), vec![]);

        assert_eq!(
            policy.report().decision,
            crate::pr_policy::PrPolicyDecision::Pass
        );
    }

    #[test]
    fn link_header_has_next_detects_quoted_rel_next() {
        let header = "<https://api.github.com/repositories/1/issues?page=2>; rel=\"next\", \
                      <https://api.github.com/repositories/1/issues?page=5>; rel=\"last\"";
        assert!(link_header_has_next(header));
    }

    #[test]
    fn link_header_has_next_detects_unquoted_rel_next() {
        // RFC 5988 makes quoting optional. GitHub always quotes today,
        // but the parser shouldn't trust that to stay true.
        let header = "<https://api.github.com/repos/o/r/pulls/1/comments?page=2>; rel=next";
        assert!(link_header_has_next(header));
    }

    #[test]
    fn link_header_has_next_handles_multi_token_rel() {
        // Per RFC 5988 a rel value may contain space-separated tokens.
        let header = "<https://api.github.com/x?page=2>; rel=\"next prev\"";
        assert!(link_header_has_next(header));
    }

    #[test]
    fn link_header_has_next_rejects_last_page() {
        // Last page typically has only `prev` and `first` rels.
        let header = "<https://api.github.com/x?page=4>; rel=\"prev\", \
                      <https://api.github.com/x?page=1>; rel=\"first\"";
        assert!(!link_header_has_next(header));
    }

    #[test]
    fn link_header_has_next_rejects_empty_and_garbage() {
        assert!(!link_header_has_next(""));
        assert!(!link_header_has_next("not a link header"));
        assert!(!link_header_has_next("<https://x>; rel=\"nextish\""));
    }

    // Minimal blocking HTTP/1.1 mock server used by `paginated_get`
    // tests. It is deliberately not a general server: every request is
    // answered by `responses` in order, regardless of method or path.
    // Returns the bound URL once the server has accepted its listening
    // port, so the caller can build a client against it.
    fn spawn_mock_server(
        responses: Vec<(reqwest::StatusCode, Option<String>, String)>,
    ) -> (String, std::thread::JoinHandle<usize>) {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(error) => panic!("mock server should bind: {error}"),
        };
        let port = match listener.local_addr() {
            Ok(addr) => addr.port(),
            Err(error) => panic!("mock server should report port: {error}"),
        };
        let url = format!("http://127.0.0.1:{port}/");

        let handle = std::thread::spawn(move || {
            let mut served = 0;
            for (status, link, body) in responses {
                let (mut stream, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(_) => return served,
                };
                let mut buffer = [0u8; 8192];
                // We only need to drain enough of the request to unblock the
                // client. A single read is sufficient for these small
                // synthetic requests; reqwest sends the full request in one
                // packet over loopback.
                let _ = stream.read(&mut buffer);

                let link_header = link
                    .map(|value| format!("Link: {value}\r\n"))
                    .unwrap_or_default();
                let response = format!(
                    "HTTP/1.1 {} OK\r\n\
                     Content-Type: application/json\r\n\
                     Content-Length: {}\r\n\
                     {link_header}\
                     Connection: close\r\n\
                     \r\n\
                     {body}",
                    status.as_u16(),
                    body.len(),
                );
                if stream.write_all(response.as_bytes()).is_err() {
                    return served;
                }
                let _ = stream.flush();
                served += 1;
            }
            served
        });

        (url, handle)
    }

    fn read_http_request(stream: &mut std::net::TcpStream) -> String {
        use std::io::Read;

        let mut request = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            let read = stream
                .read(&mut buffer)
                .unwrap_or_else(|error| panic!("mock server should read request: {error}"));
            assert!(read > 0, "client closed the request before sending a body");
            request.extend_from_slice(&buffer[..read]);

            let Some(header_end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") else {
                continue;
            };
            let headers = std::str::from_utf8(&request[..header_end])
                .unwrap_or_else(|error| panic!("request headers should be UTF-8: {error}"));
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    if name.eq_ignore_ascii_case("content-length") {
                        value.trim().parse::<usize>().ok()
                    } else {
                        None
                    }
                })
                .unwrap_or(0);
            if request.len() >= header_end + 4 + content_length {
                return String::from_utf8(request)
                    .unwrap_or_else(|error| panic!("request should be UTF-8: {error}"));
            }
        }
    }
    fn spawn_recording_mock_server(
        responses: Vec<(u16, String)>,
    ) -> (String, std::thread::JoinHandle<Vec<String>>) {
        use std::io::Write;
        use std::net::TcpListener;
        use std::time::{Duration, Instant};

        let listener = TcpListener::bind("127.0.0.1:0")
            .unwrap_or_else(|error| panic!("mock server should bind: {error}"));
        listener
            .set_nonblocking(true)
            .unwrap_or_else(|error| panic!("mock server should become non-blocking: {error}"));
        let port = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("mock server should report port: {error}"))
            .port();
        let url = format!("http://127.0.0.1:{port}/");

        let handle = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            let mut requests = Vec::new();
            while requests.len() < responses.len() && Instant::now() < deadline {
                let (mut stream, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!("mock server should accept: {error}"),
                };
                stream.set_nonblocking(false).unwrap_or_else(|error| {
                    panic!("accepted mock connection should block: {error}")
                });
                let (status, body) = &responses[requests.len()];
                requests.push(read_http_request(&mut stream));
                let response = format!(
                    "HTTP/1.1 {status} OK\r\n\
                     Content-Type: application/json\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\
                     \r\n\
                     {body}",
                    body.len(),
                );
                stream
                    .write_all(response.as_bytes())
                    .unwrap_or_else(|error| panic!("mock server should respond: {error}"));
            }
            requests
        });

        (url, handle)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn summary_comment_create_then_update_uses_new_head_sha_and_preserves_human_markers() {
        let (url, handle) = spawn_recording_mock_server(vec![
            (
                200,
                serde_json::json!([
                    {
                        "id": 76,
                        "body": format!("{COMMENT_MARKER}\nhuman marker"),
                        "performed_via_github_app": null,
                    },
                    {
                        "id": 77,
                        "body": format!("{COMMENT_MARKER}\nlegacy app marker"),
                        "performed_via_github_app": { "id": 42 },
                    },
                    {
                        "id": 78,
                        "body": format!("{COMMENT_MARKER}\nother app marker"),
                        "performed_via_github_app": { "id": 99 },
                    },
                ])
                .to_string(),
            ),
            (200, "[]".to_string()),
            (201, "{}".to_string()),
            (204, String::new()),
            (200, "[]".to_string()),
            (
                200,
                serde_json::json!([{
                    "id": 99,
                    "body": format!("{COMMENT_MARKER}\nold summary"),
                    "performed_via_github_app": { "id": 42 },
                }])
                .to_string(),
            ),
            (200, "{}".to_string()),
        ]);
        let client = GitHubReviewClient::new(&url, 42)
            .unwrap_or_else(|error| panic!("client should build: {error}"));
        let findings = vec![finding(Severity::High, 10), dependency_finding(11)];
        let changed_lines = HashMap::from([
            ("src/app.js".to_string(), HashSet::from([10usize])),
            ("package-lock.json".to_string(), HashSet::from([11usize])),
        ]);
        let first_source = scanned_revision(
            "https://github.example.com/fork-owner/fork-repo",
            "0123456789abcdef",
        );
        let second_source = scanned_revision(
            "https://github.example.com/fork-owner/fork-repo",
            "fedcba9876543210",
        );

        let first = client
            .post_pull_request_review(
                "owner/repo",
                42,
                &findings,
                &first_source,
                "test-token",
                Some(&changed_lines),
            )
            .await
            .unwrap_or_else(|error| panic!("summary should post: {error}"));
        let second = client
            .post_pull_request_review(
                "owner/repo",
                42,
                &findings,
                &second_source,
                "test-token",
                Some(&changed_lines),
            )
            .await
            .unwrap_or_else(|error| panic!("summary should update: {error}"));

        assert_eq!(
            first,
            PostReviewOutcome {
                deleted_comments: 1,
                review_messages: 1,
            }
        );
        assert_eq!(
            second,
            PostReviewOutcome {
                deleted_comments: 0,
                review_messages: 1,
            }
        );

        let requests = handle
            .join()
            .unwrap_or_else(|_| panic!("mock server thread should join"));
        assert_eq!(requests.len(), 7);
        assert!(requests[0].starts_with(
            "GET /repos/owner/repo/pulls/42/comments?per_page=100&page=1 HTTP/1.1\r\n"
        ));
        assert!(requests[1].starts_with(
            "GET /repos/owner/repo/issues/42/comments?per_page=100&page=1 HTTP/1.1\r\n"
        ));
        assert!(requests[2].starts_with("POST /repos/owner/repo/issues/42/comments HTTP/1.1\r\n"));
        assert!(requests[3].starts_with("DELETE /repos/owner/repo/pulls/comments/77 HTTP/1.1\r\n"));
        assert!(requests[4].starts_with(
            "GET /repos/owner/repo/pulls/42/comments?per_page=100&page=1 HTTP/1.1\r\n"
        ));
        assert!(requests[5].starts_with(
            "GET /repos/owner/repo/issues/42/comments?per_page=100&page=1 HTTP/1.1\r\n"
        ));
        assert!(requests[6].starts_with("PATCH /repos/owner/repo/issues/comments/99 HTTP/1.1\r\n"));
        assert!(requests.iter().all(|request| {
            !request.contains("/reviews")
                && !request.starts_with("PUT ")
                && !request.starts_with("POST /repos/owner/repo/pulls/comments ")
        }));
        assert!(requests
            .iter()
            .all(|request| !request.contains("/pulls/comments/76")));
        assert!(requests
            .iter()
            .all(|request| !request.contains("/pulls/comments/78")));

        let (_, create_payload) = requests[2]
            .split_once("\r\n\r\n")
            .unwrap_or_else(|| panic!("create request should contain JSON payload"));
        let create_payload: Value = serde_json::from_str(create_payload)
            .unwrap_or_else(|error| panic!("create payload should be JSON: {error}"));
        assert!(create_payload.get("event").is_none());
        assert!(create_payload.get("commit_id").is_none());
        let create_body = create_payload["body"]
            .as_str()
            .unwrap_or_else(|| panic!("create payload body should be a string"));
        assert!(create_body.contains(
            "https://github.example.com/fork-owner/fork-repo/blob/0123456789abcdef/package-lock.json#L11"
        ));
        assert!(create_body.contains("GHSA-r9p9-mrjm-926w"));

        let (_, update_payload) = requests[6]
            .split_once("\r\n\r\n")
            .unwrap_or_else(|| panic!("update request should contain JSON payload"));
        let update_payload: Value = serde_json::from_str(update_payload)
            .unwrap_or_else(|error| panic!("update payload should be JSON: {error}"));
        let update_body = update_payload["body"]
            .as_str()
            .unwrap_or_else(|| panic!("update payload body should be a string"));
        assert!(update_body.contains(
            "https://github.example.com/fork-owner/fork-repo/blob/fedcba9876543210/package-lock.json#L11"
        ));
        assert!(!update_body.contains("0123456789abcdef"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn patchless_changed_manifest_line_zero_dependencies_are_file_linked_through_updates() {
        let (url, handle) = spawn_recording_mock_server(vec![
            (200, "[]".to_string()),
            (200, "[]".to_string()),
            (
                200,
                serde_json::json!([{
                    "filename": "package-lock.json",
                    "patch": null,
                }])
                .to_string(),
            ),
            (201, "{}".to_string()),
            (200, "[]".to_string()),
            (
                200,
                serde_json::json!([{
                    "id": 99,
                    "body": format!("{COMMENT_MARKER}\nold summary"),
                    "performed_via_github_app": { "id": 42 },
                }])
                .to_string(),
            ),
            (
                200,
                serde_json::json!([{
                    "filename": "package-lock.json",
                    "patch": null,
                }])
                .to_string(),
            ),
            (200, "{}".to_string()),
        ]);
        let client = GitHubReviewClient::new(&url, 42)
            .unwrap_or_else(|error| panic!("client should build: {error}"));
        let mut line_bearing_finding = dependency_finding(9);
        line_bearing_finding.file = "package-lock.json".to_string();
        let mut unchanged_finding = dependency_finding(0);
        unchanged_finding.file = "yarn.lock".to_string();
        let findings = vec![
            dependency_finding(0),
            line_bearing_finding,
            unchanged_finding,
        ];
        let source = scanned_revision(
            "https://github.com/fork-owner/fork-repo",
            "0123456789abcdef",
        );

        let first = client
            .post_pull_request_review("owner/repo", 42, &findings, &source, "test-token", None)
            .await
            .unwrap_or_else(|error| panic!("summary should post: {error}"));
        let second = client
            .post_pull_request_review("owner/repo", 42, &findings, &source, "test-token", None)
            .await
            .unwrap_or_else(|error| panic!("summary should update: {error}"));

        assert_eq!(first.review_messages, 1);
        assert_eq!(second.review_messages, 1);

        let requests = handle
            .join()
            .unwrap_or_else(|_| panic!("mock server thread should join"));
        assert_eq!(requests.len(), 8);
        assert!(requests[2]
            .starts_with("GET /repos/owner/repo/pulls/42/files?per_page=100&page=1 HTTP/1.1\r\n"));
        assert!(requests[3].starts_with("POST /repos/owner/repo/issues/42/comments HTTP/1.1\r\n"));
        assert!(requests[6]
            .starts_with("GET /repos/owner/repo/pulls/42/files?per_page=100&page=1 HTTP/1.1\r\n"));
        assert!(requests[7].starts_with("PATCH /repos/owner/repo/issues/comments/99 HTTP/1.1\r\n"));

        let expected_link = "[`package-lock.json`](<https://github.com/fork-owner/fork-repo/blob/0123456789abcdef/package-lock.json>)";
        for request in [&requests[3], &requests[7]] {
            let (_, payload) = request
                .split_once("\r\n\r\n")
                .unwrap_or_else(|| panic!("summary request should contain JSON payload"));
            let payload: Value = serde_json::from_str(payload)
                .unwrap_or_else(|error| panic!("summary payload should be JSON: {error}"));
            let body = payload["body"]
                .as_str()
                .unwrap_or_else(|| panic!("summary payload body should be a string"));
            assert!(body.contains(expected_link));
            assert!(!body.contains("yarn.lock"));
            assert!(!body.contains("package-lock.json:9"));
            assert!(!body.contains("#L0"));
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn duplicate_owned_summary_comments_converge_after_canonical_update() {
        let (url, handle) = spawn_recording_mock_server(vec![
            (200, "[]".to_string()),
            (
                200,
                serde_json::json!([
                    {
                        "id": 80,
                        "body": format!("{COMMENT_MARKER}\nhuman marker"),
                        "performed_via_github_app": null,
                    },
                    {
                        "id": 88,
                        "body": format!("{COMMENT_MARKER}\nold owned summary"),
                        "performed_via_github_app": { "id": 42 },
                    },
                    {
                        "id": 93,
                        "body": format!("{COMMENT_MARKER}\nother app summary"),
                        "performed_via_github_app": { "id": 99 },
                    },
                    {
                        "id": 99,
                        "body": format!("{COMMENT_MARKER}\ncanonical owned summary"),
                        "performed_via_github_app": { "id": 42 },
                    },
                ])
                .to_string(),
            ),
            (200, "{}".to_string()),
            (204, String::new()),
        ]);
        let client = GitHubReviewClient::new(&url, 42)
            .unwrap_or_else(|error| panic!("client should build: {error}"));
        let source = scanned_revision("https://github.com/owner/repo", "0123456789abcdef");

        let outcome = client
            .post_pull_request_review("owner/repo", 42, &[], &source, "test-token", None)
            .await
            .unwrap_or_else(|error| panic!("summary should converge: {error}"));
        assert_eq!(
            outcome,
            PostReviewOutcome {
                deleted_comments: 0,
                review_messages: 1,
            }
        );

        let requests = handle
            .join()
            .unwrap_or_else(|_| panic!("mock server thread should join"));
        assert_eq!(requests.len(), 4);
        assert!(requests[0].starts_with(
            "GET /repos/owner/repo/pulls/42/comments?per_page=100&page=1 HTTP/1.1\r\n"
        ));
        assert!(requests[1].starts_with(
            "GET /repos/owner/repo/issues/42/comments?per_page=100&page=1 HTTP/1.1\r\n"
        ));
        assert!(requests[2].starts_with("PATCH /repos/owner/repo/issues/comments/99 HTTP/1.1\r\n"));
        assert!(requests[3].starts_with("DELETE /repos/owner/repo/issues/comments/88 HTTP/1.1\r\n"));
        assert!(requests
            .iter()
            .all(|request| !request.contains("/issues/comments/80")));
        assert!(requests
            .iter()
            .all(|request| !request.contains("/issues/comments/93")));
        assert!(requests
            .iter()
            .all(|request| !request.starts_with("POST /repos/owner/repo/issues/42/comments ")));

        let (_, update_payload) = requests[2]
            .split_once("\r\n\r\n")
            .unwrap_or_else(|| panic!("update request should contain JSON payload"));
        let update_payload: Value = serde_json::from_str(update_payload)
            .unwrap_or_else(|error| panic!("update payload should be JSON: {error}"));
        assert!(update_payload["body"]
            .as_str()
            .is_some_and(|body| body.contains("found no issues in this PR revision")));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn paginated_get_follows_link_header_through_short_page() {
        // Three pages: a full 100-item first page, a *short* 30-item
        // second page that still has a `rel="next"` link, and a final
        // page with no Link header. The previous size-based terminator
        // would have stopped after page 2 and silently dropped page 3.
        let page_one: Vec<u64> = (1..=100).collect();
        let page_two: Vec<u64> = (101..=130).collect();
        let page_three: Vec<u64> = (131..=140).collect();
        let responses = vec![
            (
                reqwest::StatusCode::OK,
                Some(
                    "<http://example/x?page=2>; rel=\"next\", \
                     <http://example/x?page=3>; rel=\"last\""
                        .to_string(),
                ),
                serde_json::to_string(&page_one).expect("serialize page one"),
            ),
            (
                reqwest::StatusCode::OK,
                // Short page but `rel="next"` says there's more. This
                // is the case the old `len() < PAGE_SIZE` check missed.
                Some(
                    "<http://example/x?page=3>; rel=\"next\", \
                     <http://example/x?page=1>; rel=\"first\""
                        .to_string(),
                ),
                serde_json::to_string(&page_two).expect("serialize page two"),
            ),
            (
                reqwest::StatusCode::OK,
                // No Link header at all = terminal page.
                None,
                serde_json::to_string(&page_three).expect("serialize page three"),
            ),
        ];

        let (url, handle) = spawn_mock_server(responses);
        let client = match GitHubReviewClient::new(&url, 42) {
            Ok(client) => client,
            Err(error) => panic!("client should build: {error}"),
        };

        let items: Vec<u64> = match client.paginated_get("items", "test-token").await {
            Ok(items) => items,
            Err(error) => panic!("paginated_get should succeed: {error}"),
        };

        let mut expected: Vec<u64> = (1..=100).collect();
        expected.extend(101..=130);
        expected.extend(131..=140);
        assert_eq!(items, expected);
        let served = handle.join().expect("server thread should join");
        assert_eq!(served, 3, "client should issue exactly three requests");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn paginated_get_stops_when_link_header_omits_next() {
        // Single-page response with no Link header at all: behaves like
        // the small-collection path.
        let page: Vec<u64> = (1..=5).collect();
        let responses = vec![(
            reqwest::StatusCode::OK,
            None,
            serde_json::to_string(&page).expect("serialize page"),
        )];

        let (url, handle) = spawn_mock_server(responses);
        let client = match GitHubReviewClient::new(&url, 42) {
            Ok(client) => client,
            Err(error) => panic!("client should build: {error}"),
        };

        let items: Vec<u64> = match client.paginated_get("items", "test-token").await {
            Ok(items) => items,
            Err(error) => panic!("paginated_get should succeed: {error}"),
        };

        assert_eq!(items, page);
        let served = handle.join().expect("server thread should join");
        assert_eq!(served, 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn paginated_get_stops_when_full_page_has_no_next_rel() {
        // Edge case: a page is exactly PAGE_SIZE items but the server
        // signals there is no next page. The old size-based check would
        // have requested another page (likely 404 or empty); the
        // header-based check stops correctly.
        let page: Vec<u64> = (1..=100).collect();
        let responses = vec![(
            reqwest::StatusCode::OK,
            Some("<http://example/x?page=1>; rel=\"first\"".to_string()),
            serde_json::to_string(&page).expect("serialize page"),
        )];

        let (url, handle) = spawn_mock_server(responses);
        let client = match GitHubReviewClient::new(&url, 42) {
            Ok(client) => client,
            Err(error) => panic!("client should build: {error}"),
        };

        let items: Vec<u64> = match client.paginated_get("items", "test-token").await {
            Ok(items) => items,
            Err(error) => panic!("paginated_get should succeed: {error}"),
        };

        assert_eq!(items, page);
        let served = handle.join().expect("server thread should join");
        assert_eq!(served, 1, "client should not request a second page");
    }
}
