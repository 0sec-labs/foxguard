//! foxguard-github-app — webhook receiver for the foxguard GitHub App.
//!
//! See `src/github_app/README.md` and the tracking issue at
//! <https://github.com/0sec-labs/foxguard/issues/246> for the design
//! discussion.
//!
//! This binary receives webhook deliveries, verifies the signature,
//! routes supported event types, and runs the Phase-1 GitHub App loop:
//! `pull_request` -> clone -> scan -> PR review comments + check run.
//!
//! Build:    `cargo build --release --features github-app --bin foxguard-github-app`
//! Run:      `FOXGUARD_WEBHOOK_SECRET=xxx FOXGUARD_BIND=0.0.0.0:8080 foxguard-github-app`
//! Docker:   `docker build -f Dockerfile.github-app -t ghcr.io/0sec-labs/foxguard-github-app .`

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Router,
};
use foxguard::github_app::auth::{
    AppCredentials, AuthError, GitHubAppAuthClient, InstallationToken, InstallationTokenCache,
};
use foxguard::github_app::installation_store::{InstallationMetadataInput, InstallationStore};
use foxguard::github_app::review::GitHubReviewClient;
use foxguard::github_app::webhook::{verify_signature, EventKind, SignatureError};
use foxguard::report::github_pr::relative_path;
use foxguard::Finding;
use serde::Deserialize;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

/// Hard cap on incoming webhook body size. GitHub's largest legitimate
/// `pull_request` payload sits around 200 KB; 1 MiB leaves comfortable
/// headroom while making it cheap to reject anything weaponised.
const MAX_BODY_BYTES: usize = 1 << 20; // 1 MiB
const MAX_REPO_BYTES: u64 = 1_000_000_000; // 1 GB
const PULL_REQUEST_SCAN_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone)]
struct AppState {
    webhook_secret: Vec<u8>,
    auth: GitHubAppAuthClient,
    review: GitHubReviewClient,
    /// Cached installation tokens keyed by installation id. Uses a
    /// `tokio::sync::Mutex` so contention while we wait on a GitHub
    /// API round-trip doesn't block the runtime, and so we cannot
    /// silently poison the cache on a panic.
    installation_tokens: Arc<tokio::sync::Mutex<InstallationTokenCache>>,
    /// Per-installation locks that serialize concurrent token
    /// refreshes for the same installation. Without this, two
    /// simultaneous webhooks for the same installation both miss the
    /// cache and both hit GitHub's `access_tokens` endpoint, wasting
    /// API quota.
    installation_token_locks: Arc<tokio::sync::Mutex<HashMap<u64, Arc<tokio::sync::Mutex<()>>>>>,
    installations: Arc<Mutex<InstallationStore>>,
}

#[derive(Debug, Deserialize)]
struct GitHubWebhookPayload {
    action: Option<String>,
    installation: Option<GitHubInstallation>,
    pull_request: Option<GitHubPullRequest>,
    repository: Option<GitHubRepository>,
    repositories: Option<Vec<GitHubRepositorySummary>>,
    repositories_added: Option<Vec<GitHubRepositorySummary>>,
    repositories_removed: Option<Vec<GitHubRepositorySummary>>,
}

#[derive(Debug, Deserialize)]
struct GitHubInstallation {
    id: u64,
    account: Option<GitHubAccount>,
    repository_selection: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubAccount {
    id: Option<u64>,
    login: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubPullRequest {
    number: u64,
    head: GitHubPullRequestHead,
}

#[derive(Debug, Deserialize)]
struct GitHubPullRequestHead {
    sha: String,
    repo: GitHubRepository,
}

#[derive(Debug, Deserialize)]
struct GitHubRepository {
    clone_url: String,
    full_name: String,
}

#[derive(Debug, Deserialize)]
struct GitHubRepositorySummary {
    full_name: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,foxguard=debug")),
        )
        .init();

    let secret = std::env::var("FOXGUARD_WEBHOOK_SECRET").map_err(|_| {
        "FOXGUARD_WEBHOOK_SECRET is required — set it to the same secret you \
         configured on the GitHub App"
    })?;
    if secret.is_empty() {
        return Err("FOXGUARD_WEBHOOK_SECRET must be non-empty".into());
    }

    let bind: SocketAddr = std::env::var("FOXGUARD_BIND")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_string())
        .parse()?;

    let credentials = AppCredentials::from_env()?;
    let review = GitHubReviewClient::new(credentials.api_base_url())?;
    let state = AppState {
        webhook_secret: secret.into_bytes(),
        auth: GitHubAppAuthClient::new(credentials)?,
        review,
        installation_tokens: Arc::new(tokio::sync::Mutex::new(InstallationTokenCache::new())),
        installation_token_locks: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        installations: Arc::new(Mutex::new(InstallationStore::from_env_or_default()?)),
    };

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/webhook", post(webhook))
        // Cap incoming bodies before they hit the handler so a hostile
        // multi-GB delivery cannot exhaust memory.
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    info!(%bind, "foxguard-github-app starting");
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            match tokio::signal::ctrl_c().await {
                Ok(()) => {
                    info!("shutdown signal received");
                }
                Err(error) => {
                    warn!(%error, "failed to install Ctrl-C handler");
                    std::future::pending::<()>().await;
                }
            }
        })
        .await?;

    Ok(())
}

async fn healthz() -> &'static str {
    "ok"
}

/// Webhook handler. Verifies the GitHub HMAC, parses the event type
/// from the `X-GitHub-Event` header, and dispatches to a per-kind
/// stub. All paths return 202 except for verification failures
/// (401) and oversized / unparseable inputs (400) — keeping retry
/// semantics correct on GitHub's end.
async fn webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> StatusCode {
    let signature = match headers
        .get("X-Hub-Signature-256")
        .and_then(|h| h.to_str().ok())
    {
        Some(v) => v,
        None => {
            warn!("webhook delivery missing X-Hub-Signature-256");
            return StatusCode::UNAUTHORIZED;
        }
    };

    if let Err(e) = verify_signature(&state.webhook_secret, signature, &body) {
        // Log internally with detail; respond externally with the
        // same status either way so we don't leak the failure mode.
        match e {
            SignatureError::MalformedHeader => {
                warn!("webhook signature header malformed");
            }
            SignatureError::Mismatch => {
                warn!("webhook signature mismatch — possible forgery attempt");
            }
        }
        return StatusCode::UNAUTHORIZED;
    }

    let event = headers
        .get("X-GitHub-Event")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let kind = EventKind::from_header(event);
    let delivery = headers
        .get("X-GitHub-Delivery")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("?");

    match kind {
        EventKind::Ping => {
            info!(delivery, "ping received");
        }
        EventKind::Installation => match parse_webhook_payload(&body) {
            Ok(payload) => {
                if let Some(installation) = payload.installation.as_ref() {
                    if payload.action.as_deref() == Some("deleted") {
                        remove_cached_installation_token(&state, installation.id).await;
                    }
                    let persisted = match persist_installation_event(&state, &payload) {
                        Ok(persisted) => persisted,
                        Err(error) => {
                            warn!(delivery, installation_id = installation.id, %error, "failed to persist installation metadata");
                            false
                        }
                    };
                    info!(
                        delivery,
                        installation_id = installation.id,
                        action = payload.action.as_deref().unwrap_or("?"),
                        persisted,
                        "installation event processed"
                    );
                } else {
                    warn!(delivery, "installation event missing installation.id");
                }
            }
            Err(error) => {
                warn!(delivery, %error, "installation payload was not valid JSON");
            }
        },
        EventKind::PullRequest => match parse_webhook_payload(&body) {
            Ok(payload) => {
                if let Some(installation) = payload.installation {
                    let state_for_task = state.clone();
                    let delivery = delivery.to_string();
                    let action = payload.action.unwrap_or_else(|| "?".to_string());
                    let installation_id = installation.id;
                    let pull_request = payload.pull_request;
                    let repository = payload.repository;
                    std::mem::drop(tokio::spawn(async move {
                        match process_pull_request_delivery(
                            state_for_task,
                            installation_id,
                            pull_request,
                            repository,
                        )
                        .await
                        {
                            Ok(result) => {
                                info!(
                                    delivery,
                                    installation_id,
                                    action,
                                    pr_number = result.pr_number,
                                    repo = result.repo,
                                    findings = result.findings.len(),
                                    posted_comments = result.posted_comments,
                                    deleted_comments = result.deleted_comments,
                                    posted_check_annotations = result.posted_check_annotations,
                                    "pull_request scan complete and GitHub surfaces updated"
                                );
                            }
                            Err(error) => {
                                warn!(
                                    delivery,
                                    installation_id,
                                    %error,
                                    "failed to prepare pull_request auth"
                                );
                            }
                        }
                    }));
                } else {
                    warn!(delivery, "pull_request event missing installation.id");
                }
            }
            Err(error) => {
                warn!(delivery, %error, "pull_request payload was not valid JSON");
            }
        },
        EventKind::Other => {
            // Acknowledge so GitHub doesn't retry. We log at debug
            // because a noisy install can subscribe us to events we
            // don't care about and we don't want to flood info-level.
            tracing::debug!(delivery, event, "unhandled event acknowledged");
        }
    }

    StatusCode::ACCEPTED
}

fn parse_webhook_payload(body: &[u8]) -> Result<GitHubWebhookPayload, serde_json::Error> {
    serde_json::from_slice(body)
}

fn persist_installation_event(
    state: &AppState,
    payload: &GitHubWebhookPayload,
) -> Result<bool, String> {
    let installation = payload
        .installation
        .as_ref()
        .ok_or_else(|| "installation payload missing installation.id".to_string())?;
    let mut store = state
        .installations
        .lock()
        .map_err(|error| format!("installation store lock poisoned: {error}"))?;

    match payload.action.as_deref() {
        Some("deleted") => store
            .remove(installation.id)
            .map_err(|error| error.to_string()),
        Some("added") => {
            let repositories = repository_names(payload.repositories_added.as_deref());
            store
                .add_repositories(installation.id, repositories)
                .map(|()| true)
                .map_err(|error| error.to_string())
        }
        Some("removed") => {
            let repositories = repository_names(payload.repositories_removed.as_deref());
            store
                .remove_repositories(installation.id, repositories)
                .map(|()| true)
                .map_err(|error| error.to_string())
        }
        _ => store
            .upsert(InstallationMetadataInput {
                installation_id: installation.id,
                account_login: installation
                    .account
                    .as_ref()
                    .and_then(|account| account.login.clone()),
                account_id: installation.account.as_ref().and_then(|account| account.id),
                account_type: installation
                    .account
                    .as_ref()
                    .and_then(|account| account.kind.clone()),
                repository_selection: installation.repository_selection.clone(),
                repositories: repository_names(payload.repositories.as_deref()),
            })
            .map(|()| true)
            .map_err(|error| error.to_string()),
    }
}

fn repository_names(repositories: Option<&[GitHubRepositorySummary]>) -> Vec<String> {
    repositories
        .unwrap_or_default()
        .iter()
        .map(|repository| repository.full_name.clone())
        .collect()
}

#[derive(Debug)]
struct PullRequestScanResult {
    pr_number: u64,
    repo: String,
    head_sha: String,
    findings: Vec<Finding>,
    posted_comments: usize,
    deleted_comments: usize,
    posted_check_annotations: usize,
}

#[derive(Debug)]
struct CloneTarget {
    url: String,
    auth_header_key: String,
}

async fn process_pull_request_delivery(
    state: AppState,
    installation_id: u64,
    pull_request: Option<GitHubPullRequest>,
    repository: Option<GitHubRepository>,
) -> Result<PullRequestScanResult, String> {
    let pull_request =
        pull_request.ok_or_else(|| "pull_request payload missing PR data".to_string())?;
    let repository =
        repository.ok_or_else(|| "pull_request payload missing repository".to_string())?;
    let token = installation_token_for(&state, installation_id)
        .await
        .map_err(|error| error.to_string())?;

    let scan_token = token.clone();
    let mut result = tokio::task::spawn_blocking(move || {
        run_pull_request_scan(pull_request, &repository.full_name, &scan_token)
    })
    .await
    .map_err(|error| format!("pull_request scan task failed: {error}"))??;

    let changed_lines = state
        .review
        .pull_request_changed_lines(&result.repo, result.pr_number, &token)
        .await
        .map_err(|error| error.to_string())?;

    let review = state
        .review
        .post_pull_request_review(
            &result.repo,
            result.pr_number,
            &result.head_sha,
            &result.findings,
            None,
            &token,
            Some(&changed_lines),
        )
        .await
        .map_err(|error| error.to_string())?;
    result.posted_comments = review.posted_comments;
    result.deleted_comments = review.deleted_comments;
    match state
        .review
        .post_check_run(
            &result.repo,
            &result.head_sha,
            &result.findings,
            &token,
            Some(&changed_lines),
        )
        .await
    {
        Ok(check_run) => {
            result.posted_check_annotations = check_run.posted_annotations;
        }
        Err(error) => {
            warn!(
                repo = result.repo,
                pr_number = result.pr_number,
                %error,
                "failed to post foxguard check run"
            );
        }
    }
    Ok(result)
}

fn run_pull_request_scan(
    pull_request: GitHubPullRequest,
    target_repo: &str,
    installation_token: &str,
) -> Result<PullRequestScanResult, String> {
    let workspace =
        tempfile::tempdir().map_err(|error| format!("failed to create scan workspace: {error}"))?;
    let checkout = workspace.path().join("repo");
    let clone_target = validate_clone_url(&pull_request.head.repo.clone_url)?;

    git_clone_head(
        &clone_target,
        &pull_request.head.sha,
        installation_token,
        &checkout,
    )?;
    let repo_size = directory_size(&checkout)?;
    if repo_size > MAX_REPO_BYTES {
        return Err(format!(
            "scan skipped: repository checkout is {} bytes, above {} byte cap",
            repo_size, MAX_REPO_BYTES
        ));
    }

    let output = run_scanner(&checkout)?;
    let mut findings = parse_json_findings(&output)?;
    for finding in &mut findings {
        finding.file = relative_path(&finding.file, Some(&checkout));
    }
    Ok(PullRequestScanResult {
        pr_number: pull_request.number,
        repo: target_repo.to_string(),
        head_sha: pull_request.head.sha,
        findings,
        posted_comments: 0,
        deleted_comments: 0,
        posted_check_annotations: 0,
    })
}

fn validate_clone_url(clone_url: &str) -> Result<CloneTarget, String> {
    let url = reqwest::Url::parse(clone_url)
        .map_err(|error| format!("invalid repository clone_url: {error}"))?;
    if url.scheme() != "https" {
        return Err("repository clone_url must use https".to_string());
    }
    if url.username() != "" || url.password().is_some() {
        return Err("repository clone_url must not contain credentials".to_string());
    }

    let host = url
        .host_str()
        .ok_or_else(|| "repository clone_url host is required".to_string())?;
    if !is_allowed_github_host(host) {
        return Err(format!(
            "repository clone_url host {host} is not allowlisted"
        ));
    }

    Ok(CloneTarget {
        url: url.to_string(),
        auth_header_key: format!("http.https://{host}/.extraheader"),
    })
}

fn is_allowed_github_host(host: &str) -> bool {
    host == "github.com"
        || std::env::var("FOXGUARD_GITHUB_ALLOWED_API_HOSTS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .any(|allowed| allowed.eq_ignore_ascii_case(host))
}

fn git_clone_head(
    clone_target: &CloneTarget,
    head_sha: &str,
    installation_token: &str,
    checkout: &Path,
) -> Result<(), String> {
    let authed_url = clone_target
        .url
        .replace("https://", &format!("https://x-access-token:{installation_token}@"));
    run_git(
        &[
            "clone",
            "--filter=blob:none",
            "--no-checkout",
            &authed_url,
            checkout
                .to_str()
                .ok_or_else(|| "checkout path is not valid UTF-8".to_string())?,
        ],
        &clone_target.auth_header_key,
        installation_token,
        None,
    )?;
    run_git(
        &["fetch", "origin", head_sha, "--depth=1"],
        &clone_target.auth_header_key,
        installation_token,
        Some(checkout),
    )?;
    run_git(
        &["checkout", "--detach", head_sha],
        &clone_target.auth_header_key,
        installation_token,
        Some(checkout),
    )
}

fn run_git(
    args: &[&str],
    auth_header_key: &str,
    installation_token: &str,
    current_dir: Option<&Path>,
) -> Result<(), String> {
    let mut command = Command::new("git");
    command
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(current_dir) = current_dir {
        command.current_dir(current_dir);
    }
    run_command_with_timeout(command, PULL_REQUEST_SCAN_TIMEOUT, "git")
        .map(|_| ())
        .map_err(|error| redact_git_error(&error, installation_token))
}

/// Strip the installation token (and any line that names the
/// `AUTHORIZATION` header) from a git error string before we let it
/// propagate into logs. Some git versions can echo the configured
/// extraheader on protocol failures; without this scrub the bearer
/// token lands in stderr and from there into the structured logs.
fn redact_git_error(error: &str, installation_token: &str) -> String {
    const REDACTED: &str = "<redacted>";
    let mut redacted = if installation_token.is_empty() {
        error.to_string()
    } else {
        error.replace(installation_token, REDACTED)
    };
    if redacted
        .lines()
        .any(|line| line.to_ascii_uppercase().contains("AUTHORIZATION:"))
    {
        redacted = redacted
            .lines()
            .map(|line| {
                if line.to_ascii_uppercase().contains("AUTHORIZATION:") {
                    REDACTED
                } else {
                    line
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
    }
    redacted
}

fn run_scanner(checkout: &Path) -> Result<String, String> {
    let mut command = Command::new("foxguard");
    command
        .arg(checkout)
        .arg("--format")
        .arg("json")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    run_command_with_timeout(command, PULL_REQUEST_SCAN_TIMEOUT, "foxguard")
}

fn run_command_with_timeout(
    mut command: Command,
    timeout: Duration,
    label: &str,
) -> Result<String, String> {
    use foxguard::engine::process::{wait_with_output_timeout, TimedOutput};

    let child = command
        .spawn()
        .map_err(|error| format!("failed to run {label}: {error}"))?;

    let result = wait_with_output_timeout(child, timeout)
        .map_err(|error| format!("failed to wait for {label}: {error}"))?;

    match result {
        TimedOutput::TimedOut { .. } => {
            Err(format!("{label} timed out after {}s", timeout.as_secs()))
        }
        TimedOutput::Finished(output) => {
            let status = output.status;
            if !status.success() && label != "foxguard" {
                return Err(format!(
                    "{label} failed with {status}: {}",
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
            if label == "foxguard" && !matches!(status.code(), Some(0) | Some(1)) {
                return Err(format!(
                    "{label} failed with {status}: {}",
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        }
    }
}

fn parse_json_findings(output: &str) -> Result<Vec<Finding>, String> {
    let value: serde_json::Value = serde_json::from_str(output)
        .map_err(|error| format!("failed to parse foxguard JSON output: {error}"))?;
    if let Some(findings) = value.get("findings") {
        return serde_json::from_value(findings.clone())
            .map_err(|error| format!("failed to parse foxguard findings: {error}"));
    }
    if value.is_array() {
        return serde_json::from_value(value)
            .map_err(|error| format!("failed to parse foxguard findings: {error}"));
    }
    Err("foxguard JSON output did not contain findings".to_string())
}

fn directory_size(path: &Path) -> Result<u64, String> {
    fn visit(path: &Path, total: &mut u64) -> Result<(), String> {
        for entry in std::fs::read_dir(path)
            .map_err(|error| format!("failed to read {}: {error}", path.display()))?
        {
            let entry =
                entry.map_err(|error| format!("failed to read directory entry: {error}"))?;
            let metadata = entry
                .metadata()
                .map_err(|error| format!("failed to stat {}: {error}", entry.path().display()))?;
            if metadata.is_dir() {
                visit(&entry.path(), total)?;
            } else {
                *total = total.saturating_add(metadata.len());
            }
        }
        Ok(())
    }

    let mut total = 0;
    visit(path, &mut total)?;
    Ok(total)
}

async fn installation_token_for(
    state: &AppState,
    installation_id: u64,
) -> Result<String, AuthError> {
    installation_token_with_fetch(
        &state.installation_tokens,
        &state.installation_token_locks,
        installation_id,
        || state.auth.create_installation_token(installation_id),
    )
    .await
}

/// Core serialization logic for token refreshes, extracted so it can
/// be exercised by tests without standing up a full GitHub auth
/// client. Concurrent callers for the same `installation_id` go
/// through a per-installation lock and re-check the cache inside
/// that lock, so only the first caller actually invokes `fetch`.
async fn installation_token_with_fetch<F, Fut>(
    tokens: &tokio::sync::Mutex<InstallationTokenCache>,
    locks: &tokio::sync::Mutex<HashMap<u64, Arc<tokio::sync::Mutex<()>>>>,
    installation_id: u64,
    fetch: F,
) -> Result<String, AuthError>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<InstallationToken, AuthError>>,
{
    // Fast path: another task may have already populated the cache.
    if let Some(token) = tokens
        .lock()
        .await
        .lookup(installation_id, std::time::SystemTime::now())
        .map(str::to_owned)
    {
        return Ok(token);
    }

    // Slow path: take a per-installation lock so that concurrent
    // webhooks for the same installation only call GitHub's
    // `access_tokens` endpoint once. We hold the lock across the
    // GitHub round-trip, so other waiters re-check the cache
    // afterwards and reuse the freshly-stored token.
    let installation_lock = {
        let mut map = locks.lock().await;
        map.entry(installation_id)
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    };
    let _fetch_guard = installation_lock.lock().await;

    if let Some(token) = tokens
        .lock()
        .await
        .lookup(installation_id, std::time::SystemTime::now())
        .map(str::to_owned)
    {
        return Ok(token);
    }

    let token = fetch().await?;
    let value = token.token.clone();
    tokens
        .lock()
        .await
        .remember(installation_id, token, std::time::SystemTime::now());
    Ok(value)
}

async fn remove_cached_installation_token(state: &AppState, installation_id: u64) {
    state
        .installation_tokens
        .lock()
        .await
        .remove(installation_id);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_installation_id_from_pull_request_payload() {
        let payload = match parse_webhook_payload(
            br#"{
                "action":"opened",
                "installation":{"id":12345},
                "pull_request":{
                    "number":7,
                    "head":{
                        "sha":"0123456789abcdef",
                        "repo":{
                            "clone_url":"https://github.com/0sec-labs/foxguard.git",
                            "full_name":"0sec-labs/foxguard"
                        }
                    }
                }
            }"#,
        ) {
            Ok(payload) => payload,
            Err(error) => panic!("payload should parse: {error}"),
        };

        assert_eq!(payload.action.as_deref(), Some("opened"));
        assert_eq!(
            payload.installation.map(|installation| installation.id),
            Some(12345)
        );
        let pull_request = match payload.pull_request {
            Some(pull_request) => pull_request,
            None => panic!("pull_request should parse"),
        };
        assert_eq!(pull_request.number, 7);
        assert_eq!(pull_request.head.sha, "0123456789abcdef");
        assert_eq!(pull_request.head.repo.full_name, "0sec-labs/foxguard");
    }

    #[test]
    fn parses_payload_without_installation_id() {
        let payload = match parse_webhook_payload(br#"{"action":"synchronize"}"#) {
            Ok(payload) => payload,
            Err(error) => panic!("payload should parse: {error}"),
        };

        assert_eq!(payload.action.as_deref(), Some("synchronize"));
        assert!(payload.installation.is_none());
    }

    #[test]
    fn parses_installation_metadata_payload() {
        let payload = match parse_webhook_payload(
            br#"{
                "action":"created",
                "installation":{
                    "id":12345,
                    "repository_selection":"selected",
                    "account":{"id":99,"login":"octo-org","type":"Organization"}
                },
                "repositories":[
                    {"full_name":"octo-org/app"},
                    {"full_name":"octo-org/service"}
                ]
            }"#,
        ) {
            Ok(payload) => payload,
            Err(error) => panic!("payload should parse: {error}"),
        };

        let installation = match payload.installation {
            Some(installation) => installation,
            None => panic!("installation should parse"),
        };
        let account = match installation.account {
            Some(account) => account,
            None => panic!("account should parse"),
        };

        assert_eq!(installation.id, 12345);
        assert_eq!(
            installation.repository_selection.as_deref(),
            Some("selected")
        );
        assert_eq!(account.login.as_deref(), Some("octo-org"));
        assert_eq!(
            repository_names(payload.repositories.as_deref()),
            vec!["octo-org/app".to_string(), "octo-org/service".to_string()]
        );
    }

    #[test]
    fn validates_https_github_clone_url() {
        assert_eq!(
            validate_clone_url("https://github.com/0sec-labs/foxguard.git")
                .map(|target| (target.url, target.auth_header_key)),
            Ok((
                "https://github.com/0sec-labs/foxguard.git".to_string(),
                "http.https://github.com/.extraheader".to_string()
            ))
        );
    }

    #[test]
    fn rejects_clone_url_credentials() {
        let error = match validate_clone_url("https://token@github.com/0sec-labs/foxguard.git") {
            Ok(_) => panic!("credentials should be rejected"),
            Err(error) => error,
        };
        assert!(error.contains("credentials"));
    }

    #[test]
    fn rejects_unallowlisted_clone_host() {
        let error = match validate_clone_url("https://169.254.169.254/repo.git") {
            Ok(_) => panic!("metadata host should be rejected"),
            Err(error) => error,
        };
        assert!(error.contains("not allowlisted"));
    }

    #[test]
    fn parses_enveloped_findings() {
        let json = format!(
            r#"{{"findings":[{},{}]}}"#,
            sample_finding_json("x"),
            sample_finding_json("y")
        );
        let findings = match parse_json_findings(&json) {
            Ok(findings) => findings,
            Err(error) => panic!("findings should parse: {error}"),
        };

        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].rule_id, "x");
    }

    #[test]
    fn parses_legacy_findings_array() {
        let json = format!("[{}]", sample_finding_json("x"));
        let findings = match parse_json_findings(&json) {
            Ok(findings) => findings,
            Err(error) => panic!("findings should parse: {error}"),
        };

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "x");
    }

    fn sample_finding_json(rule_id: &str) -> String {
        serde_json::json!({
            "rule_id": rule_id,
            "severity": "high",
            "cwe": null,
            "description": "demo finding",
            "file": "src/lib.rs",
            "line": 1,
            "column": 1,
            "end_line": 1,
            "end_column": 5,
            "snippet": "demo"
        })
        .to_string()
    }

    #[test]
    fn redact_git_error_strips_bearer_token() {
        // Synthetic token literal used solely to verify redact_git_error scrubs it.
        // foxguard: ignore[rs/no-hardcoded-secret]
        let token = "ghs_supersecret_token_value";
        let raw = format!(
            "git failed with exit status: 128: fatal: unable to access: \
             header AUTHORIZATION: bearer {token}"
        );
        let redacted = redact_git_error(&raw, token);
        assert!(!redacted.contains(token), "token leaked: {redacted}");
        assert!(
            !redacted.to_ascii_uppercase().contains("AUTHORIZATION:"),
            "authorization line leaked: {redacted}"
        );
        assert!(redacted.contains("<redacted>"));
    }

    #[test]
    fn redact_git_error_handles_timeout_messages() {
        // Synthetic token literal used solely to exercise redact_git_error's timeout path.
        // foxguard: ignore[rs/no-hardcoded-secret]
        let token = "ghs_anothertoken";
        let raw = "git timed out after 60s".to_string();
        // Timeout path has no auth content; output is unchanged but
        // the function must still be safe to call.
        let redacted = redact_git_error(&raw, token);
        assert_eq!(redacted, raw);
    }

    #[test]
    fn redact_git_error_redacts_token_even_without_authorization_header() {
        // Synthetic token literal used solely to verify redact_git_error scrubs tokens outside the auth header.
        // foxguard: ignore[rs/no-hardcoded-secret]
        let token = "ghs_tokenwithoutheader";
        let raw = format!("fatal: could not read from remote: cred={token} ok");
        let redacted = redact_git_error(&raw, token);
        assert!(!redacted.contains(token));
        assert!(redacted.contains("<redacted>"));
    }

    #[test]
    fn redact_git_error_is_noop_with_empty_token() {
        let raw = "git failed: nothing sensitive here";
        let redacted = redact_git_error(raw, "");
        assert_eq!(redacted, raw);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn installation_token_with_fetch_dedupes_concurrent_calls() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let tokens = Arc::new(tokio::sync::Mutex::new(InstallationTokenCache::new()));
        let locks: Arc<tokio::sync::Mutex<HashMap<u64, Arc<tokio::sync::Mutex<()>>>>> =
            Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let fetch_count = Arc::new(AtomicUsize::new(0));

        // Fire eight concurrent callers for the same installation.
        // Without per-installation serialization every caller would
        // miss the cache and call `fetch`; with it, only the first
        // does and the rest receive the cached token.
        let mut handles = Vec::new();
        for _ in 0..8 {
            let tokens = Arc::clone(&tokens);
            let locks = Arc::clone(&locks);
            let fetch_count = Arc::clone(&fetch_count);
            handles.push(tokio::spawn(async move {
                installation_token_with_fetch(&tokens, &locks, 42, move || {
                    let fetch_count = Arc::clone(&fetch_count);
                    async move {
                        // Yield so concurrent waiters all park on the
                        // per-installation lock before this resolves.
                        tokio::time::sleep(Duration::from_millis(25)).await;
                        fetch_count.fetch_add(1, Ordering::SeqCst);
                        Ok(InstallationToken {
                            token: "deduped-token".to_string(),
                            expires_at: "2099-01-01T00:00:00Z".to_string(),
                        })
                    }
                })
                .await
            }));
        }

        for handle in handles {
            let token = match handle.await {
                Ok(result) => result.expect("token fetch should succeed"),
                Err(error) => panic!("task panicked: {error}"),
            };
            assert_eq!(token, "deduped-token");
        }
        assert_eq!(
            fetch_count.load(Ordering::SeqCst),
            1,
            "fetch should only execute once for a single installation"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn installation_token_with_fetch_does_not_serialize_distinct_installations() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let tokens = Arc::new(tokio::sync::Mutex::new(InstallationTokenCache::new()));
        let locks: Arc<tokio::sync::Mutex<HashMap<u64, Arc<tokio::sync::Mutex<()>>>>> =
            Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let fetch_count = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for installation_id in 1..=4 {
            let tokens = Arc::clone(&tokens);
            let locks = Arc::clone(&locks);
            let fetch_count = Arc::clone(&fetch_count);
            handles.push(tokio::spawn(async move {
                installation_token_with_fetch(&tokens, &locks, installation_id, move || {
                    let fetch_count = Arc::clone(&fetch_count);
                    async move {
                        fetch_count.fetch_add(1, Ordering::SeqCst);
                        Ok(InstallationToken {
                            token: format!("token-{installation_id}"),
                            expires_at: "2099-01-01T00:00:00Z".to_string(),
                        })
                    }
                })
                .await
            }));
        }

        for handle in handles {
            match handle.await {
                Ok(result) => {
                    let _ = result.expect("token fetch should succeed");
                }
                Err(error) => panic!("task panicked: {error}"),
            }
        }
        // Each installation gets exactly one fetch.
        assert_eq!(fetch_count.load(Ordering::SeqCst), 4);
    }
}
