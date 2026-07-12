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

use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::OsString;
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
use base64::Engine;
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
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

/// Hard cap on incoming webhook body size. GitHub's largest legitimate
/// `pull_request` payload sits around 200 KB; 1 MiB leaves comfortable
/// headroom while making it cheap to reject anything weaponised.
const MAX_BODY_BYTES: usize = 1 << 20; // 1 MiB
const MAX_REPO_BYTES: u64 = 1_000_000_000; // 1 GB
const DEFAULT_PR_QUEUE_CAPACITY: usize = 128;
const DEFAULT_PR_WORKERS: usize = 4;
const RECENT_DELIVERY_CAPACITY: usize = 4096;
/// Wall-clock timeout applied to each `git` clone and each `foxguard` scan
/// during a pull-request review, configurable via the
/// `FOXGUARD_SCAN_TIMEOUT_SECS` environment variable (default `60`).
///
/// Large repositories — or PRs that surface hundreds of findings — can exceed
/// 60s; in production ~20% of scans were hitting the fixed 60s ceiling and
/// being killed. Raising this (e.g. `180`) reduces those timeouts at the cost
/// of holding a scan worker slot longer. A missing, unparseable, or `0` value
/// falls back to the 60s default.
fn pull_request_scan_timeout() -> Duration {
    parse_scan_timeout(std::env::var("FOXGUARD_SCAN_TIMEOUT_SECS").ok())
}

/// Pure parser for [`pull_request_scan_timeout`]: a positive integer number of
/// seconds, or the 60s default when the value is missing, unparseable, or `0`.
fn parse_scan_timeout(value: Option<String>) -> Duration {
    let secs = value
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|&secs| secs > 0)
        .unwrap_or(60);
    Duration::from_secs(secs)
}

fn parse_positive_usize(value: Option<String>, default: usize) -> usize {
    value
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|&value| value > 0)
        .unwrap_or(default)
}

impl PullRequestDispatcher {
    fn new(capacity: usize) -> (Self, tokio::sync::mpsc::Receiver<PullRequestJob>) {
        let (sender, receiver) = tokio::sync::mpsc::channel(capacity);
        (
            Self {
                sender,
                admission: Arc::new(Mutex::new(PullRequestAdmission::default())),
            },
            receiver,
        )
    }

    fn try_dispatch(&self, job: PullRequestJob) -> DispatchOutcome {
        let mut admission = self.admission.lock().unwrap_or_else(|e| e.into_inner());
        if admission.recent_deliveries.contains(&job.delivery) {
            return DispatchOutcome::DuplicateDelivery;
        }
        if admission.outstanding.contains(&job.key) {
            admission.remember_delivery(job.delivery.clone());
            admission.coalesced.insert(job.key.clone(), job);
            return DispatchOutcome::Coalesced;
        }

        admission.outstanding.insert(job.key.clone());
        let delivery = job.delivery.clone();
        match self.sender.try_send(job) {
            Ok(()) => {
                admission.remember_delivery(delivery);
                DispatchOutcome::Enqueued
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(job)) => {
                admission.outstanding.remove(&job.key);
                DispatchOutcome::QueueFull
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(job)) => {
                admission.outstanding.remove(&job.key);
                DispatchOutcome::QueueClosed
            }
        }
    }

    fn complete(&self, key: &PullRequestKey) -> Option<PullRequestJob> {
        let mut admission = self.admission.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(job) = admission.coalesced.remove(key) {
            return Some(job);
        }
        admission.outstanding.remove(key);
        None
    }
}

impl PullRequestAdmission {
    fn remember_delivery(&mut self, delivery: String) {
        self.recent_deliveries.insert(delivery.clone());
        self.delivery_order.push_back(delivery);
        while self.delivery_order.len() > RECENT_DELIVERY_CAPACITY {
            if let Some(expired) = self.delivery_order.pop_front() {
                self.recent_deliveries.remove(&expired);
            }
        }
    }
}

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
    /// The on-disk path the install store persists to, captured at
    /// startup so a persistence failure can be logged with the exact
    /// location an operator needs to fix (e.g. a read-only volume).
    installations_path: Arc<Path>,
    pull_request_dispatcher: PullRequestDispatcher,
}

#[derive(Clone)]
struct PullRequestDispatcher {
    sender: tokio::sync::mpsc::Sender<PullRequestJob>,
    admission: Arc<Mutex<PullRequestAdmission>>,
}

#[derive(Default)]
struct PullRequestAdmission {
    outstanding: HashSet<PullRequestKey>,
    coalesced: HashMap<PullRequestKey, PullRequestJob>,
    recent_deliveries: HashSet<String>,
    delivery_order: VecDeque<String>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct PullRequestKey {
    repository: String,
    number: u64,
}

#[derive(Debug)]
struct PullRequestJob {
    delivery: String,
    action: String,
    installation_id: u64,
    pull_request: Option<GitHubPullRequest>,
    repository: Option<GitHubRepository>,
    key: PullRequestKey,
}

#[derive(Debug, Eq, PartialEq)]
enum DispatchOutcome {
    Enqueued,
    DuplicateDelivery,
    Coalesced,
    QueueFull,
    QueueClosed,
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
    let installations = InstallationStore::from_env_or_default()?;
    let installations_path: Arc<Path> = Arc::from(installations.path());
    info!(path = %installations_path.display(), "installation store ready");
    let queue_capacity = parse_positive_usize(
        std::env::var("FOXGUARD_PR_QUEUE_CAPACITY").ok(),
        DEFAULT_PR_QUEUE_CAPACITY,
    );
    let worker_count = parse_positive_usize(
        std::env::var("FOXGUARD_PR_WORKERS").ok(),
        DEFAULT_PR_WORKERS,
    );
    let (pull_request_dispatcher, pull_request_receiver) =
        PullRequestDispatcher::new(queue_capacity);
    let state = AppState {
        webhook_secret: secret.into_bytes(),
        auth: GitHubAppAuthClient::new(credentials)?,
        review,
        installation_tokens: Arc::new(tokio::sync::Mutex::new(InstallationTokenCache::new())),
        installation_token_locks: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        installations: Arc::new(Mutex::new(installations)),
        installations_path,
        pull_request_dispatcher,
    };
    start_pull_request_workers(state.clone(), pull_request_receiver, worker_count);
    info!(queue_capacity, worker_count, "pull_request workers ready");

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

fn start_pull_request_workers(
    state: AppState,
    receiver: tokio::sync::mpsc::Receiver<PullRequestJob>,
    worker_count: usize,
) {
    let receiver = Arc::new(tokio::sync::Mutex::new(receiver));
    for worker_id in 0..worker_count {
        let state = state.clone();
        let receiver = Arc::clone(&receiver);
        std::mem::drop(tokio::spawn(async move {
            loop {
                let job = {
                    let mut receiver = receiver.lock().await;
                    receiver.recv().await
                };
                let Some(mut job) = job else {
                    break;
                };

                loop {
                    match process_pull_request_delivery(
                        state.clone(),
                        job.installation_id,
                        job.pull_request,
                        job.repository,
                    )
                    .await
                    {
                        Ok(result) => {
                            info!(
                                delivery = job.delivery,
                                worker_id,
                                installation_id = job.installation_id,
                                action = job.action,
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
                                delivery = job.delivery,
                                worker_id,
                                installation_id = job.installation_id,
                                %error,
                                "failed to process pull_request delivery"
                            );
                        }
                    }
                    match state.pull_request_dispatcher.complete(&job.key) {
                        Some(coalesced) => job = coalesced,
                        None => break,
                    }
                }
            }
        }));
    }
}

fn pull_request_key(payload: &GitHubWebhookPayload) -> Option<PullRequestKey> {
    let pull_request = payload.pull_request.as_ref()?;
    let repository = payload
        .repository
        .as_ref()
        .unwrap_or(&pull_request.head.repo);
    Some(PullRequestKey {
        repository: repository.full_name.clone(),
        number: pull_request.number,
    })
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
                            // Surface at error level with the configured
                            // path: a persistent failure here (e.g. a
                            // read-only or unwritable store directory)
                            // means install state is silently lost across
                            // restarts, and an operator must see it.
                            error!(
                                delivery,
                                installation_id = installation.id,
                                path = %state.installations_path.display(),
                                %error,
                                "failed to persist installation metadata"
                            );
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
                let action = payload.action.clone().unwrap_or_else(|| "?".to_string());
                if !should_process_pull_request_action(&action) {
                    tracing::debug!(delivery, action, "pull_request action ignored");
                } else if let Some(installation) = payload.installation.as_ref() {
                    let installation_id = installation.id;
                    if let Some(key) = pull_request_key(&payload) {
                        let repo = key.repository.clone();
                        let pr_number = key.number;
                        let outcome = state.pull_request_dispatcher.try_dispatch(PullRequestJob {
                            delivery: delivery.to_string(),
                            action,
                            installation_id,
                            pull_request: payload.pull_request,
                            repository: payload.repository,
                            key,
                        });
                        match outcome {
                            DispatchOutcome::Enqueued => info!(
                                delivery,
                                installation_id,
                                repo,
                                pr_number,
                                "pull_request delivery queued"
                            ),
                            DispatchOutcome::DuplicateDelivery => tracing::debug!(
                                delivery,
                                repo,
                                pr_number,
                                "duplicate pull_request delivery acknowledged"
                            ),
                            DispatchOutcome::Coalesced => info!(
                                delivery,
                                repo,
                                pr_number,
                                "pull_request delivery coalesced behind active scan"
                            ),
                            DispatchOutcome::QueueFull => warn!(
                                delivery,
                                repo,
                                pr_number,
                                "pull_request queue full; delivery acknowledged without enqueue"
                            ),
                            DispatchOutcome::QueueClosed => error!(
                                delivery,
                                repo,
                                pr_number,
                                "pull_request queue unavailable; delivery acknowledged without enqueue"
                            ),
                        }
                    } else {
                        warn!(delivery, "pull_request event missing PR or repository data");
                    }
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

fn should_process_pull_request_action(action: &str) -> bool {
    matches!(
        action,
        "opened" | "reopened" | "synchronize" | "ready_for_review"
    )
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

    let pr_number = pull_request.number;
    let repo_full_name = repository.full_name.clone();

    // Fetch the PR's changed lines BEFORE scanning so the scan can be
    // diff-scoped to just the changed files — while still cloning the full
    // repo so the analysis root preserves cross-file taint. On failure we
    // fall back to a full-tree scan (safer: keeps coverage) and log it.
    let changed_lines: Option<HashMap<String, HashSet<usize>>> = match state
        .review
        .pull_request_changed_lines(&repo_full_name, pr_number, &token)
        .await
    {
        Ok(lines) => Some(lines),
        Err(error) => {
            warn!(
                repo = repo_full_name,
                pr_number,
                %error,
                "failed to fetch PR changed lines; falling back to full-tree scan"
            );
            None
        }
    };
    let changed_files: Option<Vec<String>> = changed_lines
        .as_ref()
        .map(|lines| lines.keys().cloned().collect());

    let scan_token = token.clone();
    let mut result = tokio::task::spawn_blocking(move || {
        run_pull_request_scan(
            pull_request,
            &repository.full_name,
            &scan_token,
            changed_files,
        )
    })
    .await
    .map_err(|error| format!("pull_request scan task failed: {error}"))??;

    let review = state
        .review
        .post_pull_request_review(
            &result.repo,
            result.pr_number,
            &result.head_sha,
            &result.findings,
            None,
            &token,
            changed_lines.as_ref(),
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
            changed_lines.as_ref(),
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
    changed_files: Option<Vec<String>>,
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

    // Full-tree scan FIRST — this preserves whole-repo cross-file taint context
    // (a source in an unchanged file reaching a sink in a changed file is still
    // caught), which is foxguard's headline capability. The ~80% of PRs whose
    // repos scan within the timeout get this full coverage.
    //
    // Only when the full scan TIMES OUT — which in production happens on large
    // repos / monorepos (e.g. the biggest offenders had every PR blow the 60s
    // cap and get NO review at all) — do we fall back to a diff-scoped scan of
    // just the PR's changed files. That scan keeps the full checkout as its
    // analysis root (so cross-file taint AMONG the changed files is preserved)
    // and is fast, so a large-repo PR gets *some* review instead of none. The
    // accepted, bounded tradeoff on the fallback path: a cross-file flow whose
    // source is in an unchanged file is not caught (only the changed-file set
    // is analysed). This is strictly better than the previous "timeout = no
    // review" behaviour and never reduces coverage for scans that finish.
    let changed_files_list = match &changed_files {
        Some(files) if !files.is_empty() => {
            let list_path = workspace.path().join("changed-files.txt");
            std::fs::write(&list_path, files.join("\n"))
                .map_err(|error| format!("failed to write changed-files list: {error}"))?;
            Some(list_path)
        }
        _ => None,
    };

    let output = match run_scanner(&checkout, None) {
        Ok(output) => output,
        Err(error) if is_scan_timeout(&error) && changed_files_list.is_some() => {
            warn!(
                repo = target_repo,
                pr_number = pull_request.number,
                "full-tree scan timed out; falling back to a diff-scoped scan of \
                 the PR's changed files (cross-file taint from unchanged files not \
                 analysed on this path)"
            );
            run_scanner(&checkout, changed_files_list.as_deref())?
        }
        Err(error) => return Err(error),
    };
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
    let checkout_path = checkout
        .to_str()
        .ok_or_else(|| "checkout path is not valid UTF-8".to_string())?;
    run_git(
        &[
            "clone",
            "--filter=blob:none",
            "--no-checkout",
            clone_target.url.as_str(),
            checkout_path,
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
    let command = build_git_command(args, auth_header_key, installation_token, current_dir);
    run_command_with_timeout(command, pull_request_scan_timeout(), "git")
        .map(|_| ())
        .map_err(|error| redact_git_error(&error, installation_token))
}

fn build_git_command(
    args: &[&str],
    auth_header_key: &str,
    installation_token: &str,
    current_dir: Option<&Path>,
) -> Command {
    let mut command = Command::new("git");
    command
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    install_git_auth_env(&mut command, auth_header_key, installation_token);
    if let Some(current_dir) = current_dir {
        command.current_dir(current_dir);
    }
    command
}

fn install_git_auth_env(command: &mut Command, auth_header_key: &str, installation_token: &str) {
    // Use git's environment-backed config so the installation token stays out
    // of `git` argv while still scoping the extra header to the validated host.
    command
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", auth_header_key)
        .env(
            "GIT_CONFIG_VALUE_0",
            git_auth_header_value(installation_token),
        );
}

fn git_auth_header_value(installation_token: &str) -> String {
    let credentials = format!("x-access-token:{installation_token}");
    let encoded = base64::engine::general_purpose::STANDARD.encode(credentials);
    format!("AUTHORIZATION: basic {encoded}")
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

/// Path globs excluded from every PR scan to strip clearly non-reviewable
/// files (fixtures, vendored deps, generated/minified bundles). This cuts scan
/// time — a major driver of the 60s timeouts — without dropping real code.
const SCAN_EXCLUDE_GLOBS: &[&str] = &[
    "tests/fixtures",
    "**/examples/**",
    "*-min.js",
    "**/vendor/**",
    "**/node_modules/**",
    "**/*.min.*",
    "**/dist/**",
    "**/build/**",
];

/// Build the `foxguard` argument vector. When `changed_files_list` is provided
/// the scan is diff-scoped to that file (with `checkout` as the analysis root,
/// preserving cross-file taint); path exclusions are always applied. Pure and
/// unit-tested — the live invocation in `run_scanner` just feeds these to the
/// process.
fn build_scanner_args(checkout: &Path, changed_files_list: Option<&Path>) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec![checkout.as_os_str().to_owned()];
    if let Some(list) = changed_files_list {
        args.push("--changed-files-from".into());
        args.push(list.as_os_str().to_owned());
    }
    for glob in SCAN_EXCLUDE_GLOBS {
        args.push("--exclude".into());
        args.push(OsString::from(*glob));
    }
    args.push("--format".into());
    args.push("json".into());
    args
}

fn run_scanner(checkout: &Path, changed_files_list: Option<&Path>) -> Result<String, String> {
    let mut command = Command::new("foxguard");
    command
        .args(build_scanner_args(checkout, changed_files_list))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    run_command_with_timeout(command, pull_request_scan_timeout(), "foxguard")
}

/// True when a scan failure is the wall-clock timeout (as opposed to a spawn or
/// other error). Used to decide whether to retry with a diff-scoped scan. The
/// marker is the message produced by [`run_command_with_timeout`] on the
/// `TimedOut` branch.
fn is_scan_timeout(error: &str) -> bool {
    error.contains("timed out after")
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

    fn pull_request_job(delivery: &str, repository: &str, number: u64) -> PullRequestJob {
        PullRequestJob {
            delivery: delivery.to_string(),
            action: "synchronize".to_string(),
            installation_id: 1,
            pull_request: None,
            repository: None,
            key: PullRequestKey {
                repository: repository.to_string(),
                number,
            },
        }
    }

    #[test]
    fn pull_request_dispatcher_applies_backpressure_without_leaking_admission() {
        let (dispatcher, mut receiver) = PullRequestDispatcher::new(1);
        assert_eq!(
            dispatcher.try_dispatch(pull_request_job("delivery-1", "owner/repo", 1)),
            DispatchOutcome::Enqueued
        );
        assert_eq!(
            dispatcher.try_dispatch(pull_request_job("delivery-2", "owner/repo", 2)),
            DispatchOutcome::QueueFull
        );

        let first = receiver.try_recv().expect("first job should be queued");
        assert!(dispatcher.complete(&first.key).is_none());
        assert_eq!(
            dispatcher.try_dispatch(pull_request_job("delivery-2", "owner/repo", 2)),
            DispatchOutcome::Enqueued,
            "a queue-full rejection must release its admission key"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pull_request_dispatcher_dedupes_concurrent_repository_pr_jobs() {
        let (dispatcher, mut receiver) = PullRequestDispatcher::new(32);
        let barrier = Arc::new(tokio::sync::Barrier::new(17));
        let mut handles = Vec::new();
        for index in 0..16 {
            let dispatcher = dispatcher.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                dispatcher.try_dispatch(pull_request_job(
                    &format!("delivery-{index}"),
                    "owner/repo",
                    7,
                ))
            }));
        }
        barrier.wait().await;

        let mut enqueued = 0;
        let mut coalesced = 0;
        for handle in handles {
            match handle.await.expect("dispatch task should not panic") {
                DispatchOutcome::Enqueued => enqueued += 1,
                DispatchOutcome::Coalesced => coalesced += 1,
                outcome => panic!("unexpected dispatch outcome: {outcome:?}"),
            }
        }
        assert_eq!(enqueued, 1);
        assert_eq!(coalesced, 15);
        let first = receiver.try_recv().expect("one job should enter the queue");
        assert!(receiver.try_recv().is_err());
        let latest = dispatcher
            .complete(&first.key)
            .expect("concurrent updates should coalesce into one follow-up");
        assert_eq!(latest.key, first.key);
        assert!(dispatcher.complete(&latest.key).is_none());
    }

    #[test]
    fn pull_request_dispatcher_remembers_completed_delivery_ids() {
        let (dispatcher, mut receiver) = PullRequestDispatcher::new(2);
        let original = pull_request_job("same-delivery", "owner/repo", 7);
        assert_eq!(dispatcher.try_dispatch(original), DispatchOutcome::Enqueued);
        let completed = receiver.try_recv().expect("job should be queued");
        assert!(dispatcher.complete(&completed.key).is_none());

        assert_eq!(
            dispatcher.try_dispatch(pull_request_job("same-delivery", "owner/repo", 7)),
            DispatchOutcome::DuplicateDelivery
        );
        assert_eq!(
            dispatcher.try_dispatch(pull_request_job("new-delivery", "owner/repo", 7)),
            DispatchOutcome::Enqueued,
            "a newer delivery may rescan a completed PR"
        );
    }

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
    fn build_scanner_args_diff_scopes_and_excludes_noise() {
        let checkout = Path::new("/work/repo");
        let list = Path::new("/work/changed-files.txt");
        let args = build_scanner_args(checkout, Some(list));
        let args: Vec<String> = args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();

        // Scans the checkout as the analysis root (cross-file taint context).
        assert_eq!(args.first().map(String::as_str), Some("/work/repo"));
        // Diff-scoped to the changed-files list.
        let idx = args
            .iter()
            .position(|a| a == "--changed-files-from")
            .expect("expected --changed-files-from flag");
        assert_eq!(
            args.get(idx + 1).map(String::as_str),
            Some("/work/changed-files.txt")
        );
        // JSON output for machine parsing.
        assert!(args
            .windows(2)
            .any(|w| w[0] == "--format" && w[1] == "json"));
        // Every configured noise glob is passed as an --exclude.
        for glob in SCAN_EXCLUDE_GLOBS {
            assert!(
                args.windows(2)
                    .any(|w| w[0] == "--exclude" && w[1] == *glob),
                "missing --exclude {glob}"
            );
        }
    }

    #[test]
    fn is_scan_timeout_detects_only_the_timeout_error() {
        use super::is_scan_timeout;
        // The exact message run_command_with_timeout emits on the TimedOut branch.
        assert!(is_scan_timeout("foxguard timed out after 60s"));
        assert!(is_scan_timeout("git timed out after 60s"));
        // Other scan failures must NOT trigger the diff-scoped fallback.
        assert!(!is_scan_timeout(
            "failed to run foxguard: No such file or directory"
        ));
        assert!(!is_scan_timeout("foxguard failed with exit status: 101"));
        assert!(!is_scan_timeout(""));
    }

    #[test]
    fn build_scanner_args_full_tree_fallback_omits_changed_files_flag() {
        let args = build_scanner_args(Path::new("/work/repo"), None);
        let args: Vec<String> = args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();

        // No diff-scoping flag when the changed-files list is unavailable.
        assert!(!args.iter().any(|a| a == "--changed-files-from"));
        // Exclusions still apply to keep the fallback scan cheaper.
        assert!(args
            .windows(2)
            .any(|w| w[0] == "--exclude" && w[1] == "**/vendor/**"));
        assert!(args
            .windows(2)
            .any(|w| w[0] == "--format" && w[1] == "json"));
    }

    #[test]
    fn pull_request_action_filter_matches_code_changing_events() {
        assert!(should_process_pull_request_action("opened"));
        assert!(should_process_pull_request_action("reopened"));
        assert!(should_process_pull_request_action("synchronize"));
        assert!(should_process_pull_request_action("ready_for_review"));
        assert!(!should_process_pull_request_action("edited"));
        assert!(!should_process_pull_request_action("labeled"));
        assert!(!should_process_pull_request_action("?"));
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
    fn git_auth_header_value_uses_basic_auth_without_leaking_token() {
        // Synthetic token literal used solely to verify auth header construction.
        // foxguard: ignore[rs/no-hardcoded-secret]
        let token = "ghs_header_test_token";
        let header = git_auth_header_value(token);
        assert!(header.starts_with("AUTHORIZATION: basic "));
        assert!(
            !header.contains(token),
            "token leaked into header: {header}"
        );
    }

    #[test]
    fn build_git_command_uses_raw_clone_url_and_env_backed_auth() {
        let clone_target = CloneTarget {
            url: "https://github.com/0sec-labs/foxguard.git".to_string(),
            auth_header_key: "http.https://github.com/.extraheader".to_string(),
        };
        let checkout_path = "/tmp/foxguard-checkout";
        // Synthetic token literal used solely to verify command construction.
        // foxguard: ignore[rs/no-hardcoded-secret]
        let token = "ghs_command_test_token";
        let command = build_git_command(
            &[
                "clone",
                "--filter=blob:none",
                "--no-checkout",
                clone_target.url.as_str(),
                checkout_path,
            ],
            &clone_target.auth_header_key,
            token,
            None,
        );

        let args: Vec<String> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args,
            vec![
                "clone",
                "--filter=blob:none",
                "--no-checkout",
                "https://github.com/0sec-labs/foxguard.git",
                "/tmp/foxguard-checkout",
            ]
        );
        assert!(
            args.iter().all(|arg| !arg.contains(token)),
            "token leaked into git argv: {args:?}"
        );

        let envs: HashMap<String, String> = command
            .get_envs()
            .map(|(key, value)| {
                (
                    key.to_string_lossy().into_owned(),
                    value
                        .map(|value| value.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                )
            })
            .collect();
        assert_eq!(envs.get("GIT_CONFIG_COUNT").map(String::as_str), Some("1"));
        assert_eq!(
            envs.get("GIT_CONFIG_KEY_0").map(String::as_str),
            Some("http.https://github.com/.extraheader")
        );
        let Some(header) = envs.get("GIT_CONFIG_VALUE_0") else {
            panic!("git auth header should be configured");
        };
        assert!(header.starts_with("AUTHORIZATION: basic "));
        assert!(!header.contains(token), "token leaked into auth header");
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
    fn parse_scan_timeout_reads_override_and_falls_back() {
        use super::parse_scan_timeout;
        // A valid positive override is honoured.
        assert_eq!(parse_scan_timeout(Some("180".into())).as_secs(), 180);
        assert_eq!(parse_scan_timeout(Some("  120 ".into())).as_secs(), 120);
        // Missing / unparseable / zero all fall back to the 60s default.
        assert_eq!(parse_scan_timeout(None).as_secs(), 60);
        assert_eq!(parse_scan_timeout(Some("".into())).as_secs(), 60);
        assert_eq!(parse_scan_timeout(Some("banana".into())).as_secs(), 60);
        assert_eq!(parse_scan_timeout(Some("0".into())).as_secs(), 60);
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
