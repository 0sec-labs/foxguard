//! foxguard-github-app — webhook receiver for the foxguard GitHub App.
//!
//! See `src/github_app/README.md` and the tracking issue at
//! <https://github.com/0sec-labs/foxguard/issues/246> for the design
//! discussion.
//!
//! This binary receives webhook deliveries, verifies the signature,
//! routes supported event types, and runs the Phase-1 GitHub App loop:
//! `pull_request` -> clone -> scan -> one PR review message + check run.
//!
//! Build:    `cargo build --release --features github-app --bin foxguard-github-app`
//! Run:      `FOXGUARD_WEBHOOK_SECRET=xxx FOXGUARD_BIND=0.0.0.0:8080 foxguard-github-app`
//! Docker:   `docker build -f Dockerfile.github-app -t ghcr.io/0sec-labs/foxguard-github-app .`

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Router,
};
use base64::Engine;
use foxguard::config::load_for_scan;
use foxguard::github_app::auth::{
    AppCredentials, AuthError, GitHubAppAuthClient, InstallationToken, InstallationTokenCache,
};
use foxguard::github_app::installation_store::{InstallationMetadataInput, InstallationStore};
use foxguard::github_app::pull_request_job_store::{
    CheckRunAttachment, CheckRunCreationState, PullRequestJobAdmission, PullRequestJobInput,
    PullRequestJobStatus, PullRequestJobStore, StoredPullRequestJob,
};
use foxguard::github_app::review::{
    CheckRunPolicy, GitHubReviewClient, ReviewError, SourceRevision,
};
use foxguard::github_app::webhook::{verify_signature, EventKind, SignatureError};
use foxguard::pr_policy::{
    evaluate, resolve as resolve_pr_security_policy, PrPolicyEvaluation, PrPolicyNotEvaluated,
    PrPolicyNotEvaluatedReason, PrSecurityPolicyInput,
};
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
const LIFECYCLE_DRIVER_INTERVAL: Duration = Duration::from_secs(1);
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
    fn new(
        capacity: usize,
        jobs: PullRequestJobStore,
    ) -> (Self, tokio::sync::mpsc::Receiver<PullRequestJob>) {
        let (sender, receiver) = tokio::sync::mpsc::channel(capacity);
        (
            Self {
                sender,
                admission: Arc::new(Mutex::new(PullRequestAdmission::default())),
                jobs: Arc::new(Mutex::new(jobs)),
            },
            receiver,
        )
    }

    /// Persist a delivery before acknowledging it. Scheduling happens only
    /// after the caller has had a chance to create its queued check run.
    fn admit(&self, job: PullRequestJob) -> Result<DispatchOutcome, String> {
        let key = job.key.clone();
        let admission = self.admission.lock().unwrap_or_else(|e| e.into_inner());
        let was_outstanding = admission.outstanding.contains(&key);
        let mut jobs = self.jobs.lock().unwrap_or_else(|e| e.into_inner());
        match jobs
            .accept(job.into_store_input()?)
            .map_err(|error| error.to_string())?
        {
            PullRequestJobAdmission::DuplicateDelivery => Ok(DispatchOutcome::DuplicateDelivery),
            PullRequestJobAdmission::Accepted {
                job,
                cancellation_pending,
            } => Ok(DispatchOutcome::Accepted {
                job,
                cancellation_pending,
                coalesced: was_outstanding,
            }),
        }
    }

    fn recover(&self) -> Result<usize, String> {
        let mut jobs = self.jobs.lock().unwrap_or_else(|e| e.into_inner());
        let recovered = jobs
            .recover_non_terminal()
            .map_err(|error| error.to_string())?;
        Ok(recovered.queued.len())
    }

    fn schedule(&self) {
        let mut admission = self.admission.lock().unwrap_or_else(|e| e.into_inner());
        let jobs = self.jobs.lock().unwrap_or_else(|e| e.into_inner());
        self.schedule_locked(&mut admission, &jobs);
    }

    fn mark_running(&self, delivery: &str) -> Result<Option<StoredPullRequestJob>, String> {
        let mut jobs = self.jobs.lock().unwrap_or_else(|e| e.into_inner());
        match jobs.mark_running(delivery) {
            Ok(job) => Ok(job),
            Err(error) if error.state_transition_applied() => {
                let applied = jobs.job(delivery);
                if matches!(
                    applied.as_ref(),
                    Some(job) if job.status == PullRequestJobStatus::Running
                ) {
                    warn!(
                        delivery,
                        %error,
                        "pull_request job was durably marked running before directory sync failed; continuing it"
                    );
                    Ok(applied)
                } else {
                    Err(error.to_string())
                }
            }
            Err(error) => Err(error.to_string()),
        }
    }

    fn mark_check_run_creation_started(
        &self,
        delivery: &str,
    ) -> Result<Option<StoredPullRequestJob>, String> {
        let mut jobs = self.jobs.lock().unwrap_or_else(|e| e.into_inner());
        match jobs.mark_check_run_creation_started(delivery) {
            Ok(job) => Ok(job),
            Err(error) if error.state_transition_applied() => {
                let applied = jobs.job(delivery);
                if matches!(
                    applied.as_ref(),
                    Some(job) if job.check_run_creation == CheckRunCreationState::Creating
                ) {
                    warn!(
                        delivery,
                        %error,
                        "check-run creation intent was durably recorded before directory sync failed; continuing create"
                    );
                    Ok(applied)
                } else {
                    Err(error.to_string())
                }
            }
            Err(error) => Err(error.to_string()),
        }
    }

    fn reset_check_run_creation(
        &self,
        delivery: &str,
    ) -> Result<Option<StoredPullRequestJob>, String> {
        let mut jobs = self.jobs.lock().unwrap_or_else(|e| e.into_inner());
        match jobs.reset_check_run_creation(delivery) {
            Ok(job) => Ok(job),
            Err(error) if error.state_transition_applied() => {
                let applied = jobs.job(delivery);
                if matches!(
                    applied.as_ref(),
                    Some(job) if job.check_run_creation == CheckRunCreationState::NotStarted
                ) {
                    warn!(
                        delivery,
                        %error,
                        "check-run creation reset was durably applied before directory sync failed"
                    );
                    Ok(applied)
                } else {
                    Err(error.to_string())
                }
            }
            Err(error) => Err(error.to_string()),
        }
    }

    fn attach_check_run_id(
        &self,
        delivery: &str,
        check_run_id: u64,
    ) -> Result<CheckRunAttachment, String> {
        self.jobs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .attach_check_run_id(delivery, check_run_id)
            .map_err(|error| error.to_string())
    }

    fn cancellation_pending_jobs(&self) -> Vec<StoredPullRequestJob> {
        self.jobs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .cancellation_pending_jobs()
    }

    fn is_cancellation_pending(&self, delivery: &str) -> bool {
        self.cancellation_pending_jobs()
            .iter()
            .any(|job| job.delivery_id == delivery)
    }

    fn mark_cancellation_pending(
        &self,
        delivery: &str,
        reason: String,
    ) -> Result<Option<StoredPullRequestJob>, String> {
        self.jobs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .mark_cancellation_pending(delivery, reason)
            .map_err(|error| error.to_string())
    }

    fn mark_superseded(&self, delivery: &str) -> Result<Option<StoredPullRequestJob>, String> {
        self.jobs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .mark_superseded(delivery)
            .map_err(|error| error.to_string())
    }

    fn mark_completed(
        &self,
        delivery: &str,
        finding_count: usize,
    ) -> Result<Option<StoredPullRequestJob>, String> {
        self.jobs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .mark_completed(delivery, finding_count)
            .map_err(|error| error.to_string())
    }

    fn mark_failed(
        &self,
        delivery: &str,
        error: String,
    ) -> Result<Option<StoredPullRequestJob>, String> {
        self.jobs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .mark_failed(delivery, error)
            .map_err(|error| error.to_string())
    }

    fn mark_retry_pending(
        &self,
        delivery: &str,
        error: String,
    ) -> Result<Option<StoredPullRequestJob>, String> {
        self.jobs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .mark_retry_pending(delivery, error)
            .map_err(|error| error.to_string())
    }

    fn requeue_due_retry_pending(&self, now_unix_ms: u64) -> Result<usize, String> {
        let mut jobs = self.jobs.lock().unwrap_or_else(|e| e.into_inner());
        match jobs.requeue_due_retry_pending(now_unix_ms) {
            Ok(jobs) => Ok(jobs.len()),
            Err(error) if error.state_transition_applied() => {
                warn!(
                    %error,
                    "durable pull_request retry became queued before directory sync failed; scheduling it"
                );
                Ok(1)
            }
            Err(error) => Err(error.to_string()),
        }
    }

    /// Requeue only `Running` jobs whose worker finished without persisting a
    /// successor state. The abandoned set is in-memory; restart recovery owns
    /// all durable `Running` jobs.
    fn requeue_abandoned_running(&self) -> Result<usize, String> {
        let mut admission = self.admission.lock().unwrap_or_else(|e| e.into_inner());
        let mut jobs = self.jobs.lock().unwrap_or_else(|e| e.into_inner());
        admission.abandoned_deliveries.retain(|delivery| {
            matches!(
                jobs.job(delivery),
                Some(job) if job.status == PullRequestJobStatus::Running
            )
        });
        let deliveries: Vec<_> = admission.abandoned_deliveries.iter().cloned().collect();
        if deliveries.is_empty() {
            return Ok(0);
        }
        match jobs.requeue_abandoned_running(&deliveries) {
            Ok(requeued) => {
                let requeued = requeued.len();
                admission
                    .abandoned_deliveries
                    .retain(|delivery| matches!(jobs.job(delivery), Some(job) if job.status == PullRequestJobStatus::Running));
                if requeued > 0 {
                    self.schedule_locked(&mut admission, &jobs);
                }
                Ok(requeued)
            }
            Err(error) if error.state_transition_applied() => {
                let before = admission.abandoned_deliveries.len();
                admission
                    .abandoned_deliveries
                    .retain(|delivery| matches!(jobs.job(delivery), Some(job) if job.status == PullRequestJobStatus::Running));
                let requeued = before.saturating_sub(admission.abandoned_deliveries.len());
                if requeued > 0 {
                    warn!(
                        %error,
                        requeued,
                        "abandoned pull_request jobs requeued before directory sync failed; scheduling them"
                    );
                    self.schedule_locked(&mut admission, &jobs);
                }
                Ok(requeued)
            }
            Err(error) => Err(error.to_string()),
        }
    }

    fn defer_cancellation_retry(
        &self,
        delivery: &str,
        error: String,
    ) -> Result<Option<StoredPullRequestJob>, String> {
        self.jobs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .defer_cancellation_retry(delivery, error)
            .map_err(|error| error.to_string())
    }

    fn complete(&self, key: &PullRequestKey, delivery: &str) {
        let mut admission = self.admission.lock().unwrap_or_else(|e| e.into_inner());
        let jobs = self.jobs.lock().unwrap_or_else(|e| e.into_inner());
        if matches!(
            jobs.job(delivery),
            Some(job) if job.status == PullRequestJobStatus::Running
        ) {
            admission.abandoned_deliveries.insert(delivery.to_string());
        } else {
            admission.abandoned_deliveries.remove(delivery);
        }
        admission.outstanding.remove(key);
        self.schedule_locked(&mut admission, &jobs);
    }

    fn schedule_locked(&self, admission: &mut PullRequestAdmission, jobs: &PullRequestJobStore) {
        for stored in jobs.queued_jobs() {
            let job = PullRequestJob::from_stored(&stored);
            if admission.outstanding.contains(&job.key) {
                continue;
            }
            match self.sender.try_send(job) {
                Ok(()) => {
                    admission.outstanding.insert(PullRequestKey {
                        repository: stored.repository,
                        number: stored.pull_request,
                    });
                }
                Err(tokio::sync::mpsc::error::TrySendError::Full(_))
                | Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => break,
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
    /// Serializes external transitions for one durable delivery so a late
    /// `in_progress` PATCH cannot overwrite its cancellation.
    check_lifecycle_locks: Arc<tokio::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
    /// Serializes authoritative head lookup and durable admission for one PR,
    /// closing the race where an older webhook finishes lookup after a newer
    /// delivery has already superseded it.
    pull_request_admission_locks:
        Arc<tokio::sync::Mutex<HashMap<PullRequestKey, Arc<tokio::sync::Mutex<()>>>>>,
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
    jobs: Arc<Mutex<PullRequestJobStore>>,
}

#[derive(Default)]
struct PullRequestAdmission {
    /// Keys currently in the mpsc queue or running on a worker. A newer
    /// persisted delivery for one key waits until the current job finishes.
    outstanding: HashSet<PullRequestKey>,
    /// Deliveries whose worker ended while their durable job remained
    /// `Running`; retried by the idle lifecycle driver after parent sync.
    abandoned_deliveries: HashSet<String>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct PullRequestKey {
    repository: String,
    number: u64,
}

#[derive(Clone, Debug)]
struct PullRequestJob {
    delivery: String,
    action: String,
    installation_id: u64,
    pull_request: Option<GitHubPullRequest>,
    repository: Option<GitHubRepository>,
    key: PullRequestKey,
}

impl PullRequestJob {
    fn into_store_input(self) -> Result<PullRequestJobInput, String> {
        let pull_request = self
            .pull_request
            .ok_or_else(|| "pull_request payload missing PR data".to_string())?;
        let repository = self
            .repository
            .unwrap_or_else(|| pull_request.head.repo.clone());
        Ok(PullRequestJobInput {
            delivery_id: self.delivery,
            action: self.action,
            installation_id: self.installation_id,
            repository: repository.full_name,
            pull_request: pull_request.number,
            head_sha: pull_request.head.sha,
            clone_url: pull_request.head.repo.clone_url,
        })
    }

    fn from_stored(job: &StoredPullRequestJob) -> Self {
        let head_repo = GitHubRepository {
            clone_url: job.clone_url.clone(),
            full_name: job.repository.clone(),
        };
        Self {
            delivery: job.delivery_id.clone(),
            action: job.action.clone(),
            installation_id: job.installation_id,
            pull_request: Some(GitHubPullRequest {
                number: job.pull_request,
                head: GitHubPullRequestHead {
                    sha: job.head_sha.clone(),
                    repo: head_repo.clone(),
                },
            }),
            repository: Some(head_repo),
            key: PullRequestKey {
                repository: job.repository.clone(),
                number: job.pull_request,
            },
        }
    }
}

#[derive(Debug)]
enum DispatchOutcome {
    Accepted {
        job: Box<StoredPullRequestJob>,
        cancellation_pending: Vec<StoredPullRequestJob>,
        coalesced: bool,
    },
    DuplicateDelivery,
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

#[derive(Clone, Debug, Deserialize)]
struct GitHubPullRequest {
    number: u64,
    head: GitHubPullRequestHead,
}

#[derive(Clone, Debug, Deserialize)]
struct GitHubPullRequestHead {
    sha: String,
    repo: GitHubRepository,
}

#[derive(Clone, Debug, Deserialize)]
struct GitHubRepository {
    clone_url: String,
    html_url: String,
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
    let review = GitHubReviewClient::new(credentials.api_base_url(), credentials.app_id())?;
    let installations = InstallationStore::from_env_or_default()?;
    let installations_path: Arc<Path> = Arc::from(installations.path());
    info!(path = %installations_path.display(), "installation store ready");
    let jobs = PullRequestJobStore::from_env_or_default()?;
    info!(path = %jobs.path().display(), "pull-request job store ready");
    let queue_capacity = parse_positive_usize(
        std::env::var("FOXGUARD_PR_QUEUE_CAPACITY").ok(),
        DEFAULT_PR_QUEUE_CAPACITY,
    );
    let worker_count = parse_positive_usize(
        std::env::var("FOXGUARD_PR_WORKERS").ok(),
        DEFAULT_PR_WORKERS,
    );
    let (pull_request_dispatcher, pull_request_receiver) =
        PullRequestDispatcher::new(queue_capacity, jobs);
    let state = AppState {
        webhook_secret: secret.into_bytes(),
        auth: GitHubAppAuthClient::new(credentials)?,
        review,
        installation_tokens: Arc::new(tokio::sync::Mutex::new(InstallationTokenCache::new())),
        installation_token_locks: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        check_lifecycle_locks: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        pull_request_admission_locks: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        installations: Arc::new(Mutex::new(installations)),
        installations_path,
        pull_request_dispatcher,
    };
    let recovered = state
        .pull_request_dispatcher
        .recover()
        .map_err(std::io::Error::other)?;
    reconcile_pending_job_checks(&state, unix_time_millis(), false).await;
    state.pull_request_dispatcher.schedule();
    start_pull_request_workers(state.clone(), pull_request_receiver, worker_count);
    start_pull_request_lifecycle_driver(state.clone());
    info!(
        queue_capacity,
        worker_count, recovered, "pull_request workers ready"
    );

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
                let Some(job) = job else {
                    break;
                };

                let mut stored = match state.pull_request_dispatcher.mark_running(&job.delivery) {
                    Ok(Some(job)) => job,
                    Ok(None) => {
                        // A newer delivery superseded this job while it was
                        // waiting in the in-memory queue.
                        state
                            .pull_request_dispatcher
                            .complete(&job.key, &job.delivery);
                        continue;
                    }
                    Err(error) => {
                        error!(
                            delivery = job.delivery,
                            worker_id,
                            %error,
                            "failed to persist pull_request job as running"
                        );
                        state
                            .pull_request_dispatcher
                            .complete(&job.key, &job.delivery);
                        continue;
                    }
                };

                match mark_job_check_running(&state, &mut stored).await {
                    Ok(true) => {}
                    Ok(false) => {
                        reconcile_pending_job_checks(&state, unix_time_millis(), true).await;
                        state
                            .pull_request_dispatcher
                            .complete(&job.key, &job.delivery);
                        continue;
                    }
                    Err(error) => {
                        warn!(
                            delivery = job.delivery,
                            worker_id,
                            %error,
                            "failed to expose running pull_request scan status"
                        );
                        if let Err(store_error) = state
                            .pull_request_dispatcher
                            .mark_retry_pending(&job.delivery, error)
                        {
                            error!(
                                delivery = job.delivery,
                                worker_id,
                                %store_error,
                                "failed to persist retryable pull_request check status"
                            );
                        }
                        state
                            .pull_request_dispatcher
                            .complete(&job.key, &job.delivery);
                        continue;
                    }
                }

                match process_pull_request_delivery(
                    state.clone(),
                    &job.delivery,
                    job.installation_id,
                    job.pull_request.clone(),
                    job.repository.clone(),
                    stored.check_run_id,
                )
                .await
                {
                    Ok(result) => {
                        if let Err(error) = state
                            .pull_request_dispatcher
                            .mark_completed(&job.delivery, result.findings.len())
                        {
                            error!(
                                delivery = job.delivery,
                                worker_id,
                                %error,
                                "failed to persist completed pull_request job"
                            );
                        }
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
                    Err(PullRequestProcessError::CheckUpdateFailed(error)) => {
                        if let Err(store_error) = state
                            .pull_request_dispatcher
                            .mark_retry_pending(&job.delivery, error.clone())
                        {
                            error!(
                                delivery = job.delivery,
                                worker_id,
                                %store_error,
                                "failed to persist retryable terminal check update"
                            );
                        }
                        warn!(
                            delivery = job.delivery,
                            worker_id,
                            %error,
                            "retaining pull_request job until terminal check update can retry"
                        );
                    }
                    Err(PullRequestProcessError::StaleHead { expected, actual }) => {
                        let reason = format!(
                            "authoritative pull_request head changed from {expected} to {actual}"
                        );
                        if let Err(error) = state
                            .pull_request_dispatcher
                            .mark_cancellation_pending(&job.delivery, reason)
                        {
                            error!(
                                delivery = job.delivery,
                                worker_id,
                                %error,
                                "failed to persist stale pull_request cancellation"
                            );
                        }
                        reconcile_pending_job_checks(&state, unix_time_millis(), true).await;
                        info!(
                            delivery = job.delivery,
                            worker_id,
                            expected,
                            actual,
                            "skipped stale pull_request delivery before rendering"
                        );
                    }
                    Err(PullRequestProcessError::Superseded) => {
                        reconcile_pending_job_checks(&state, unix_time_millis(), true).await;
                    }
                    Err(PullRequestProcessError::Failed(error)) => {
                        match complete_failed_job_check(&state, &stored, &error).await {
                            Ok(()) => {
                                if let Err(store_error) = state
                                    .pull_request_dispatcher
                                    .mark_failed(&job.delivery, error.clone())
                                {
                                    error!(
                                        delivery = job.delivery,
                                        worker_id,
                                        %store_error,
                                        "failed to persist pull_request job failure"
                                    );
                                }
                            }
                            Err(status_error) => {
                                warn!(
                                    delivery = job.delivery,
                                    worker_id,
                                    %status_error,
                                    "failed to expose pull_request scan failure status"
                                );
                                if let Err(store_error) = state
                                    .pull_request_dispatcher
                                    .mark_retry_pending(&job.delivery, status_error)
                                {
                                    error!(
                                        delivery = job.delivery,
                                        worker_id,
                                        %store_error,
                                        "failed to persist retryable failure check update"
                                    );
                                }
                            }
                        }
                        warn!(
                            delivery = job.delivery,
                            worker_id,
                            installation_id = job.installation_id,
                            %error,
                            "failed to process pull_request delivery"
                        );
                    }
                }
                state
                    .pull_request_dispatcher
                    .complete(&job.key, &job.delivery);
            }
        }));
    }
}

fn unix_time_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

/// Drive persisted lifecycle work even when no more webhooks arrive. Retry
/// deadlines live in the store, so a restart cannot lose the outbox intent.
async fn drive_pending_lifecycle(state: &AppState, now_unix_ms: u64) {
    reconcile_pending_job_checks(state, now_unix_ms, false).await;
    match state
        .pull_request_dispatcher
        .requeue_due_retry_pending(now_unix_ms)
    {
        Ok(requeued) if requeued > 0 => {
            info!(requeued, "requeued durable pull_request lifecycle retries");
            state.pull_request_dispatcher.schedule();
        }
        Ok(_) => {}
        Err(error) => warn!(%error, "failed to requeue durable pull_request lifecycle retries"),
    }
    match state.pull_request_dispatcher.requeue_abandoned_running() {
        Ok(requeued) if requeued > 0 => {
            info!(requeued, "requeued abandoned durable pull_request workers");
        }
        Ok(_) => {}
        Err(error) => warn!(%error, "failed to requeue abandoned pull_request workers"),
    }
}

fn start_pull_request_lifecycle_driver(state: AppState) {
    std::mem::drop(tokio::spawn(async move {
        let mut interval = tokio::time::interval(LIFECYCLE_DRIVER_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            drive_pending_lifecycle(&state, unix_time_millis()).await;
        }
    }));
}

fn check_run_external_id(delivery_id: &str) -> String {
    format!("foxguard-pr-scan:{delivery_id}")
}

async fn job_check_lifecycle_lock(
    state: &AppState,
    delivery_id: &str,
) -> tokio::sync::OwnedMutexGuard<()> {
    let lock = {
        let mut locks = state.check_lifecycle_locks.lock().await;
        locks
            .entry(delivery_id.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    };
    lock.lock_owned().await
}

async fn pull_request_admission_lock(
    state: &AppState,
    key: &PullRequestKey,
) -> tokio::sync::OwnedMutexGuard<()> {
    let lock = {
        let mut locks = state.pull_request_admission_locks.lock().await;
        locks
            .entry(key.clone())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    };
    lock.lock_owned().await
}

fn check_create_definitely_did_not_happen(error: &ReviewError) -> bool {
    match error {
        ReviewError::Http(error) => {
            error.is_connect()
                || error
                    .status()
                    .is_some_and(|status| status.is_client_error())
        }
        ReviewError::InvalidApiBaseUrl(_)
        | ReviewError::InvalidRepository(_)
        | ReviewError::InvalidEndpoint(_) => true,
    }
}
async fn ensure_queued_job_check_unlocked(
    state: &AppState,
    job: &StoredPullRequestJob,
) -> Result<Option<CheckRunAttachment>, String> {
    if state
        .pull_request_dispatcher
        .is_cancellation_pending(&job.delivery_id)
    {
        return Ok(None);
    }
    let token = installation_token_for(state, job.installation_id)
        .await
        .map_err(|error| error.to_string())?;
    let external_id = check_run_external_id(&job.delivery_id);
    let check_run_id = match state
        .review
        .find_check_run_by_external_id(&job.repository, &job.head_sha, &external_id, &token)
        .await
        .map_err(|error| error.to_string())?
    {
        Some(check_run_id) => check_run_id,
        None if job.check_run_creation != CheckRunCreationState::NotStarted => {
            return Err(
                "queued check-run creation is not yet observable; retrying external-id lookup"
                    .to_string(),
            );
        }
        None => {
            let Some(creation) = state
                .pull_request_dispatcher
                .mark_check_run_creation_started(&job.delivery_id)?
            else {
                return Ok(None);
            };
            debug_assert_eq!(creation.check_run_creation, CheckRunCreationState::Creating);
            match state
                .review
                .create_queued_check_run(&job.repository, &job.head_sha, &external_id, &token)
                .await
            {
                Ok(check_run_id) => check_run_id,
                Err(error) => {
                    if check_create_definitely_did_not_happen(&error) {
                        if let Err(reset_error) = state
                            .pull_request_dispatcher
                            .reset_check_run_creation(&job.delivery_id)
                        {
                            warn!(
                                delivery = job.delivery_id,
                                %reset_error,
                                "failed to clear definitely-unsubmitted check-run creation intent"
                            );
                        }
                    }
                    return Err(error.to_string());
                }
            }
        }
    };
    state
        .pull_request_dispatcher
        .attach_check_run_id(&job.delivery_id, check_run_id)
        .map(Some)
}

async fn create_queued_job_check(
    state: &AppState,
    job: &StoredPullRequestJob,
) -> Result<Option<CheckRunAttachment>, String> {
    let _guard = job_check_lifecycle_lock(state, &job.delivery_id).await;
    ensure_queued_job_check_unlocked(state, job).await
}

/// Returns `false` if a newer delivery has already made this check-run's
/// cancellation authoritative. The lifecycle lock ensures any cancellation
/// PATCH that races this running PATCH is sent afterwards.
async fn mark_job_check_running(
    state: &AppState,
    job: &mut StoredPullRequestJob,
) -> Result<bool, String> {
    let _guard = job_check_lifecycle_lock(state, &job.delivery_id).await;
    if state
        .pull_request_dispatcher
        .is_cancellation_pending(&job.delivery_id)
    {
        return Ok(false);
    }
    if job.check_run_id.is_none() {
        match ensure_queued_job_check_unlocked(state, job).await? {
            Some(CheckRunAttachment::Attached(persisted)) => {
                job.check_run_id = persisted.check_run_id
            }
            Some(CheckRunAttachment::CancellationPending(_))
            | Some(CheckRunAttachment::IgnoredTerminal)
            | Some(CheckRunAttachment::Missing)
            | None => return Ok(false),
        }
    }
    if state
        .pull_request_dispatcher
        .is_cancellation_pending(&job.delivery_id)
    {
        return Ok(false);
    }
    let token = installation_token_for(state, job.installation_id)
        .await
        .map_err(|error| error.to_string())?;
    state
        .review
        .mark_check_run_running(
            &job.repository,
            job.check_run_id.expect("check run id is set"),
            &token,
        )
        .await
        .map_err(|error| error.to_string())?;
    Ok(true)
}

async fn complete_failed_job_check(
    state: &AppState,
    job: &StoredPullRequestJob,
    error: &str,
) -> Result<(), String> {
    let _guard = job_check_lifecycle_lock(state, &job.delivery_id).await;
    if state
        .pull_request_dispatcher
        .is_cancellation_pending(&job.delivery_id)
    {
        return Ok(());
    }
    let check_run_id = match job.check_run_id {
        Some(check_run_id) => check_run_id,
        None => match ensure_queued_job_check_unlocked(state, job).await? {
            Some(CheckRunAttachment::Attached(persisted)) => persisted
                .check_run_id
                .expect("persisted check attachment has an id"),
            Some(CheckRunAttachment::CancellationPending(_))
            | Some(CheckRunAttachment::IgnoredTerminal)
            | Some(CheckRunAttachment::Missing)
            | None => return Ok(()),
        },
    };
    let token = installation_token_for(state, job.installation_id)
        .await
        .map_err(|token_error| token_error.to_string())?;
    state
        .review
        .complete_failed_check_run(&job.repository, check_run_id, error, &token)
        .await
        .map_err(|status_error| status_error.to_string())
}

/// Record a retryable cancellation failure without allowing an idle process
/// to strand the persisted job forever.
fn defer_cancellation_retry(state: &AppState, job: &StoredPullRequestJob, error: String) {
    if let Err(store_error) = state
        .pull_request_dispatcher
        .defer_cancellation_retry(&job.delivery_id, error)
    {
        warn!(
            delivery = job.delivery_id,
            %store_error,
            "failed to persist cancellation lifecycle retry"
        );
    }
}

/// Reconcile persisted cancellation requests. Calls made from an event may
/// force the first attempt; the idle lifecycle driver honors each durable
/// backoff deadline.
async fn reconcile_pending_job_checks(state: &AppState, now_unix_ms: u64, force: bool) {
    for job in state.pull_request_dispatcher.cancellation_pending_jobs() {
        if !force && !job.retry_is_due(now_unix_ms) {
            continue;
        }
        let _guard = job_check_lifecycle_lock(state, &job.delivery_id).await;
        if !state
            .pull_request_dispatcher
            .is_cancellation_pending(&job.delivery_id)
        {
            continue;
        }
        let token = match installation_token_for(state, job.installation_id).await {
            Ok(token) => token,
            Err(error) => {
                warn!(
                    delivery = job.delivery_id,
                    %error,
                    "failed to obtain token for cancellation-pending pull_request scan"
                );
                defer_cancellation_retry(
                    state,
                    &job,
                    format!("failed to obtain cancellation token: {error}"),
                );
                continue;
            }
        };
        let check_run_id = match job.check_run_id {
            Some(check_run_id) => Some(check_run_id),
            None => {
                let external_id = check_run_external_id(&job.delivery_id);
                match state
                    .review
                    .find_check_run_by_external_id(
                        &job.repository,
                        &job.head_sha,
                        &external_id,
                        &token,
                    )
                    .await
                {
                    Ok(Some(check_run_id)) => {
                        match state
                            .pull_request_dispatcher
                            .attach_check_run_id(&job.delivery_id, check_run_id)
                        {
                            Ok(_) => Some(check_run_id),
                            Err(error) => {
                                warn!(
                                    delivery = job.delivery_id,
                                    %error,
                                    "failed to persist recovered pull_request check-run id"
                                );
                                defer_cancellation_retry(
                                    state,
                                    &job,
                                    format!("failed to persist recovered check-run id: {error}"),
                                );
                                None
                            }
                        }
                    }
                    Ok(None) if job.check_run_creation == CheckRunCreationState::NotStarted => {
                        // No create request was ever started, so there is no
                        // external check that needs a cancellation PATCH.
                        if let Err(error) = state
                            .pull_request_dispatcher
                            .mark_superseded(&job.delivery_id)
                        {
                            warn!(
                                delivery = job.delivery_id,
                                %error,
                                "failed to persist no-check supersession"
                            );
                            defer_cancellation_retry(
                                state,
                                &job,
                                format!("failed to persist no-check supersession: {error}"),
                            );
                        } else {
                            tracing::debug!(
                                delivery = job.delivery_id,
                                "terminalized superseded delivery whose check creation never began"
                            );
                        }
                        None
                    }
                    Ok(None) => {
                        // `Creating` is durable evidence that a POST may have
                        // reached GitHub even if its response was lost. A
                        // single list miss is not proof that no check exists.
                        defer_cancellation_retry(
                            state,
                            &job,
                            "created check is not yet observable".to_string(),
                        );
                        None
                    }
                    Err(error) => {
                        warn!(
                            delivery = job.delivery_id,
                            %error,
                            "failed to look up cancellation-pending pull_request check"
                        );
                        defer_cancellation_retry(
                            state,
                            &job,
                            format!("failed to look up cancellation-pending check: {error}"),
                        );
                        None
                    }
                }
            }
        };
        let Some(check_run_id) = check_run_id else {
            continue;
        };
        match state
            .review
            .complete_superseded_check_run(&job.repository, check_run_id, &token)
            .await
        {
            Ok(()) => {
                if let Err(error) = state
                    .pull_request_dispatcher
                    .mark_superseded(&job.delivery_id)
                {
                    warn!(
                        delivery = job.delivery_id,
                        %error,
                        "failed to persist terminalized superseded pull_request job"
                    );
                    defer_cancellation_retry(
                        state,
                        &job,
                        format!("failed to persist terminalized cancellation: {error}"),
                    );
                }
            }
            Err(error) => {
                warn!(
                    delivery = job.delivery_id,
                    %error,
                    "failed to cancel superseded pull_request check; retaining retryable state"
                );
                defer_cancellation_retry(
                    state,
                    &job,
                    format!("failed to cancel superseded check: {error}"),
                );
            }
        }
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
/// stub. Accepted deliveries return 202; a valid pull-request delivery whose
/// authoritative head cannot be checked or whose durable write fails returns
/// 503 so GitHub retries it. Verification failures return 401 and oversized or
/// unparseable inputs return 400.
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
                        let expected_head = payload
                            .pull_request
                            .as_ref()
                            .expect("pull_request_key requires pull_request data")
                            .head
                            .sha
                            .clone();
                        let outcome = match admit_authoritative_pull_request(
                            &state,
                            PullRequestJob {
                                delivery: delivery.to_string(),
                                action,
                                installation_id,
                                pull_request: payload.pull_request,
                                repository: payload.repository,
                                key,
                            },
                        )
                        .await
                        {
                            Ok(outcome) => outcome,
                            Err(PullRequestProcessError::StaleHead { actual, .. }) => {
                                info!(
                                    delivery,
                                    installation_id,
                                    repo,
                                    pr_number,
                                    expected_head,
                                    actual,
                                    "ignored delayed pull_request delivery before it could supersede current work"
                                );
                                return StatusCode::ACCEPTED;
                            }
                            Err(error) => {
                                error!(
                                    delivery,
                                    installation_id,
                                    repo,
                                    pr_number,
                                    %error,
                                    "failed to validate authoritative pull_request head before admission"
                                );
                                return StatusCode::SERVICE_UNAVAILABLE;
                            }
                        };
                        match outcome {
                            DispatchOutcome::DuplicateDelivery => {
                                // A prior atomic rename can be visible even
                                // when its directory sync reported an error.
                                // GitHub's retry then sees a duplicate, but it
                                // must still wake that durable queued job.
                                state.pull_request_dispatcher.schedule();
                                tracing::debug!(
                                    delivery,
                                    repo,
                                    pr_number,
                                    "duplicate pull_request delivery acknowledged"
                                );
                            }
                            DispatchOutcome::Accepted {
                                job,
                                cancellation_pending,
                                coalesced,
                            } => {
                                if let Err(error) = create_queued_job_check(&state, &job).await {
                                    warn!(
                                        delivery,
                                        installation_id,
                                        repo,
                                        pr_number,
                                        %error,
                                        "pull_request job is durable but queued status was not posted"
                                    );
                                }
                                reconcile_pending_job_checks(&state, unix_time_millis(), true)
                                    .await;
                                state.pull_request_dispatcher.schedule();
                                if coalesced {
                                    info!(
                                        delivery,
                                        installation_id,
                                        repo,
                                        pr_number,
                                        cancellation_pending = cancellation_pending.len(),
                                        "pull_request delivery coalesced behind active scan"
                                    );
                                } else {
                                    info!(
                                        delivery,
                                        installation_id,
                                        repo,
                                        pr_number,
                                        cancellation_pending = cancellation_pending.len(),
                                        "pull_request delivery persisted and queued"
                                    );
                                }
                            }
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
enum PullRequestPolicyOutcome {
    Evaluated(PrPolicyEvaluation),
    NotEvaluated(PrPolicyNotEvaluated),
}

#[derive(Debug)]
struct PullRequestScanResult {
    pr_number: u64,
    repo: String,
    head_sha: String,
    head_repo_web_url: String,
    findings: Vec<Finding>,
    policy_outcome: PullRequestPolicyOutcome,
    review_messages: usize,
    deleted_comments: usize,
    posted_check_annotations: usize,
}

impl PullRequestScanResult {
    fn findings_for_transport(&self) -> &[Finding] {
        match &self.policy_outcome {
            PullRequestPolicyOutcome::Evaluated(evaluation) => &evaluation.findings,
            PullRequestPolicyOutcome::NotEvaluated(_) => &self.findings,
        }
    }

    fn check_run_policy(&self) -> CheckRunPolicy<'_> {
        match &self.policy_outcome {
            PullRequestPolicyOutcome::Evaluated(evaluation) => {
                CheckRunPolicy::Evaluated(evaluation)
            }
            PullRequestPolicyOutcome::NotEvaluated(policy) => CheckRunPolicy::NotEvaluated {
                findings: &self.findings,
                policy,
            },
        }
    }
}

#[derive(Debug)]
enum PullRequestProcessError {
    Failed(String),
    /// Review/scan work completed, but GitHub has not accepted its terminal
    /// check-run update. The durable job must remain retryable.
    CheckUpdateFailed(String),
    StaleHead {
        expected: String,
        actual: String,
    },
    Superseded,
}

impl std::fmt::Display for PullRequestProcessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Failed(error) => f.write_str(error),
            Self::CheckUpdateFailed(error) => {
                write!(f, "terminal pull_request check update failed: {error}")
            }
            Self::StaleHead { expected, actual } => write!(
                f,
                "pull_request head changed from queued {expected} to authoritative {actual}"
            ),
            Self::Superseded => f.write_str("pull_request delivery was superseded"),
        }
    }
}

impl From<String> for PullRequestProcessError {
    fn from(error: String) -> Self {
        Self::Failed(error)
    }
}

fn validate_authoritative_pull_request_head(
    expected: &str,
    actual: String,
) -> Result<(), PullRequestProcessError> {
    if actual == expected {
        Ok(())
    } else {
        Err(PullRequestProcessError::StaleHead {
            expected: expected.to_string(),
            actual,
        })
    }
}

async fn ensure_authoritative_pull_request_head(
    state: &AppState,
    repository: &str,
    pull_request: u64,
    expected_head: &str,
    installation_token: &str,
) -> Result<(), PullRequestProcessError> {
    let actual = state
        .review
        .pull_request_head_sha(repository, pull_request, installation_token)
        .await
        .map_err(|error| PullRequestProcessError::Failed(error.to_string()))?;
    validate_authoritative_pull_request_head(expected_head, actual)
}

/// Atomically order a webhook's authoritative-head observation and its
/// durable admission relative to other deliveries for the same pull request.
async fn admit_authoritative_pull_request(
    state: &AppState,
    job: PullRequestJob,
) -> Result<DispatchOutcome, PullRequestProcessError> {
    let expected_head = job
        .pull_request
        .as_ref()
        .ok_or_else(|| {
            PullRequestProcessError::Failed("pull_request payload missing PR data".to_string())
        })?
        .head
        .sha
        .clone();
    let _guard = pull_request_admission_lock(state, &job.key).await;
    let token = installation_token_for(state, job.installation_id)
        .await
        .map_err(|error| PullRequestProcessError::Failed(error.to_string()))?;
    ensure_authoritative_pull_request_head(
        state,
        &job.key.repository,
        job.key.number,
        &expected_head,
        &token,
    )
    .await?;
    state
        .pull_request_dispatcher
        .admit(job)
        .map_err(PullRequestProcessError::Failed)
}

#[derive(Debug)]
struct CloneTarget {
    url: String,
    auth_header_key: String,
}

/// Prevent a newer delivery from superseding a validated head while this
/// delivery renders or removes its review comments.
async fn validate_and_render_pull_request_review(
    state: &AppState,
    delivery_id: &str,
    result: &mut PullRequestScanResult,
    installation_token: &str,
    changed_lines: Option<&HashMap<String, HashSet<usize>>>,
) -> Result<(), PullRequestProcessError> {
    let key = PullRequestKey {
        repository: result.repo.clone(),
        number: result.pr_number,
    };
    let _gate = pull_request_admission_lock(state, &key).await;
    ensure_authoritative_pull_request_head(
        state,
        &result.repo,
        result.pr_number,
        &result.head_sha,
        installation_token,
    )
    .await?;
    if state
        .pull_request_dispatcher
        .is_cancellation_pending(delivery_id)
    {
        return Err(PullRequestProcessError::Superseded);
    }
    let source_revision = SourceRevision::new(&result.head_repo_web_url, &result.head_sha)
        .map_err(|error| error.to_string())?;
    let review = state
        .review
        .post_pull_request_review(
            &result.repo,
            result.pr_number,
            result.findings_for_transport(),
            &source_revision,
            installation_token,
            changed_lines,
        )
        .await
        .map_err(|error| error.to_string())?;
    result.review_messages = review.review_messages;
    result.deleted_comments = review.deleted_comments;
    Ok(())
}

async fn process_pull_request_delivery(
    state: AppState,
    delivery_id: &str,
    installation_id: u64,
    pull_request: Option<GitHubPullRequest>,
    repository: Option<GitHubRepository>,
    check_run_id: Option<u64>,
) -> Result<PullRequestScanResult, PullRequestProcessError> {
    let pull_request =
        pull_request.ok_or_else(|| "pull_request payload missing PR data".to_string())?;
    let repository =
        repository.ok_or_else(|| "pull_request payload missing repository".to_string())?;
    let token = installation_token_for(&state, installation_id)
        .await
        .map_err(|error| error.to_string())?;

    let pr_number = pull_request.number;
    let repo_full_name = repository.full_name.clone();
    ensure_authoritative_pull_request_head(
        &state,
        &repo_full_name,
        pr_number,
        &pull_request.head.sha,
        &token,
    )
    .await?;

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
    validate_and_render_pull_request_review(
        &state,
        delivery_id,
        &mut result,
        &token,
        changed_lines.as_ref(),
    )
    .await?;
    let _check_lifecycle_guard = job_check_lifecycle_lock(&state, delivery_id).await;
    if state
        .pull_request_dispatcher
        .is_cancellation_pending(delivery_id)
    {
        return Err(PullRequestProcessError::Superseded);
    }
    let check_run_id = check_run_id.ok_or_else(|| {
        PullRequestProcessError::CheckUpdateFailed(
            "queued check-run id was not persisted before terminal update".to_string(),
        )
    })?;
    let check_run = state
        .review
        .complete_check_run(
            &result.repo,
            check_run_id,
            result.check_run_policy(),
            &token,
            changed_lines.as_ref(),
        )
        .await
        .map_err(|error| PullRequestProcessError::CheckUpdateFailed(error.to_string()))?;
    result.posted_check_annotations = check_run.posted_annotations;
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

    let config = load_for_scan(&checkout, None)
        .map_err(|error| format!("failed to load PR security policy config: {error}"))?;
    let policy_overrides = PrSecurityPolicyInput::default();
    let policy = resolve_pr_security_policy(
        config
            .as_ref()
            .and_then(|config| config.pr_security_policy.as_ref()),
        &policy_overrides,
    )
    .map_err(|error| format!("invalid PR security policy: {error}"))?;

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

    let (output, full_repository_scan) = match run_scanner(&checkout, None) {
        Ok(output) => (output, true),
        Err(error) if is_scan_timeout(&error) && changed_files_list.is_some() => {
            warn!(
                repo = target_repo,
                pr_number = pull_request.number,
                "full-tree scan timed out; falling back to a diff-scoped scan of \
                 the PR's changed files (cross-file taint from unchanged files not \
                 analysed on this path); v1 repository policy will not be evaluated"
            );
            (
                run_scanner(&checkout, changed_files_list.as_deref())?,
                false,
            )
        }
        Err(error) => return Err(error),
    };
    let mut findings = parse_json_findings(&output)?;
    for finding in &mut findings {
        finding.file = relative_path(&finding.file, Some(&checkout));
    }
    let (findings, policy_outcome) = if full_repository_scan {
        (
            Vec::new(),
            PullRequestPolicyOutcome::Evaluated(evaluate(policy, findings)),
        )
    } else {
        (
            findings,
            PullRequestPolicyOutcome::NotEvaluated(PrPolicyNotEvaluated::new(
                policy,
                PrPolicyNotEvaluatedReason::ChangedFilesFallback,
            )),
        )
    };
    Ok(PullRequestScanResult {
        pr_number: pull_request.number,
        repo: target_repo.to_string(),
        head_sha: pull_request.head.sha,
        head_repo_web_url: pull_request.head.repo.html_url,
        findings,
        policy_outcome,
        review_messages: 0,
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
    use foxguard::github_app::pull_request_job_store::PullRequestJobStatus;

    fn pull_request_job(
        delivery: &str,
        repository: &str,
        number: u64,
        head_sha: &str,
    ) -> PullRequestJob {
        let head_repo = GitHubRepository {
            clone_url: format!("https://github.com/{repository}.git"),
            full_name: repository.to_string(),
        };
        PullRequestJob {
            delivery: delivery.to_string(),
            action: "synchronize".to_string(),
            installation_id: 1,
            pull_request: Some(GitHubPullRequest {
                number,
                head: GitHubPullRequestHead {
                    sha: head_sha.to_string(),
                    repo: head_repo.clone(),
                },
            }),
            repository: Some(head_repo),
            key: PullRequestKey {
                repository: repository.to_string(),
                number,
            },
        }
    }

    fn dispatcher() -> (
        tempfile::TempDir,
        PullRequestDispatcher,
        tokio::sync::mpsc::Receiver<PullRequestJob>,
    ) {
        let dir = tempfile::tempdir().expect("tempdir should be created");
        let store = PullRequestJobStore::open(dir.path().join("pull-request-jobs.json"))
            .expect("job store should open");
        let (dispatcher, receiver) = PullRequestDispatcher::new(1, store);
        (dir, dispatcher, receiver)
    }

    fn test_state_with_review(
        jobs: PullRequestJobStore,
        review_url: &str,
    ) -> (tempfile::TempDir, AppState) {
        let dir = tempfile::tempdir().expect("tempdir should be created");
        let installations = InstallationStore::open(dir.path().join("installations.json"))
            .expect("installation store should open");
        let installations_path: Arc<Path> = Arc::from(installations.path());
        let (pull_request_dispatcher, _receiver) = PullRequestDispatcher::new(1, jobs);
        let credentials = AppCredentials::new(1, b"not-a-real-private-key".to_vec());
        (
            dir,
            AppState {
                webhook_secret: b"test-webhook-secret".to_vec(),
                auth: GitHubAppAuthClient::new(credentials).expect("auth client should build"),
                review: GitHubReviewClient::new(review_url).expect("review client should build"),
                installation_tokens: Arc::new(tokio::sync::Mutex::new(
                    InstallationTokenCache::new(),
                )),
                installation_token_locks: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
                check_lifecycle_locks: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
                pull_request_admission_locks: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
                installations: Arc::new(Mutex::new(installations)),
                installations_path,
                pull_request_dispatcher,
            },
        )
    }

    fn signed_pull_request_headers(body: &[u8]) -> HeaderMap {
        use hmac::Mac;

        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(b"test-webhook-secret")
            .expect("HMAC key should be accepted");
        mac.update(body);
        let signature = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Hub-Signature-256",
            signature.parse().expect("signature header should parse"),
        );
        headers.insert(
            "X-GitHub-Event",
            "pull_request".parse().expect("event header should parse"),
        );
        headers.insert(
            "X-GitHub-Delivery",
            "delivery-1".parse().expect("delivery header should parse"),
        );
        headers
    }

    fn spawn_check_update_server(status: u16) -> (String, std::thread::JoinHandle<()>) {
        spawn_json_response_server(status, "{}")
    }

    fn spawn_json_response_server(
        status: u16,
        body: &'static str,
    ) -> (String, std::thread::JoinHandle<()>) {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("mock server should bind");
        let port = listener
            .local_addr()
            .expect("mock server should report its address")
            .port();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("mock server should accept");
            let mut request = [0_u8; 8192];
            let _ = stream.read(&mut request);
            let response = format!(
                "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .expect("mock server should respond");
            stream.flush().expect("mock server should flush");
        });
        (format!("http://127.0.0.1:{port}/"), handle)
    }

    fn spawn_json_response_then_refuse(
        status: u16,
        body: &'static str,
    ) -> (String, std::thread::JoinHandle<()>) {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("mock server should bind");
        let port = listener
            .local_addr()
            .expect("mock server should report its address")
            .port();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("mock server should accept");
            drop(listener);
            let mut request = [0_u8; 8192];
            let _ = stream.read(&mut request);
            let response = format!(
                "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .expect("mock server should respond");
            stream.flush().expect("mock server should flush");
        });
        (format!("http://127.0.0.1:{port}/"), handle)
    }

    fn spawn_json_response_sequence(
        responses: Vec<(u16, String)>,
    ) -> (String, std::thread::JoinHandle<usize>) {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("mock server should bind");
        let port = listener
            .local_addr()
            .expect("mock server should report its address")
            .port();
        let handle = std::thread::spawn(move || {
            let mut served = 0;
            for (status, body) in responses {
                let (mut stream, _) = listener.accept().expect("mock server should accept");
                let mut request = [0_u8; 8192];
                let _ = stream.read(&mut request);
                let response = format!(
                    "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("mock server should respond");
                stream.flush().expect("mock server should flush");
                served += 1;
            }
            served
        });
        (format!("http://127.0.0.1:{port}/"), handle)
    }

    fn spawn_json_or_disconnect_sequence(
        responses: Vec<Option<(u16, String)>>,
    ) -> (String, std::thread::JoinHandle<usize>) {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("mock server should bind");
        let port = listener
            .local_addr()
            .expect("mock server should report its address")
            .port();
        let handle = std::thread::spawn(move || {
            let mut served = 0;
            for response in responses {
                let (mut stream, _) = listener.accept().expect("mock server should accept");
                let mut request = [0_u8; 8192];
                let _ = stream.read(&mut request);
                if let Some((status, body)) = response {
                    let response = format!(
                        "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    stream
                        .write_all(response.as_bytes())
                        .expect("mock server should respond");
                    stream.flush().expect("mock server should flush");
                }
                served += 1;
            }
            served
        });
        (format!("http://127.0.0.1:{port}/"), handle)
    }

    fn spawn_interleaved_head_server(
        first_body: &'static str,
        second_body: &'static str,
    ) -> (
        String,
        tokio::sync::oneshot::Receiver<()>,
        std::sync::mpsc::Sender<()>,
        tokio::sync::mpsc::UnboundedReceiver<()>,
        std::thread::JoinHandle<()>,
    ) {
        use std::io::{ErrorKind, Read, Write};
        use std::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").expect("mock server should bind");
        listener
            .set_nonblocking(true)
            .expect("mock server should become nonblocking");
        let port = listener
            .local_addr()
            .expect("mock server should report its address")
            .port();
        let (first_started_tx, first_started_rx) = tokio::sync::oneshot::channel();
        let (release_first_tx, release_first_rx) = std::sync::mpsc::channel();
        let (second_request_tx, second_request_rx) = tokio::sync::mpsc::unbounded_channel();
        let handle = std::thread::spawn(move || {
            let read_request = |stream: &mut TcpStream| {
                let mut request = [0_u8; 8192];
                let _ = stream.read(&mut request);
            };
            let write_response = |stream: &mut TcpStream, body: &str| {
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("mock server should respond");
                stream.flush().expect("mock server should flush");
            };
            let mut first = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("mock server should accept first request: {error}"),
                }
            };
            read_request(&mut first);
            let _ = first_started_tx.send(());
            let mut second = None;
            let mut second_was_read = false;
            loop {
                if release_first_rx.try_recv().is_ok() {
                    break;
                }
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        read_request(&mut stream);
                        let _ = second_request_tx.send(());
                        second_was_read = true;
                        second = Some(stream);
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("mock server should accept second request: {error}"),
                }
            }
            write_response(&mut first, first_body);
            let (mut second, second_was_read) = match second {
                Some(stream) => (stream, second_was_read),
                None => (
                    loop {
                        match listener.accept() {
                            Ok((stream, _)) => break stream,
                            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                                std::thread::sleep(Duration::from_millis(1));
                            }
                            Err(error) => {
                                panic!("mock server should accept second request: {error}")
                            }
                        }
                    },
                    false,
                ),
            };
            if !second_was_read {
                read_request(&mut second);
                let _ = second_request_tx.send(());
            }
            write_response(&mut second, second_body);
        });
        (
            format!("http://127.0.0.1:{port}/"),
            first_started_rx,
            release_first_tx,
            second_request_rx,
            handle,
        )
    }

    fn spawn_interleaved_render_server(
        older_head: &'static str,
        newer_head: &'static str,
    ) -> (
        String,
        tokio::sync::oneshot::Receiver<()>,
        std::sync::mpsc::Sender<()>,
        tokio::sync::mpsc::UnboundedReceiver<()>,
        std::thread::JoinHandle<()>,
    ) {
        use std::io::{ErrorKind, Read, Write};
        use std::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").expect("mock server should bind");
        listener
            .set_nonblocking(true)
            .expect("mock server should become nonblocking");
        let port = listener
            .local_addr()
            .expect("mock server should report its address")
            .port();
        let (render_started_tx, render_started_rx) = tokio::sync::oneshot::channel();
        let (release_render_tx, release_render_rx) = std::sync::mpsc::channel();
        let (newer_request_tx, newer_request_rx) = tokio::sync::mpsc::unbounded_channel();
        let handle = std::thread::spawn(move || {
            let read_request = |stream: &mut TcpStream| {
                let mut request = [0_u8; 8192];
                let _ = stream.read(&mut request);
            };
            let write_response = |stream: &mut TcpStream, body: &str| {
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("mock server should respond");
                stream.flush().expect("mock server should flush");
            };
            let accept_stream = || loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("mock server should accept request: {error}"),
                }
            };

            let mut head_lookup = accept_stream();
            read_request(&mut head_lookup);
            write_response(&mut head_lookup, older_head);

            let mut render_request = accept_stream();
            read_request(&mut render_request);
            let _ = render_started_tx.send(());
            let mut newer_request = None;
            loop {
                if release_render_rx.try_recv().is_ok() {
                    break;
                }
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        read_request(&mut stream);
                        let _ = newer_request_tx.send(());
                        newer_request = Some(stream);
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("mock server should accept newer request: {error}"),
                }
            }
            write_response(&mut render_request, "[]");

            let (mut newer_request, was_read) = match newer_request {
                Some(stream) => (stream, true),
                None => (accept_stream(), false),
            };
            if !was_read {
                read_request(&mut newer_request);
                let _ = newer_request_tx.send(());
            }
            write_response(&mut newer_request, newer_head);
        });
        (
            format!("http://127.0.0.1:{port}/"),
            render_started_rx,
            release_render_tx,
            newer_request_rx,
            handle,
        )
    }

    async fn remember_test_token(state: &AppState) {
        state.installation_tokens.lock().await.remember(
            1,
            InstallationToken {
                token: "test-installation-token".to_string(),
                expires_at: "2099-01-01T00:00:00Z".to_string(),
            },
            std::time::SystemTime::now(),
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn persistence_failure_returns_503_and_retry_is_admitted_durably() {
        let body = br#"{
            "action":"synchronize",
            "installation":{"id":1},
            "pull_request":{
                "number":7,
                "head":{
                    "sha":"0123456789abcdef0123456789abcdef01234567",
                    "repo":{
                        "clone_url":"https://github.com/owner/repo.git",
                        "full_name":"owner/repo"
                    }
                }
            },
            "repository":{
                "clone_url":"https://github.com/owner/repo.git",
                "full_name":"owner/repo"
            }
        }"#;
        let failed_dir = tempfile::tempdir().expect("failure tempdir should be created");
        let failed_path = failed_dir.path().join("pull-request-jobs.json");
        let failing_store =
            PullRequestJobStore::open(failed_path.clone()).expect("store should open");
        std::fs::create_dir(&failed_path).expect("target directory injects rename failure");
        let (failed_url, failed_server) = spawn_json_response_server(
            200,
            r#"{"head":{"sha":"0123456789abcdef0123456789abcdef01234567"}}"#,
        );
        let (_state_dir, failed_state) = test_state_with_review(failing_store, &failed_url);
        remember_test_token(&failed_state).await;
        assert_eq!(
            webhook(
                State(failed_state),
                signed_pull_request_headers(body),
                axum::body::Bytes::from_static(body),
            )
            .await,
            StatusCode::SERVICE_UNAVAILABLE
        );
        failed_server
            .join()
            .expect("authoritative head mock server should join");

        let retry_dir = tempfile::tempdir().expect("retry tempdir should be created");
        let retry_path = retry_dir.path().join("pull-request-jobs.json");
        let retry_store =
            PullRequestJobStore::open(retry_path.clone()).expect("retry store should open");
        let (retry_url, retry_server) = spawn_json_response_server(
            200,
            r#"{"head":{"sha":"0123456789abcdef0123456789abcdef01234567"}}"#,
        );
        let (_state_dir, retry_state) = test_state_with_review(retry_store, &retry_url);
        remember_test_token(&retry_state).await;
        assert_eq!(
            webhook(
                State(retry_state),
                signed_pull_request_headers(body),
                axum::body::Bytes::from_static(body),
            )
            .await,
            StatusCode::ACCEPTED
        );
        retry_server
            .join()
            .expect("authoritative head mock server should join");
        let durable = PullRequestJobStore::open(retry_path).expect("retry delivery should persist");
        assert_eq!(durable.queued_jobs().len(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn delayed_webhook_head_does_not_supersede_authoritative_queued_head() {
        let job_dir = tempfile::tempdir().expect("job tempdir should be created");
        let job_path = job_dir.path().join("pull-request-jobs.json");
        let mut store = PullRequestJobStore::open(job_path.clone()).expect("store should open");
        assert!(matches!(
            store.accept(PullRequestJobInput {
                delivery_id: "current-delivery".to_string(),
                action: "synchronize".to_string(),
                installation_id: 1,
                repository: "owner/repo".to_string(),
                pull_request: 7,
                head_sha: "89abcdef0123456789abcdef0123456789abcdef".to_string(),
                clone_url: "https://github.com/owner/repo.git".to_string(),
            }),
            Ok(PullRequestJobAdmission::Accepted { .. })
        ));
        let (review_url, server) = spawn_json_response_server(
            200,
            r#"{"head":{"sha":"89abcdef0123456789abcdef0123456789abcdef"}}"#,
        );
        let (_state_dir, state) = test_state_with_review(store, &review_url);
        remember_test_token(&state).await;
        let delayed_body = br#"{
            "action":"synchronize",
            "installation":{"id":1},
            "pull_request":{
                "number":7,
                "head":{
                    "sha":"0123456789abcdef0123456789abcdef01234567",
                    "repo":{
                        "clone_url":"https://github.com/owner/repo.git",
                        "full_name":"owner/repo"
                    }
                }
            },
            "repository":{
                "clone_url":"https://github.com/owner/repo.git",
                "full_name":"owner/repo"
            }
        }"#;
        assert_eq!(
            webhook(
                State(state.clone()),
                signed_pull_request_headers(delayed_body),
                axum::body::Bytes::from_static(delayed_body),
            )
            .await,
            StatusCode::ACCEPTED
        );
        server
            .join()
            .expect("authoritative head mock server should join");
        assert!(
            state
                .pull_request_dispatcher
                .cancellation_pending_jobs()
                .is_empty(),
            "a delayed webhook must not cancel the current head"
        );
        drop(state);
        let durable = PullRequestJobStore::open(job_path).expect("current job should persist");
        let queued = durable.queued_jobs();
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].delivery_id, "current-delivery");
        assert_eq!(
            queued[0].head_sha,
            "89abcdef0123456789abcdef0123456789abcdef"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn authoritative_lookup_and_admission_are_serialized_per_pull_request() {
        const H1: &str = "0123456789abcdef0123456789abcdef01234567";
        const H2: &str = "89abcdef0123456789abcdef0123456789abcdef";

        let job_dir = tempfile::tempdir().expect("job tempdir should be created");
        let job_path = job_dir.path().join("pull-request-jobs.json");
        let store = PullRequestJobStore::open(job_path.clone()).expect("store should open");
        let (review_url, first_started, release_first, mut second_request, server) =
            spawn_interleaved_head_server(
                r#"{"head":{"sha":"0123456789abcdef0123456789abcdef01234567"}}"#,
                r#"{"head":{"sha":"89abcdef0123456789abcdef0123456789abcdef"}}"#,
            );
        let (_state_dir, state) = test_state_with_review(store, &review_url);
        remember_test_token(&state).await;

        let first_state = state.clone();
        let first = tokio::spawn(async move {
            admit_authoritative_pull_request(
                &first_state,
                pull_request_job("delivery-h1", "owner/repo", 7, H1),
            )
            .await
        });
        first_started
            .await
            .expect("first authoritative lookup should reach the server");

        let second_state = state.clone();
        let second = tokio::spawn(async move {
            admit_authoritative_pull_request(
                &second_state,
                pull_request_job("delivery-h2", "owner/repo", 7, H2),
            )
            .await
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(50), second_request.recv())
                .await
                .is_err(),
            "the later delivery must wait for the first lookup and admission gate"
        );
        release_first
            .send(())
            .expect("mock server should still await the first response release");

        assert!(matches!(
            first.await.expect("first admission task should join"),
            Ok(DispatchOutcome::Accepted { .. })
        ));
        assert!(matches!(
            second.await.expect("second admission task should join"),
            Ok(DispatchOutcome::Accepted { .. })
        ));
        server.join().expect("interleaving mock server should join");

        drop(state);
        let durable =
            PullRequestJobStore::open(job_path).expect("admitted deliveries should persist");
        let queued = durable.queued_jobs();
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].delivery_id, "delivery-h2");
        let pending = durable.cancellation_pending_jobs();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].delivery_id, "delivery-h1");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn final_review_rendering_and_newer_admission_share_the_pull_request_gate() {
        const H1: &str = "0123456789abcdef0123456789abcdef01234567";
        const H2: &str = "89abcdef0123456789abcdef0123456789abcdef";

        let job_dir = tempfile::tempdir().expect("job tempdir should be created");
        let job_path = job_dir.path().join("pull-request-jobs.json");
        let mut store = PullRequestJobStore::open(job_path).expect("store should open");
        assert!(matches!(
            store.accept(PullRequestJobInput {
                delivery_id: "delivery-h1".to_string(),
                action: "synchronize".to_string(),
                installation_id: 1,
                repository: "owner/repo".to_string(),
                pull_request: 7,
                head_sha: H1.to_string(),
                clone_url: "https://github.com/owner/repo.git".to_string(),
            }),
            Ok(PullRequestJobAdmission::Accepted { .. })
        ));
        let (review_url, render_started, release_render, mut newer_request, server) =
            spawn_interleaved_render_server(
                r#"{"head":{"sha":"0123456789abcdef0123456789abcdef01234567"}}"#,
                r#"{"head":{"sha":"89abcdef0123456789abcdef0123456789abcdef"}}"#,
            );
        let (_state_dir, state) = test_state_with_review(store, &review_url);
        remember_test_token(&state).await;

        let rendering_state = state.clone();
        let rendering = tokio::spawn(async move {
            let mut result = PullRequestScanResult {
                pr_number: 7,
                repo: "owner/repo".to_string(),
                head_sha: H1.to_string(),
                findings: Vec::new(),
                posted_comments: 0,
                deleted_comments: 0,
                posted_check_annotations: 0,
            };
            validate_and_render_pull_request_review(
                &rendering_state,
                "delivery-h1",
                &mut result,
                "test-installation-token",
                None,
            )
            .await
            .map(|()| result)
        });
        render_started
            .await
            .expect("old-head render should reach the held review request");

        let newer_state = state.clone();
        let newer = tokio::spawn(async move {
            admit_authoritative_pull_request(
                &newer_state,
                pull_request_job("delivery-h2", "owner/repo", 7, H2),
            )
            .await
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(50), newer_request.recv())
                .await
                .is_err(),
            "newer admission must not cancel the old delivery while its review renders"
        );
        release_render
            .send(())
            .expect("mock server should still await render release");

        let rendered = rendering
            .await
            .expect("render task should join")
            .expect("old review should render before newer admission");
        assert_eq!(rendered.posted_comments, 0);
        assert_eq!(rendered.deleted_comments, 0);
        assert!(matches!(
            newer.await.expect("newer admission task should join"),
            Ok(DispatchOutcome::Accepted { .. })
        ));
        server.join().expect("interleaving mock server should join");
        let pending = state.pull_request_dispatcher.cancellation_pending_jobs();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].delivery_id, "delivery-h1");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn failed_check_cancellation_is_reconciled_after_restart() {
        let job_dir = tempfile::tempdir().expect("job tempdir should be created");
        let job_path = job_dir.path().join("pull-request-jobs.json");
        let mut store = PullRequestJobStore::open(job_path.clone()).expect("store should open");
        let input = |delivery_id: &str, head_sha: &str| PullRequestJobInput {
            delivery_id: delivery_id.to_string(),
            action: "synchronize".to_string(),
            installation_id: 1,
            repository: "owner/repo".to_string(),
            pull_request: 7,
            head_sha: head_sha.to_string(),
            clone_url: "https://github.com/owner/repo.git".to_string(),
        };
        let first = match store
            .accept(input(
                "delivery-1",
                "0123456789abcdef0123456789abcdef01234567",
            ))
            .expect("first delivery should persist")
        {
            PullRequestJobAdmission::Accepted { job, .. } => *job,
            PullRequestJobAdmission::DuplicateDelivery => panic!("first delivery must be accepted"),
        };
        store
            .attach_check_run_id(&first.delivery_id, 91)
            .expect("check attachment should persist");
        assert!(matches!(
            store.accept(input(
                "delivery-2",
                "89abcdef0123456789abcdef0123456789abcdef",
            )),
            Ok(PullRequestJobAdmission::Accepted { .. })
        ));
        drop(store);

        let (failure_url, failure_server) = spawn_check_update_server(503);
        let (failure_state_dir, failure_state) = test_state_with_review(
            PullRequestJobStore::open(job_path.clone()).expect("store should reopen"),
            &failure_url,
        );
        remember_test_token(&failure_state).await;
        reconcile_pending_job_checks(&failure_state, unix_time_millis(), true).await;
        failure_server
            .join()
            .expect("failure mock server should join");
        assert_eq!(
            failure_state
                .pull_request_dispatcher
                .cancellation_pending_jobs()
                .len(),
            1,
            "a failed external cancellation must remain retryable"
        );
        drop(failure_state);
        drop(failure_state_dir);

        let (success_url, success_server) = spawn_check_update_server(200);
        let (restart_state_dir, restart_state) = test_state_with_review(
            PullRequestJobStore::open(job_path).expect("store should reopen after failure"),
            &success_url,
        );
        restart_state
            .pull_request_dispatcher
            .recover()
            .expect("restart recovery should persist");
        remember_test_token(&restart_state).await;
        reconcile_pending_job_checks(&restart_state, unix_time_millis(), true).await;
        success_server
            .join()
            .expect("success mock server should join");
        assert!(
            restart_state
                .pull_request_dispatcher
                .cancellation_pending_jobs()
                .is_empty(),
            "a successful retry must terminalize the superseded job"
        );
        drop(restart_state_dir);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn failed_terminal_check_patch_persists_a_retryable_job() {
        let job_dir = tempfile::tempdir().expect("job tempdir should be created");
        let job_path = job_dir.path().join("pull-request-jobs.json");
        let mut store = PullRequestJobStore::open(job_path.clone()).expect("store should open");
        let delivery_id = "delivery-1";
        let input = PullRequestJobInput {
            delivery_id: delivery_id.to_string(),
            action: "synchronize".to_string(),
            installation_id: 1,
            repository: "owner/repo".to_string(),
            pull_request: 7,
            head_sha: "0123456789abcdef0123456789abcdef01234567".to_string(),
            clone_url: "https://github.com/owner/repo.git".to_string(),
        };
        assert!(matches!(
            store.accept(input),
            Ok(PullRequestJobAdmission::Accepted { .. })
        ));
        let mut running = store
            .mark_running(delivery_id)
            .expect("running transition should persist")
            .expect("queued job should become running");
        store
            .attach_check_run_id(delivery_id, 91)
            .expect("check attachment should persist");
        running.check_run_id = Some(91);

        let (failure_url, failure_server) = spawn_check_update_server(503);
        let (state_dir, state) = test_state_with_review(store, &failure_url);
        remember_test_token(&state).await;
        let terminal_update_error = complete_failed_job_check(&state, &running, "scan failed")
            .await
            .expect_err(
                "a rejected terminal check PATCH must be surfaced to the durable job lifecycle",
            );
        failure_server
            .join()
            .expect("failure mock server should join");
        let retry = state
            .pull_request_dispatcher
            .mark_retry_pending(delivery_id, terminal_update_error)
            .expect("retry transition should persist")
            .expect("running job should remain retryable");
        assert_eq!(retry.status, PullRequestJobStatus::RetryPending);
        drop(state);
        drop(state_dir);

        let mut restarted =
            PullRequestJobStore::open(job_path).expect("retryable job should survive restart");
        let recovered = restarted
            .recover_non_terminal()
            .expect("retryable job should requeue during restart recovery");
        assert_eq!(recovered.queued.len(), 1);
        assert_eq!(recovered.queued[0].delivery_id, delivery_id);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn lifecycle_driver_requeues_terminal_update_failures_without_restart() {
        let job_dir = tempfile::tempdir().expect("job tempdir should be created");
        let job_path = job_dir.path().join("pull-request-jobs.json");
        let mut store = PullRequestJobStore::open(job_path).expect("store should open");
        let delivery_id = "delivery-1";
        assert!(matches!(
            store.accept(PullRequestJobInput {
                delivery_id: delivery_id.to_string(),
                action: "synchronize".to_string(),
                installation_id: 1,
                repository: "owner/repo".to_string(),
                pull_request: 7,
                head_sha: "0123456789abcdef0123456789abcdef01234567".to_string(),
                clone_url: "https://github.com/owner/repo.git".to_string(),
            }),
            Ok(PullRequestJobAdmission::Accepted { .. })
        ));
        store
            .mark_running(delivery_id)
            .expect("running transition should persist");
        let retry = store
            .mark_retry_pending(delivery_id, "terminal PATCH failed".to_string())
            .expect("retry transition should persist")
            .expect("running job should become retryable");
        let retry_deadline = retry
            .retry_not_before_unix_ms
            .expect("retryable job should persist a deadline");
        let (_state_dir, state) = test_state_with_review(store, "http://127.0.0.1:1/");

        drive_pending_lifecycle(&state, retry_deadline).await;
        let retried = state
            .pull_request_dispatcher
            .mark_running(delivery_id)
            .expect("lifecycle driver should make the job runnable")
            .expect("retryable job should requeue without restart");
        assert_eq!(retried.attempts, 2);
        let terminal = state
            .pull_request_dispatcher
            .mark_completed(delivery_id, 0)
            .expect("successful retry should persist terminal state")
            .expect("retried job should terminalize");
        assert_eq!(terminal.status, PullRequestJobStatus::Succeeded);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn lifecycle_driver_retries_cancel_after_a_transient_failure_without_restart() {
        let job_dir = tempfile::tempdir().expect("job tempdir should be created");
        let job_path = job_dir.path().join("pull-request-jobs.json");
        let mut store = PullRequestJobStore::open(job_path).expect("store should open");
        let input = |delivery_id: &str, head_sha: &str| PullRequestJobInput {
            delivery_id: delivery_id.to_string(),
            action: "synchronize".to_string(),
            installation_id: 1,
            repository: "owner/repo".to_string(),
            pull_request: 7,
            head_sha: head_sha.to_string(),
            clone_url: "https://github.com/owner/repo.git".to_string(),
        };
        let first = match store
            .accept(input(
                "delivery-1",
                "0123456789abcdef0123456789abcdef01234567",
            ))
            .expect("first delivery should persist")
        {
            PullRequestJobAdmission::Accepted { job, .. } => *job,
            PullRequestJobAdmission::DuplicateDelivery => panic!("first delivery must be accepted"),
        };
        store
            .attach_check_run_id(&first.delivery_id, 91)
            .expect("check attachment should persist");
        assert!(matches!(
            store.accept(input(
                "delivery-2",
                "89abcdef0123456789abcdef0123456789abcdef",
            )),
            Ok(PullRequestJobAdmission::Accepted { .. })
        ));
        let (review_url, server) =
            spawn_json_response_sequence(vec![(503, "{}".to_string()), (200, "{}".to_string())]);
        let (_state_dir, state) = test_state_with_review(store, &review_url);
        remember_test_token(&state).await;

        reconcile_pending_job_checks(&state, unix_time_millis(), true).await;
        let retry = state.pull_request_dispatcher.cancellation_pending_jobs();
        assert_eq!(retry.len(), 1);
        let retry_deadline = retry[0]
            .retry_not_before_unix_ms
            .expect("failed cancellation should persist a backoff deadline");
        drive_pending_lifecycle(&state, retry_deadline).await;
        assert!(
            state
                .pull_request_dispatcher
                .cancellation_pending_jobs()
                .is_empty(),
            "the idle lifecycle driver should terminalize after the retry succeeds"
        );
        assert_eq!(server.join().expect("mock server should join"), 2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn persisted_creating_check_survives_a_lookup_miss_until_it_can_be_cancelled() {
        let job_dir = tempfile::tempdir().expect("job tempdir should be created");
        let job_path = job_dir.path().join("pull-request-jobs.json");
        let mut store = PullRequestJobStore::open(job_path).expect("store should open");
        let input = |delivery_id: &str, head_sha: &str| PullRequestJobInput {
            delivery_id: delivery_id.to_string(),
            action: "synchronize".to_string(),
            installation_id: 1,
            repository: "owner/repo".to_string(),
            pull_request: 7,
            head_sha: head_sha.to_string(),
            clone_url: "https://github.com/owner/repo.git".to_string(),
        };
        let first = match store
            .accept(input(
                "delivery-1",
                "0123456789abcdef0123456789abcdef01234567",
            ))
            .expect("first delivery should persist")
        {
            PullRequestJobAdmission::Accepted { job, .. } => *job,
            PullRequestJobAdmission::DuplicateDelivery => panic!("first delivery must be accepted"),
        };
        store
            .mark_check_run_creation_started(&first.delivery_id)
            .expect("creation intent should persist");
        assert!(matches!(
            store.accept(input(
                "delivery-2",
                "89abcdef0123456789abcdef0123456789abcdef",
            )),
            Ok(PullRequestJobAdmission::Accepted { .. })
        ));
        let (review_url, server) = spawn_json_response_sequence(vec![
            (200, r#"{"check_runs":[]}"#.to_string()),
            (
                200,
                r#"{"check_runs":[{"id":91,"external_id":"foxguard-pr-scan:delivery-1"}]}"#
                    .to_string(),
            ),
            (200, "{}".to_string()),
        ]);
        let (_state_dir, state) = test_state_with_review(store, &review_url);
        remember_test_token(&state).await;

        reconcile_pending_job_checks(&state, unix_time_millis(), true).await;
        let pending = state.pull_request_dispatcher.cancellation_pending_jobs();
        assert_eq!(pending.len(), 1);
        assert_eq!(
            pending[0].check_run_creation,
            CheckRunCreationState::Creating
        );
        let retry_deadline = pending[0]
            .retry_not_before_unix_ms
            .expect("a lookup miss after creation intent must persist a retry");

        drive_pending_lifecycle(&state, retry_deadline).await;
        assert!(
            state
                .pull_request_dispatcher
                .cancellation_pending_jobs()
                .is_empty(),
            "the later lookup must cancel the discovered check rather than leak it"
        );
        assert_eq!(server.join().expect("mock server should join"), 3);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn lost_queued_check_create_response_retries_lookup_without_a_second_post() {
        let job_dir = tempfile::tempdir().expect("job tempdir should be created");
        let job_path = job_dir.path().join("pull-request-jobs.json");
        let mut store = PullRequestJobStore::open(job_path).expect("store should open");
        let stored = match store
            .accept(PullRequestJobInput {
                delivery_id: "delivery-1".to_string(),
                action: "synchronize".to_string(),
                installation_id: 1,
                repository: "owner/repo".to_string(),
                pull_request: 7,
                head_sha: "0123456789abcdef0123456789abcdef01234567".to_string(),
                clone_url: "https://github.com/owner/repo.git".to_string(),
            })
            .expect("delivery should persist")
        {
            PullRequestJobAdmission::Accepted { job, .. } => *job,
            PullRequestJobAdmission::DuplicateDelivery => panic!("delivery must be accepted"),
        };
        let (review_url, server) = spawn_json_or_disconnect_sequence(vec![
            Some((200, r#"{"check_runs":[]}"#.to_string())),
            None,
            Some((200, r#"{"check_runs":[]}"#.to_string())),
            Some((200, r#"{"check_runs":[]}"#.to_string())),
        ]);
        let (_state_dir, state) = test_state_with_review(store, &review_url);
        remember_test_token(&state).await;

        create_queued_job_check(&state, &stored)
            .await
            .expect_err("a dropped create response must leave the intent unresolved");
        let mut running = state
            .pull_request_dispatcher
            .mark_running(&stored.delivery_id)
            .expect("running transition should persist")
            .expect("queued job should become running");
        let lookup_error = mark_job_check_running(&state, &mut running)
            .await
            .expect_err("a creating check that is still absent must retry lookup");
        assert!(lookup_error.contains("not yet observable"));
        let retry = state
            .pull_request_dispatcher
            .mark_retry_pending(&stored.delivery_id, lookup_error)
            .expect("retry transition should persist")
            .expect("running job should become retryable");
        assert_eq!(retry.status, PullRequestJobStatus::RetryPending);
        assert_eq!(retry.check_run_creation, CheckRunCreationState::Creating);
        let retry_deadline = retry
            .retry_not_before_unix_ms
            .expect("unresolved creation must persist a retry deadline");

        drive_pending_lifecycle(&state, retry_deadline).await;
        let mut retried = state
            .pull_request_dispatcher
            .mark_running(&stored.delivery_id)
            .expect("lifecycle retry should persist")
            .expect("retryable job should requeue without restart");
        let lookup_error = mark_job_check_running(&state, &mut retried)
            .await
            .expect_err("the retried job must perform another lookup, not another create");
        assert!(lookup_error.contains("not yet observable"));
        assert_eq!(
            server.join().expect("mock server should join"),
            4,
            "only the initial create POST may be sent"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unsubmitted_queued_check_create_resets_intent_before_a_later_successful_post() {
        let job_dir = tempfile::tempdir().expect("job tempdir should be created");
        let job_path = job_dir.path().join("pull-request-jobs.json");
        let mut store = PullRequestJobStore::open(job_path.clone()).expect("store should open");
        let stored = match store
            .accept(PullRequestJobInput {
                delivery_id: "delivery-1".to_string(),
                action: "synchronize".to_string(),
                installation_id: 1,
                repository: "owner/repo".to_string(),
                pull_request: 7,
                head_sha: "0123456789abcdef0123456789abcdef01234567".to_string(),
                clone_url: "https://github.com/owner/repo.git".to_string(),
            })
            .expect("delivery should persist")
        {
            PullRequestJobAdmission::Accepted { job, .. } => *job,
            PullRequestJobAdmission::DuplicateDelivery => panic!("delivery must be accepted"),
        };
        let (failed_url, failed_server) =
            spawn_json_response_then_refuse(200, r#"{"check_runs":[]}"#);
        let (failed_state_dir, failed_state) = test_state_with_review(store, &failed_url);
        remember_test_token(&failed_state).await;
        create_queued_job_check(&failed_state, &stored)
            .await
            .expect_err("a refused create connection must be reported");
        failed_server
            .join()
            .expect("initial lookup mock server should join");
        assert_eq!(
            failed_state
                .pull_request_dispatcher
                .jobs
                .lock()
                .expect("job store lock should not poison")
                .job(&stored.delivery_id)
                .expect("durable job should remain visible")
                .check_run_creation,
            CheckRunCreationState::NotStarted,
            "a definitely unsubmitted create must clear its durable intent"
        );
        drop(failed_state);
        drop(failed_state_dir);

        let retried_store = PullRequestJobStore::open(job_path).expect("store should reopen");
        let retried = retried_store
            .queued_jobs()
            .into_iter()
            .next()
            .expect("job should remain queued for a later create");
        let (success_url, success_server) = spawn_json_response_sequence(vec![
            (200, r#"{"check_runs":[]}"#.to_string()),
            (201, r#"{"id":91}"#.to_string()),
        ]);
        let (_success_state_dir, success_state) =
            test_state_with_review(retried_store, &success_url);
        remember_test_token(&success_state).await;
        assert!(matches!(
            create_queued_job_check(&success_state, &retried)
                .await
                .expect("a later lookup may safely create the check"),
            Some(CheckRunAttachment::Attached(job)) if job.check_run_id == Some(91)
        ));
        assert_eq!(
            success_server
                .join()
                .expect("successful create mock should join"),
            2
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn superseded_delivery_without_an_observable_check_terminalizes_safely() {
        let job_dir = tempfile::tempdir().expect("job tempdir should be created");
        let job_path = job_dir.path().join("pull-request-jobs.json");
        let mut store = PullRequestJobStore::open(job_path).expect("store should open");
        let input = |delivery_id: &str, head_sha: &str| PullRequestJobInput {
            delivery_id: delivery_id.to_string(),
            action: "synchronize".to_string(),
            installation_id: 1,
            repository: "owner/repo".to_string(),
            pull_request: 7,
            head_sha: head_sha.to_string(),
            clone_url: "https://github.com/owner/repo.git".to_string(),
        };
        assert!(matches!(
            store.accept(input(
                "delivery-1",
                "0123456789abcdef0123456789abcdef01234567",
            )),
            Ok(PullRequestJobAdmission::Accepted { .. })
        ));
        assert!(matches!(
            store.accept(input(
                "delivery-2",
                "89abcdef0123456789abcdef0123456789abcdef",
            )),
            Ok(PullRequestJobAdmission::Accepted { .. })
        ));

        let (review_url, server) = spawn_json_response_server(200, r#"{"check_runs":[]}"#);
        let (_state_dir, state) = test_state_with_review(store, &review_url);
        remember_test_token(&state).await;
        reconcile_pending_job_checks(&state, unix_time_millis(), true).await;
        server.join().expect("check lookup mock server should join");
        assert!(
            state
                .pull_request_dispatcher
                .cancellation_pending_jobs()
                .is_empty(),
            "a superseded delivery with no external check must not remain pending forever"
        );
    }

    #[test]
    fn dispatcher_keeps_newer_head_durable_until_active_scan_completes() {
        let (_dir, dispatcher, mut receiver) = dispatcher();
        let first = pull_request_job("delivery-1", "owner/repo", 7, "head-1");
        match dispatcher.admit(first) {
            Ok(DispatchOutcome::Accepted {
                coalesced: false, ..
            }) => {}
            outcome => panic!("first delivery should persist: {outcome:?}"),
        }
        dispatcher.schedule();
        let active = receiver.try_recv().expect("first job should be queued");
        dispatcher
            .mark_running(&active.delivery)
            .expect("running transition should persist");

        let second = pull_request_job("delivery-2", "owner/repo", 7, "head-2");
        match dispatcher.admit(second) {
            Ok(DispatchOutcome::Accepted {
                coalesced: true, ..
            }) => {}
            outcome => panic!("newer head should coalesce: {outcome:?}"),
        }
        dispatcher.schedule();
        assert!(
            receiver.try_recv().is_err(),
            "active key blocks a second scan"
        );

        dispatcher.complete(&active.key, &active.delivery);
        let follow_up = receiver.try_recv().expect("newer head should be scheduled");
        let head = follow_up
            .pull_request
            .as_ref()
            .map(|pull_request| pull_request.head.sha.as_str());
        assert_eq!(head, Some("head-2"));
    }

    #[test]
    fn dispatcher_requeues_abandoned_running_work_only_after_worker_completion() {
        let (_dir, dispatcher, mut receiver) = dispatcher();
        let job = pull_request_job("delivery-1", "owner/repo", 7, "head-1");
        assert!(matches!(
            dispatcher.admit(job),
            Ok(DispatchOutcome::Accepted { .. })
        ));
        dispatcher.schedule();
        let active = receiver.try_recv().expect("first job should be queued");
        assert!(dispatcher
            .mark_running(&active.delivery)
            .expect("running transition should persist")
            .is_some());
        assert_eq!(
            dispatcher
                .requeue_abandoned_running()
                .expect("active worker must not be requeued"),
            0
        );
        assert!(
            receiver.try_recv().is_err(),
            "an active worker must not be duplicated"
        );

        // Simulate the worker finishing after a later durable transition
        // failed, leaving its already-persisted `Running` state behind.
        dispatcher.complete(&active.key, &active.delivery);
        assert_eq!(
            dispatcher
                .requeue_abandoned_running()
                .expect("finished running work should be recovered"),
            1
        );
        assert_eq!(
            receiver
                .try_recv()
                .expect("recovered job should be scheduled")
                .delivery,
            "delivery-1"
        );
    }

    #[test]
    fn dispatcher_dedupes_persisted_delivery_ids() {
        let (_dir, dispatcher, _receiver) = dispatcher();
        let first = pull_request_job("same-delivery", "owner/repo", 7, "head-1");
        assert!(matches!(
            dispatcher.admit(first),
            Ok(DispatchOutcome::Accepted { .. })
        ));
        let duplicate = pull_request_job("same-delivery", "owner/repo", 7, "head-1");
        assert!(matches!(
            dispatcher.admit(duplicate),
            Ok(DispatchOutcome::DuplicateDelivery)
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn concurrent_newer_delivery_and_late_check_attachment_retain_cancellation() {
        let (_dir, dispatcher, _receiver) = dispatcher();
        let first = match dispatcher
            .admit(pull_request_job("delivery-1", "owner/repo", 7, "head-1"))
            .expect("first delivery should persist")
        {
            DispatchOutcome::Accepted { job, .. } => job,
            DispatchOutcome::DuplicateDelivery => panic!("first delivery must be accepted"),
        };
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let attach_dispatcher = dispatcher.clone();
        let attach_delivery = first.delivery_id.clone();
        let attach_barrier = Arc::clone(&barrier);
        let attachment = tokio::spawn(async move {
            attach_barrier.wait().await;
            attach_dispatcher.attach_check_run_id(&attach_delivery, 91)
        });
        let admit_dispatcher = dispatcher.clone();
        let admit_barrier = Arc::clone(&barrier);
        let newer_delivery = tokio::spawn(async move {
            admit_barrier.wait().await;
            admit_dispatcher.admit(pull_request_job("delivery-2", "owner/repo", 7, "head-2"))
        });
        barrier.wait().await;

        assert!(matches!(
            attachment.await.expect("attachment task should join"),
            Ok(CheckRunAttachment::Attached(_)) | Ok(CheckRunAttachment::CancellationPending(_))
        ));
        assert!(matches!(
            newer_delivery.await.expect("admission task should join"),
            Ok(DispatchOutcome::Accepted { .. })
        ));
        let pending = dispatcher.cancellation_pending_jobs();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].delivery_id, "delivery-1");
        assert_eq!(pending[0].check_run_id, Some(91));
    }

    #[test]
    fn authoritative_newer_head_marks_delayed_delivery_stale_before_rendering() {
        let error = validate_authoritative_pull_request_head(
            "0123456789abcdef0123456789abcdef01234567",
            "89abcdef0123456789abcdef0123456789abcdef".to_string(),
        )
        .expect_err("a delayed delivery must not render against a newer head");
        assert!(matches!(
            error,
            PullRequestProcessError::StaleHead { expected, actual }
                if expected == "0123456789abcdef0123456789abcdef01234567"
                    && actual == "89abcdef0123456789abcdef0123456789abcdef"
        ));
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
                            "html_url":"https://github.com/0sec-labs/foxguard",
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
        assert_eq!(
            pull_request.head.repo.html_url,
            "https://github.com/0sec-labs/foxguard"
        );
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
