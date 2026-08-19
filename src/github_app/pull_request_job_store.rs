//! Durable pull-request scan jobs for the GitHub App receiver.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_STORE_DIR: &str = ".foxguard-github-app";
const DEFAULT_STORE_FILE: &str = "pull-request-jobs.json";
const STORE_SCHEMA_VERSION: u32 = 3;
const RECENT_DELIVERY_CAPACITY: usize = 4096;
const RETRY_BACKOFF_BASE_MILLIS: u64 = 1_000;
const RETRY_BACKOFF_MAX_MILLIS: u64 = 60_000;

#[derive(Debug)]
pub enum PullRequestJobStoreError {
    InvalidPath(String),
    Io(std::io::Error),
    Json(serde_json::Error),
    /// The new registry was atomically renamed into place, but syncing its
    /// parent directory failed afterwards. The transition is visible and must
    /// be treated differently from a failed write.
    PostRenameDirectorySync(Box<PullRequestJobStoreError>),
}

impl fmt::Display for PullRequestJobStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath(error) => write!(f, "invalid pull-request job store path: {error}"),
            Self::Io(error) => write!(f, "pull-request job store I/O failed: {error}"),
            Self::Json(error) => write!(f, "pull-request job store JSON failed: {error}"),
            Self::PostRenameDirectorySync(error) => write!(
                f,
                "pull-request job store state was applied but parent directory sync failed: {error}"
            ),
        }
    }
}

impl std::error::Error for PullRequestJobStoreError {}

impl PullRequestJobStoreError {
    pub fn state_transition_applied(&self) -> bool {
        matches!(self, Self::PostRenameDirectorySync(_))
    }
}

impl From<std::io::Error> for PullRequestJobStoreError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for PullRequestJobStoreError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

#[derive(Debug)]
pub struct PullRequestJobStore {
    path: PathBuf,
    registry: PullRequestJobRegistry,
    /// A rename has made `registry` visible on disk, but syncing its parent
    /// directory failed. New writes must quiesce until that sync succeeds.
    directory_sync_pending: bool,
    #[cfg(test)]
    fail_next_save: bool,
    #[cfg(test)]
    fail_next_post_rename_sync: bool,
    #[cfg(test)]
    fail_next_parent_sync: bool,
}

impl PullRequestJobStore {
    pub fn from_env_or_default() -> Result<Self, PullRequestJobStoreError> {
        let path = match std::env::var("FOXGUARD_PULL_REQUEST_JOBS_PATH") {
            Ok(value) => {
                let path = PathBuf::from(value); // foxguard: ignore[rs/no-path-traversal]
                validate_operator_path(&path)?;
                path
            }
            Err(_) => std::env::current_dir()?
                .join(DEFAULT_STORE_DIR)
                .join(DEFAULT_STORE_FILE),
        };
        Self::open(path)
    }

    pub fn open(path: PathBuf) -> Result<Self, PullRequestJobStoreError> {
        validate_store_path(&path)?;
        recover_stray_temp_file(&path)?;
        let registry = if path.exists() {
            let bytes = std::fs::read(&path)?; // foxguard: ignore[rs/no-path-traversal]
            let registry = serde_json::from_slice(&bytes)?;
            let parent = path.parent().ok_or_else(|| {
                PullRequestJobStoreError::InvalidPath("path has no parent".to_string())
            })?;
            sync_parent_directory(parent)?;
            registry
        } else {
            PullRequestJobRegistry::default()
        };
        Ok(Self {
            path,
            registry,
            directory_sync_pending: false,
            #[cfg(test)]
            fail_next_save: false,
            #[cfg(test)]
            fail_next_post_rename_sync: false,
            #[cfg(test)]
            fail_next_parent_sync: false,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Persist a newly accepted delivery before it can be acknowledged. The
    /// candidate registry is flushed first; in-memory state changes only after
    /// the durable write succeeds.
    pub fn accept(
        &mut self,
        input: PullRequestJobInput,
    ) -> Result<PullRequestJobAdmission, PullRequestJobStoreError> {
        self.ensure_parent_synced()?;
        if self.registry.jobs.contains_key(&input.delivery_id) {
            return Ok(PullRequestJobAdmission::DuplicateDelivery);
        }
        self.transaction(move |registry| {
            let mut cancellation_pending = Vec::new();
            for existing in registry.jobs.values_mut() {
                if existing.repository == input.repository
                    && existing.pull_request == input.pull_request
                    && matches!(
                        existing.status,
                        PullRequestJobStatus::Queued
                            | PullRequestJobStatus::Running
                            | PullRequestJobStatus::RetryPending
                    )
                {
                    existing.status = PullRequestJobStatus::CancellationPending;
                    existing.terminal_error = Some(format!(
                        "superseded by newer delivery {}",
                        input.delivery_id
                    ));
                    cancellation_pending.push(existing.clone());
                }
            }

            let sequence = registry.next_sequence;
            registry.next_sequence += 1;
            let job = StoredPullRequestJob {
                delivery_id: input.delivery_id.clone(),
                action: input.action,
                installation_id: input.installation_id,
                repository: input.repository,
                pull_request: input.pull_request,
                head_sha: input.head_sha,
                clone_url: input.clone_url,
                status: PullRequestJobStatus::Queued,
                attempts: 0,
                check_run_id: None,
                check_run_creation: CheckRunCreationState::NotStarted,
                finding_count: None,
                terminal_error: None,
                retry_not_before_unix_ms: None,
                lifecycle_retry_attempts: 0,
                sequence,
            };
            registry.jobs.insert(input.delivery_id, job.clone());
            prune_terminal_jobs(registry);
            PullRequestJobAdmission::Accepted {
                job: Box::new(job),
                cancellation_pending,
            }
        })
    }

    /// Requeue interrupted work after a restart. Jobs that need an external
    /// check-run cancellation remain non-terminal until that cancellation is
    /// durably reconciled.
    pub fn recover_non_terminal(
        &mut self,
    ) -> Result<PullRequestJobRecovery, PullRequestJobStoreError> {
        self.ensure_parent_synced()?;
        let mut next = self.registry.clone();
        let mut changed = false;
        for job in next.jobs.values_mut() {
            if matches!(
                job.status,
                PullRequestJobStatus::Running | PullRequestJobStatus::RetryPending
            ) {
                job.status = PullRequestJobStatus::Queued;
                job.retry_not_before_unix_ms = None;
                changed = true;
            }
        }

        let mut newest_by_key: BTreeMap<(String, u64), (u64, String)> = BTreeMap::new();
        for job in next.jobs.values() {
            if job.status != PullRequestJobStatus::Queued {
                continue;
            }
            let key = (job.repository.clone(), job.pull_request);
            if newest_by_key
                .get(&key)
                .is_none_or(|(sequence, _)| job.sequence > *sequence)
            {
                newest_by_key.insert(key, (job.sequence, job.delivery_id.clone()));
            }
        }
        for job in next.jobs.values_mut() {
            if job.status != PullRequestJobStatus::Queued {
                continue;
            }
            let key = (job.repository.clone(), job.pull_request);
            let newest_delivery = newest_by_key
                .get(&key)
                .map(|(_, delivery)| delivery.as_str());
            if newest_delivery != Some(job.delivery_id.as_str()) {
                job.status = PullRequestJobStatus::CancellationPending;
                job.terminal_error = Some("superseded during restart recovery".to_string());
                changed = true;
            }
        }

        if changed {
            prune_terminal_jobs(&mut next);
            self.persist_registry(&next)?;
            self.registry = next;
        }
        Ok(PullRequestJobRecovery {
            queued: self.queued_jobs(),
            cancellation_pending: self.cancellation_pending_jobs(),
        })
    }

    pub fn queued_jobs(&self) -> Vec<StoredPullRequestJob> {
        jobs_with_status(&self.registry, PullRequestJobStatus::Queued)
    }

    pub fn cancellation_pending_jobs(&self) -> Vec<StoredPullRequestJob> {
        jobs_with_status(&self.registry, PullRequestJobStatus::CancellationPending)
    }

    pub fn job(&self, delivery_id: &str) -> Option<StoredPullRequestJob> {
        self.registry.jobs.get(delivery_id).cloned()
    }

    /// Make terminal-update work eligible for another worker after its
    /// persisted backoff expires.
    pub fn requeue_due_retry_pending(
        &mut self,
        now_unix_ms: u64,
    ) -> Result<Vec<StoredPullRequestJob>, PullRequestJobStoreError> {
        self.ensure_parent_synced()?;
        if !self.registry.jobs.values().any(|job| {
            job.status == PullRequestJobStatus::RetryPending && job.retry_is_due(now_unix_ms)
        }) {
            return Ok(Vec::new());
        }
        self.transaction(|registry| {
            let mut requeued = Vec::new();
            for job in registry.jobs.values_mut() {
                if job.status == PullRequestJobStatus::RetryPending && job.retry_is_due(now_unix_ms)
                {
                    job.status = PullRequestJobStatus::Queued;
                    job.retry_not_before_unix_ms = None;
                    requeued.push(job.clone());
                }
            }
            requeued
        })
    }

    /// Requeue running jobs that a finished worker explicitly abandoned after
    /// it could not persist a later state transition.
    pub fn requeue_abandoned_running(
        &mut self,
        delivery_ids: &[String],
    ) -> Result<Vec<StoredPullRequestJob>, PullRequestJobStoreError> {
        self.ensure_parent_synced()?;
        if delivery_ids.is_empty() {
            return Ok(Vec::new());
        }
        self.transaction(|registry| {
            let mut requeued = Vec::new();
            for delivery_id in delivery_ids {
                let Some(job) = registry.jobs.get_mut(delivery_id) else {
                    continue;
                };
                if job.status != PullRequestJobStatus::Running {
                    continue;
                }
                job.status = PullRequestJobStatus::Queued;
                job.retry_not_before_unix_ms = None;
                requeued.push(job.clone());
            }
            requeued
        })
    }

    pub fn mark_running(
        &mut self,
        delivery_id: &str,
    ) -> Result<Option<StoredPullRequestJob>, PullRequestJobStoreError> {
        self.ensure_parent_synced()?;
        if self
            .registry
            .jobs
            .get(delivery_id)
            .is_none_or(|job| job.status != PullRequestJobStatus::Queued)
        {
            return Ok(None);
        }
        self.transaction(|registry| {
            let job = registry
                .jobs
                .get_mut(delivery_id)
                .expect("queued job was checked before transaction");
            job.status = PullRequestJobStatus::Running;
            job.terminal_error = None;
            job.retry_not_before_unix_ms = None;
            job.attempts += 1;
            Some(job.clone())
        })
    }

    /// Record that a check-run POST is about to begin while the caller holds
    /// the per-delivery lifecycle lock. A later cancellation can distinguish
    /// an intentionally absent check from a lost create response.
    pub fn mark_check_run_creation_started(
        &mut self,
        delivery_id: &str,
    ) -> Result<Option<StoredPullRequestJob>, PullRequestJobStoreError> {
        self.ensure_parent_synced()?;
        let Some(existing) = self.registry.jobs.get(delivery_id) else {
            return Ok(None);
        };
        if existing.status.is_terminal()
            || existing.status == PullRequestJobStatus::CancellationPending
            || existing.check_run_id.is_some()
        {
            return Ok(None);
        }
        if existing.check_run_creation == CheckRunCreationState::Creating {
            return Ok(Some(existing.clone()));
        }
        self.transaction(|registry| {
            let job = registry
                .jobs
                .get_mut(delivery_id)
                .expect("active job was checked before transaction");
            job.check_run_creation = CheckRunCreationState::Creating;
            Some(job.clone())
        })
    }

    /// Clear durable create intent only when no create request could have
    /// succeeded, allowing a later retry to safely issue its first POST.
    pub fn reset_check_run_creation(
        &mut self,
        delivery_id: &str,
    ) -> Result<Option<StoredPullRequestJob>, PullRequestJobStoreError> {
        self.ensure_parent_synced()?;
        let Some(existing) = self.registry.jobs.get(delivery_id) else {
            return Ok(None);
        };
        if existing.status.is_terminal()
            || existing.status == PullRequestJobStatus::CancellationPending
            || existing.check_run_id.is_some()
            || existing.check_run_creation != CheckRunCreationState::Creating
        {
            return Ok(None);
        }
        self.transaction(|registry| {
            let job = registry
                .jobs
                .get_mut(delivery_id)
                .expect("creating job was checked before transaction");
            job.check_run_creation = CheckRunCreationState::NotStarted;
            Some(job.clone())
        })
    }

    /// Record an externally-created check-run id even if the job became
    /// cancellation-pending while its POST request was in flight.
    pub fn attach_check_run_id(
        &mut self,
        delivery_id: &str,
        check_run_id: u64,
    ) -> Result<CheckRunAttachment, PullRequestJobStoreError> {
        self.ensure_parent_synced()?;
        let Some(existing) = self.registry.jobs.get(delivery_id) else {
            return Ok(CheckRunAttachment::Missing);
        };
        if existing.status.is_terminal() {
            return Ok(CheckRunAttachment::IgnoredTerminal);
        }
        if existing.check_run_id == Some(check_run_id)
            && existing.check_run_creation == CheckRunCreationState::Attached
        {
            return Ok(
                if existing.status == PullRequestJobStatus::CancellationPending {
                    CheckRunAttachment::CancellationPending(existing.clone())
                } else {
                    CheckRunAttachment::Attached(existing.clone())
                },
            );
        }
        self.transaction(|registry| {
            let job = registry
                .jobs
                .get_mut(delivery_id)
                .expect("job was checked before transaction");
            job.check_run_id = Some(check_run_id);
            job.check_run_creation = CheckRunCreationState::Attached;
            if job.status == PullRequestJobStatus::CancellationPending {
                CheckRunAttachment::CancellationPending(job.clone())
            } else {
                CheckRunAttachment::Attached(job.clone())
            }
        })
    }
    pub fn mark_completed(
        &mut self,
        delivery_id: &str,
        finding_count: usize,
    ) -> Result<Option<StoredPullRequestJob>, PullRequestJobStoreError> {
        self.mark_terminal(
            delivery_id,
            if finding_count == 0 {
                PullRequestJobStatus::Succeeded
            } else {
                PullRequestJobStatus::Findings
            },
            Some(finding_count),
            None,
        )
    }

    pub fn mark_failed(
        &mut self,
        delivery_id: &str,
        error: String,
    ) -> Result<Option<StoredPullRequestJob>, PullRequestJobStoreError> {
        self.mark_terminal(delivery_id, PullRequestJobStatus::Failed, None, Some(error))
    }

    /// The scanner/review finished, but GitHub did not accept its terminal
    /// check update. Keep the job non-terminal for crash-safe rescheduling.
    pub fn mark_retry_pending(
        &mut self,
        delivery_id: &str,
        error: String,
    ) -> Result<Option<StoredPullRequestJob>, PullRequestJobStoreError> {
        self.ensure_parent_synced()?;
        if self
            .registry
            .jobs
            .get(delivery_id)
            .is_none_or(|job| job.status != PullRequestJobStatus::Running)
        {
            return Ok(None);
        }
        let now_unix_ms = unix_time_millis();
        self.transaction(|registry| {
            let job = registry
                .jobs
                .get_mut(delivery_id)
                .expect("running job was checked before transaction");
            job.status = PullRequestJobStatus::RetryPending;
            job.terminal_error = Some(error);
            job.lifecycle_retry_attempts = job.lifecycle_retry_attempts.saturating_add(1);
            job.retry_not_before_unix_ms = Some(retry_not_before_unix_ms(
                now_unix_ms,
                job.lifecycle_retry_attempts,
            ));
            Some(job.clone())
        })
    }

    pub fn mark_cancellation_pending(
        &mut self,
        delivery_id: &str,
        reason: String,
    ) -> Result<Option<StoredPullRequestJob>, PullRequestJobStoreError> {
        self.ensure_parent_synced()?;
        let Some(existing) = self.registry.jobs.get(delivery_id) else {
            return Ok(None);
        };
        if existing.status == PullRequestJobStatus::CancellationPending {
            return Ok(Some(existing.clone()));
        }
        if existing.status.is_terminal() {
            return Ok(None);
        }
        self.transaction(|registry| {
            let job = registry
                .jobs
                .get_mut(delivery_id)
                .expect("non-terminal job was checked before transaction");
            job.status = PullRequestJobStatus::CancellationPending;
            job.terminal_error = Some(reason);
            job.retry_not_before_unix_ms = None;
            job.lifecycle_retry_attempts = 0;
            Some(job.clone())
        })
    }
    /// Persist a bounded backoff after a transient cancellation lookup or
    /// update failure, leaving the job visible for the lifecycle driver.
    pub fn defer_cancellation_retry(
        &mut self,
        delivery_id: &str,
        error: String,
    ) -> Result<Option<StoredPullRequestJob>, PullRequestJobStoreError> {
        self.ensure_parent_synced()?;
        if self
            .registry
            .jobs
            .get(delivery_id)
            .is_none_or(|job| job.status != PullRequestJobStatus::CancellationPending)
        {
            return Ok(None);
        }
        let now_unix_ms = unix_time_millis();
        self.transaction(|registry| {
            let job = registry
                .jobs
                .get_mut(delivery_id)
                .expect("cancellation-pending job was checked before transaction");
            job.terminal_error = Some(error);
            job.lifecycle_retry_attempts = job.lifecycle_retry_attempts.saturating_add(1);
            job.retry_not_before_unix_ms = Some(retry_not_before_unix_ms(
                now_unix_ms,
                job.lifecycle_retry_attempts,
            ));
            Some(job.clone())
        })
    }

    /// This transition is deliberately separate from `mark_cancellation_pending`:
    /// callers invoke it only after GitHub accepted the cancelled check-run
    /// update, so a failed external update remains retryable after restart.
    pub fn mark_superseded(
        &mut self,
        delivery_id: &str,
    ) -> Result<Option<StoredPullRequestJob>, PullRequestJobStoreError> {
        self.ensure_parent_synced()?;
        if self
            .registry
            .jobs
            .get(delivery_id)
            .is_none_or(|job| job.status != PullRequestJobStatus::CancellationPending)
        {
            return Ok(None);
        }
        self.transaction(|registry| {
            let job = registry
                .jobs
                .get_mut(delivery_id)
                .expect("cancellation-pending job was checked before transaction");
            job.status = PullRequestJobStatus::Superseded;
            let job = job.clone();
            prune_terminal_jobs(registry);
            Some(job)
        })
    }

    fn mark_terminal(
        &mut self,
        delivery_id: &str,
        status: PullRequestJobStatus,
        finding_count: Option<usize>,
        terminal_error: Option<String>,
    ) -> Result<Option<StoredPullRequestJob>, PullRequestJobStoreError> {
        debug_assert!(status.is_terminal());
        self.ensure_parent_synced()?;
        if self
            .registry
            .jobs
            .get(delivery_id)
            .is_none_or(|job| job.status != PullRequestJobStatus::Running)
        {
            return Ok(None);
        }
        self.transaction(|registry| {
            let job = registry
                .jobs
                .get_mut(delivery_id)
                .expect("running job was checked before transaction");
            job.status = status;
            job.finding_count = finding_count;
            job.terminal_error = terminal_error;
            let job = job.clone();
            prune_terminal_jobs(registry);
            Some(job)
        })
    }

    fn transaction<T>(
        &mut self,
        update: impl FnOnce(&mut PullRequestJobRegistry) -> T,
    ) -> Result<T, PullRequestJobStoreError> {
        self.ensure_parent_synced()?;
        let mut next = self.registry.clone();
        let result = update(&mut next);
        self.persist_registry(&next)?;
        self.registry = next;
        Ok(result)
    }

    fn ensure_parent_synced(&mut self) -> Result<(), PullRequestJobStoreError> {
        if !self.directory_sync_pending {
            return Ok(());
        }
        let parent = self.path.parent().ok_or_else(|| {
            PullRequestJobStoreError::InvalidPath("path has no parent".to_string())
        })?;
        #[cfg(test)]
        if std::mem::take(&mut self.fail_next_parent_sync) {
            return Err(PullRequestJobStoreError::Io(std::io::Error::other(
                "injected parent directory sync failure",
            )));
        }
        sync_parent_directory(parent)?;
        self.directory_sync_pending = false;
        Ok(())
    }

    fn persist_registry(
        &mut self,
        registry: &PullRequestJobRegistry,
    ) -> Result<(), PullRequestJobStoreError> {
        #[cfg(test)]
        if std::mem::take(&mut self.fail_next_save) {
            return Err(PullRequestJobStoreError::Io(std::io::Error::other(
                "injected pull-request job store save failure",
            )));
        }

        let parent = self
            .path
            .parent()
            .ok_or_else(|| PullRequestJobStoreError::InvalidPath("path has no parent".to_string()))?
            .to_path_buf();
        std::fs::create_dir_all(&parent)?; // foxguard: ignore[rs/no-path-traversal]
        let bytes = serde_json::to_vec_pretty(registry)?;
        let prefix = temp_file_prefix(&self.path)?;
        let mut temp = tempfile::Builder::new()
            .prefix(&prefix)
            .tempfile_in(&parent)?; // foxguard: ignore[rs/no-path-traversal]
        temp.write_all(&bytes)?;
        temp.as_file().sync_all()?;
        temp.persist(&self.path)
            .map_err(|error| PullRequestJobStoreError::Io(error.error))?; // foxguard: ignore[rs/no-path-traversal]
        if let Err(error) = self.sync_parent_after_rename(&parent) {
            // The rename is already visible. Adopt the candidate, then quiesce
            // future writes until a retry of the parent sync succeeds.
            self.registry = registry.clone();
            self.directory_sync_pending = true;
            return Err(PullRequestJobStoreError::PostRenameDirectorySync(Box::new(
                error,
            )));
        }
        Ok(())
    }

    fn sync_parent_after_rename(&mut self, parent: &Path) -> Result<(), PullRequestJobStoreError> {
        #[cfg(test)]
        if std::mem::take(&mut self.fail_next_post_rename_sync) {
            return Err(PullRequestJobStoreError::Io(std::io::Error::other(
                "injected post-rename directory sync failure",
            )));
        }
        sync_parent_directory(parent)
    }

    #[cfg(test)]
    fn fail_next_save(&mut self) {
        self.fail_next_save = true;
    }

    #[cfg(test)]
    fn fail_next_post_rename_sync(&mut self) {
        self.fail_next_post_rename_sync = true;
    }

    #[cfg(test)]
    fn fail_next_parent_sync(&mut self) {
        self.fail_next_parent_sync = true;
    }
}

#[derive(Debug, Clone)]
pub struct PullRequestJobInput {
    pub delivery_id: String,
    pub action: String,
    pub installation_id: u64,
    pub repository: String,
    pub pull_request: u64,
    pub head_sha: String,
    pub clone_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PullRequestJobAdmission {
    Accepted {
        job: Box<StoredPullRequestJob>,
        cancellation_pending: Vec<StoredPullRequestJob>,
    },
    DuplicateDelivery,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckRunAttachment {
    Attached(StoredPullRequestJob),
    CancellationPending(StoredPullRequestJob),
    IgnoredTerminal,
    Missing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullRequestJobRecovery {
    pub queued: Vec<StoredPullRequestJob>,
    pub cancellation_pending: Vec<StoredPullRequestJob>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredPullRequestJob {
    pub delivery_id: String,
    pub action: String,
    pub installation_id: u64,
    pub repository: String,
    pub pull_request: u64,
    pub head_sha: String,
    pub clone_url: String,
    pub status: PullRequestJobStatus,
    pub attempts: u32,
    pub check_run_id: Option<u64>,
    #[serde(default)]
    pub check_run_creation: CheckRunCreationState,
    pub finding_count: Option<usize>,
    pub terminal_error: Option<String>,
    #[serde(default)]
    pub retry_not_before_unix_ms: Option<u64>,
    #[serde(default)]
    pub lifecycle_retry_attempts: u32,
    sequence: u64,
}

impl StoredPullRequestJob {
    pub fn retry_is_due(&self, now_unix_ms: u64) -> bool {
        self.retry_not_before_unix_ms
            .is_none_or(|not_before| not_before <= now_unix_ms)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PullRequestJobStatus {
    Queued,
    Running,
    /// A terminal check-run PATCH failed. This remains non-terminal and is
    /// rescheduled after restart rather than being locally finalized first.
    RetryPending,
    CancellationPending,
    Succeeded,
    Findings,
    Failed,
    Superseded,
}

impl PullRequestJobStatus {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Findings | Self::Failed | Self::Superseded
        )
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckRunCreationState {
    #[default]
    NotStarted,
    Creating,
    Attached,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PullRequestJobRegistry {
    schema_version: u32,
    next_sequence: u64,
    jobs: BTreeMap<String, StoredPullRequestJob>,
}

impl Default for PullRequestJobRegistry {
    fn default() -> Self {
        Self {
            schema_version: STORE_SCHEMA_VERSION,
            next_sequence: 1,
            jobs: BTreeMap::new(),
        }
    }
}

fn jobs_with_status(
    registry: &PullRequestJobRegistry,
    status: PullRequestJobStatus,
) -> Vec<StoredPullRequestJob> {
    let mut jobs: Vec<_> = registry
        .jobs
        .values()
        .filter(|job| job.status == status)
        .cloned()
        .collect();
    jobs.sort_by_key(|job| job.sequence);
    jobs
}

fn unix_time_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn retry_not_before_unix_ms(now_unix_ms: u64, retry_attempts: u32) -> u64 {
    let exponent = retry_attempts.saturating_sub(1).min(6);
    let delay = RETRY_BACKOFF_BASE_MILLIS
        .saturating_mul(1_u64 << exponent)
        .min(RETRY_BACKOFF_MAX_MILLIS);
    now_unix_ms.saturating_add(delay)
}

fn prune_terminal_jobs(registry: &mut PullRequestJobRegistry) {
    let mut terminal_jobs: Vec<_> = registry
        .jobs
        .values()
        .filter(|job| job.status.is_terminal())
        .map(|job| (job.sequence, job.delivery_id.clone()))
        .collect();
    terminal_jobs.sort_unstable();
    let overflow = terminal_jobs.len().saturating_sub(RECENT_DELIVERY_CAPACITY);
    for (_, delivery_id) in terminal_jobs.into_iter().take(overflow) {
        registry.jobs.remove(&delivery_id);
    }
}

fn temp_file_prefix(path: &Path) -> Result<String, PullRequestJobStoreError> {
    let file_name = path.file_name().ok_or_else(|| {
        PullRequestJobStoreError::InvalidPath("path must include a file name".to_string())
    })?;
    Ok(format!(".{}.tmp.", file_name.to_string_lossy()))
}

fn recover_stray_temp_file(path: &Path) -> Result<(), PullRequestJobStoreError> {
    if path.exists() {
        // A primary file is authoritative; stale temp files are ignored rather
        // than removed so a concurrent writer can never lose its candidate.
        return Ok(());
    }
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    if !parent.exists() {
        return Ok(());
    }
    let prefix = temp_file_prefix(path)?;
    let mut candidates = Vec::new();
    for entry in std::fs::read_dir(parent)? {
        let entry = entry?;
        let name = entry.file_name();
        if !name.to_string_lossy().starts_with(&prefix) {
            continue;
        }
        let metadata = entry.metadata()?;
        if !metadata.is_file() {
            continue;
        }
        candidates.push((
            metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            entry.path(),
        ));
    }
    candidates.sort_by(|left, right| right.0.cmp(&left.0));
    for (_, candidate) in candidates {
        let Ok(bytes) = std::fs::read(&candidate) else {
            continue;
        };
        if serde_json::from_slice::<PullRequestJobRegistry>(&bytes).is_err() {
            continue;
        }
        std::fs::rename(&candidate, path)?; // foxguard: ignore[rs/no-path-traversal]
        sync_parent_directory(parent)?;
        break;
    }
    Ok(())
}

fn sync_parent_directory(parent: &Path) -> Result<(), PullRequestJobStoreError> {
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn validate_operator_path(path: &Path) -> Result<(), PullRequestJobStoreError> {
    if !path.is_absolute() {
        return Err(PullRequestJobStoreError::InvalidPath(
            "FOXGUARD_PULL_REQUEST_JOBS_PATH must be absolute".to_string(),
        ));
    }
    validate_store_path(path)
}

fn validate_store_path(path: &Path) -> Result<(), PullRequestJobStoreError> {
    if path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::CurDir | Component::Prefix(_)
        )
    }) {
        return Err(PullRequestJobStoreError::InvalidPath(
            "path must not contain traversal components".to_string(),
        ));
    }
    if path.file_name().is_none() {
        return Err(PullRequestJobStoreError::InvalidPath(
            "path must include a file name".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store_path() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir should be created");
        let path = dir.path().join("pull-request-jobs.json");
        (dir, path)
    }

    fn job(delivery_id: &str, head_sha: &str) -> PullRequestJobInput {
        PullRequestJobInput {
            delivery_id: delivery_id.to_string(),
            action: "synchronize".to_string(),
            installation_id: 42,
            repository: "octo-org/app".to_string(),
            pull_request: 7,
            head_sha: head_sha.to_string(),
            clone_url: "https://github.com/octo-org/app.git".to_string(),
        }
    }

    fn accepted_job(
        store: &mut PullRequestJobStore,
        delivery_id: &str,
        head_sha: &str,
    ) -> StoredPullRequestJob {
        let PullRequestJobAdmission::Accepted { job, .. } = store
            .accept(job(delivery_id, head_sha))
            .expect("job should persist")
        else {
            panic!("new delivery should be accepted");
        };
        *job
    }

    #[test]
    fn restart_recovers_running_job_as_queued() {
        let (_dir, path) = store_path();
        let mut store = PullRequestJobStore::open(path.clone()).expect("store should open");
        let job = accepted_job(&mut store, "delivery-1", "head-1");
        store
            .mark_running(&job.delivery_id)
            .expect("job should become running");
        drop(store);

        let mut restarted = PullRequestJobStore::open(path).expect("store should reopen");
        let recovered = restarted
            .recover_non_terminal()
            .expect("recovery should persist");
        assert_eq!(recovered.queued.len(), 1);
        assert_eq!(recovered.queued[0].delivery_id, "delivery-1");
        assert_eq!(recovered.queued[0].status, PullRequestJobStatus::Queued);
        assert_eq!(recovered.queued[0].attempts, 1);
    }

    #[test]
    fn failed_save_leaves_delivery_retryable_and_durable() {
        let (_dir, path) = store_path();
        let mut store = PullRequestJobStore::open(path.clone()).expect("store should open");
        store.fail_next_save();
        assert!(store.accept(job("delivery-1", "head-1")).is_err());
        assert!(store.queued_jobs().is_empty());
        drop(store);

        let mut restarted = PullRequestJobStore::open(path.clone()).expect("store should reopen");
        assert!(matches!(
            restarted
                .accept(job("delivery-1", "head-1"))
                .expect("retry should be admitted"),
            PullRequestJobAdmission::Accepted { .. }
        ));
        drop(restarted);

        let durable = PullRequestJobStore::open(path).expect("store should reopen after retry");
        assert_eq!(durable.queued_jobs().len(), 1);
    }

    #[test]
    fn post_rename_sync_failure_adopts_the_visible_candidate_before_retrying() {
        let (_dir, path) = store_path();
        let mut store = PullRequestJobStore::open(path.clone()).expect("store should open");
        store.fail_next_post_rename_sync();
        let error = store
            .accept(job("delivery-1", "head-1"))
            .expect_err("the caller must learn that the parent directory sync needs retrying");
        assert!(error.state_transition_applied());
        assert_eq!(
            store.queued_jobs().len(),
            1,
            "the successful rename must become the in-memory source of truth"
        );
        assert!(matches!(
            store
                .accept(job("delivery-1", "head-1"))
                .expect("a retry should see the already-renamed delivery"),
            PullRequestJobAdmission::DuplicateDelivery
        ));
        let mut later_job = job("delivery-2", "head-2");
        later_job.pull_request = 8;
        assert!(matches!(
            store
                .accept(later_job)
                .expect("a later write should sync first and preserve the candidate"),
            PullRequestJobAdmission::Accepted { .. }
        ));
        drop(store);

        let restarted = PullRequestJobStore::open(path).expect("store should reopen");
        let deliveries: Vec<_> = restarted
            .queued_jobs()
            .into_iter()
            .map(|job| job.delivery_id)
            .collect();
        assert_eq!(deliveries, ["delivery-1", "delivery-2"]);
    }

    #[test]
    fn failed_transition_does_not_mutate_in_memory_job_state() {
        let (_dir, path) = store_path();
        let mut store = PullRequestJobStore::open(path).expect("store should open");
        let job = accepted_job(&mut store, "delivery-1", "head-1");
        store.fail_next_save();
        let error = store
            .mark_running(&job.delivery_id)
            .expect_err("pre-write failure must be reported");
        assert!(!error.state_transition_applied());
        assert_eq!(store.queued_jobs()[0].status, PullRequestJobStatus::Queued);
        assert!(store
            .mark_running(&job.delivery_id)
            .expect("retry should persist")
            .is_some());
    }

    #[test]
    fn post_rename_failure_preserves_applied_running_and_requeue_transitions() {
        let (_dir, path) = store_path();
        let mut store = PullRequestJobStore::open(path).expect("store should open");
        let job = accepted_job(&mut store, "delivery-1", "head-1");

        store.fail_next_post_rename_sync();
        let error = store
            .mark_running(&job.delivery_id)
            .expect_err("post-rename sync failure should be surfaced");
        assert!(error.state_transition_applied());
        assert_eq!(
            store
                .job(&job.delivery_id)
                .expect("applied running job should remain visible")
                .status,
            PullRequestJobStatus::Running
        );

        store
            .mark_retry_pending(&job.delivery_id, "terminal check update failed".to_string())
            .expect("the next transition should retry the parent sync");
        store.fail_next_post_rename_sync();
        let error = store
            .requeue_due_retry_pending(u64::MAX)
            .expect_err("post-rename sync failure should be surfaced");
        assert!(error.state_transition_applied());
        assert_eq!(
            store
                .job(&job.delivery_id)
                .expect("applied requeue should remain visible")
                .status,
            PullRequestJobStatus::Queued
        );
    }

    #[test]
    fn applied_running_survives_repeated_parent_sync_failure_until_requeued() {
        let (_dir, path) = store_path();
        let mut store = PullRequestJobStore::open(path).expect("store should open");
        let job = accepted_job(&mut store, "delivery-1", "head-1");

        store.fail_next_post_rename_sync();
        let error = store
            .mark_running(&job.delivery_id)
            .expect_err("the running transition should report the post-rename sync failure");
        assert!(error.state_transition_applied());
        store.fail_next_parent_sync();
        assert!(
            store
                .mark_retry_pending(&job.delivery_id, "terminal update failed".to_string())
                .is_err(),
            "a second parent sync failure must leave the durable running state intact"
        );
        assert_eq!(
            store
                .job(&job.delivery_id)
                .expect("applied running job should remain visible")
                .status,
            PullRequestJobStatus::Running
        );

        let recovered = store
            .requeue_abandoned_running(std::slice::from_ref(&job.delivery_id))
            .expect("a later parent sync should requeue the abandoned running job");
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].status, PullRequestJobStatus::Queued);
    }

    #[test]
    fn newer_head_waits_for_external_cancellation_before_terminalizing() {
        let (_dir, path) = store_path();
        let mut store = PullRequestJobStore::open(path).expect("store should open");
        let first = accepted_job(&mut store, "delivery-1", "head-1");
        assert!(matches!(
            store
                .attach_check_run_id(&first.delivery_id, 91)
                .expect("attachment should persist"),
            CheckRunAttachment::Attached(_)
        ));
        let PullRequestJobAdmission::Accepted {
            cancellation_pending,
            ..
        } = store
            .accept(job("delivery-2", "head-2"))
            .expect("newer delivery should persist")
        else {
            panic!("newer delivery should be accepted");
        };
        assert_eq!(cancellation_pending.len(), 1);
        assert_eq!(
            cancellation_pending[0].status,
            PullRequestJobStatus::CancellationPending
        );
        assert_eq!(cancellation_pending[0].check_run_id, Some(91));
        assert!(store
            .mark_superseded(&first.delivery_id)
            .expect("terminal cancellation should persist")
            .is_some());
        assert!(store.cancellation_pending_jobs().is_empty());
    }

    #[test]
    fn cancellation_pending_check_survives_restart_for_reconciliation() {
        let (_dir, path) = store_path();
        let mut store = PullRequestJobStore::open(path.clone()).expect("store should open");
        let first = accepted_job(&mut store, "delivery-1", "head-1");
        store
            .attach_check_run_id(&first.delivery_id, 91)
            .expect("attachment should persist");
        let _ = accepted_job(&mut store, "delivery-2", "head-2");
        drop(store);

        let mut restarted = PullRequestJobStore::open(path).expect("store should reopen");
        let recovered = restarted
            .recover_non_terminal()
            .expect("recovery should persist");
        assert_eq!(recovered.cancellation_pending.len(), 1);
        assert_eq!(recovered.cancellation_pending[0].delivery_id, "delivery-1");
        assert_eq!(recovered.cancellation_pending[0].check_run_id, Some(91));
    }

    #[test]
    fn late_check_attachment_after_supersession_requests_cancellation() {
        let (_dir, path) = store_path();
        let mut store = PullRequestJobStore::open(path).expect("store should open");
        let first = accepted_job(&mut store, "delivery-1", "head-1");
        let _ = accepted_job(&mut store, "delivery-2", "head-2");
        let attachment = store
            .attach_check_run_id(&first.delivery_id, 91)
            .expect("late attachment should persist");
        let CheckRunAttachment::CancellationPending(job) = attachment else {
            panic!("late attachment must be cancelled");
        };
        assert_eq!(job.check_run_id, Some(91));
        assert_eq!(job.status, PullRequestJobStatus::CancellationPending);
    }

    #[test]
    fn recovers_valid_stray_temp_file_when_primary_is_missing() {
        let (_dir, path) = store_path();
        let prefix = temp_file_prefix(&path).expect("prefix should build");
        let candidate = path
            .parent()
            .expect("parent exists")
            .join(format!("{prefix}recovery"));
        std::fs::write(
            &candidate,
            serde_json::to_vec(&PullRequestJobRegistry::default()).expect("registry serializes"),
        )
        .expect("stray temp should write");
        let _store = PullRequestJobStore::open(path.clone()).expect("store should recover temp");
        assert!(path.exists());
        assert!(!candidate.exists());
    }

    #[test]
    fn rejects_traversal_store_path() {
        assert!(PullRequestJobStore::open(PathBuf::from("../jobs.json")).is_err());
    }
}
