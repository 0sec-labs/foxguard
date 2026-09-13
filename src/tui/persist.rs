use super::state::{BaselineFilter, ReviewFilter, ReviewState, SortMode};
use crate::Severity;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

const STORE_VERSION: u32 = 1;

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub(super) struct FilterSettings {
    pub search_query: String,
    pub min_severity: Option<Severity>,
    pub min_confidence: f32,
    pub review_filter: ReviewFilter,
    pub sort_mode: SortMode,
    pub baseline_filter: BaselineFilter,
}

#[derive(Debug, Default)]
pub(super) struct SessionData {
    pub review_states: HashMap<String, ReviewState>,
    pub filters: BTreeMap<String, FilterSettings>,
}

#[derive(Deserialize)]
struct SessionFile {
    version: u32,
    review_states: HashMap<String, ReviewState>,
    filters: BTreeMap<String, FilterSettings>,
}

#[derive(Serialize)]
struct SessionWrite<'a> {
    version: u32,
    review_states: &'a HashMap<String, ReviewState>,
    filters: &'a BTreeMap<String, FilterSettings>,
}

pub(super) fn state_directory() -> Result<PathBuf, String> {
    fn absolute_env(name: &str) -> Option<PathBuf> {
        std::env::var_os(name)
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
    }
    #[cfg(target_os = "windows")]
    let root = absolute_env("LOCALAPPDATA");
    #[cfg(target_os = "macos")]
    let root = absolute_env("HOME").map(|home| home.join("Library/Application Support"));
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let root = absolute_env("XDG_STATE_HOME")
        .or_else(|| absolute_env("HOME").map(|home| home.join(".local/state")));
    root.map(|root| root.join("foxguard/tui"))
        .ok_or_else(|| "cannot determine an absolute per-user review state directory from HOME/XDG_STATE_HOME/LOCALAPPDATA".into())
}

fn read_optional(path: &Path) -> Result<Option<Vec<u8>>, String> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("cannot read {}: {error}", path.display())),
    }
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn validate(
    review_states: &HashMap<String, ReviewState>,
    filters: &BTreeMap<String, FilterSettings>,
) -> Result<(), String> {
    if review_states
        .keys()
        .any(|key| key.len() != 64 || !key.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return Err("review marks must be keyed by SHA-256 finding fingerprints".into());
    }
    for (name, settings) in filters {
        if name.trim().is_empty() {
            return Err("a saved filter name cannot be empty".into());
        }
        if !settings.min_confidence.is_finite() || !(0.0..=1.0).contains(&settings.min_confidence) {
            return Err(format!("saved filter {name:?} has confidence outside 0..1"));
        }
    }
    Ok(())
}

/// The lock lives beside the JSON, never on the inode replaced by an atomic save.
/// Revision checks under that same lock protect both existing and absent files.
pub(super) struct SessionStore {
    path: PathBuf,
    revision: Option<[u8; 32]>,
    writable: bool,
}

impl SessionStore {
    pub(super) fn new(base: &Path, project: &Path, mode: &str) -> Self {
        let mut hash = Sha256::new();
        hash.update(project.as_os_str().as_encoded_bytes());
        hash.update(b"\0");
        hash.update(mode.as_bytes());
        Self {
            path: base.join(format!("{:x}.json", hash.finalize())),
            revision: None,
            writable: false,
        }
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    fn lock(&self) -> Result<File, String> {
        let parent = self
            .path
            .parent()
            .expect("session path includes a filename");
        fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        options.mode(0o600);
        let lock_path = self.path.with_extension("lock");
        let lock = options
            .open(&lock_path)
            .map_err(|error| format!("cannot open review lock {}: {error}", lock_path.display()))?;
        FileExt::try_lock_exclusive(&lock).map_err(|error| format!("review state is busy or cannot be locked; retry after the other writer finishes: {error}"))?;
        Ok(lock)
    }

    pub(super) fn load(&mut self) -> Result<SessionData, String> {
        self.writable = false;
        let _lock = self.lock()?;
        let Some(bytes) = read_optional(&self.path)? else {
            self.revision = None;
            self.writable = true;
            return Ok(SessionData::default());
        };
        let data: SessionFile = serde_json::from_slice(&bytes)
            .map_err(|error| format!("invalid review state {}: {error}; reload after repairing it, or explicitly back up and reset", self.path.display()))?;
        if data.version != STORE_VERSION {
            return Err(format!(
                "unsupported review state version {} in {}; expected {STORE_VERSION}",
                data.version,
                self.path.display()
            ));
        }
        validate(&data.review_states, &data.filters)?;
        self.revision = Some(digest(&bytes));
        self.writable = true;
        Ok(SessionData {
            review_states: data.review_states,
            filters: data.filters,
        })
    }

    pub(super) fn save(
        &mut self,
        review_states: &HashMap<String, ReviewState>,
        filters: &BTreeMap<String, FilterSettings>,
    ) -> Result<(), String> {
        if !self.writable {
            return Err("review state has not been loaded successfully; reload or explicitly back up and reset before saving".into());
        }
        validate(review_states, filters)?;
        let _lock = self.lock()?;
        let current = read_optional(&self.path)?;
        if current.as_deref().map(digest) != self.revision {
            return Err(format!("review state {} changed in another session; reload before saving (reload discards unsaved local changes)", self.path.display()));
        }
        let bytes = serde_json::to_vec_pretty(&SessionWrite {
            version: STORE_VERSION,
            review_states,
            filters,
        })
        .map_err(|error| format!("cannot serialize review state: {error}"))?;
        let parent = self
            .path
            .parent()
            .expect("session path includes a filename");
        let mut temporary = tempfile::NamedTempFile::new_in(parent)
            .map_err(|error| format!("cannot create review state temporary file: {error}"))?;
        temporary
            .write_all(&bytes)
            .and_then(|()| temporary.as_file().sync_all())
            .map_err(|error| format!("cannot write and sync review state: {error}"))?;
        temporary
            .persist(&self.path)
            .map_err(|error| format!("cannot replace review state: {error}"))?;
        // A directory sync failure must not make our own committed bytes look
        // like a conflicting writer on retry.
        self.revision = Some(digest(&bytes));
        sync_directory(parent).map_err(|error| {
            format!("review file was written, but its directory could not be synced: {error}")
        })?;
        Ok(())
    }

    /// Called only after explicit confirmation. Reserve a unique backup name,
    /// then atomically move the original bytes there without copying or parsing.
    pub(super) fn recover(&mut self) -> Result<Option<PathBuf>, String> {
        let _lock = self.lock()?;
        match fs::symlink_metadata(&self.path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.revision = None;
                self.writable = true;
                return Ok(None);
            }
            Err(error) => return Err(format!("cannot inspect review state for recovery: {error}")),
            Ok(metadata) if !metadata.is_file() => {
                return Err("review state is not a regular file; refusing to reset it".into())
            }
            Ok(_) => {}
        }
        let parent = self
            .path
            .parent()
            .expect("session path includes a filename");
        let prefix = format!(
            "{}.backup-",
            self.path
                .file_name()
                .expect("session filename")
                .to_string_lossy()
        );
        let backup = tempfile::Builder::new()
            .prefix(&prefix)
            .tempfile_in(parent)
            .map_err(|error| format!("cannot reserve review backup: {error}"))?
            .into_temp_path()
            .keep()
            .map_err(|error| format!("cannot keep review backup reservation: {error}"))?;
        if let Err(error) = fs::rename(&self.path, &backup) {
            let _ = fs::remove_file(&backup);
            return Err(format!(
                "cannot move review state to {}: {error}",
                backup.display()
            ));
        }
        self.revision = None;
        self.writable = true;
        sync_directory(parent).map_err(|error| {
            format!(
                "review state preserved at {}, but directory sync failed: {error}",
                backup.display()
            )
        })?;
        Ok(Some(backup))
    }
}

fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn marks(state: ReviewState) -> HashMap<String, ReviewState> {
        HashMap::from([("a".repeat(64), state)])
    }

    #[test]
    fn review_and_named_filters_survive_restart_without_cross_scope_leakage() {
        let directory = tempfile::tempdir().unwrap();
        let project = directory.path().join("project");
        let mut first = SessionStore::new(directory.path(), &project, "scan");
        first.load().unwrap();
        let settings = FilterSettings {
            search_query: "command injection".into(),
            min_severity: Some(Severity::High),
            min_confidence: 0.75,
            review_filter: ReviewFilter::Todo,
            sort_mode: SortMode::ConfidenceDesc,
            baseline_filter: BaselineFilter::Recurring,
        };
        let filters = BTreeMap::from([("follow up".into(), settings)]);
        first.save(&marks(ReviewState::Todo), &filters).unwrap();
        let restored = SessionStore::new(directory.path(), &project, "scan")
            .load()
            .unwrap();
        assert_eq!(restored.review_states, marks(ReviewState::Todo));
        assert_eq!(restored.filters, filters);
        assert!(SessionStore::new(directory.path(), &project, "secrets")
            .load()
            .unwrap()
            .review_states
            .is_empty());
        assert!(
            SessionStore::new(directory.path(), &directory.path().join("other"), "scan")
                .load()
                .unwrap()
                .filters
                .is_empty()
        );
    }

    #[test]
    fn locked_missing_changed_and_deleted_revisions_cannot_be_clobbered() {
        let directory = tempfile::tempdir().unwrap();
        let mut first = SessionStore::new(directory.path(), directory.path(), "scan");
        let mut second = SessionStore::new(directory.path(), directory.path(), "scan");
        first.load().unwrap();
        second.load().unwrap();
        let lock = second.lock().unwrap();
        assert!(first
            .save(&marks(ReviewState::Reviewed), &BTreeMap::new())
            .is_err());
        assert!(!first.path().exists());
        drop(lock);
        first
            .save(&marks(ReviewState::Reviewed), &BTreeMap::new())
            .unwrap();
        assert!(second
            .save(&marks(ReviewState::Todo), &BTreeMap::new())
            .is_err());
        assert_eq!(
            second.load().unwrap().review_states,
            marks(ReviewState::Reviewed)
        );
        first
            .save(&marks(ReviewState::IgnoreCandidate), &BTreeMap::new())
            .unwrap();
        assert!(second
            .save(&marks(ReviewState::Todo), &BTreeMap::new())
            .is_err());
        assert_eq!(
            second.load().unwrap().review_states,
            marks(ReviewState::IgnoreCandidate)
        );
        fs::remove_file(first.path()).unwrap();
        assert!(first
            .save(&marks(ReviewState::Reviewed), &BTreeMap::new())
            .is_err());
        assert!(!first.path().exists());
    }

    #[test]
    fn unreadable_state_requires_explicit_recovery_and_backups_never_overwrite() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = SessionStore::new(directory.path(), directory.path(), "scan");
        let original = b"not JSON, preserve these bytes";
        fs::write(store.path(), original).unwrap();
        assert!(store.load().is_err());
        assert!(store
            .save(&marks(ReviewState::Todo), &BTreeMap::new())
            .is_err());
        assert_eq!(fs::read(store.path()).unwrap(), original);
        let first_backup = store.recover().unwrap().unwrap();
        assert_eq!(fs::read(&first_backup).unwrap(), original);
        let future = br#"{"version":99,"review_states":{},"filters":{}}"#;
        fs::write(store.path(), future).unwrap();
        assert!(store.load().is_err());
        let second_backup = store.recover().unwrap().unwrap();
        assert_ne!(first_backup, second_backup);
        assert_eq!(fs::read(first_backup).unwrap(), original);
        assert_eq!(fs::read(second_backup).unwrap(), future);
        assert!(store.load().unwrap().review_states.is_empty());
        store
            .save(&marks(ReviewState::Reviewed), &BTreeMap::new())
            .unwrap();
    }

    #[test]
    fn invalid_filter_updates_leave_the_previous_session_intact() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = SessionStore::new(directory.path(), directory.path(), "scan");
        store.load().unwrap();
        store
            .save(&marks(ReviewState::Reviewed), &BTreeMap::new())
            .unwrap();
        let previous = fs::read(store.path()).unwrap();
        let invalid = FilterSettings {
            min_confidence: f32::NAN,
            ..FilterSettings::default()
        };
        assert!(store
            .save(
                &marks(ReviewState::Todo),
                &BTreeMap::from([("invalid".into(), invalid)])
            )
            .is_err());
        assert_eq!(fs::read(store.path()).unwrap(), previous);
        assert_eq!(
            store.load().unwrap().review_states,
            marks(ReviewState::Reviewed)
        );
    }
}
