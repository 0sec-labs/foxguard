//! Persistent installation metadata for the GitHub App receiver.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_STORE_DIR: &str = ".foxguard-github-app";
const DEFAULT_STORE_FILE: &str = "installations.json";
const STORE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug)]
pub enum InstallationStoreError {
    InvalidPath(String),
    Io(std::io::Error),
    Json(serde_json::Error),
    Time(std::time::SystemTimeError),
}

impl fmt::Display for InstallationStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath(error) => write!(f, "invalid installation store path: {error}"),
            Self::Io(error) => write!(f, "installation store I/O failed: {error}"),
            Self::Json(error) => write!(f, "installation store JSON failed: {error}"),
            Self::Time(error) => write!(f, "system time is before Unix epoch: {error}"),
        }
    }
}

impl std::error::Error for InstallationStoreError {}

impl From<std::io::Error> for InstallationStoreError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for InstallationStoreError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl From<std::time::SystemTimeError> for InstallationStoreError {
    fn from(error: std::time::SystemTimeError) -> Self {
        Self::Time(error)
    }
}

#[derive(Debug)]
pub struct InstallationStore {
    path: PathBuf,
    registry: InstallationRegistry,
    revision: u64,
}

impl InstallationStore {
    pub fn from_env_or_default() -> Result<Self, InstallationStoreError> {
        let path = match std::env::var("FOXGUARD_INSTALLATIONS_PATH") {
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

    pub fn open(path: PathBuf) -> Result<Self, InstallationStoreError> {
        validate_store_path(&path)?;
        let registry = if path.exists() {
            let bytes = std::fs::read(&path)?; // foxguard: ignore[rs/no-path-traversal]
            serde_json::from_slice(&bytes)?
        } else {
            InstallationRegistry::default()
        };
        Ok(Self {
            path,
            registry,
            revision: 0,
        })
    }

    pub fn upsert(
        &mut self,
        input: InstallationMetadataInput,
    ) -> Result<(), InstallationStoreError> {
        let updated_at_unix = unix_now()?;
        let installation = self
            .registry
            .installations
            .entry(input.installation_id.to_string())
            .or_insert_with(|| StoredInstallation::new_placeholder(input.installation_id));
        installation.apply_metadata(input, updated_at_unix);
        self.save()
    }

    pub fn remove(&mut self, installation_id: u64) -> Result<bool, InstallationStoreError> {
        let removed = self
            .registry
            .installations
            .remove(&installation_id.to_string())
            .is_some();
        self.save()?;
        Ok(removed)
    }

    pub fn add_repositories(
        &mut self,
        installation_id: u64,
        repositories: impl IntoIterator<Item = String>,
    ) -> Result<(), InstallationStoreError> {
        let updated_at_unix = unix_now()?;
        let installation = self
            .registry
            .installations
            .entry(installation_id.to_string())
            .or_insert_with(|| StoredInstallation::new_placeholder(installation_id));
        installation.repositories.extend(repositories);
        installation.updated_at_unix = updated_at_unix;
        self.save()
    }

    pub fn remove_repositories(
        &mut self,
        installation_id: u64,
        repositories: impl IntoIterator<Item = String>,
    ) -> Result<(), InstallationStoreError> {
        let updated_at_unix = unix_now()?;
        let installation = self
            .registry
            .installations
            .entry(installation_id.to_string())
            .or_insert_with(|| StoredInstallation::new_placeholder(installation_id));
        for repository in repositories {
            installation.repositories.remove(&repository);
        }
        installation.updated_at_unix = updated_at_unix;
        self.save()
    }

    /// The on-disk path this store persists to. Used by the webhook
    /// receiver to name the configured location when a persist fails,
    /// so an operator can see *which* path (e.g. a read-only
    /// `/var/lib/foxguard`) could not be written.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Captured before fetching GitHub state, so a refresh cannot overwrite
    /// installation webhooks that arrived while the API request was in flight.
    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// Apply a complete, authoritative installation list. Repository names are
    /// retained unless the caller supplies a repository snapshot explicitly.
    pub fn reconcile(
        &mut self,
        expected_revision: u64,
        inputs: Vec<InstallationMetadataInput>,
    ) -> Result<bool, InstallationStoreError> {
        if self.revision != expected_revision {
            return Ok(false);
        }
        let now = unix_now()?;
        let mut refreshed = BTreeMap::new();
        for input in inputs {
            let key = input.installation_id.to_string();
            let mut installation = self
                .registry
                .installations
                .get(&key)
                .cloned()
                .unwrap_or_else(|| StoredInstallation::new_placeholder(input.installation_id));
            installation.apply_metadata(input, now);
            refreshed.insert(key, installation);
        }
        let previous = std::mem::replace(&mut self.registry.installations, refreshed);
        if let Err(error) = self.save() {
            self.registry.installations = previous;
            return Err(error);
        }
        Ok(true)
    }

    #[cfg(test)]
    fn get(&self, installation_id: u64) -> Option<&StoredInstallation> {
        self.registry
            .installations
            .get(&installation_id.to_string())
    }

    fn save(&mut self) -> Result<(), InstallationStoreError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?; // foxguard: ignore[rs/no-path-traversal]
        }
        let mut temp_path = self.path.clone();
        temp_path.set_extension(format!(
            "{}.tmp.{}",
            self.path
                .extension()
                .and_then(|extension| extension.to_str())
                .unwrap_or("json"),
            std::process::id()
        ));
        let bytes = serde_json::to_vec_pretty(&self.registry)?;
        std::fs::write(&temp_path, bytes)?; // foxguard: ignore[rs/no-path-traversal]
        std::fs::rename(&temp_path, &self.path)?; // foxguard: ignore[rs/no-path-traversal]
        self.revision = self.revision.wrapping_add(1);
        Ok(())
    }
}

#[derive(Debug)]
pub struct InstallationMetadataInput {
    pub installation_id: u64,
    pub account_login: Option<String>,
    pub account_id: Option<u64>,
    pub account_type: Option<String>,
    pub repository_selection: Option<String>,
    /// None preserves observed repositories; Some replaces an explicit snapshot.
    pub repositories: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct InstallationRegistry {
    schema_version: u32,
    installations: BTreeMap<String, StoredInstallation>,
}

impl Default for InstallationRegistry {
    fn default() -> Self {
        Self {
            schema_version: STORE_SCHEMA_VERSION,
            installations: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredInstallation {
    installation_id: u64,
    account_login: Option<String>,
    account_id: Option<u64>,
    account_type: Option<String>,
    repository_selection: Option<String>,
    repositories: BTreeSet<String>,
    updated_at_unix: u64,
}

impl StoredInstallation {
    fn apply_metadata(&mut self, input: InstallationMetadataInput, now: u64) {
        if let Some(value) = input.account_login {
            self.account_login = Some(value);
        }
        if let Some(value) = input.account_id {
            self.account_id = Some(value);
        }
        if let Some(value) = input.account_type {
            self.account_type = Some(value);
        }
        if let Some(value) = input.repository_selection {
            self.repository_selection = Some(value);
        }
        if let Some(repositories) = input.repositories {
            self.repositories = repositories.into_iter().collect();
        }
        self.updated_at_unix = now;
    }

    fn new_placeholder(installation_id: u64) -> Self {
        Self {
            installation_id,
            account_login: None,
            account_id: None,
            account_type: None,
            repository_selection: None,
            repositories: BTreeSet::new(),
            updated_at_unix: 0,
        }
    }
}

fn validate_operator_path(path: &Path) -> Result<(), InstallationStoreError> {
    if !path.is_absolute() {
        return Err(InstallationStoreError::InvalidPath(
            "FOXGUARD_INSTALLATIONS_PATH must be absolute".to_string(),
        ));
    }
    validate_store_path(path)
}

fn validate_store_path(path: &Path) -> Result<(), InstallationStoreError> {
    if path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::CurDir | Component::Prefix(_)
        )
    }) {
        return Err(InstallationStoreError::InvalidPath(
            "path must not contain traversal components".to_string(),
        ));
    }
    if path.file_name().is_none() {
        return Err(InstallationStoreError::InvalidPath(
            "path must include a file name".to_string(),
        ));
    }
    Ok(())
}

fn unix_now() -> Result<u64, InstallationStoreError> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store_path() -> (tempfile::TempDir, PathBuf) {
        let dir = match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(error) => panic!("tempdir should be created: {error}"),
        };
        let path = dir.path().join("installations.json");
        (dir, path)
    }

    #[test]
    fn upsert_persists_installation_metadata() {
        let (_dir, path) = store_path();
        let mut store = match InstallationStore::open(path.clone()) {
            Ok(store) => store,
            Err(error) => panic!("store should open: {error}"),
        };

        if let Err(error) = store.upsert(InstallationMetadataInput {
            installation_id: 42,
            account_login: Some("octo-org".to_string()),
            account_id: Some(99),
            account_type: Some("Organization".to_string()),
            repository_selection: Some("selected".to_string()),
            repositories: Some(vec![
                "octo-org/app".to_string(),
                "octo-org/service".to_string(),
            ]),
        }) {
            panic!("upsert should persist: {error}");
        }

        let reloaded = match InstallationStore::open(path) {
            Ok(store) => store,
            Err(error) => panic!("store should reload: {error}"),
        };
        let installation = match reloaded.get(42) {
            Some(installation) => installation,
            None => panic!("installation should exist"),
        };

        assert_eq!(installation.account_login.as_deref(), Some("octo-org"));
        assert!(installation.repositories.contains("octo-org/app"));
        assert!(installation.repositories.contains("octo-org/service"));
    }

    #[test]
    fn repository_delta_events_update_existing_installation() {
        let (_dir, path) = store_path();
        let mut store = match InstallationStore::open(path) {
            Ok(store) => store,
            Err(error) => panic!("store should open: {error}"),
        };

        if let Err(error) = store.add_repositories(
            42,
            ["octo-org/app".to_string(), "octo-org/service".to_string()],
        ) {
            panic!("repositories should be added: {error}");
        }
        if let Err(error) = store.remove_repositories(42, ["octo-org/app".to_string()]) {
            panic!("repositories should be removed: {error}");
        }

        let installation = match store.get(42) {
            Some(installation) => installation,
            None => panic!("installation should exist"),
        };
        assert!(!installation.repositories.contains("octo-org/app"));
        assert!(installation.repositories.contains("octo-org/service"));
    }

    #[test]
    fn delete_removes_installation() {
        let (_dir, path) = store_path();
        let mut store = match InstallationStore::open(path) {
            Ok(store) => store,
            Err(error) => panic!("store should open: {error}"),
        };

        if let Err(error) = store.add_repositories(42, ["octo-org/app".to_string()]) {
            panic!("repository should be added: {error}");
        }
        match store.remove(42) {
            Ok(true) => {}
            Ok(false) => panic!("installation should be removed"),
            Err(error) => panic!("installation removal should persist: {error}"),
        }
        assert!(store.get(42).is_none());
    }

    #[test]
    fn rejects_traversal_paths() {
        assert!(InstallationStore::open(PathBuf::from("../installations.json")).is_err());
    }

    #[test]
    fn save_creates_missing_parent_directories() {
        // Reproduces production root-cause #1: the configured store path
        // (e.g. `/var/lib/foxguard/installations.json`) may live under a
        // directory that does not exist yet. `save()` must create the
        // parent chain rather than failing with `NotFound`.
        let base = std::env::temp_dir().join(format!(
            "foxguard-install-store-{}-{}",
            std::process::id(),
            unix_now().unwrap_or_default()
        ));
        // Two levels of not-yet-existing parents to prove `create_dir_all`
        // (not just a single `create_dir`) is used.
        let path = base.join("nested").join("dir").join("installations.json");
        assert!(!base.exists(), "precondition: base dir must not exist yet");

        let mut store = match InstallationStore::open(path.clone()) {
            Ok(store) => store,
            Err(error) => panic!("store should open even without parent dir: {error}"),
        };
        if let Err(error) = store.upsert(InstallationMetadataInput {
            installation_id: 7,
            account_login: Some("acme".to_string()),
            account_id: Some(1),
            account_type: Some("Organization".to_string()),
            repository_selection: Some("all".to_string()),
            repositories: Some(vec!["acme/api".to_string()]),
        }) {
            let _ = std::fs::remove_dir_all(&base);
            panic!("save() should create missing parent dirs and persist: {error}");
        }

        assert!(path.exists(), "installations.json should have been written");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn round_trip_record_repositories_then_reload() {
        // Task test #2: record an installation + repositories, save, load
        // from the same path, and assert the persisted data matches.
        let (_dir, path) = store_path();
        let mut store = match InstallationStore::open(path.clone()) {
            Ok(store) => store,
            Err(error) => panic!("store should open: {error}"),
        };
        if let Err(error) = store.upsert(InstallationMetadataInput {
            installation_id: 100,
            account_login: Some("octo-org".to_string()),
            account_id: Some(5),
            account_type: Some("Organization".to_string()),
            repository_selection: Some("selected".to_string()),
            repositories: Some(vec!["octo-org/app".to_string()]),
        }) {
            panic!("upsert should persist: {error}");
        }
        if let Err(error) = store.add_repositories(100, ["octo-org/service".to_string()]) {
            panic!("add_repositories should persist: {error}");
        }

        let reloaded = match InstallationStore::open(path) {
            Ok(store) => store,
            Err(error) => panic!("store should reload: {error}"),
        };
        let installation = match reloaded.get(100) {
            Some(installation) => installation,
            None => panic!("installation should survive a save/load round-trip"),
        };
        assert_eq!(installation.installation_id, 100);
        assert_eq!(installation.account_login.as_deref(), Some("octo-org"));
        assert_eq!(installation.account_id, Some(5));
        assert_eq!(installation.account_type.as_deref(), Some("Organization"));
        assert_eq!(
            installation.repository_selection.as_deref(),
            Some("selected")
        );
        assert!(installation.repositories.contains("octo-org/app"));
        assert!(installation.repositories.contains("octo-org/service"));
    }

    fn metadata(id: u64, login: Option<&str>) -> InstallationMetadataInput {
        InstallationMetadataInput {
            installation_id: id,
            account_login: login.map(str::to_owned),
            account_id: None,
            account_type: None,
            repository_selection: None,
            repositories: None,
        }
    }

    #[test]
    fn authoritative_refresh_repairs_placeholders_without_losing_observed_repositories() {
        let (_dir, path) = store_path();
        let mut store = InstallationStore::open(path.clone()).unwrap();
        store
            .add_repositories(42, ["active/project".to_string()])
            .unwrap();
        store.upsert(metadata(99, Some("uninstalled"))).unwrap();
        let revision = store.revision();
        assert!(store
            .reconcile(
                revision,
                vec![
                    metadata(42, Some("active")),
                    metadata(77, Some("previously-missed")),
                ]
            )
            .unwrap());
        let reloaded = InstallationStore::open(path).unwrap();
        assert_eq!(
            reloaded.get(42).unwrap().account_login.as_deref(),
            Some("active")
        );
        assert!(reloaded
            .get(42)
            .unwrap()
            .repositories
            .contains("active/project"));
        assert_eq!(
            reloaded.get(77).unwrap().account_login.as_deref(),
            Some("previously-missed")
        );
        assert!(reloaded.get(99).is_none());
    }

    #[test]
    fn refresh_does_not_overwrite_a_concurrent_installation_webhook() {
        let (_dir, path) = store_path();
        let mut store = InstallationStore::open(path.clone()).unwrap();
        let revision = store.revision();
        store.upsert(metadata(42, Some("new-install"))).unwrap();
        assert!(!store.reconcile(revision, vec![]).unwrap());
        assert!(InstallationStore::open(path).unwrap().get(42).is_some());
    }

    #[test]
    fn omitted_metadata_preserves_state_but_explicit_empty_repository_list_clears_it() {
        let (_dir, path) = store_path();
        let mut store = InstallationStore::open(path.clone()).unwrap();
        let mut initial = metadata(42, Some("active"));
        initial.repositories = Some(vec!["active/project".to_string()]);
        store.upsert(initial).unwrap();
        store.upsert(metadata(42, None)).unwrap();
        let reloaded = InstallationStore::open(path.clone()).unwrap();
        assert_eq!(
            reloaded.get(42).unwrap().account_login.as_deref(),
            Some("active")
        );
        assert!(reloaded
            .get(42)
            .unwrap()
            .repositories
            .contains("active/project"));
        let mut cleared = metadata(42, None);
        cleared.repositories = Some(vec![]);
        store.upsert(cleared).unwrap();
        assert!(InstallationStore::open(path)
            .unwrap()
            .get(42)
            .unwrap()
            .repositories
            .is_empty());
    }

    #[test]
    fn failed_refresh_keeps_previous_registry_in_memory() {
        let (_dir, path) = store_path();
        let mut store = InstallationStore::open(path.clone()).unwrap();
        store.upsert(metadata(42, Some("active"))).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(store.reconcile(store.revision(), vec![]).is_err());
        assert_eq!(
            store.get(42).unwrap().account_login.as_deref(),
            Some("active")
        );
    }
}
