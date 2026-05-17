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
        Ok(Self { path, registry })
    }

    pub fn upsert(
        &mut self,
        input: InstallationMetadataInput,
    ) -> Result<(), InstallationStoreError> {
        let updated_at_unix = unix_now()?;
        let key = input.installation_id.to_string();
        let repositories = input.repositories.into_iter().collect();
        self.registry.installations.insert(
            key,
            StoredInstallation {
                installation_id: input.installation_id,
                account_login: input.account_login,
                account_id: input.account_id,
                account_type: input.account_type,
                repository_selection: input.repository_selection,
                repositories,
                updated_at_unix,
            },
        );
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

    #[cfg(test)]
    fn get(&self, installation_id: u64) -> Option<&StoredInstallation> {
        self.registry
            .installations
            .get(&installation_id.to_string())
    }

    fn save(&self) -> Result<(), InstallationStoreError> {
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
    pub repositories: Vec<String>,
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
            repositories: vec!["octo-org/app".to_string(), "octo-org/service".to_string()],
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
}
