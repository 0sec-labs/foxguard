//! Typed description of what a Foxguard scan should analyze.
//!
//! Frontends should resolve their input into a `ScanPlan` before invoking the
//! scanner. This keeps target selection and path semantics out of individual
//! callers (CLI, GitHub App, MCP, and future workers).

use crate::engine::PathExcludeMatcher;
use crate::git::{changed_files, ChangeSelection};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanTargetRequest {
    FullTree,
    GitChanges(ChangeSelection),
    ChangedFilesList(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanTargets {
    FullTree,
    Paths(Vec<PathBuf>),
}

/// A resolved, frontend-independent scan plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanPlan {
    pub root: PathBuf,
    pub targets: ScanTargets,
    pub excludes: Vec<String>,
    pub max_file_size: u64,
}

impl ScanPlan {
    pub fn resolve(
        root: impl Into<PathBuf>,
        request: ScanTargetRequest,
        excludes: Vec<String>,
        max_file_size: u64,
    ) -> Result<Self, String> {
        let root = root.into();
        let targets = match request {
            ScanTargetRequest::FullTree => ScanTargets::FullTree,
            ScanTargetRequest::GitChanges(selection) => ScanTargets::Paths(
                changed_files(&root, selection)
                    .map_err(|error| format!("failed to resolve changed files: {error}"))?,
            ),
            ScanTargetRequest::ChangedFilesList(list) => {
                ScanTargets::Paths(resolve_changed_files_list(&root, &list)?)
            }
        };

        // Validate globs while constructing the plan, before any scanner work.
        PathExcludeMatcher::new(&excludes)?;
        Ok(Self {
            root,
            targets,
            excludes,
            max_file_size,
        })
    }

    pub fn exclude_matcher(&self) -> Result<PathExcludeMatcher, String> {
        PathExcludeMatcher::new(&self.excludes)
    }

    pub fn paths(&self) -> Option<&[PathBuf]> {
        match &self.targets {
            ScanTargets::FullTree => None,
            ScanTargets::Paths(paths) => Some(paths),
        }
    }
}

fn resolve_changed_files_list(root: &Path, list_file: &Path) -> Result<Vec<PathBuf>, String> {
    let contents = std::fs::read_to_string(list_file).map_err(|error| {
        format!(
            "failed to read changed-files list '{}': {error}",
            list_file.display()
        )
    })?;

    let mut files = Vec::new();
    for line in contents.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let candidate = root.join(line);
        // Deleted paths in a PR are expected; only present files are targets.
        if candidate.is_file() {
            files.push(candidate);
        }
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_tree_plan_has_no_explicit_paths() {
        let plan = ScanPlan::resolve("repo", ScanTargetRequest::FullTree, vec![], 42).unwrap();
        assert_eq!(plan.root, PathBuf::from("repo"));
        assert_eq!(plan.paths(), None);
        assert_eq!(plan.max_file_size, 42);
    }

    #[test]
    fn changed_file_list_ignores_comments_blanks_and_missing_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/lib.rs"), "fn main() {}").unwrap();
        let list = dir.path().join("changed.txt");
        std::fs::write(&list, "\n# pull request files\nsrc/lib.rs\ndeleted.rs\n").unwrap();

        let plan = ScanPlan::resolve(
            dir.path(),
            ScanTargetRequest::ChangedFilesList(list),
            vec!["vendor/**".into()],
            1_048_576,
        )
        .unwrap();

        assert_eq!(plan.paths(), Some(&[dir.path().join("src/lib.rs")][..]));
        assert_eq!(plan.excludes, vec!["vendor/**"]);
    }

    #[test]
    fn invalid_exclude_is_rejected_during_planning() {
        let error =
            ScanPlan::resolve(".", ScanTargetRequest::FullTree, vec!["[".into()], 1).unwrap_err();
        assert!(error.contains("Invalid exclude glob"), "{error}");
    }
}
