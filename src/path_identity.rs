use std::path::{Component, Path, PathBuf};
use std::process::Command;

/// Resolve the directory that should anchor finding identity.
///
/// Prefer an explicitly configured project root, then the Git repository root,
/// then the scan root. Callers use this as the base for stable baseline and
/// suppression keys while leaving reported finding paths unchanged.
pub fn project_root(scan_path: &Path, configured_root: Option<&Path>) -> PathBuf {
    if let Some(root) = configured_root {
        return resolve_path_for_boundary(root);
    }

    git_repo_root(scan_path).unwrap_or_else(|| resolve_scan_root(scan_path))
}

pub fn resolve_scan_root(scan_path: &Path) -> PathBuf {
    let scan_root = resolve_path_for_boundary(scan_path);
    if scan_root.is_file() {
        scan_root
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    } else {
        scan_root
    }
}

/// Resolve a path for trust-boundary comparisons.
///
/// Existing paths are canonicalized. Missing leaf paths are resolved through
/// the deepest canonical ancestor so config values like a not-yet-created
/// baseline still compare against the correct root.
pub fn resolve_path_for_boundary(path: &Path) -> PathBuf {
    if is_windows_drive_absolute_path(path) {
        return normalize_path(path);
    }

    if let Ok(canonical) = path.canonicalize() {
        return canonical;
    }

    let absolute = absolutize_path(path);
    for ancestor in absolute.ancestors() {
        if let Ok(canonical_ancestor) = ancestor.canonicalize() {
            let suffix = absolute
                .strip_prefix(ancestor)
                .unwrap_or_else(|_| Path::new(""));
            return normalize_path(&canonical_ancestor.join(suffix));
        }
    }

    normalize_path(&absolute)
}

/// Normalize a scanner-emitted finding file path to the project-root-relative
/// identity form. Relative finding paths are interpreted the same way the
/// scanner emitted them: relative to the current process directory.
pub fn finding_path_key(root: &Path, finding_file: &str) -> String {
    let value = normalize_separators(finding_file);
    let path = Path::new(&value);
    let resolved = if path.is_absolute() || is_windows_drive_absolute(&value) {
        resolve_path_for_boundary(path)
    } else {
        resolve_path_for_boundary(&current_dir().join(path))
    };
    root_relative_key(root, &resolved)
}

/// Normalize a persisted path from config or baseline data. Relative persisted
/// paths are already project-root-relative; absolute paths are stripped back to
/// the same identity form when they live under `root`.
pub fn stored_path_key(root: &Path, stored_path: &str) -> String {
    let value = normalize_separators(stored_path);
    let path = Path::new(&value);
    if path.is_absolute() || is_windows_drive_absolute(&value) {
        root_relative_key(root, &resolve_path_for_boundary(path))
    } else {
        slash_path(&normalize_path(path))
    }
}

fn root_relative_key(root: &Path, path: &Path) -> String {
    let root = resolve_path_for_boundary(root);
    let path = resolve_path_for_boundary(path);
    let relative = path.strip_prefix(&root).unwrap_or(path.as_path());
    slash_path(relative)
}

fn git_repo_root(scan_path: &Path) -> Option<PathBuf> {
    let dir = if scan_path.is_dir() {
        scan_path
    } else {
        scan_path.parent().unwrap_or_else(|| Path::new("."))
    };

    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let root = String::from_utf8_lossy(&output.stdout);
    let root = root.trim();
    if root.is_empty() {
        None
    } else {
        Some(resolve_path_for_boundary(Path::new(root)))
    }
}

fn current_dir() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn absolutize_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        current_dir().join(path)
    }
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();

    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    normalized.push(component.as_os_str());
                }
            }
            Component::Normal(part) => normalized.push(part),
        }
    }

    normalized
}

fn normalize_separators(path: &str) -> String {
    path.replace('\\', "/")
}

fn is_windows_drive_absolute_path(path: &Path) -> bool {
    is_windows_drive_absolute(&path.to_string_lossy().replace('\\', "/"))
}

fn is_windows_drive_absolute(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'/'
}

fn slash_path(path: &Path) -> String {
    let normalized = normalize_path(path).to_string_lossy().replace('\\', "/");
    normalized
        .strip_prefix("./")
        .unwrap_or(normalized.as_str())
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn stored_relative_paths_use_forward_slashes() {
        let repo = TempDir::new().expect("failed to create temp dir");

        assert_eq!(
            stored_path_key(repo.path(), "src\\nested\\app.py"),
            "src/nested/app.py"
        );
    }

    #[test]
    fn absolute_paths_under_root_become_root_relative() {
        let repo = TempDir::new().expect("failed to create temp dir");
        let path = repo.path().join("src/app.py");

        assert_eq!(
            stored_path_key(repo.path(), path.to_str().expect("non-utf8 path")),
            "src/app.py"
        );
    }

    #[test]
    fn windows_drive_absolute_paths_are_not_treated_as_cwd_relative() {
        let root = Path::new("C:/repo");

        assert_eq!(
            finding_path_key(root, "C:\\repo\\src\\app.py"),
            "src/app.py"
        );
        assert_eq!(stored_path_key(root, "C:\\repo\\src\\app.py"), "src/app.py");
    }
}
