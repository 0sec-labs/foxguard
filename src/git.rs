use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeSelection {
    Legacy,
    Staged,
    Unstaged,
    All,
}

fn run_git(repo_root: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(args)
        .output()
        .map_err(|e| format!("Failed to run git: {}", e))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

pub fn changed_files(scan_root: &Path, selection: ChangeSelection) -> Result<Vec<PathBuf>, String> {
    let git_dir = if scan_root.is_dir() {
        scan_root
    } else {
        scan_root.parent().unwrap_or_else(|| Path::new("."))
    };

    let repo_root = run_git(git_dir, &["rev-parse", "--show-toplevel"])?;
    let repo_root = PathBuf::from(repo_root.trim());
    let scan_root = scan_root
        .canonicalize()
        .map_err(|e| format!("Failed to resolve scan root {}: {}", scan_root.display(), e))?;

    let staged = || {
        collect_changed_paths(
            &repo_root,
            &scan_root,
            &["diff", "--cached", "--name-only", "--diff-filter=ACMR"],
        )
    };
    let unstaged = || collect_unstaged_paths(&repo_root, &scan_root);

    let paths = match selection {
        ChangeSelection::Legacy => {
            let staged = staged()?;
            if staged.is_empty() {
                unstaged()?
            } else {
                staged
            }
        }
        ChangeSelection::Staged => staged()?,
        ChangeSelection::Unstaged => unstaged()?,
        ChangeSelection::All => {
            let mut paths = staged()?;
            paths.extend(unstaged()?);
            dedupe_paths(paths)
        }
    };

    Ok(paths)
}

fn collect_unstaged_paths(repo_root: &Path, scan_root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut paths = collect_changed_paths(
        repo_root,
        scan_root,
        &["diff", "--name-only", "--diff-filter=ACMR"],
    )?;
    paths.extend(collect_changed_paths(
        repo_root,
        scan_root,
        &["ls-files", "--others", "--exclude-standard"],
    )?);
    Ok(dedupe_paths(paths))
}

fn dedupe_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut unique = Vec::new();
    for path in paths {
        if !unique.contains(&path) {
            unique.push(path);
        }
    }
    unique
}

fn collect_changed_paths(
    repo_root: &Path,
    scan_root: &Path,
    git_args: &[&str],
) -> Result<Vec<PathBuf>, String> {
    let stdout = run_git(repo_root, git_args)?;
    let mut files = Vec::new();

    for line in stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let path = repo_root.join(line);
        if !path.exists() {
            continue;
        }

        let Ok(canonical) = path.canonicalize() else {
            continue;
        };

        if canonical.starts_with(scan_root) {
            files.push(canonical);
        }
    }

    Ok(files)
}
