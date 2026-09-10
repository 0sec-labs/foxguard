#![cfg(unix)]

use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .current_dir(root)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn release_fixture() -> TempDir {
    let root = tempfile::tempdir().unwrap();
    git(root.path(), &["init", "--initial-branch=release/test"]);
    git(
        root.path(),
        &["config", "user.email", "release-test@example.invalid"],
    );
    git(root.path(), &["config", "user.name", "Release test"]);
    fs::write(
        root.path().join("Cargo.toml"),
        "[package]\nname = \"foxguard\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    git(root.path(), &["add", "Cargo.toml"]);
    git(root.path(), &["commit", "-m", "fixture"]);
    fs::create_dir_all(root.path().join("docs/releases")).unwrap();
    fs::write(
        root.path().join("docs/releases/v0.2.0.md"),
        "Release fixture\n",
    )
    .unwrap();
    root
}

fn assert_preparation_rejected(root: &Path) {
    let manifest = fs::read(root.join("Cargo.toml")).unwrap();
    let head = git(root, &["rev-parse", "HEAD"]);
    let tags = git(root, &["tag", "--list"]);
    let output = Command::new("bash")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/release.sh"))
        .arg("0.2.0")
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "preparation unexpectedly succeeded"
    );
    assert_eq!(fs::read(root.join("Cargo.toml")).unwrap(), manifest);
    assert_eq!(git(root, &["rev-parse", "HEAD"]), head);
    assert_eq!(git(root, &["tag", "--list"]), tags);
}

#[test]
fn release_preparation_rejects_unrelated_changes_before_mutating_metadata() {
    let root = release_fixture();
    fs::write(root.path().join("unrelated.txt"), "keep this work\n").unwrap();
    assert_preparation_rejected(root.path());
    assert_eq!(
        fs::read_to_string(root.path().join("unrelated.txt")).unwrap(),
        "keep this work\n"
    );
}

#[test]
fn release_preparation_rejects_missing_notes_and_main_branch() {
    let root = release_fixture();
    fs::remove_file(root.path().join("docs/releases/v0.2.0.md")).unwrap();
    assert_preparation_rejected(root.path());
    fs::write(
        root.path().join("docs/releases/v0.2.0.md"),
        "Release fixture\n",
    )
    .unwrap();
    git(root.path(), &["branch", "-m", "main"]);
    assert_preparation_rejected(root.path());
}

#[test]
fn release_preparation_fails_closed_when_origin_cannot_be_checked() {
    let root = release_fixture();
    git(
        root.path(),
        &[
            "remote",
            "add",
            "origin",
            root.path().join("missing.git").to_str().unwrap(),
        ],
    );
    assert_preparation_rejected(root.path());
}

#[test]
fn release_preparation_preserves_existing_local_and_remote_tags() {
    let root = release_fixture();
    git(root.path(), &["tag", "v0.2.0"]);
    assert_preparation_rejected(root.path());
    git(root.path(), &["tag", "-d", "v0.2.0"]);
    let remote = tempfile::tempdir().unwrap();
    git(remote.path(), &["init", "--bare"]);
    git(
        root.path(),
        &["remote", "add", "origin", remote.path().to_str().unwrap()],
    );
    git(root.path(), &["push", "origin", "HEAD:refs/tags/v0.2.0"]);
    let remote_tag = git(remote.path(), &["rev-parse", "refs/tags/v0.2.0"]);
    assert_preparation_rejected(root.path());
    assert_eq!(
        git(remote.path(), &["rev-parse", "refs/tags/v0.2.0"]),
        remote_tag
    );
}
