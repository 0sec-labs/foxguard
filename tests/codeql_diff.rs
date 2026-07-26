#![cfg(unix)]

use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

fn git(repo: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .expect("failed to run git");
    assert!(
        output.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
}

fn setup_repo() -> TempDir {
    let repo = TempDir::new().expect("failed to create repository");
    git(repo.path(), &["init", "-b", "main"]);
    fs::create_dir_all(repo.path().join("src")).expect("failed to create source directory");
    fs::write(
        repo.path().join("src/app.c"),
        "int main(void) { return 0; }\n",
    )
    .expect("failed to write base source");
    fs::write(
        repo.path().join("src/shared.c"),
        "base line 1\nbase line 2\nbase line 3\n",
    )
    .expect("failed to write base shared source");
    git(repo.path(), &["add", "."]);
    git(
        repo.path(),
        &[
            "-c",
            "user.name=Foxguard Test",
            "-c",
            "user.email=foxguard@example.test",
            "commit",
            "-m",
            "base",
        ],
    );
    fs::write(
        repo.path().join("src/app.c"),
        "int main(void) { return 1; }\n",
    )
    .expect("failed to write head source");
    let head_shared = (1..=24)
        .map(|line| format!("head line {line}"))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(repo.path().join("src/shared.c"), format!("{head_shared}\n"))
        .expect("failed to write head shared source");
    repo
}

fn write_rule(repo: &Path) -> PathBuf {
    let query = repo.join("query.ql");
    fs::write(&query, "import cpp\n").expect("failed to write query");
    let rules = repo.join("rules.yml");
    fs::write(
        &rules,
        "rules:\n  - id: test/codeql-diff\n    engine: codeql\n    severity: high\n    message: fake CodeQL result\n    query: query.ql\n",
    )
    .expect("failed to write CodeQL rule");
    rules
}

fn write_database_source_root(database: &Path, source_root: &str) {
    fs::write(
        database.join("codeql-database.yml"),
        format!("sourceLocationPrefix: {source_root}\n"),
    )
    .expect("failed to write CodeQL database metadata");
}

fn write_fake_codeql(dir: &Path) -> PathBuf {
    let codeql = dir.join("codeql");
    fs::write(
        &codeql,
        r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  if [ "$FOXGUARD_TEST_CODEQL_MODE" = "unavailable" ]; then
    echo "fake CodeQL unavailable" >&2
    exit 1
  fi
  echo "fake CodeQL"
  exit 0
fi

output=""
for arg in "$@"; do
  case "$arg" in
    --output=*) output="${arg#--output=}" ;;
  esac
done

if [ "$FOXGUARD_TEST_CODEQL_MODE" = "malformed" ]; then
  printf 'not SARIF' > "$output"
  exit 0
fi

if [ "$FOXGUARD_TEST_CODEQL_MODE" = "malformed-json" ]; then
  printf '%s' '{"version":"2.1.0","runs":[{"results":[]}]}' > "$output"
  exit 0
fi

if [ "$FOXGUARD_TEST_CODEQL_MODE" = "unsupported-version" ]; then
  printf '%s' '{"version":"2.0.0","runs":[{"tool":{"driver":{"name":"CodeQL"}},"results":[]}]}' > "$output"
  exit 0
fi

if [ "$FOXGUARD_TEST_CODEQL_MODE" = "empty" ]; then
  printf '%s' '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"CodeQL"}},"results":[]}]}' > "$output"
  exit 0
fi

if [ "$FOXGUARD_TEST_CODEQL_MODE" = "absolute-paths" ]; then
  case "$3" in
    *base*)
      printf '%s' '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"CodeQL"}},"results":[{"message":{"text":"shared"},"partialFingerprints":{"primaryLocationLineHash":"stable-shared"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"file:///tmp/base/src/shared.c"},"region":{"startLine":3,"startColumn":1,"snippet":{"text":"base"}}}}]}]}]}' > "$output"
      ;;
    *head*)
      printf '%s' '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"CodeQL"}},"results":[{"message":{"text":"shared"},"partialFingerprints":{"primaryLocationLineHash":"stable-shared"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"file:///tmp/head/src/shared.c"},"region":{"startLine":17,"startColumn":1,"snippet":{"text":"head"}}}}]}]}]}' > "$output"
      ;;
  esac
  exit 0
fi

if [ "$FOXGUARD_TEST_CODEQL_MODE" = "unrooted-absolute" ]; then
  printf '%s' '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"CodeQL"}},"results":[{"message":{"text":"shared"},"partialFingerprints":{"primaryLocationLineHash":"stable-shared"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"file:///tmp/no-source-root/src/shared.c"},"region":{"startLine":3,"startColumn":1,"snippet":{"text":"shared"}}}}]}]}]}' > "$output"
  exit 0
fi

if [ "$FOXGUARD_TEST_CODEQL_MODE" = "uri-base-namespaces" ]; then
  case "$3" in
    *base*)
      printf '%s' '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"CodeQL"}},"originalUriBaseIds":{"PKG_A":{"uri":"file:///tmp/base/pkg-a/"},"PKG_B":{"uri":"file:///tmp/base/pkg-b/"}},"results":[{"message":{"text":"pkg-a"},"partialFingerprints":{"primaryLocationLineHash":"same-tail"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/x.c","uriBaseId":"PKG_A"},"region":{"startLine":3,"startColumn":1,"snippet":{"text":"pkg-a"}}}}]}]}]}' > "$output"
      ;;
    *head*)
      printf '%s' '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"CodeQL"}},"originalUriBaseIds":{"PKG_A":{"uri":"file:///tmp/head/pkg-a/"},"PKG_B":{"uri":"file:///tmp/head/pkg-b/"}},"results":[{"message":{"text":"pkg-a"},"partialFingerprints":{"primaryLocationLineHash":"same-tail"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/x.c","uriBaseId":"PKG_A"},"region":{"startLine":17,"startColumn":1,"snippet":{"text":"pkg-a"}}}}]},{"message":{"text":"pkg-b"},"partialFingerprints":{"primaryLocationLineHash":"same-tail"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/x.c","uriBaseId":"PKG_B"},"region":{"startLine":17,"startColumn":1,"snippet":{"text":"pkg-b"}}}}]}]}]}' > "$output"
      ;;
  esac
  exit 0
fi

if [ "$FOXGUARD_TEST_CODEQL_MODE" = "singleton-mixed" ]; then
  case "$3" in
    *base*)
      printf '%s' '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"CodeQL"}},"originalUriBaseIds":{"BASE_LABEL":{"uri":"file:///tmp/base/"}},"results":[{"message":{"text":"shared"},"partialFingerprints":{"primaryLocationLineHash":"singleton"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/shared.c","uriBaseId":"BASE_LABEL"},"region":{"startLine":3,"startColumn":1,"snippet":{"text":"base"}}}}]}]}]}' > "$output"
      ;;
    *head*)
      printf '%s' '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"CodeQL"}},"results":[{"message":{"text":"shared"},"partialFingerprints":{"primaryLocationLineHash":"singleton"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"file:///tmp/head/src/shared.c"},"region":{"startLine":17,"startColumn":1,"snippet":{"text":"head"}}}}]}]}]}' > "$output"
      ;;
  esac
  exit 0
fi

if [ "$FOXGUARD_TEST_CODEQL_MODE" = "singleton-labels" ]; then
  case "$3" in
    *base*)
      printf '%s' '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"CodeQL"}},"originalUriBaseIds":{"BASE_LABEL":{"uri":"file:///tmp/base/"}},"results":[{"message":{"text":"shared"},"partialFingerprints":{"primaryLocationLineHash":"singleton"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/shared.c","uriBaseId":"BASE_LABEL"},"region":{"startLine":3,"startColumn":1,"snippet":{"text":"base"}}}}]}]}]}' > "$output"
      ;;
    *head*)
      printf '%s' '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"CodeQL"}},"originalUriBaseIds":{"HEAD_LABEL":{"uri":"file:///tmp/head/"}},"results":[{"message":{"text":"shared"},"partialFingerprints":{"primaryLocationLineHash":"singleton"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/shared.c","uriBaseId":"HEAD_LABEL"},"region":{"startLine":17,"startColumn":1,"snippet":{"text":"head"}}}}]}]}]}' > "$output"
      ;;
  esac
  exit 0
fi

if [ "$FOXGUARD_TEST_CODEQL_MODE" = "multi-base-label-mismatch" ]; then
  case "$3" in
    *base*)
      printf '%s' '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"CodeQL"}},"originalUriBaseIds":{"PKG_A":{"uri":"file:///tmp/base/pkg-a/"},"PKG_B":{"uri":"file:///tmp/base/pkg-b/"}},"results":[{"message":{"text":"pkg-a"},"partialFingerprints":{"primaryLocationLineHash":"multi"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/x.c","uriBaseId":"PKG_A"},"region":{"startLine":3,"startColumn":1,"snippet":{"text":"pkg-a"}}}}]}]}]}' > "$output"
      ;;
    *head*)
      printf '%s' '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"CodeQL"}},"originalUriBaseIds":{"HEAD_A":{"uri":"file:///tmp/head/pkg-a/"},"HEAD_B":{"uri":"file:///tmp/head/pkg-b/"}},"results":[{"message":{"text":"pkg-a"},"partialFingerprints":{"primaryLocationLineHash":"multi"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/x.c","uriBaseId":"HEAD_A"},"region":{"startLine":17,"startColumn":1,"snippet":{"text":"pkg-a"}}}}]}]}]}' > "$output"
      ;;
  esac
  exit 0
fi

case "$3" in
  *failure*)
    echo "forced CodeQL analysis failure" >&2
    exit 1
    ;;
  *base*)
    cat > "$output" <<'SARIF'
{
  "version": "2.1.0",
  "runs": [
    {
      "tool": {"driver": {"name": "CodeQL"}},
      "results": [
        {
          "message": {"text": "shared base content"},
          "partialFingerprints": {"primaryLocationLineHash": "stable-shared"},
          "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "src/shared.c"},
            "region": {"startLine": 3, "startColumn": 1, "snippet": {"text": "base database source"}}
          }}]
        },
        {
          "message": {"text": "removed"},
          "partialFingerprints": {"primaryLocationLineHash": "removed"},
          "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "src/removed.c"},
            "region": {"startLine": 1, "startColumn": 1, "snippet": {"text": "removed database source"}}
          }}]
        }
      ]
    }
  ]
}
SARIF
    ;;
  *head*)
    cat > "$output" <<'SARIF'
{
  "version": "2.1.0",
  "runs": [
    {
      "tool": {"driver": {"name": "CodeQL"}},
      "results": [
        {
          "message": {"text": "shared head content"},
          "partialFingerprints": {"primaryLocationLineHash": "stable-shared"},
          "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "src/shared.c"},
            "region": {"startLine": 17, "startColumn": 1, "snippet": {"text": "head database source"}}
          }}]
        },
        {
          "message": {"text": "shared head content"},
          "partialFingerprints": {"primaryLocationLineHash": "stable-shared"},
          "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "src/shared.c"},
            "region": {"startLine": 17, "startColumn": 1, "snippet": {"text": "head database source"}}
          }}]
        },
        {
          "message": {"text": "introduced"},
          "partialFingerprints": {"primaryLocationLineHash": "introduced"},
          "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "src/shared.c"},
            "region": {"startLine": 19, "startColumn": 1, "snippet": {"text": "introduced database source"}}
          }}]
        }
      ]
    }
  ]
}
SARIF
    ;;
  *)
    echo "unexpected database: $3" >&2
    exit 1
    ;;
esac
"#,
    )
    .expect("failed to write fake CodeQL");
    fs::set_permissions(&codeql, fs::Permissions::from_mode(0o755))
        .expect("failed to make fake CodeQL executable");
    codeql
}

fn foxguard_diff(repo: &Path, fake_codeql_dir: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_foxguard"));
    let mut path = fake_codeql_dir.as_os_str().to_os_string();
    path.push(":");
    path.push(env::var_os("PATH").expect("PATH should be set for git"));
    command.current_dir(repo).env("PATH", path).args([
        "diff",
        "main",
        ".",
        "--no-builtins",
        "-f",
        "json",
    ]);
    command
}

#[test]
fn paired_databases_use_sarif_identity_for_moved_findings() {
    let repo = setup_repo();
    let rules = write_rule(repo.path());
    let fake_bin = TempDir::new().expect("failed to create fake CodeQL directory");
    write_fake_codeql(fake_bin.path());
    let base = repo.path().join("base-db");
    let head = repo.path().join("head-db");
    fs::create_dir_all(&base).expect("failed to create base database directory");
    fs::create_dir_all(&head).expect("failed to create head database directory");

    let output = foxguard_diff(repo.path(), fake_bin.path())
        .args([
            "--rules",
            rules.to_str().expect("non-UTF-8 rules path"),
            "--codeql-base-db",
            base.to_str().expect("non-UTF-8 base database path"),
            "--codeql-head-db",
            head.to_str().expect("non-UTF-8 head database path"),
        ])
        .output()
        .expect("failed to execute foxguard diff");

    assert_eq!(
        output.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("expected JSON diff report");
    let findings = report["findings"].as_array().expect("findings array");
    assert_eq!(findings.len(), 1, "head-only result should appear once");
    assert_eq!(findings[0]["file"].as_str(), Some("src/shared.c"));
    assert_eq!(findings[0]["line"].as_u64(), Some(19));
    assert_eq!(findings[0]["description"].as_str(), Some("introduced"));
    assert_eq!(
        findings[0]["snippet"].as_str(),
        Some("introduced database source")
    );
    assert_eq!(findings[0]["rule_id"].as_str(), Some("test/codeql-diff"));
}

#[test]
fn paired_databases_normalize_absolute_sarif_paths_from_database_metadata() {
    let repo = setup_repo();
    let rules = write_rule(repo.path());
    let fake_bin = TempDir::new().expect("failed to create fake CodeQL directory");
    write_fake_codeql(fake_bin.path());
    let base = repo.path().join("base-db");
    let head = repo.path().join("head-db");
    fs::create_dir_all(&base).expect("failed to create base database directory");
    fs::create_dir_all(&head).expect("failed to create head database directory");
    write_database_source_root(&base, "/tmp/base");
    write_database_source_root(&head, "/tmp/head");

    let output = foxguard_diff(repo.path(), fake_bin.path())
        .env("FOXGUARD_TEST_CODEQL_MODE", "absolute-paths")
        .args([
            "--rules",
            rules.to_str().expect("non-UTF-8 rules path"),
            "--codeql-base-db",
            base.to_str().expect("non-UTF-8 base database path"),
            "--codeql-head-db",
            head.to_str().expect("non-UTF-8 head database path"),
        ])
        .output()
        .expect("failed to execute foxguard diff");

    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("expected JSON diff report");
    assert!(
        report["findings"]
            .as_array()
            .expect("findings array")
            .is_empty(),
        "equivalent absolute-source-root findings must be suppressed"
    );
}

#[test]
fn paired_databases_keep_uri_base_ids_with_identical_tails_distinct() {
    let repo = setup_repo();
    let rules = write_rule(repo.path());
    let fake_bin = TempDir::new().expect("failed to create fake CodeQL directory");
    write_fake_codeql(fake_bin.path());
    let base = repo.path().join("base-db");
    let head = repo.path().join("head-db");
    fs::create_dir_all(&base).expect("failed to create base database directory");
    fs::create_dir_all(&head).expect("failed to create head database directory");

    let output = foxguard_diff(repo.path(), fake_bin.path())
        .env("FOXGUARD_TEST_CODEQL_MODE", "uri-base-namespaces")
        .args([
            "--rules",
            rules.to_str().expect("non-UTF-8 rules path"),
            "--codeql-base-db",
            base.to_str().expect("non-UTF-8 base database path"),
            "--codeql-head-db",
            head.to_str().expect("non-UTF-8 head database path"),
        ])
        .output()
        .expect("failed to execute foxguard diff");

    assert_eq!(
        output.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("expected JSON diff report");
    let findings = report["findings"].as_array().expect("findings array");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["file"].as_str(), Some("src/x.c"));
    assert_eq!(findings[0]["description"].as_str(), Some("pkg-b"));
}

#[test]
fn paired_databases_match_equivalent_singletons_across_encodings_and_labels() {
    let repo = setup_repo();
    let rules = write_rule(repo.path());
    let fake_bin = TempDir::new().expect("failed to create fake CodeQL directory");
    write_fake_codeql(fake_bin.path());
    let base = repo.path().join("base-db");
    let head = repo.path().join("head-db");
    fs::create_dir_all(&base).expect("failed to create base database directory");
    fs::create_dir_all(&head).expect("failed to create head database directory");
    write_database_source_root(&head, "/tmp/head");

    for mode in ["singleton-mixed", "singleton-labels"] {
        let output = foxguard_diff(repo.path(), fake_bin.path())
            .env("FOXGUARD_TEST_CODEQL_MODE", mode)
            .args([
                "--rules",
                rules.to_str().expect("non-UTF-8 rules path"),
                "--codeql-base-db",
                base.to_str().expect("non-UTF-8 base database path"),
                "--codeql-head-db",
                head.to_str().expect("non-UTF-8 head database path"),
            ])
            .output()
            .expect("failed to execute foxguard diff");

        assert_eq!(
            output.status.code(),
            Some(0),
            "{mode}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("expected JSON diff report");
        assert!(
            report["findings"]
                .as_array()
                .expect("findings array")
                .is_empty(),
            "{mode}: equivalent singleton findings must be suppressed"
        );
    }
}

#[test]
fn incompatible_multi_base_namespaces_fail_without_a_clean_report() {
    let repo = setup_repo();
    let rules = write_rule(repo.path());
    let fake_bin = TempDir::new().expect("failed to create fake CodeQL directory");
    write_fake_codeql(fake_bin.path());
    let base = repo.path().join("base-db");
    let head = repo.path().join("head-db");
    fs::create_dir_all(&base).expect("failed to create base database directory");
    fs::create_dir_all(&head).expect("failed to create head database directory");

    let output = foxguard_diff(repo.path(), fake_bin.path())
        .env("FOXGUARD_TEST_CODEQL_MODE", "multi-base-label-mismatch")
        .args([
            "--rules",
            rules.to_str().expect("non-UTF-8 rules path"),
            "--codeql-base-db",
            base.to_str().expect("non-UTF-8 base database path"),
            "--codeql-head-db",
            head.to_str().expect("non-UTF-8 head database path"),
        ])
        .output()
        .expect("failed to execute foxguard diff");

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("incompatible multi-base uriBaseId namespaces"));
    assert!(
        output.stdout.is_empty(),
        "incompatible multi-base namespaces must not report a clean JSON delta"
    );
}

#[test]
fn paired_databases_accept_valid_empty_sarif_results() {
    let repo = setup_repo();
    let rules = write_rule(repo.path());
    let fake_bin = TempDir::new().expect("failed to create fake CodeQL directory");
    write_fake_codeql(fake_bin.path());
    let base = repo.path().join("base-db");
    let head = repo.path().join("head-db");
    fs::create_dir_all(&base).expect("failed to create base database directory");
    fs::create_dir_all(&head).expect("failed to create head database directory");

    let output = foxguard_diff(repo.path(), fake_bin.path())
        .env("FOXGUARD_TEST_CODEQL_MODE", "empty")
        .args([
            "--rules",
            rules.to_str().expect("non-UTF-8 rules path"),
            "--codeql-base-db",
            base.to_str().expect("non-UTF-8 base database path"),
            "--codeql-head-db",
            head.to_str().expect("non-UTF-8 head database path"),
        ])
        .output()
        .expect("failed to execute foxguard diff");

    assert_eq!(output.status.code(), Some(0));
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("expected JSON diff report");
    assert!(report["findings"]
        .as_array()
        .expect("findings array")
        .is_empty());
}

#[test]
fn malformed_json_sarif_and_unsupported_versions_fail_without_a_clean_report() {
    let repo = setup_repo();
    let rules = write_rule(repo.path());
    let fake_bin = TempDir::new().expect("failed to create fake CodeQL directory");
    write_fake_codeql(fake_bin.path());
    let base = repo.path().join("base-db");
    let head = repo.path().join("head-db");
    fs::create_dir_all(&base).expect("failed to create base database directory");
    fs::create_dir_all(&head).expect("failed to create head database directory");

    for (mode, expected_error) in [
        ("malformed-json", "lacks a tool object"),
        ("unsupported-version", "unsupported SARIF version"),
    ] {
        let output = foxguard_diff(repo.path(), fake_bin.path())
            .env("FOXGUARD_TEST_CODEQL_MODE", mode)
            .args([
                "--rules",
                rules.to_str().expect("non-UTF-8 rules path"),
                "--codeql-base-db",
                base.to_str().expect("non-UTF-8 base database path"),
                "--codeql-head-db",
                head.to_str().expect("non-UTF-8 head database path"),
            ])
            .output()
            .expect("failed to execute foxguard diff");

        assert_eq!(output.status.code(), Some(2));
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected_error),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.stdout.is_empty(),
            "invalid SARIF must not report a clean JSON delta"
        );
    }
}

#[test]
fn unrooted_absolute_sarif_path_fails_without_a_clean_report() {
    let repo = setup_repo();
    let rules = write_rule(repo.path());
    let fake_bin = TempDir::new().expect("failed to create fake CodeQL directory");
    write_fake_codeql(fake_bin.path());
    let base = repo.path().join("base-db");
    let head = repo.path().join("head-db");
    fs::create_dir_all(&base).expect("failed to create base database directory");
    fs::create_dir_all(&head).expect("failed to create head database directory");

    let output = foxguard_diff(repo.path(), fake_bin.path())
        .env("FOXGUARD_TEST_CODEQL_MODE", "unrooted-absolute")
        .args([
            "--rules",
            rules.to_str().expect("non-UTF-8 rules path"),
            "--codeql-base-db",
            base.to_str().expect("non-UTF-8 base database path"),
            "--codeql-head-db",
            head.to_str().expect("non-UTF-8 head database path"),
        ])
        .output()
        .expect("failed to execute foxguard diff");

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("no matching CodeQL source root"));
    assert!(
        output.stdout.is_empty(),
        "an unrooted absolute artifact must not report a clean JSON delta"
    );
}

#[test]
fn incomplete_codeql_database_pairs_are_rejected() {
    let repo = setup_repo();
    let fake_bin = TempDir::new().expect("failed to create fake CodeQL directory");
    let base = repo.path().join("base-db");
    fs::create_dir_all(&base).expect("failed to create base database directory");

    let cli = foxguard_diff(repo.path(), fake_bin.path())
        .args([
            "--codeql-base-db",
            base.to_str().expect("non-UTF-8 base database path"),
        ])
        .output()
        .expect("failed to execute foxguard diff");
    assert_eq!(cli.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&cli.stderr).contains("--codeql-head-db"));

    let config = repo.path().join("foxguard.yml");
    fs::write(&config, "diff:\n  codeql_base_db: base-db\n")
        .expect("failed to write incomplete config");
    let configured = foxguard_diff(repo.path(), fake_bin.path())
        .args(["--config", config.to_str().expect("non-UTF-8 config path")])
        .output()
        .expect("failed to execute configured foxguard diff");
    assert_eq!(configured.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&configured.stderr)
        .contains("diff.codeql_base_db and diff.codeql_head_db"));
}

#[test]
fn unavailable_codeql_fails_without_a_clean_diff_report() {
    let repo = setup_repo();
    let rules = write_rule(repo.path());
    let fake_bin = TempDir::new().expect("failed to create fake CodeQL directory");
    write_fake_codeql(fake_bin.path());
    let base = repo.path().join("base-db");
    let head = repo.path().join("head-db");
    fs::create_dir_all(&base).expect("failed to create base database directory");
    fs::create_dir_all(&head).expect("failed to create head database directory");

    let output = foxguard_diff(repo.path(), fake_bin.path())
        .env("FOXGUARD_TEST_CODEQL_MODE", "unavailable")
        .args([
            "--rules",
            rules.to_str().expect("non-UTF-8 rules path"),
            "--codeql-base-db",
            base.to_str().expect("non-UTF-8 base database path"),
            "--codeql-head-db",
            head.to_str().expect("non-UTF-8 head database path"),
        ])
        .output()
        .expect("failed to execute foxguard diff");

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("CodeQL diff skipped"));
    assert!(
        output.stdout.is_empty(),
        "a failed CodeQL comparison must not report clean JSON"
    );
}

#[test]
fn failed_head_analysis_fails_without_a_clean_diff_report() {
    let repo = setup_repo();
    let rules = write_rule(repo.path());
    let fake_bin = TempDir::new().expect("failed to create fake CodeQL directory");
    write_fake_codeql(fake_bin.path());
    let base = repo.path().join("base-db");
    let head = repo.path().join("failure-head-db");
    fs::create_dir_all(&base).expect("failed to create base database directory");
    fs::create_dir_all(&head).expect("failed to create head database directory");

    let output = foxguard_diff(repo.path(), fake_bin.path())
        .args([
            "--rules",
            rules.to_str().expect("non-UTF-8 rules path"),
            "--codeql-base-db",
            base.to_str().expect("non-UTF-8 base database path"),
            "--codeql-head-db",
            head.to_str().expect("non-UTF-8 head database path"),
        ])
        .output()
        .expect("failed to execute foxguard diff");

    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("forced CodeQL analysis failure"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "a failed CodeQL comparison must not report clean JSON"
    );
}

#[test]
fn malformed_sarif_fails_without_a_clean_diff_report() {
    let repo = setup_repo();
    let rules = write_rule(repo.path());
    let fake_bin = TempDir::new().expect("failed to create fake CodeQL directory");
    write_fake_codeql(fake_bin.path());
    let base = repo.path().join("base-db");
    let head = repo.path().join("head-db");
    fs::create_dir_all(&base).expect("failed to create base database directory");
    fs::create_dir_all(&head).expect("failed to create head database directory");

    let output = foxguard_diff(repo.path(), fake_bin.path())
        .env("FOXGUARD_TEST_CODEQL_MODE", "malformed")
        .args([
            "--rules",
            rules.to_str().expect("non-UTF-8 rules path"),
            "--codeql-base-db",
            base.to_str().expect("non-UTF-8 base database path"),
            "--codeql-head-db",
            head.to_str().expect("non-UTF-8 head database path"),
        ])
        .output()
        .expect("failed to execute foxguard diff");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("produced invalid SARIF"), "{stderr}");
    assert!(stderr.contains("invalid JSON"), "{stderr}");
    assert!(
        output.stdout.is_empty(),
        "malformed CodeQL output must not report clean JSON"
    );
}

#[test]
fn invalid_or_unloadable_codeql_rules_fail_the_paired_comparison() {
    let repo = setup_repo();
    write_rule(repo.path());
    let fake_bin = TempDir::new().expect("failed to create fake CodeQL directory");
    let base = repo.path().join("base-db");
    let head = repo.path().join("head-db");
    fs::create_dir_all(&base).expect("failed to create base database directory");
    fs::create_dir_all(&head).expect("failed to create head database directory");

    let invalid = repo.path().join("invalid-codeql.yml");
    fs::write(
        &invalid,
        "rules:\n  - id: test/invalid\n    engine: codeql\n    severity: nope\n    message: invalid\n    query: query.ql\n",
    )
    .expect("failed to write invalid rule");
    let invalid_output = foxguard_diff(repo.path(), fake_bin.path())
        .args([
            "--rules",
            invalid.to_str().expect("non-UTF-8 invalid rule path"),
            "--codeql-base-db",
            base.to_str().expect("non-UTF-8 base database path"),
            "--codeql-head-db",
            head.to_str().expect("non-UTF-8 head database path"),
        ])
        .output()
        .expect("failed to execute invalid CodeQL diff");
    assert_eq!(invalid_output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&invalid_output.stderr)
        .contains("CodeQL diff failed to load rules"));
    assert!(invalid_output.stdout.is_empty());

    let missing_query = repo.path().join("missing-query-codeql.yml");
    fs::write(
        &missing_query,
        "rules:\n  - id: test/missing-query\n    engine: codeql\n    severity: high\n    message: missing query\n    query: queries/missing.ql\n",
    )
    .expect("failed to write missing-query rule");
    let missing_query_output = foxguard_diff(repo.path(), fake_bin.path())
        .args([
            "--rules",
            missing_query
                .to_str()
                .expect("non-UTF-8 missing-query rule path"),
            "--codeql-base-db",
            base.to_str().expect("non-UTF-8 base database path"),
            "--codeql-head-db",
            head.to_str().expect("non-UTF-8 head database path"),
        ])
        .output()
        .expect("failed to execute unloadable CodeQL diff");
    assert_eq!(missing_query_output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&missing_query_output.stderr).contains("query"));
    assert!(missing_query_output.stdout.is_empty());
}
