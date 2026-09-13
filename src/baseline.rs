use crate::Finding;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineFile {
    pub version: u32,
    pub entries: Vec<BaselineEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineEntry {
    pub fingerprint: String,
    pub rule_id: String,
    pub file: String,
    pub line: usize,
}

/// A report delta under the current scan's scope and configuration.
/// Missing entries are not proof that the underlying issue was remediated.
#[derive(Debug, Clone, Default, Serialize)]
pub struct BaselineComparison {
    pub introduced: Vec<usize>,
    pub recurring: Vec<usize>,
    pub resolved: Vec<BaselineEntry>,
}

struct BaselineMatcher<'a> {
    fingerprints: HashSet<&'a str>,
    paths: HashMap<String, HashSet<&'a str>>,
}

impl<'a> BaselineMatcher<'a> {
    fn new(baseline: &'a BaselineFile, root: &Path) -> Self {
        let mut paths: HashMap<String, HashSet<&str>> = HashMap::new();
        let mut seen_paths = HashSet::new();
        for entry in &baseline.entries {
            if seen_paths.insert(entry.file.as_str()) {
                paths
                    .entry(crate::path_identity::stored_path_key(root, &entry.file))
                    .or_default()
                    .insert(entry.file.as_str());
            }
        }
        Self {
            fingerprints: baseline
                .entries
                .iter()
                .map(|entry| entry.fingerprint.as_str())
                .collect(),
            paths,
        }
    }

    fn visit_matches(
        &self,
        finding: &Finding,
        root: &Path,
        mut matched: impl FnMut(&'a str),
    ) -> bool {
        let normalized = crate::path_identity::finding_path_key(root, &finding.file);
        let mut found = false;
        let mut visit = |file: &str| {
            let fingerprint = fingerprint_finding_with_file(finding, file);
            if let Some(&stored) = self.fingerprints.get(fingerprint.as_str()) {
                found = true;
                matched(stored);
            }
        };
        visit(&normalized);
        if finding.file != normalized {
            visit(&finding.file);
        }
        // Legacy spellings are accepted only for the same normalized file.
        // Substituting an unrelated entry's path would suppress identical code
        // in a different file and produce a false recurring/resolved result.
        if let Some(spellings) = self.paths.get(&normalized) {
            for &file in spellings {
                if file != normalized && file != finding.file {
                    visit(file);
                }
            }
        }
        found
    }
}

pub fn compare_with_baseline_at_root(
    findings: &[Finding],
    baseline: &BaselineFile,
    identity_root: &Path,
) -> BaselineComparison {
    let matcher = BaselineMatcher::new(baseline, identity_root);
    let mut comparison = BaselineComparison::default();
    let mut matched = HashSet::new();
    for (index, finding) in findings.iter().enumerate() {
        if matcher.visit_matches(finding, identity_root, |fingerprint| {
            matched.insert(fingerprint);
        }) {
            comparison.recurring.push(index);
        } else {
            comparison.introduced.push(index);
        }
    }
    comparison.resolved = baseline
        .entries
        .iter()
        .filter(|entry| !matched.contains(entry.fingerprint.as_str()))
        .cloned()
        .collect();
    comparison
}

impl BaselineFile {
    pub fn from_findings(findings: &[Finding]) -> Self {
        let entries = findings.iter().map(BaselineEntry::from_finding).collect();
        Self {
            version: 1,
            entries,
        }
    }

    pub fn from_findings_at_root(findings: &[Finding], identity_root: &Path) -> Self {
        let entries = findings
            .iter()
            .map(|finding| BaselineEntry::from_finding_at_root(finding, identity_root))
            .collect();
        Self {
            version: 1,
            entries,
        }
    }

    pub fn add_finding(&mut self, finding: &Finding) -> bool {
        let entry = BaselineEntry::from_finding(finding);
        if self
            .entries
            .iter()
            .any(|existing| existing.fingerprint == entry.fingerprint)
        {
            return false;
        }

        self.entries.push(entry);
        true
    }

    pub fn add_finding_at_root(&mut self, finding: &Finding, identity_root: &Path) -> bool {
        let entry = BaselineEntry::from_finding_at_root(finding, identity_root);
        if self
            .entries
            .iter()
            .any(|existing| existing.fingerprint == entry.fingerprint)
        {
            return false;
        }

        self.entries.push(entry);
        true
    }
}

impl BaselineEntry {
    pub fn from_finding(finding: &Finding) -> Self {
        Self {
            fingerprint: fingerprint_finding(finding),
            rule_id: finding.rule_id.clone(),
            file: finding.file.clone(),
            line: finding.line,
        }
    }

    pub fn from_finding_at_root(finding: &Finding, identity_root: &Path) -> Self {
        let normalized_file = crate::path_identity::finding_path_key(identity_root, &finding.file);
        Self {
            fingerprint: fingerprint_finding_with_file(finding, &normalized_file),
            rule_id: finding.rule_id.clone(),
            file: normalized_file,
            line: finding.line,
        }
    }
}

pub fn fingerprint_finding(finding: &Finding) -> String {
    fingerprint_finding_with_file(finding, &finding.file)
}

pub fn fingerprint_finding_at_root(finding: &Finding, identity_root: &Path) -> String {
    let normalized_file = crate::path_identity::finding_path_key(identity_root, &finding.file);
    fingerprint_finding_with_file(finding, &normalized_file)
}

fn fingerprint_finding_with_file(finding: &Finding, file: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(finding.rule_id.as_bytes());
    hasher.update([0]);
    hasher.update(file.as_bytes());
    hasher.update([0]);
    hasher.update(finding.line.to_string().as_bytes());
    hasher.update([0]);
    hasher.update(finding.column.to_string().as_bytes());
    hasher.update([0]);
    hasher.update(finding.end_line.to_string().as_bytes());
    hasher.update([0]);
    hasher.update(finding.end_column.to_string().as_bytes());
    hasher.update([0]);
    hasher.update(finding.description.as_bytes());
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn load_baseline(path: &Path) -> Result<Option<BaselineFile>, String> {
    if !path.exists() {
        return Ok(None);
    }

    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read baseline {}: {}", path.display(), e))?;
    let baseline = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse baseline {}: {}", path.display(), e))?;
    Ok(Some(baseline))
}

pub fn write_baseline(path: &Path, findings: &[Finding]) -> Result<(), String> {
    write_baseline_file(path, BaselineFile::from_findings(findings))
}

pub fn write_baseline_at_root(
    path: &Path,
    findings: &[Finding],
    identity_root: &Path,
) -> Result<(), String> {
    write_baseline_file(
        path,
        BaselineFile::from_findings_at_root(findings, identity_root),
    )
}

fn write_baseline_file(path: &Path, baseline: BaselineFile) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let write = || -> Result<(), Box<dyn std::error::Error>> {
        std::fs::create_dir_all(parent)?;
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        if let Ok(metadata) = std::fs::metadata(path) {
            temporary
                .as_file()
                .set_permissions(metadata.permissions())?;
        }
        serde_json::to_writer_pretty(temporary.as_file_mut(), &baseline)?;
        temporary.as_file().sync_all()?;
        temporary.persist(path)?;
        #[cfg(unix)]
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    };
    write().map_err(|error| format!("Failed to write baseline {}: {error}", path.display()))
}

pub fn append_finding_to_baseline(path: &Path, finding: &Finding) -> Result<bool, String> {
    append_finding_to_baseline_inner(path, finding, None)
}

pub fn append_finding_to_baseline_at_root(
    path: &Path,
    finding: &Finding,
    identity_root: &Path,
) -> Result<bool, String> {
    append_finding_to_baseline_inner(path, finding, Some(identity_root))
}

/// Append a confirmed batch with one read and one atomic replacement.
pub fn append_findings_to_baseline_at_root<'a>(
    path: &Path,
    findings: impl IntoIterator<Item = &'a Finding>,
    identity_root: &Path,
) -> Result<usize, String> {
    let mut baseline = load_baseline(path)?.unwrap_or(BaselineFile {
        version: 1,
        entries: Vec::new(),
    });
    let mut fingerprints: std::collections::HashSet<String> = baseline
        .entries
        .iter()
        .map(|entry| entry.fingerprint.clone())
        .collect();
    let mut added = 0;
    for finding in findings {
        let entry = BaselineEntry::from_finding_at_root(finding, identity_root);
        if fingerprints.insert(entry.fingerprint.clone()) {
            baseline.entries.push(entry);
            added += 1;
        }
    }
    if added > 0 {
        write_baseline_file(path, baseline)?;
    }
    Ok(added)
}

fn append_finding_to_baseline_inner(
    path: &Path,
    finding: &Finding,
    identity_root: Option<&Path>,
) -> Result<bool, String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            format!(
                "Failed to create baseline directory {}: {}",
                parent.display(),
                e
            )
        })?;
    }

    let mut baseline = load_baseline(path)?.unwrap_or(BaselineFile {
        version: 1,
        entries: Vec::new(),
    });
    let added = if let Some(identity_root) = identity_root {
        baseline.add_finding_at_root(finding, identity_root)
    } else {
        baseline.add_finding(finding)
    };

    write_baseline_file(path, baseline)?;

    Ok(added)
}

pub fn suppress_with_baseline(
    findings: Vec<Finding>,
    baseline: Option<&BaselineFile>,
) -> Vec<Finding> {
    suppress_with_baseline_inner(findings, baseline, None)
}

pub fn suppress_with_baseline_at_root(
    findings: Vec<Finding>,
    baseline: Option<&BaselineFile>,
    identity_root: &Path,
) -> Vec<Finding> {
    suppress_with_baseline_inner(findings, baseline, Some(identity_root))
}

fn suppress_with_baseline_inner(
    findings: Vec<Finding>,
    baseline: Option<&BaselineFile>,
    identity_root: Option<&Path>,
) -> Vec<Finding> {
    let Some(baseline) = baseline else {
        return findings;
    };

    let root = identity_root.unwrap_or_else(|| Path::new("."));
    let matcher = BaselineMatcher::new(baseline, root);
    findings
        .into_iter()
        .filter(|finding| !matcher.visit_matches(finding, root, |_| {}))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Severity;
    use tempfile::TempDir;

    fn finding() -> Finding {
        Finding {
            rule_id: "py/no-command-injection".to_string(),
            severity: Severity::High,
            cwe: Some("CWE-78".to_string()),
            description: "tainted input reaches command sink".to_string(),
            file: "src/app.py".to_string(),
            line: 10,
            column: 5,
            end_line: 10,
            end_column: 20,
            snippet: "os.system(cmd)".to_string(),
            source_line: None,
            source_description: None,
            sink_line: None,
            sink_description: None,
            fix_suggestion: None,
            sink_start_byte: None,
            sink_end_byte: None,
            confidence: crate::default_confidence(),
            taint_hops: None,
            tags: vec![],
            crypto_algorithm: None,
            cnsa2_deadline: None,
            dep_name: None,
            dep_version: None,
            dep_ecosystem: None,
            dep_purl: None,
            dep_vulnerability_id: None,
            dep_fixed_version: None,
            dep_source: None,
            dep_vulnerability_severity: None,
            dep_path: vec![],
            crypto_material: None,
        }
    }

    #[test]
    fn baseline_delta_does_not_suppress_identical_findings_in_other_files() {
        let temp = TempDir::new().expect("temporary project");
        let mut recurring = finding();
        recurring.file = temp.path().join("a.py").to_string_lossy().into_owned();
        let mut introduced = recurring.clone();
        introduced.file = temp.path().join("b.py").to_string_lossy().into_owned();
        let mut absent = recurring.clone();
        absent.file = temp
            .path()
            .join("removed.py")
            .to_string_lossy()
            .into_owned();
        let baseline =
            BaselineFile::from_findings_at_root(&[recurring.clone(), absent], temp.path());
        let findings = vec![recurring, introduced];

        let comparison = compare_with_baseline_at_root(&findings, &baseline, temp.path());
        assert_eq!(comparison.recurring, vec![0]);
        assert_eq!(comparison.introduced, vec![1]);
        assert_eq!(
            comparison
                .resolved
                .iter()
                .map(|entry| entry.file.as_str())
                .collect::<Vec<_>>(),
            vec!["removed.py"]
        );
        let remaining = suppress_with_baseline_at_root(findings, Some(&baseline), temp.path());
        assert_eq!(
            remaining
                .iter()
                .map(|finding| Path::new(&finding.file).file_name().unwrap())
                .collect::<Vec<_>>(),
            vec!["b.py"]
        );
    }

    #[test]
    fn baseline_delta_matches_legacy_path_aliases_but_not_changed_locations() {
        let temp = TempDir::new().expect("temporary project");
        let mut current = finding();
        current.file = temp.path().join("app.py").to_string_lossy().into_owned();
        let baseline = BaselineFile {
            version: 1,
            entries: vec![
                BaselineEntry::from_finding(&current),
                BaselineEntry::from_finding_at_root(&current, temp.path()),
            ],
        };
        let unchanged =
            compare_with_baseline_at_root(std::slice::from_ref(&current), &baseline, temp.path());
        assert_eq!(unchanged.recurring, vec![0]);
        assert!(unchanged.resolved.is_empty());

        current.line += 1;
        current.end_line += 1;
        let moved = compare_with_baseline_at_root(&[current], &baseline, temp.path());
        assert_eq!(moved.introduced, vec![0]);
        assert!(moved.recurring.is_empty());
        assert_eq!(moved.resolved.len(), 2);
    }

    #[test]
    fn append_finding_to_baseline_adds_new_entry_once() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let path = temp.path().join(".foxguard/baseline.json");
        let finding = finding();

        assert!(append_finding_to_baseline(&path, &finding).expect("append should succeed"));
        assert!(
            !append_finding_to_baseline(&path, &finding).expect("duplicate append should succeed")
        );

        let baseline = load_baseline(&path)
            .expect("load should succeed")
            .expect("baseline should exist");
        assert_eq!(baseline.entries.len(), 1);
    }

    #[test]
    fn legacy_finding_json_without_confidence_field_deserializes_with_default() {
        // JSON written before `confidence` was added omits the field.
        // Serde should fill in the default (1.0). Regression guard for
        // issue #207 — callers that persist Finding JSON (e.g. the
        // `foxguard scan -f json` output piped to disk) should keep
        // deserializing after upgrading.
        let legacy_json = r#"{
            "rule_id": "py/no-eval",
            "severity": "high",
            "cwe": null,
            "description": "eval used",
            "file": "src/app.py",
            "line": 5,
            "column": 1,
            "end_line": 5,
            "end_column": 10,
            "snippet": "eval(x)"
        }"#;
        let finding: Finding = serde_json::from_str(legacy_json).expect("should deserialize");
        assert_eq!(finding.confidence, 1.0);
    }
}
