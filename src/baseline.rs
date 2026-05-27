use crate::Finding;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            format!(
                "Failed to create baseline directory {}: {}",
                parent.display(),
                e
            )
        })?;
    }

    let content = serde_json::to_string_pretty(&baseline)
        .map_err(|e| format!("Failed to serialize baseline: {}", e))?;
    std::fs::write(path, content)
        .map_err(|e| format!("Failed to write baseline {}: {}", path.display(), e))
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

    let content = serde_json::to_string_pretty(&baseline)
        .map_err(|e| format!("Failed to serialize baseline: {}", e))?;
    std::fs::write(path, content)
        .map_err(|e| format!("Failed to write baseline {}: {}", path.display(), e))?;

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

    findings
        .into_iter()
        .filter(|finding| {
            let fingerprint = identity_root
                .map(|root| fingerprint_finding_at_root(finding, root))
                .unwrap_or_else(|| fingerprint_finding(finding));
            let legacy_fingerprint = fingerprint_finding(finding);
            !baseline.entries.iter().any(|entry| {
                entry.fingerprint == fingerprint
                    || entry.fingerprint == legacy_fingerprint
                    || entry.fingerprint == fingerprint_finding_with_file(finding, &entry.file)
            })
        })
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
        }
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
