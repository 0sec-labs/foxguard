use crate::{Finding, Severity};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// Encode a file path as a URI suitable for SARIF `artifactLocation.uri`.
/// Normalizes backslashes to forward slashes and percent-encodes characters
/// that are not valid in URI path segments.
fn path_to_uri(path: &str) -> String {
    let normalized = path.replace('\\', "/");
    if has_uri_scheme(&normalized) {
        return normalized;
    }

    let normalized = normalized.strip_prefix("./").unwrap_or(&normalized);
    let encoded = normalized
        .split('/')
        .map(|segment| {
            segment
                .replace('%', "%25")
                .replace(' ', "%20")
                .replace('#', "%23")
                .replace('?', "%3F")
                .replace('[', "%5B")
                .replace(']', "%5D")
        })
        .collect::<Vec<_>>()
        .join("/");

    if normalized.starts_with('/') {
        format!("file://{encoded}")
    } else if is_windows_drive_absolute(normalized) {
        format!("file:///{encoded}")
    } else {
        encoded
    }
}

fn has_uri_scheme(value: &str) -> bool {
    let Some(colon) = value.find(':') else {
        return false;
    };
    if colon == 1 && value.as_bytes()[0].is_ascii_alphabetic() {
        return false;
    }
    value[..colon]
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
}

fn is_windows_drive_absolute(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'/'
}

#[derive(Debug, Clone)]
struct RuleMetadata {
    severity: Severity,
    description: String,
    tags: BTreeSet<String>,
}

fn collect_rules(findings: &[Finding]) -> (Vec<serde_json::Value>, BTreeMap<String, usize>) {
    let mut by_id: BTreeMap<String, RuleMetadata> = BTreeMap::new();

    for finding in findings {
        let entry = by_id
            .entry(finding.rule_id.clone())
            .or_insert_with(|| RuleMetadata {
                severity: finding.severity,
                description: finding.description.clone(),
                tags: BTreeSet::new(),
            });

        if finding.severity > entry.severity {
            entry.severity = finding.severity;
        }
        if entry.description.trim().is_empty() && !finding.description.trim().is_empty() {
            entry.description = finding.description.clone();
        }

        entry.tags.insert("security".to_string());
        entry.tags.extend(finding.tags.iter().cloned());
        if let Some(cwe) = &finding.cwe {
            entry.tags.insert(cwe.clone());
        }
    }

    let mut indices = BTreeMap::new();
    let rules = by_id
        .into_iter()
        .enumerate()
        .map(|(index, (id, metadata))| {
            indices.insert(id.clone(), index);
            let description =
                non_empty_text(&metadata.description, &format!("Foxguard rule {id}"), 1024);
            json!({
                "id": id,
                "name": non_empty_text(&id, "foxguard-rule", 255),
                "shortDescription": {
                    "text": description
                },
                "fullDescription": {
                    "text": description
                },
                "defaultConfiguration": {
                    "level": level_for_severity(metadata.severity)
                },
                "properties": {
                    "tags": metadata.tags.into_iter().collect::<Vec<_>>(),
                    "precision": "high",
                    "security-severity": security_severity_score(metadata.severity)
                }
            })
        })
        .collect();

    (rules, indices)
}

fn non_empty_text(value: &str, fallback: &str, max_chars: usize) -> String {
    let trimmed = value.trim();
    let source = if trimmed.is_empty() {
        fallback
    } else {
        trimmed
    };
    source.chars().take(max_chars).collect()
}

fn level_for_severity(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

fn security_severity_score(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "9.5",
        Severity::High => "8.0",
        Severity::Medium => "5.0",
        Severity::Low => "2.0",
    }
}

fn primary_location_line_hash(finding: &Finding, artifact_uri: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(finding.rule_id.as_bytes());
    hasher.update([0]);
    hasher.update(artifact_uri.as_bytes());
    hasher.update([0]);
    hasher.update(finding.line.to_string().as_bytes());
    hasher.update([0]);
    hasher.update(finding.column.to_string().as_bytes());
    hasher.update([0]);
    hasher.update(finding.end_line.to_string().as_bytes());
    hasher.update([0]);
    hasher.update(finding.end_column.to_string().as_bytes());
    hasher.update([0]);
    hasher.update(normalized_fingerprint_snippet(finding).as_bytes());
    let digest = hasher.finalize();
    let hex = digest
        .iter()
        .take(8)
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    format!("{hex}:1")
}

fn normalized_fingerprint_snippet(finding: &Finding) -> String {
    let mut normalized = finding
        .snippet
        .replace("\r\n", "\n")
        .replace('\r', "\n")
        .chars()
        .filter(|c| *c != ' ' && *c != '\t')
        .collect::<String>();
    if normalized.trim().is_empty() {
        normalized = finding.description.trim().to_string();
    }
    normalized
}

fn taint_code_flows(finding: &Finding, artifact_uri: &str) -> Option<Value> {
    let (Some(source_line), Some(source_description), Some(sink_line), Some(sink_description)) = (
        finding.source_line,
        finding.source_description.as_deref(),
        finding.sink_line,
        finding.sink_description.as_deref(),
    ) else {
        return None;
    };

    if source_line == 0 || sink_line == 0 {
        return None;
    }

    Some(json!([{
        "threadFlows": [{
            "locations": [
                thread_flow_location(artifact_uri, source_line, source_description),
                thread_flow_location(artifact_uri, sink_line, sink_description)
            ]
        }]
    }]))
}

fn thread_flow_location(artifact_uri: &str, line: usize, message: &str) -> Value {
    json!({
        "location": {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": artifact_uri
                },
                "region": {
                    "startLine": line
                }
            },
            "message": {
                "text": non_empty_text(message, "taint flow location", 1024)
            }
        }
    })
}

pub fn build_sarif(findings: &[Finding]) -> serde_json::Value {
    let (rules, rule_indices) = collect_rules(findings);
    let results: Vec<_> = findings
        .iter()
        .map(|f| {
            let artifact_uri = path_to_uri(&f.file);
            let mut props = serde_json::Map::new();
            let mut tags: Vec<String> = f.tags.clone();
            if let Some(cwe) = &f.cwe {
                tags.push(cwe.clone());
            }
            if !tags.is_empty() {
                props.insert("tags".to_string(), json!(tags));
            }
            // Expose confidence in properties so downstream tooling that
            // ignores the native `rank` field can still consume it.
            let clamped_conf = f.confidence.clamp(0.0, 1.0);
            props.insert("confidence".to_string(), json!(clamped_conf));

            // CNSA 2.0 compliance deadline (issue #241). Always included
            // when present regardless of the `--cnsa2` flag — SARIF is a
            // machine-consumed format and the field is metadata that
            // downstream governance tooling may rely on. Key is
            // camelCase per SARIF property-bag convention (fixes #231
            // review: the prior `cnsa2_deadline` used snake_case).
            if let Some(deadline) = &f.cnsa2_deadline {
                props.insert("cnsa2Deadline".to_string(), json!(deadline));
            }
            if let Some(dep) = &f.dep_name {
                props.insert("depName".to_string(), json!(dep));
            }
            if let Some(version) = &f.dep_version {
                props.insert("depVersion".to_string(), json!(version));
            }
            if let Some(ecosystem) = &f.dep_ecosystem {
                props.insert("depEcosystem".to_string(), json!(ecosystem));
            }
            if let Some(purl) = &f.dep_purl {
                props.insert("depPurl".to_string(), json!(purl));
            }
            if let Some(id) = &f.dep_vulnerability_id {
                props.insert("depVulnerabilityId".to_string(), json!(id));
            }
            if let Some(version) = &f.dep_fixed_version {
                props.insert("depFixedVersion".to_string(), json!(version));
            }
            if let Some(source) = &f.dep_source {
                props.insert("depSource".to_string(), json!(source));
            }
            if let Some(severity) = &f.dep_vulnerability_severity {
                props.insert("depVulnerabilitySeverity".to_string(), json!(severity));
            }
            if !f.dep_path.is_empty() {
                props.insert("depPath".to_string(), json!(f.dep_path));
            }

            // SARIF `rank` is a native 0.0..=100.0 ordering hint. Map
            // confidence linearly so 1.0 → 100 and 0.0 → 0.
            let rank = clamped_conf as f64 * 100.0;

            let mut result = json!({
                "ruleId": f.rule_id,
                "ruleIndex": rule_indices.get(&f.rule_id).copied().unwrap_or(0),
                "level": level_for_severity(f.severity),
                "rank": rank,
                "message": {
                    "text": f.description
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": artifact_uri
                        },
                        "region": {
                            "startLine": f.line,
                            "startColumn": f.column,
                            "endLine": f.end_line,
                            "endColumn": f.end_column
                        }
                    }
                }],
                "partialFingerprints": {
                    "primaryLocationLineHash": primary_location_line_hash(f, &artifact_uri),
                    "primaryLocationStartColumnFingerprint": f.column.to_string()
                },
                "properties": props
            });

            if let Some(fix) = &f.fix_suggestion {
                result["fixes"] = json!([{
                    "description": {
                        "text": fix
                    }
                }]);
            }

            if let Some(code_flows) = taint_code_flows(f, &artifact_uri) {
                result["codeFlows"] = code_flows;
            }

            result
        })
        .collect();

    let sarif = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "foxguard",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://foxguard.dev",
                    "rules": rules
                }
            },
            "results": results
        }]
    });

    sarif
}

pub fn print_sarif(findings: &[Finding]) {
    println!(
        "{}",
        serde_json::to_string_pretty(&build_sarif(findings)).expect("Failed to serialize SARIF")
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(rule_id: &str, severity: Severity, file: &str) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            severity,
            cwe: Some("CWE-79".to_string()),
            description: "Use of dangerous HTML sink".to_string(),
            file: file.to_string(),
            line: 3,
            column: 5,
            end_line: 3,
            end_column: 12,
            snippet: "sink(value)".to_string(),
            source_line: None,
            source_description: None,
            sink_line: None,
            sink_description: None,
            fix_suggestion: None,
            sink_start_byte: None,
            sink_end_byte: None,
            confidence: 1.0,
            taint_hops: None,
            tags: vec!["framework".to_string()],
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
    fn relative_paths_emit_relative_artifact_uris() {
        assert_eq!(
            path_to_uri("src/app file#[].js"),
            "src/app%20file%23%5B%5D.js"
        );
        assert_eq!(path_to_uri("./src\\app.js"), "src/app.js");
    }

    #[test]
    fn absolute_paths_emit_file_uris() {
        assert_eq!(path_to_uri("/tmp/app.js"), "file:///tmp/app.js");
        assert_eq!(path_to_uri("C:\\tmp\\app.js"), "file:///C:/tmp/app.js");
    }

    #[test]
    fn sarif_includes_github_code_scanning_metadata() {
        let findings = vec![finding("js/no-xss", Severity::High, "src/app.js")];
        let sarif = build_sarif(&findings);

        let driver = &sarif["runs"][0]["tool"]["driver"];
        let Some(rules) = driver["rules"].as_array() else {
            panic!("rules array");
        };
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["id"].as_str(), Some("js/no-xss"));
        assert_eq!(
            rules[0]["defaultConfiguration"]["level"].as_str(),
            Some("error")
        );
        assert_eq!(
            rules[0]["properties"]["security-severity"].as_str(),
            Some("8.0")
        );

        let result = &sarif["runs"][0]["results"][0];
        assert_eq!(result["ruleIndex"].as_u64(), Some(0));
        assert_eq!(
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].as_str(),
            Some("src/app.js")
        );
        assert!(result["partialFingerprints"]["primaryLocationLineHash"]
            .as_str()
            .is_some_and(|value| !value.is_empty()));
    }

    #[test]
    fn sarif_omits_code_flows_without_taint_metadata() {
        let findings = vec![finding("js/no-xss", Severity::High, "src/app.js")];
        let sarif = build_sarif(&findings);

        let result = &sarif["runs"][0]["results"][0];
        assert!(
            result.get("codeFlows").is_none(),
            "non-taint findings should not emit codeFlows"
        );
    }

    #[test]
    fn sarif_includes_code_flows_for_taint_metadata() {
        let mut taint = finding("py/taint-sql-injection", Severity::High, "src/app.py");
        taint.description = "Untrusted request data reaches SQL execution".to_string();
        taint.line = 9;
        taint.column = 13;
        taint.end_line = 9;
        taint.end_column = 24;
        taint.source_line = Some(3);
        taint.source_description = Some("request.args.get(\"name\")".to_string());
        taint.sink_line = Some(9);
        taint.sink_description = Some("sqlite3.Cursor.execute".to_string());
        taint.taint_hops = Some(1);
        taint.confidence = 0.8;

        let sarif = build_sarif(&[taint]);
        let result = &sarif["runs"][0]["results"][0];

        let Some(code_flows) = result["codeFlows"].as_array() else {
            panic!("codeFlows array");
        };
        assert_eq!(code_flows.len(), 1);
        let Some(locations) = code_flows[0]["threadFlows"][0]["locations"].as_array() else {
            panic!("thread flow locations");
        };
        assert_eq!(locations.len(), 2);

        assert_eq!(
            locations[0]["location"]["physicalLocation"]["artifactLocation"]["uri"].as_str(),
            Some("src/app.py")
        );
        assert_eq!(
            locations[0]["location"]["physicalLocation"]["region"]["startLine"].as_u64(),
            Some(3)
        );
        assert_eq!(
            locations[0]["location"]["message"]["text"].as_str(),
            Some("request.args.get(\"name\")")
        );

        assert_eq!(
            locations[1]["location"]["physicalLocation"]["artifactLocation"]["uri"].as_str(),
            Some("src/app.py")
        );
        assert_eq!(
            locations[1]["location"]["physicalLocation"]["region"]["startLine"].as_u64(),
            Some(9)
        );
        assert_eq!(
            locations[1]["location"]["message"]["text"].as_str(),
            Some("sqlite3.Cursor.execute")
        );

        let Some(rank) = result["rank"].as_f64() else {
            panic!("rank");
        };
        assert!((rank - 80.0).abs() < 0.01, "unexpected rank: {rank}");
        assert!(result["partialFingerprints"]["primaryLocationLineHash"]
            .as_str()
            .is_some_and(|value| !value.is_empty()));
    }
}
