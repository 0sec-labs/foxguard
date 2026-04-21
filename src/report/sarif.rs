use crate::Finding;
use serde_json::json;

/// Encode a file path as a URI suitable for SARIF `artifactLocation.uri`.
/// Normalizes backslashes to forward slashes and percent-encodes characters
/// that are not valid in URI path segments.
fn path_to_uri(path: &str) -> String {
    let normalized = path.replace('\\', "/");
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
    format!("file://{encoded}")
}

pub fn print_sarif(findings: &[Finding]) {
    let results: Vec<_> = findings
        .iter()
        .map(|f| {
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

            // SARIF `rank` is a native 0.0..=100.0 ordering hint. Map
            // confidence linearly so 1.0 → 100 and 0.0 → 0.
            let rank = clamped_conf as f64 * 100.0;

            let mut result = json!({
                "ruleId": f.rule_id,
                "level": match f.severity {
                    crate::Severity::Critical | crate::Severity::High => "error",
                    crate::Severity::Medium => "warning",
                    crate::Severity::Low => "note",
                },
                "rank": rank,
                "message": {
                    "text": f.description
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": path_to_uri(&f.file)
                        },
                        "region": {
                            "startLine": f.line,
                            "startColumn": f.column,
                            "endLine": f.end_line,
                            "endColumn": f.end_column
                        }
                    }
                }],
                "properties": props
            });

            if let Some(fix) = &f.fix_suggestion {
                result["fixes"] = json!([{
                    "description": {
                        "text": fix
                    }
                }]);
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
                    "informationUri": "https://foxguard.dev"
                }
            },
            "results": results
        }]
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&sarif).expect("Failed to serialize SARIF")
    );
}
