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
            if let Some(cwe) = &f.cwe {
                props.insert("tags".to_string(), json!([cwe]));
            }

            let mut result = json!({
                "ruleId": f.rule_id,
                "level": match f.severity {
                    crate::Severity::Critical | crate::Severity::High => "error",
                    crate::Severity::Medium => "warning",
                    crate::Severity::Low => "note",
                },
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
