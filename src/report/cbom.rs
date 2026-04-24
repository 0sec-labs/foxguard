use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::json;
use uuid::Uuid;

use crate::Finding;

/// CycloneDX 1.6 crypto asset properties, looked up by algorithm name.
struct CryptoProps {
    asset_type: &'static str,
    primitive: Option<&'static str>,
    functions: &'static [&'static str],
    protocol_type: Option<&'static str>,
}

fn crypto_props(algo: &str) -> CryptoProps {
    match algo {
        "RSA" => CryptoProps {
            asset_type: "algorithm",
            primitive: Some("pk-encryption"),
            functions: &["encrypt", "sign"],
            protocol_type: None,
        },
        "ECDSA" | "DSA" | "Ed25519" | "Ed448" => CryptoProps {
            asset_type: "algorithm",
            primitive: Some("signature"),
            functions: &["sign", "verify"],
            protocol_type: None,
        },
        "ECDH" | "DH" | "X25519" | "X448" => CryptoProps {
            asset_type: "algorithm",
            primitive: Some("key-agree"),
            functions: &["keyagree"],
            protocol_type: None,
        },
        "AES" | "AES-CBC" | "AES-GCM" | "DES" | "3DES" | "Blowfish" | "RC4" | "RC2" => {
            CryptoProps {
                asset_type: "algorithm",
                primitive: Some("block-cipher"),
                functions: &["encrypt", "decrypt"],
                protocol_type: None,
            }
        }
        "MD5" | "SHA1" | "SHA-1" => CryptoProps {
            asset_type: "algorithm",
            primitive: Some("hash"),
            functions: &["digest"],
            protocol_type: None,
        },
        "TLS" => CryptoProps {
            asset_type: "protocol",
            primitive: None,
            functions: &[],
            protocol_type: Some("tls"),
        },
        _ => CryptoProps {
            asset_type: "related-crypto-material",
            primitive: None,
            functions: &[],
            protocol_type: None,
        },
    }
}

fn build_component(
    algo: &str,
    bom_ref: &str,
    findings: &[&Finding],
    props: &CryptoProps,
) -> serde_json::Value {
    let occurrences: Vec<_> = findings
        .iter()
        .map(|f| {
            json!({
                "location": format!("{}:{}:{}", f.file, f.line, f.column),
                "additionalContext": f.snippet.trim()
            })
        })
        .collect();

    let mut crypto_properties = json!({ "assetType": props.asset_type });

    if props.asset_type == "algorithm" {
        let mut algo_props = serde_json::Map::new();
        if let Some(prim) = props.primitive {
            algo_props.insert("primitive".to_string(), json!(prim));
        }
        if !props.functions.is_empty() {
            algo_props.insert("cryptoFunctions".to_string(), json!(props.functions));
        }
        crypto_properties["algorithmProperties"] = json!(algo_props);
    } else if props.asset_type == "protocol" {
        if let Some(proto) = props.protocol_type {
            crypto_properties["protocolProperties"] = json!({ "type": proto });
        }
    }

    json!({
        "type": "cryptographic-asset",
        "bom-ref": bom_ref,
        "name": algo,
        "cryptoProperties": crypto_properties,
        "evidence": {
            "occurrences": occurrences
        }
    })
}

fn build_vulnerability(algo: &str, bom_ref: &str, findings: &[&Finding]) -> serde_json::Value {
    // Use the highest severity from the group
    let max_severity = findings
        .iter()
        .map(|f| f.severity)
        .max()
        .unwrap_or(crate::Severity::Low);

    let severity_str = match max_severity {
        crate::Severity::Critical => "critical",
        crate::Severity::High => "high",
        crate::Severity::Medium => "medium",
        crate::Severity::Low => "low",
    };

    // Collect unique CWEs
    let cwes: Vec<u32> = findings
        .iter()
        .filter_map(|f| f.cwe.as_ref())
        .filter_map(|c| c.strip_prefix("CWE-").and_then(|n| n.parse().ok()))
        .collect::<std::collections::BTreeSet<u32>>()
        .into_iter()
        .collect();

    // Use first available fix suggestion as recommendation
    let recommendation = findings
        .iter()
        .find_map(|f| f.fix_suggestion.as_ref())
        .cloned()
        .or_else(|| findings.first().map(|f| f.description.clone()))
        .unwrap_or_default();

    let mut vuln = json!({
        "id": format!("foxguard-{}", algo.to_lowercase()),
        "source": { "name": "foxguard" },
        "ratings": [{ "severity": severity_str, "method": "other" }],
        "description": findings.first().map(|f| f.description.as_str()).unwrap_or(""),
        "affects": [{ "ref": bom_ref }],
        "recommendation": recommendation
    });

    if !cwes.is_empty() {
        vuln["cwes"] = json!(cwes);
    }

    vuln
}

fn iso8601_now() -> String {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();

    // Manual UTC breakdown (no chrono dependency)
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Days since 1970-01-01 to Y-M-D
    let mut y = 1970i64;
    let mut remaining = days as i64;
    loop {
        let days_in_year = if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) {
            366
        } else {
            365
        };
        if remaining < days_in_year {
            break;
        }
        remaining -= days_in_year;
        y += 1;
    }
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let month_days: [i64; 12] = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut m = 0usize;
    for (i, &md) in month_days.iter().enumerate() {
        if remaining < md {
            m = i;
            break;
        }
        remaining -= md;
    }

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m + 1,
        remaining + 1,
        hours,
        minutes,
        seconds
    )
}

/// Build a deterministic RFC 4122 UUIDv5 from the given data.
///
/// Uses the OID namespace so two invocations with identical component data
/// always produce the same serial number, while keeping the correct UUID
/// version (0x5) and variant (RFC 4122) bits.
fn deterministic_uuid(data: &str) -> String {
    Uuid::new_v5(&Uuid::NAMESPACE_OID, data.as_bytes()).to_string()
}

/// Build the CBOM JSON value from the supplied findings.
///
/// Pure function: returns a `serde_json::Value`. Separated from [`print_cbom`]
/// so tests can inspect the structured output without capturing stdout.
pub fn build_cbom(findings: &[Finding]) -> (serde_json::Value, bool) {
    // Group findings by crypto_algorithm
    let mut groups: BTreeMap<String, Vec<&Finding>> = BTreeMap::new();
    for f in findings {
        if let Some(algo) = &f.crypto_algorithm {
            groups.entry(algo.clone()).or_default().push(f);
        }
    }

    let empty_but_findings_present = groups.is_empty() && !findings.is_empty();

    let mut components = Vec::new();
    let mut vulnerabilities = Vec::new();

    for (algo, group_findings) in &groups {
        let bom_ref = format!("crypto-{}", algo.to_lowercase().replace(' ', "-"));
        let props = crypto_props(algo);

        components.push(build_component(algo, &bom_ref, group_findings, &props));
        vulnerabilities.push(build_vulnerability(algo, &bom_ref, group_findings));
    }

    let components_json = serde_json::to_string(&components).unwrap_or_default();
    let serial = deterministic_uuid(&components_json);

    let cbom = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "serialNumber": format!("urn:uuid:{serial}"),
        "metadata": {
            "timestamp": iso8601_now(),
            "tools": {
                "components": [{
                    "type": "application",
                    "name": "foxguard",
                    "version": env!("CARGO_PKG_VERSION")
                }]
            }
        },
        "components": components,
        "vulnerabilities": vulnerabilities
    });

    (cbom, empty_but_findings_present)
}

/// Serialize findings to a pretty-printed CycloneDX 1.6 CBOM JSON string.
#[cfg(test)]
fn serialize_cbom(findings: &[Finding]) -> String {
    let (cbom, _) = build_cbom(findings);
    serde_json::to_string_pretty(&cbom).expect("Failed to serialize CBOM")
}

/// Print findings as a CycloneDX 1.6 Cryptographic Bill of Materials (CBOM).
///
/// Only findings with `crypto_algorithm` set are included. Findings are
/// grouped by algorithm name into components, with linked vulnerability
/// entries.
pub fn print_cbom(findings: &[Finding]) {
    let (cbom, empty_but_findings_present) = build_cbom(findings);

    if empty_but_findings_present {
        eprintln!(
            "Warning: no cryptographic findings detected; CBOM is empty. \
             Use 'foxguard pqc' to scan for quantum-vulnerable cryptography."
        );
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&cbom).expect("Failed to serialize CBOM")
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_crypto_finding(algo: &str, file: &str, line: usize) -> Finding {
        Finding {
            rule_id: format!("test/pq-vulnerable-{}", algo.to_lowercase()),
            severity: crate::Severity::High,
            cwe: Some("CWE-327".to_string()),
            description: format!("{algo} is quantum-vulnerable"),
            file: file.to_string(),
            line,
            column: 1,
            end_line: line,
            end_column: 10,
            snippet: format!("use_{}()", algo.to_lowercase()),
            source_line: None,
            source_description: None,
            sink_line: None,
            sink_description: None,
            fix_suggestion: Some(format!("Migrate from {algo} to ML-KEM")),
            sink_start_byte: None,
            sink_end_byte: None,
            confidence: 1.0,
            taint_hops: None,
            tags: vec!["PQ".to_string()],
            crypto_algorithm: Some(algo.to_string()),
            cnsa2_deadline: None,
            dep_name: None,
        }
    }

    #[test]
    fn cbom_groups_by_algorithm() {
        let findings = vec![
            make_crypto_finding("RSA", "src/auth.py", 10),
            make_crypto_finding("RSA", "src/crypto.py", 42),
            make_crypto_finding("ECDSA", "src/sign.py", 5),
        ];

        let mut groups: BTreeMap<String, Vec<&Finding>> = BTreeMap::new();
        for f in &findings {
            if let Some(algo) = &f.crypto_algorithm {
                groups.entry(algo.clone()).or_default().push(f);
            }
        }

        assert_eq!(groups.len(), 2);
        assert_eq!(groups["RSA"].len(), 2);
        assert_eq!(groups["ECDSA"].len(), 1);
    }

    #[test]
    fn cbom_empty_without_crypto_findings() {
        let findings = [Finding {
            rule_id: "py/no-eval".to_string(),
            severity: crate::Severity::High,
            cwe: Some("CWE-95".to_string()),
            description: "eval() is dangerous".to_string(),
            file: "app.py".to_string(),
            line: 1,
            column: 1,
            end_line: 1,
            end_column: 10,
            snippet: "eval(x)".to_string(),
            source_line: None,
            source_description: None,
            sink_line: None,
            sink_description: None,
            fix_suggestion: None,
            sink_start_byte: None,
            sink_end_byte: None,
            confidence: 1.0,
            taint_hops: None,
            tags: vec![],
            crypto_algorithm: None,
            cnsa2_deadline: None,
            dep_name: None,
        }];

        let groups: BTreeMap<String, Vec<&Finding>> = findings
            .iter()
            .filter_map(|f| f.crypto_algorithm.as_ref().map(|a| (a.clone(), f)))
            .fold(BTreeMap::new(), |mut acc, (algo, f)| {
                acc.entry(algo).or_default().push(f);
                acc
            });

        assert!(groups.is_empty());
    }

    #[test]
    fn iso8601_format_is_valid() {
        let ts = iso8601_now();
        assert!(ts.ends_with('Z'));
        assert_eq!(ts.len(), 20); // "2026-04-19T12:34:56Z"
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[7..8], "-");
        assert_eq!(&ts[10..11], "T");
    }

    #[test]
    fn deterministic_uuid_is_stable() {
        let input = r#"[{"name":"RSA"}]"#;
        let u1 = deterministic_uuid(input);
        let u2 = deterministic_uuid(input);
        assert_eq!(u1, u2);
        assert_eq!(u1.len(), 36); // UUID format: 8-4-4-4-12

        // Parse as RFC 4122 UUID and check version/variant bits.
        let parsed = Uuid::parse_str(&u1).expect("deterministic_uuid emits valid RFC 4122 UUID");
        assert_eq!(parsed.get_version_num(), 5);
        assert_eq!(parsed.get_variant(), uuid::Variant::RFC4122);
    }

    #[test]
    fn deterministic_uuid_changes_with_input() {
        let a = deterministic_uuid(r#"[{"name":"RSA"}]"#);
        let b = deterministic_uuid(r#"[{"name":"ECDSA"}]"#);
        assert_ne!(a, b);
    }

    /// Golden-fixture test: construct findings, serialize to CBOM, parse the
    /// resulting JSON, and assert the structural shape (serial number,
    /// components[].cryptoProperties, vulnerabilities[]).
    #[test]
    fn cbom_serialization_shape_is_valid() {
        let findings = vec![
            make_crypto_finding("RSA", "src/auth.py", 10),
            make_crypto_finding("RSA", "src/crypto.py", 42),
            make_crypto_finding("ECDSA", "src/sign.py", 5),
        ];

        let json_str = serialize_cbom(&findings);
        let v: serde_json::Value =
            serde_json::from_str(&json_str).expect("CBOM output is valid JSON");

        // Top-level CycloneDX shape
        assert_eq!(v["bomFormat"], "CycloneDX");
        assert_eq!(v["specVersion"], "1.6");
        assert_eq!(v["version"], 1);

        // Serial number: urn:uuid:<valid RFC 4122 UUID>
        let serial = v["serialNumber"]
            .as_str()
            .expect("serialNumber is a string");
        let uuid_part = serial
            .strip_prefix("urn:uuid:")
            .expect("serialNumber starts with urn:uuid:");
        let parsed = Uuid::parse_str(uuid_part).expect("serial number is a valid RFC 4122 UUID");
        assert_eq!(parsed.get_version_num(), 5);
        assert_eq!(parsed.get_variant(), uuid::Variant::RFC4122);

        // Metadata presence
        assert!(v["metadata"]["timestamp"].is_string());
        assert!(v["metadata"]["tools"]["components"][0]["name"]
            .as_str()
            .unwrap()
            .contains("foxguard"));

        // Components: grouped by algorithm (RSA + ECDSA = 2 components)
        let components = v["components"].as_array().expect("components is an array");
        assert_eq!(components.len(), 2);
        let names: std::collections::BTreeSet<&str> = components
            .iter()
            .map(|c| c["name"].as_str().unwrap())
            .collect();
        assert!(names.contains("RSA"));
        assert!(names.contains("ECDSA"));

        for component in components {
            assert_eq!(component["type"], "cryptographic-asset");
            assert!(component["bom-ref"].is_string());
            let crypto_props = &component["cryptoProperties"];
            assert_eq!(crypto_props["assetType"], "algorithm");
            // RSA and ECDSA both have algorithmProperties with primitive + functions
            let algo_props = &crypto_props["algorithmProperties"];
            assert!(algo_props["primitive"].is_string());
            assert!(algo_props["cryptoFunctions"].is_array());
            // Evidence.occurrences carries at least one file/line/column.
            let occurrences = component["evidence"]["occurrences"]
                .as_array()
                .expect("occurrences is an array");
            assert!(!occurrences.is_empty());
            for occ in occurrences {
                assert!(occ["location"].as_str().unwrap().contains(':'));
            }
        }

        // RSA should have two occurrences (grouped from two findings)
        let rsa_component = components
            .iter()
            .find(|c| c["name"] == "RSA")
            .expect("RSA component present");
        assert_eq!(
            rsa_component["evidence"]["occurrences"]
                .as_array()
                .unwrap()
                .len(),
            2
        );

        // Vulnerabilities: one per algorithm group
        let vulns = v["vulnerabilities"]
            .as_array()
            .expect("vulnerabilities is an array");
        assert_eq!(vulns.len(), 2);
        for vuln in vulns {
            assert!(vuln["id"].as_str().unwrap().starts_with("foxguard-"));
            assert_eq!(vuln["source"]["name"], "foxguard");
            let ratings = vuln["ratings"].as_array().unwrap();
            assert_eq!(ratings[0]["severity"], "high");
            assert!(vuln["affects"][0]["ref"].is_string());
            assert!(vuln["cwes"].is_array());
        }
    }
}
