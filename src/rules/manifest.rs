use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;

use crate::rules::common::make_finding_from_offsets;
use crate::rules::Rule;
use crate::{Finding, Language, Severity};

// ─── Shared seed entry ─────────────────────────────────────────────────────

struct SeedEntry {
    name: &'static str,
    crypto_algorithm: Option<&'static str>,
    confidence: f32,
}

const MANIFEST_PQ_CWE: &str = "CWE-327";
const MANIFEST_PQ_DESC: &str = "Dependency uses quantum-vulnerable cryptographic algorithm";
const MANIFEST_PQ_DEADLINE: &str = "2033";

/// Apply shared PQ fields to a manifest finding.
fn finalize_manifest_finding(f: &mut Finding, entry: &SeedEntry, pkg_name: &str) {
    f.tags = vec!["PQ".into()];
    f.crypto_algorithm = entry.crypto_algorithm.map(String::from);
    f.confidence = entry.confidence;
    f.dep_name = Some(pkg_name.to_string());
}

// ─── Cargo.lock seed database ───────────────────────────────────────────────

/// Tier 1: single-purpose crypto crates with a known algorithm.
/// Tier 2: multi-algorithm crates where we can't attribute one algorithm.
const CARGO_SEEDS: &[SeedEntry] = &[
    // Tier 1 — confidence 0.9, specific algorithm
    SeedEntry {
        name: "rsa",
        crypto_algorithm: Some("RSA"),
        confidence: 0.9,
    },
    SeedEntry {
        name: "p256",
        crypto_algorithm: Some("ECDSA"),
        confidence: 0.9,
    },
    SeedEntry {
        name: "p384",
        crypto_algorithm: Some("ECDSA"),
        confidence: 0.9,
    },
    SeedEntry {
        name: "ed25519-dalek",
        crypto_algorithm: Some("Ed25519"),
        confidence: 0.9,
    },
    SeedEntry {
        name: "x25519-dalek",
        crypto_algorithm: Some("X25519"),
        confidence: 0.9,
    },
    SeedEntry {
        name: "ecdsa",
        crypto_algorithm: Some("ECDSA"),
        confidence: 0.9,
    },
    // Tier 2 — confidence 0.6, mixed algorithms
    SeedEntry {
        name: "ring",
        crypto_algorithm: None,
        confidence: 0.6,
    },
    SeedEntry {
        name: "openssl-sys",
        crypto_algorithm: None,
        confidence: 0.6,
    },
    SeedEntry {
        name: "aws-lc-rs",
        crypto_algorithm: None,
        confidence: 0.6,
    },
];

// ─── requirements.txt curated list ──────────────────────────────────────────

const PIP_PACKAGES: &[SeedEntry] = &[
    SeedEntry {
        name: "python-rsa",
        crypto_algorithm: Some("RSA"),
        confidence: 0.95,
    },
    SeedEntry {
        name: "rsa",
        crypto_algorithm: Some("RSA"),
        confidence: 0.95,
    },
    SeedEntry {
        name: "ecdsa",
        crypto_algorithm: Some("ECDSA"),
        confidence: 0.95,
    },
    SeedEntry {
        name: "ed25519",
        crypto_algorithm: Some("Ed25519"),
        confidence: 0.95,
    },
    SeedEntry {
        name: "pynacl",
        crypto_algorithm: Some("Ed25519"),
        confidence: 0.9,
    },
    SeedEntry {
        name: "paramiko",
        crypto_algorithm: Some("RSA"),
        confidence: 0.8,
    },
    SeedEntry {
        name: "fabric",
        crypto_algorithm: Some("RSA"),
        confidence: 0.7,
    },
    SeedEntry {
        name: "cryptography",
        crypto_algorithm: None,
        confidence: 0.5,
    },
    SeedEntry {
        name: "pyopenssl",
        crypto_algorithm: None,
        confidence: 0.5,
    },
    SeedEntry {
        name: "pycryptodome",
        crypto_algorithm: None,
        confidence: 0.5,
    },
    SeedEntry {
        name: "pycryptodomex",
        crypto_algorithm: None,
        confidence: 0.5,
    },
];

// ─── Rule 1: Cargo.lock ─────────────────────────────────────────────────────

pub struct CargoLockPqCrypto;

impl Rule for CargoLockPqCrypto {
    fn id(&self) -> &str {
        "manifest/cargo-pq-vulnerable-dep"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cwe(&self) -> Option<&str> {
        Some(MANIFEST_PQ_CWE)
    }
    fn description(&self) -> &str {
        MANIFEST_PQ_DESC
    }
    fn language(&self) -> Language {
        Language::Manifest
    }
    fn cnsa2_deadline(&self) -> Option<&'static str> {
        Some(MANIFEST_PQ_DEADLINE)
    }

    fn applies_to_path(&self, path: &Path) -> bool {
        path.file_name().and_then(|f| f.to_str()) == Some("Cargo.lock")
    }

    fn check(&self, source: &str, _tree: &tree_sitter::Tree) -> Vec<Finding> {
        let Ok(doc) = source.parse::<toml::Value>() else {
            return Vec::new();
        };

        let Some(packages) = doc.get("package").and_then(|p| p.as_array()) else {
            return Vec::new();
        };

        // Build name→indices and adjacency list
        let mut name_to_indices: HashMap<&str, Vec<usize>> = HashMap::new();
        let mut graph: Vec<Vec<usize>> = Vec::with_capacity(packages.len());

        for (i, pkg) in packages.iter().enumerate() {
            if let Some(name) = pkg.get("name").and_then(|n| n.as_str()) {
                name_to_indices.entry(name).or_default().push(i);
            }
            graph.push(Vec::new());
        }

        // Build edges: package[i] depends on package[j]
        for (i, pkg) in packages.iter().enumerate() {
            if let Some(deps) = pkg.get("dependencies").and_then(|d| d.as_array()) {
                for dep in deps {
                    // Cargo.lock v4: "ring" or "windows-sys 0.61.2"
                    let dep_name = match dep.as_str() {
                        Some(s) => s.split_once(' ').map_or(s, |(name, _)| name),
                        None => continue,
                    };
                    if let Some(indices) = name_to_indices.get(dep_name) {
                        for &j in indices {
                            graph[i].push(j);
                        }
                    }
                }
            }
        }

        // Build seed index
        let seed_map: HashMap<&str, &SeedEntry> = CARGO_SEEDS.iter().map(|e| (e.name, e)).collect();

        let mut findings = Vec::new();

        // BFS from each package to find reachable seed crates
        for (i, pkg) in packages.iter().enumerate() {
            let pkg_name = match pkg.get("name").and_then(|n| n.as_str()) {
                Some(n) => n,
                None => continue,
            };

            // Don't flag seed crates themselves
            if seed_map.contains_key(pkg_name) {
                continue;
            }

            let mut visited = HashSet::new();
            let mut queue = VecDeque::new();
            visited.insert(i);
            queue.push_back(i);

            let mut reached_seeds: Vec<&SeedEntry> = Vec::new();

            while let Some(node) = queue.pop_front() {
                for &neighbor in &graph[node] {
                    if !visited.insert(neighbor) {
                        continue;
                    }
                    let Some(neighbor_name) =
                        packages[neighbor].get("name").and_then(|n| n.as_str())
                    else {
                        queue.push_back(neighbor);
                        continue;
                    };
                    if let Some(entry) = seed_map.get(neighbor_name) {
                        reached_seeds.push(entry);
                    } else {
                        queue.push_back(neighbor);
                    }
                }
            }

            if reached_seeds.is_empty() {
                continue;
            }

            // Pick the highest-confidence seed
            reached_seeds.sort_by(|a, b| b.confidence.total_cmp(&a.confidence));
            let best = reached_seeds.first().unwrap();

            // Find byte offset of this package entry.
            // Use name+version to disambiguate duplicate crate names (e.g. syn 1.x vs 2.x).
            let version_str = pkg.get("version").and_then(|v| v.as_str()).unwrap_or("?");
            let name_pat = format!("name = \"{}\"", pkg_name);
            let ver_pat = format!("version = \"{}\"", version_str);
            let Some((offset, end)) = find_name_version_offset(source, &name_pat, &ver_pat) else {
                continue;
            };

            let desc = if let Some(algo) = best.crypto_algorithm {
                format!(
                    "Crate `{}` transitively depends on `{}` (PQ-vulnerable {})",
                    pkg_name, best.name, algo
                )
            } else {
                format!(
                    "Crate `{}` transitively depends on `{}` (uses mixed classical cryptography)",
                    pkg_name, best.name
                )
            };

            let mut f = make_finding_from_offsets(
                self.id(),
                self.severity(),
                self.cwe(),
                &desc,
                source,
                offset,
                end,
            );
            finalize_manifest_finding(&mut f, best, pkg_name);
            findings.push(f);
        }

        findings
    }
}

// ─── Rule 2: requirements.txt ───────────────────────────────────────────────

pub struct RequirementsTxtPqCrypto;

impl Rule for RequirementsTxtPqCrypto {
    fn id(&self) -> &str {
        "manifest/pip-pq-vulnerable-dep"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cwe(&self) -> Option<&str> {
        Some(MANIFEST_PQ_CWE)
    }
    fn description(&self) -> &str {
        MANIFEST_PQ_DESC
    }
    fn language(&self) -> Language {
        Language::Manifest
    }
    fn cnsa2_deadline(&self) -> Option<&'static str> {
        Some(MANIFEST_PQ_DEADLINE)
    }

    fn applies_to_path(&self, path: &Path) -> bool {
        path.file_name().and_then(|f| f.to_str()) == Some("requirements.txt")
    }

    fn check(&self, source: &str, _tree: &tree_sitter::Tree) -> Vec<Finding> {
        let pip_map: HashMap<String, &SeedEntry> = PIP_PACKAGES
            .iter()
            .map(|e| (e.name.to_lowercase().replace(['_', '.'], "-"), e))
            .collect();

        let mut findings = Vec::new();
        let mut byte_offset = 0usize;

        for line in source.lines() {
            let line_start = byte_offset;
            let line_end = byte_offset + line.len();
            // Account for actual line ending: \r\n (2 bytes) or \n (1 byte)
            byte_offset = if source.as_bytes().get(line_end) == Some(&b'\r')
                && source.as_bytes().get(line_end + 1) == Some(&b'\n')
            {
                line_end + 2
            } else if matches!(source.as_bytes().get(line_end), Some(&b'\r') | Some(&b'\n')) {
                line_end + 1
            } else {
                line_end // EOF, no trailing newline
            };

            let trimmed = line.trim();

            // Skip blank, comments, options, URLs
            if trimmed.is_empty()
                || trimmed.starts_with('#')
                || trimmed.starts_with('-')
                || trimmed.starts_with("git+")
                || trimmed.starts_with("http://")
                || trimmed.starts_with("https://")
            {
                continue;
            }

            // Strip environment markers, then extract package name
            let before_marker = trimmed.split(';').next().unwrap_or(trimmed).trim();
            let pkg_name = extract_pip_package_name(before_marker);
            if pkg_name.is_empty() {
                continue;
            }

            // PEP 503: normalize hyphens/underscores/dots
            let lookup = pkg_name.to_lowercase().replace(['_', '.'], "-");

            if let Some(entry) = pip_map.get(lookup.as_str()) {
                let desc = if let Some(algo) = entry.crypto_algorithm {
                    format!("Package `{}` uses {} (PQ-vulnerable)", pkg_name, algo)
                } else {
                    format!(
                        "Package `{}` may use PQ-vulnerable algorithms (RSA, ECDSA, Ed25519)",
                        pkg_name
                    )
                };

                let mut f = make_finding_from_offsets(
                    self.id(),
                    self.severity(),
                    self.cwe(),
                    &desc,
                    source,
                    line_start,
                    line_end,
                );
                finalize_manifest_finding(&mut f, entry, pkg_name);

                if entry.crypto_algorithm.is_none() {
                    f.fix_suggestion = Some(format!(
                        "Review usage — `{}` also provides PQ-safe primitives (AES, SHA-256)",
                        pkg_name
                    ));
                }

                findings.push(f);
            }
        }

        findings
    }
}

/// Find the byte offset of a `name = "X"` / `version = "Y"` pair in source.
/// Handles both LF and CRLF line endings and disambiguates duplicate crate names.
fn find_name_version_offset(source: &str, name_pat: &str, ver_pat: &str) -> Option<(usize, usize)> {
    let mut search_from = 0;
    while let Some(pos) = source[search_from..].find(name_pat) {
        let abs = search_from + pos;
        let after_name = abs + name_pat.len();
        let rest = &source[after_name..];
        if rest.starts_with('\n') || rest.starts_with("\r\n") {
            let ver_start = after_name + if rest.starts_with("\r\n") { 2 } else { 1 };
            if source[ver_start..].starts_with(ver_pat) {
                return Some((abs, ver_start + ver_pat.len()));
            }
        }
        search_from = abs + 1;
    }
    None
}

/// Extract the package name from a requirements.txt line (before version
/// specifiers or extras brackets).
fn extract_pip_package_name(s: &str) -> &str {
    let end = s
        .find(|c: char| !c.is_alphanumeric() && c != '-' && c != '_' && c != '.')
        .unwrap_or(s.len());
    &s[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_pip_name_simple() {
        assert_eq!(extract_pip_package_name("requests"), "requests");
    }

    #[test]
    fn extract_pip_name_with_version() {
        assert_eq!(extract_pip_package_name("requests>=2.28"), "requests");
        assert_eq!(extract_pip_package_name("rsa==4.9"), "rsa");
    }

    #[test]
    fn extract_pip_name_with_extras() {
        assert_eq!(extract_pip_package_name("fabric[ssh]>=3.0"), "fabric");
    }

    #[test]
    fn extract_pip_name_with_dots_and_underscores() {
        assert_eq!(
            extract_pip_package_name("my.package_name>=1.0"),
            "my.package_name"
        );
    }
}
