use std::collections::{HashMap, HashSet, VecDeque};

use crate::impl_rule;
use crate::rules::common::make_finding_from_offsets;
use crate::{Finding, Language, Severity};

// ─── Shared seed entry ─────────────────────────────────────────────────────

struct SeedEntry {
    name: &'static str,
    crypto_algorithm: Option<&'static str>,
    confidence: f32,
}

const MANIFEST_PQ_CWE: &str = "CWE-327";
const MANIFEST_PQ_DESC: &str = "Dependency uses quantum-vulnerable cryptographic algorithm";
const CARGO_PQ_DESC: &str =
    "Dependency uses quantum-vulnerable cryptographic algorithm (dev-dependencies not distinguished)";
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
    SeedEntry {
        name: "k256",
        crypto_algorithm: Some("ECDSA"),
        confidence: 0.9,
    },
    SeedEntry {
        name: "secp256k1",
        crypto_algorithm: Some("ECDSA"),
        confidence: 0.9,
    },
    SeedEntry {
        name: "libsecp256k1",
        crypto_algorithm: Some("ECDSA"),
        confidence: 0.9,
    },
    SeedEntry {
        name: "ed448-goldilocks",
        crypto_algorithm: Some("Ed448"),
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
        name: "openssl",
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
        name: "pyjwt",
        crypto_algorithm: None,
        confidence: 0.8,
    },
    SeedEntry {
        name: "authlib",
        crypto_algorithm: None,
        confidence: 0.8,
    },
    SeedEntry {
        name: "python-jose",
        crypto_algorithm: None,
        confidence: 0.8,
    },
    SeedEntry {
        name: "jwcrypto",
        crypto_algorithm: None,
        confidence: 0.8,
    },
    SeedEntry {
        name: "fabric",
        crypto_algorithm: None,
        confidence: 0.7,
    },
    SeedEntry {
        name: "m2crypto",
        crypto_algorithm: None,
        confidence: 0.6,
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

impl_rule! {
    CargoLockPqCrypto,
    id = "manifest/cargo-pq-vulnerable-dep",
    severity = Severity::High,
    cwe = Some(MANIFEST_PQ_CWE),
    description = CARGO_PQ_DESC,
    language = Language::Manifest,
    cnsa2_deadline = MANIFEST_PQ_DEADLINE,
    applies_to_filename = "Cargo.lock",
    fn check(_self, source, _tree) {
        let Ok(doc) = source.parse::<toml::Value>() else {
            return Vec::new();
        };

        let Some(packages) = doc.get("package").and_then(|p| p.as_array()) else {
            return Vec::new();
        };

        // Build lookup indices and adjacency list.
        // name_to_indices: all indices for a given crate name (may have multiple versions).
        // name_ver_to_index: exact (name, version) → index for version-qualified dep strings.
        let mut name_to_indices: HashMap<&str, Vec<usize>> = HashMap::new();
        let mut name_ver_to_index: HashMap<(&str, &str), usize> = HashMap::new();
        let mut graph: Vec<Vec<usize>> = Vec::with_capacity(packages.len());

        for (i, pkg) in packages.iter().enumerate() {
            if let Some(name) = pkg.get("name").and_then(|n| n.as_str()) {
                name_to_indices.entry(name).or_default().push(i);
                if let Some(ver) = pkg.get("version").and_then(|v| v.as_str()) {
                    name_ver_to_index.insert((name, ver), i);
                }
            }
            graph.push(Vec::new());
        }

        // Build edges: package[i] depends on package[j]
        for (i, pkg) in packages.iter().enumerate() {
            if let Some(deps) = pkg.get("dependencies").and_then(|d| d.as_array()) {
                for dep in deps {
                    let dep_str = match dep.as_str() {
                        Some(s) => s,
                        None => continue,
                    };
                    // Cargo.lock v4: "ring" (unqualified) or "syn 2.0.0" (version-qualified)
                    if let Some((name, ver)) = dep_str.split_once(' ') {
                        // Version-qualified: resolve to exact package
                        if let Some(&j) = name_ver_to_index.get(&(name, ver)) {
                            graph[i].push(j);
                        }
                    } else {
                        // Unqualified: name is unique in the lockfile
                        if let Some(indices) = name_to_indices.get(dep_str) {
                            for &j in indices {
                                graph[i].push(j);
                            }
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

            let mut reached_seeds: HashMap<&str, &SeedEntry> = HashMap::new();

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
                        reached_seeds
                            .entry(entry.name)
                            .and_modify(|existing| {
                                if entry.confidence > existing.confidence {
                                    *existing = entry;
                                }
                            })
                            .or_insert(entry);
                    } else {
                        queue.push_back(neighbor);
                    }
                }
            }

            if reached_seeds.is_empty() {
                continue;
            }

            // Pick the highest-confidence seed
            let Some((_, best)) = reached_seeds.iter().max_by(|(k1, v1), (k2, v2)| {
                v1.confidence
                    .total_cmp(&v2.confidence)
                    .then_with(|| k1.cmp(k2))
            }) else {
                continue;
            };

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
                _self.id(),
                _self.severity(),
                _self.cwe(),
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

impl_rule! {
    RequirementsTxtPqCrypto,
    id = "manifest/pip-pq-vulnerable-dep",
    severity = Severity::High,
    cwe = Some(MANIFEST_PQ_CWE),
    description = MANIFEST_PQ_DESC,
    language = Language::Manifest,
    cnsa2_deadline = MANIFEST_PQ_DEADLINE,
    applies_to_filename = "requirements.txt",
    fn check(_self, source, _tree) {
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
                    _self.id(),
                    _self.severity(),
                    _self.cwe(),
                    &desc,
                    source,
                    line_start,
                    line_end,
                );
                finalize_manifest_finding(&mut f, entry, pkg_name);

                if entry.crypto_algorithm.is_none() && entry.confidence <= 0.6 {
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

// ─── NPM seed database ────────────────────────────────────────────────────

const NPM_PACKAGES: &[SeedEntry] = &[
    SeedEntry {
        name: "node-rsa",
        crypto_algorithm: Some("RSA"),
        confidence: 0.95,
    },
    SeedEntry {
        name: "rsa",
        crypto_algorithm: Some("RSA"),
        confidence: 0.95,
    },
    SeedEntry {
        name: "elliptic",
        crypto_algorithm: Some("ECDSA"),
        confidence: 0.95,
    },
    SeedEntry {
        name: "secp256k1",
        crypto_algorithm: Some("ECDSA"),
        confidence: 0.95,
    },
    SeedEntry {
        name: "ed25519",
        crypto_algorithm: Some("Ed25519"),
        confidence: 0.95,
    },
    SeedEntry {
        name: "tweetnacl",
        crypto_algorithm: Some("Ed25519"),
        confidence: 0.9,
    },
    SeedEntry {
        name: "libsodium-wrappers",
        crypto_algorithm: Some("Ed25519"),
        confidence: 0.9,
    },
    SeedEntry {
        name: "jsonwebtoken",
        crypto_algorithm: None,
        confidence: 0.8,
    },
    SeedEntry {
        name: "jose",
        crypto_algorithm: None,
        confidence: 0.8,
    },
    SeedEntry {
        name: "node-jose",
        crypto_algorithm: None,
        confidence: 0.8,
    },
    SeedEntry {
        name: "ssh2",
        crypto_algorithm: None,
        confidence: 0.7,
    },
    SeedEntry {
        name: "node-forge",
        crypto_algorithm: None,
        confidence: 0.6,
    },
    SeedEntry {
        name: "crypto-js",
        crypto_algorithm: None,
        confidence: 0.5,
    },
];

// ─── Shared helper: flat dependency check against a seed list ──────────────
//
// poetry.lock, Pipfile.lock, pnpm-lock.yaml, and package-lock.json all
// enumerate packages without a full dependency graph — unlike Cargo.lock's
// `dependencies` arrays. For these formats we match each declared package
// directly against the relevant seed list (PIP_PACKAGES for Python,
// NPM_PACKAGES for Node).
//
// This is strictly *direct* matching: a package named "paramiko" is checked
// against the seed list, but we cannot know whether "flask" transitively
// depends on "paramiko". Transitive analysis would require building a full
// dependency graph, which not all formats support equally. Direct matching
// still covers the vast majority of cases because the seed lists include
// both leaf crypto libraries and higher-level wrappers.

fn check_flat_deps(
    rule: &dyn crate::rules::Rule,
    source: &str,
    seeds: &HashMap<String, &SeedEntry>,
    packages: &[(String, usize, usize)], // (normalized_name, start_byte, end_byte)
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (lookup, start, end) in packages {
        if let Some(entry) = seeds.get(lookup.as_str()) {
            let desc = if let Some(algo) = entry.crypto_algorithm {
                format!("Package `{}` uses {} (PQ-vulnerable)", entry.name, algo)
            } else {
                format!(
                    "Package `{}` may use PQ-vulnerable algorithms (RSA, ECDSA, Ed25519)",
                    entry.name
                )
            };

            let mut f = make_finding_from_offsets(
                rule.id(),
                rule.severity(),
                rule.cwe(),
                &desc,
                source,
                *start,
                *end,
            );
            finalize_manifest_finding(&mut f, entry, entry.name);

            if entry.crypto_algorithm.is_none() && entry.confidence <= 0.6 {
                f.fix_suggestion = Some(format!(
                    "Review usage — `{}` also provides PQ-safe primitives (AES, SHA-256)",
                    entry.name
                ));
            }

            findings.push(f);
        }
    }

    findings
}

/// Build a PEP 503-normalized seed map from PIP_PACKAGES.
fn pip_seed_map() -> HashMap<String, &'static SeedEntry> {
    PIP_PACKAGES
        .iter()
        .map(|e| (e.name.to_lowercase().replace(['_', '.'], "-"), e))
        .collect()
}

/// Build a normalized seed map from NPM_PACKAGES.
fn npm_seed_map() -> HashMap<String, &'static SeedEntry> {
    NPM_PACKAGES
        .iter()
        .map(|e| (e.name.to_string(), e))
        .collect()
}

// ─── Rule 3: poetry.lock (Python/Poetry) ───────────────────────────────────

pub struct PoetryLockPqCrypto;

impl_rule! {
    PoetryLockPqCrypto,
    id = "manifest/poetry-pq-vulnerable-dep",
    severity = Severity::High,
    cwe = Some(MANIFEST_PQ_CWE),
    description = MANIFEST_PQ_DESC,
    language = Language::Manifest,
    cnsa2_deadline = MANIFEST_PQ_DEADLINE,
    applies_to_filename = "poetry.lock",
    fn check(_self, source, _tree) {
        // poetry.lock is TOML with [[package]] sections containing
        // name and version fields.
        let Ok(doc) = source.parse::<toml::Value>() else {
            return Vec::new();
        };

        let Some(packages) = doc.get("package").and_then(|p| p.as_array()) else {
            return Vec::new();
        };

        let seeds = pip_seed_map();
        let mut parsed = Vec::new();

        for pkg in packages {
            let Some(name) = pkg.get("name").and_then(|n| n.as_str()) else {
                continue;
            };

            // PEP 503 normalize
            let lookup = name.to_lowercase().replace(['_', '.'], "-");

            // Find the byte offset of this package name in the source.
            let name_pat = format!("name = \"{}\"", name);
            if let Some(offset) = source.find(&name_pat) {
                parsed.push((lookup, offset, offset + name_pat.len()));
            }
        }

        check_flat_deps(_self, source, &seeds, &parsed)
    }
}

// ─── Rule 4: Pipfile.lock (Python/Pipenv) ──────────────────────────────────

pub struct PipfileLockPqCrypto;

impl_rule! {
    PipfileLockPqCrypto,
    id = "manifest/pipfile-pq-vulnerable-dep",
    severity = Severity::High,
    cwe = Some(MANIFEST_PQ_CWE),
    description = MANIFEST_PQ_DESC,
    language = Language::Manifest,
    cnsa2_deadline = MANIFEST_PQ_DEADLINE,
    applies_to_filename = "Pipfile.lock",
    fn check(_self, source, _tree) {
        // Pipfile.lock is JSON with "default" and "develop" sections,
        // each mapping package names to their metadata.
        let Ok(doc) = serde_json::from_str::<serde_json::Value>(source) else {
            return Vec::new();
        };

        let seeds = pip_seed_map();
        let mut parsed = Vec::new();

        for section in ["default", "develop"] {
            if let Some(deps) = doc.get(section).and_then(|s| s.as_object()) {
                for pkg_name in deps.keys() {
                    let lookup = pkg_name.to_lowercase().replace(['_', '.'], "-");

                    // Find the byte offset of this package key in the source.
                    let key_pat = format!("\"{}\"", pkg_name);
                    if let Some(offset) = source.find(&key_pat) {
                        parsed.push((lookup, offset, offset + key_pat.len()));
                    }
                }
            }
        }

        check_flat_deps(_self, source, &seeds, &parsed)
    }
}

// ─── Rule 5: pnpm-lock.yaml (Node/pnpm) ───────────────────────────────────

pub struct PnpmLockPqCrypto;

impl_rule! {
    PnpmLockPqCrypto,
    id = "manifest/pnpm-pq-vulnerable-dep",
    severity = Severity::High,
    cwe = Some(MANIFEST_PQ_CWE),
    description = MANIFEST_PQ_DESC,
    language = Language::Manifest,
    cnsa2_deadline = MANIFEST_PQ_DEADLINE,
    applies_to_filename = "pnpm-lock.yaml",
    fn check(_self, source, _tree) {
        // pnpm-lock.yaml has a `packages` mapping. Keys are package
        // specifiers like "/elliptic@6.5.4" (v6) or "elliptic@6.5.4" (v9).
        let Ok(doc) = serde_yaml_ng::from_str::<serde_yaml_ng::Value>(source) else {
            return Vec::new();
        };

        let seeds = npm_seed_map();
        let mut parsed = Vec::new();

        if let Some(packages) = doc.get("packages").and_then(|p| p.as_mapping()) {
            for key in packages.keys() {
                let Some(key_str) = key.as_str() else {
                    continue;
                };

                // Extract package name from specifier. Formats:
                //   "/elliptic@6.5.4"  (pnpm v6-v8)
                //   "elliptic@6.5.4"   (pnpm v9)
                //   "/@scope/pkg@1.0"  (scoped, v6-v8)
                //   "@scope/pkg@1.0"   (scoped, v9)
                let stripped = key_str.strip_prefix('/').unwrap_or(key_str);
                let pkg_name = if let Some(after_scope) = stripped.strip_prefix('@') {
                    // Scoped: find the second '@' (version separator)
                    if let Some(at_pos) = after_scope.find('@') {
                        &stripped[..at_pos + 1]
                    } else {
                        stripped
                    }
                } else if let Some(at_pos) = stripped.find('@') {
                    &stripped[..at_pos]
                } else {
                    stripped
                };

                let lookup = pkg_name.to_string();

                // Find the byte offset of this key in the source.
                if let Some(offset) = source.find(key_str) {
                    let name_end = offset + key_str.len();
                    parsed.push((lookup, offset, name_end));
                }
            }
        }

        check_flat_deps(_self, source, &seeds, &parsed)
    }
}

// ─── Rule 6: package-lock.json (Node/npm) ──────────────────────────────────

pub struct PackageLockPqCrypto;

impl_rule! {
    PackageLockPqCrypto,
    id = "manifest/npm-pq-vulnerable-dep",
    severity = Severity::High,
    cwe = Some(MANIFEST_PQ_CWE),
    description = MANIFEST_PQ_DESC,
    language = Language::Manifest,
    cnsa2_deadline = MANIFEST_PQ_DEADLINE,
    applies_to_filename = "package-lock.json",
    fn check(_self, source, _tree) {
        // package-lock.json (v2/v3) has "packages" with keys like
        // "node_modules/elliptic". Older v1 has "dependencies" at
        // the top level.
        let Ok(doc) = serde_json::from_str::<serde_json::Value>(source) else {
            return Vec::new();
        };

        let seeds = npm_seed_map();
        let mut parsed = Vec::new();
        let mut seen = HashSet::new();

        // v2/v3: "packages" section
        if let Some(packages) = doc.get("packages").and_then(|p| p.as_object()) {
            for key in packages.keys() {
                // Keys: "node_modules/elliptic", "node_modules/@scope/pkg", ""
                // Extract the package name from the key path.
                let pkg_name = if key.is_empty() {
                    continue; // root package entry
                } else if let Some(last) = key.rsplit_once("node_modules/") {
                    last.1
                } else {
                    key.as_str()
                };

                if pkg_name.is_empty() || !seen.insert(pkg_name.to_string()) {
                    continue;
                }

                let lookup = pkg_name.to_string();

                // Find byte offset of this key in source.
                let key_pat = format!("\"{}\"", key);
                if let Some(offset) = source.find(&key_pat) {
                    parsed.push((lookup, offset, offset + key_pat.len()));
                }
            }
        }

        // v1 fallback: "dependencies" section (flat key → object)
        if parsed.is_empty() {
            if let Some(deps) = doc.get("dependencies").and_then(|d| d.as_object()) {
                for pkg_name in deps.keys() {
                    if !seen.insert(pkg_name.to_string()) {
                        continue;
                    }

                    let lookup = pkg_name.to_string();
                    let key_pat = format!("\"{}\"", pkg_name);
                    // Skip the first occurrence which is the top-level "dependencies" key
                    // by searching after the "dependencies" key itself.
                    if let Some(deps_offset) = source.find("\"dependencies\"") {
                        if let Some(offset) = source[deps_offset..].find(&key_pat) {
                            let abs = deps_offset + offset;
                            parsed.push((lookup, abs, abs + key_pat.len()));
                        }
                    }
                }
            }
        }

        check_flat_deps(_self, source, &seeds, &parsed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::parser::parse_file;
    use crate::rules::Rule;

    fn dummy_tree(source: &str) -> tree_sitter::Tree {
        parse_file(source, Language::Manifest).expect("parse")
    }

    // ─── extract_pip_package_name ───────────────────────────────────────

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

    // ─── find_name_version_offset ──────────────────────────────────────

    #[test]
    fn offset_finds_exact_pair() {
        let src = "[[package]]\nname = \"foo\"\nversion = \"1.0\"\n";
        let r = find_name_version_offset(src, "name = \"foo\"", "version = \"1.0\"");
        assert_eq!(r, Some((12, 40)));
    }

    #[test]
    fn offset_disambiguates_duplicate_crate_names() {
        let src = "\
[[package]]\nname = \"syn\"\nversion = \"1.0\"\n\n\
[[package]]\nname = \"syn\"\nversion = \"2.0\"\n";
        let r = find_name_version_offset(src, "name = \"syn\"", "version = \"2.0\"");
        let (start, _) = r.unwrap();
        // Should point at the second occurrence, not the first
        assert!(start > 30, "expected second occurrence, got offset {start}");
    }

    #[test]
    fn offset_returns_none_when_missing() {
        let src = "[[package]]\nname = \"foo\"\nversion = \"1.0\"\n";
        assert!(find_name_version_offset(src, "name = \"bar\"", "version = \"1.0\"").is_none());
    }

    #[test]
    fn offset_returns_none_when_version_doesnt_follow() {
        // name exists but version on next line doesn't match — should return None
        let src = "[[package]]\nname = \"foo\"\nversion = \"1.0\"\n";
        assert!(find_name_version_offset(src, "name = \"foo\"", "version = \"9.9\"").is_none());
    }

    #[test]
    fn offset_handles_crlf() {
        let src = "[[package]]\r\nname = \"foo\"\r\nversion = \"1.0\"\r\n";
        let r = find_name_version_offset(src, "name = \"foo\"", "version = \"1.0\"");
        assert!(r.is_some());
    }

    // ─── CargoLockPqCrypto::check ──────────────────────────────────────

    const CARGO_LOCK_BASIC: &str = "\
[[package]]\n\
name = \"my-app\"\n\
version = \"0.1.0\"\n\
dependencies = [\"rsa\"]\n\
\n\
[[package]]\n\
name = \"rsa\"\n\
version = \"0.9.0\"\n";

    #[test]
    fn cargo_direct_seed_dep_flagged() {
        let tree = dummy_tree(CARGO_LOCK_BASIC);
        let findings = CargoLockPqCrypto.check(CARGO_LOCK_BASIC, &tree);
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.dep_name.as_deref(), Some("my-app"));
        assert_eq!(f.crypto_algorithm.as_deref(), Some("RSA"));
        assert_eq!(f.confidence, 0.9);
        assert!(f.tags.contains(&"PQ".to_string()));
    }

    #[test]
    fn cargo_seed_crate_itself_not_flagged() {
        let tree = dummy_tree(CARGO_LOCK_BASIC);
        let findings = CargoLockPqCrypto.check(CARGO_LOCK_BASIC, &tree);
        assert!(
            findings
                .iter()
                .all(|f| f.dep_name.as_deref() != Some("rsa")),
            "seed crate rsa should not be flagged"
        );
    }

    #[test]
    fn cargo_transitive_dep_flagged() {
        let src = "\
[[package]]\n\
name = \"app\"\n\
version = \"0.1.0\"\n\
dependencies = [\"mid\"]\n\
\n\
[[package]]\n\
name = \"mid\"\n\
version = \"1.0.0\"\n\
dependencies = [\"p256\"]\n\
\n\
[[package]]\n\
name = \"p256\"\n\
version = \"0.13.0\"\n";
        let tree = dummy_tree(src);
        let findings = CargoLockPqCrypto.check(src, &tree);
        // Both app (transitive) and mid (direct) should be flagged
        assert_eq!(findings.len(), 2);
        let names: Vec<_> = findings
            .iter()
            .filter_map(|f| f.dep_name.as_deref())
            .collect();
        assert!(names.contains(&"app"));
        assert!(names.contains(&"mid"));
        assert!(findings
            .iter()
            .all(|f| f.crypto_algorithm.as_deref() == Some("ECDSA")));
    }

    #[test]
    fn cargo_bfs_stops_at_seed_no_traversal_through() {
        // app → ring (tier 2, 0.6) → rsa (tier 1, 0.9)
        // If BFS traverses through ring, it finds rsa (0.9) which wins.
        // If BFS correctly stops at ring, only ring (0.6) is found.
        // The confidence value distinguishes the two behaviors.
        let src = "\
[[package]]\n\
name = \"app\"\n\
version = \"0.1.0\"\n\
dependencies = [\"ring\"]\n\
\n\
[[package]]\n\
name = \"ring\"\n\
version = \"0.17.0\"\n\
dependencies = [\"rsa\"]\n\
\n\
[[package]]\n\
name = \"rsa\"\n\
version = \"0.9.0\"\n";
        let tree = dummy_tree(src);
        let findings = CargoLockPqCrypto.check(src, &tree);
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.dep_name.as_deref(), Some("app"));
        // BFS stopped at ring — did NOT traverse through to rsa
        assert_eq!(f.confidence, 0.6, "should be ring's 0.6, not rsa's 0.9");
        assert!(
            f.crypto_algorithm.is_none(),
            "ring has no specific algorithm"
        );
    }

    #[test]
    fn cargo_tier1_beats_tier2_confidence() {
        // If a crate reaches both rsa (0.9) and ring (0.6), rsa wins
        let src = "\
[[package]]\n\
name = \"app\"\n\
version = \"0.1.0\"\n\
dependencies = [\"rsa\", \"ring\"]\n\
\n\
[[package]]\n\
name = \"rsa\"\n\
version = \"0.9.0\"\n\
\n\
[[package]]\n\
name = \"ring\"\n\
version = \"0.17.0\"\n";
        let tree = dummy_tree(src);
        let findings = CargoLockPqCrypto.check(src, &tree);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].confidence, 0.9);
        assert_eq!(findings[0].crypto_algorithm.as_deref(), Some("RSA"));
    }

    #[test]
    fn cargo_no_findings_for_clean_lockfile() {
        let src = "\
[[package]]\n\
name = \"serde\"\n\
version = \"1.0.0\"\n\
\n\
[[package]]\n\
name = \"serde_json\"\n\
version = \"1.0.0\"\n\
dependencies = [\"serde\"]\n";
        let tree = dummy_tree(src);
        let findings = CargoLockPqCrypto.check(src, &tree);
        assert!(findings.is_empty());
    }

    #[test]
    fn cargo_invalid_toml_returns_empty() {
        let src = "this is not valid toml {{{";
        let tree = dummy_tree(src);
        assert!(CargoLockPqCrypto.check(src, &tree).is_empty());
    }

    #[test]
    fn cargo_version_qualified_dep_string() {
        // Cargo.lock v4 format: "windows-sys 0.61.2"
        let src = "\
[[package]]\n\
name = \"app\"\n\
version = \"0.1.0\"\n\
dependencies = [\"rsa 0.9.0\"]\n\
\n\
[[package]]\n\
name = \"rsa\"\n\
version = \"0.9.0\"\n";
        let tree = dummy_tree(src);
        let findings = CargoLockPqCrypto.check(src, &tree);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].dep_name.as_deref(), Some("app"));
    }

    #[test]
    fn cargo_multi_version_diamond() {
        // app depends on "syn 2.0.0" (version-qualified).
        // syn 1.0 depends on rsa (tier 1, 0.9) — the WRONG version.
        // syn 2.0 depends on ring (tier 2, 0.6) — the RIGHT version.
        // If version qualifier is ignored (old bug), app fans out to both
        // syn versions and reaches rsa (0.9), which wins the sort.
        // Correct resolution: app → syn 2.0 → ring only → confidence 0.6.
        let src = "\
[[package]]\n\
name = \"app\"\n\
version = \"0.1.0\"\n\
dependencies = [\"syn 2.0.0\"]\n\
\n\
[[package]]\n\
name = \"syn\"\n\
version = \"1.0.0\"\n\
dependencies = [\"rsa\"]\n\
\n\
[[package]]\n\
name = \"syn\"\n\
version = \"2.0.0\"\n\
dependencies = [\"ring\"]\n\
\n\
[[package]]\n\
name = \"rsa\"\n\
version = \"0.9.0\"\n\
\n\
[[package]]\n\
name = \"ring\"\n\
version = \"0.17.0\"\n";
        let tree = dummy_tree(src);
        let findings = CargoLockPqCrypto.check(src, &tree);
        let app_finding = findings
            .iter()
            .find(|f| f.dep_name.as_deref() == Some("app"))
            .expect("app should be flagged");
        // app → syn 2.0 → ring (0.6). Old bug would also reach rsa (0.9).
        assert_eq!(app_finding.confidence, 0.6, "should reach ring, not rsa");
        assert!(app_finding.crypto_algorithm.is_none());
    }

    // ─── RequirementsTxtPqCrypto::check ────────────────────────────────

    #[test]
    fn pip_detects_known_packages() {
        let src = "python-rsa==4.9\nflask>=2.0\ncryptography>=41.0\n";
        let tree = dummy_tree(src);
        let findings = RequirementsTxtPqCrypto.check(src, &tree);
        let names: Vec<_> = findings
            .iter()
            .filter_map(|f| f.dep_name.as_deref())
            .collect();
        assert!(names.contains(&"python-rsa"));
        assert!(names.contains(&"cryptography"));
        assert!(!names.contains(&"flask"));
    }

    #[test]
    fn pip_high_confidence_has_algorithm() {
        let src = "python-rsa==4.9\n";
        let tree = dummy_tree(src);
        let findings = RequirementsTxtPqCrypto.check(src, &tree);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].crypto_algorithm.as_deref(), Some("RSA"));
        assert_eq!(findings[0].confidence, 0.95);
    }

    #[test]
    fn pip_kitchen_sink_has_fix_suggestion() {
        let src = "cryptography>=41.0\n";
        let tree = dummy_tree(src);
        let findings = RequirementsTxtPqCrypto.check(src, &tree);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].crypto_algorithm.is_none());
        assert!(findings[0].fix_suggestion.is_some());
    }

    #[test]
    fn pip_skips_comments_and_options() {
        let src = "# a comment\n-r other.txt\n-e .\ngit+https://example.com/foo.git\nhttps://example.com/bar.whl\n";
        let tree = dummy_tree(src);
        assert!(RequirementsTxtPqCrypto.check(src, &tree).is_empty());
    }

    #[test]
    fn pip_strips_environment_markers() {
        let src = "paramiko>=2.0; python_version >= \"3.8\"\n";
        let tree = dummy_tree(src);
        let findings = RequirementsTxtPqCrypto.check(src, &tree);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].dep_name.as_deref(), Some("paramiko"));
    }

    #[test]
    fn pip_strips_extras() {
        let src = "fabric[ssh]>=3.0\n";
        let tree = dummy_tree(src);
        let findings = RequirementsTxtPqCrypto.check(src, &tree);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].dep_name.as_deref(), Some("fabric"));
    }

    #[test]
    fn pip_pep503_normalization() {
        // PyNaCl with mixed case and no version spec
        let src = "PyNaCl\n";
        let tree = dummy_tree(src);
        let findings = RequirementsTxtPqCrypto.check(src, &tree);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].dep_name.as_deref(), Some("PyNaCl"));
    }

    #[test]
    fn pip_crlf_offsets_correct() {
        let src = "flask>=2.0\r\npython-rsa==4.9\r\nrequests>=2.28\r\n";
        let tree = dummy_tree(src);
        let findings = RequirementsTxtPqCrypto.check(src, &tree);
        assert_eq!(findings.len(), 1);
        // python-rsa starts after "flask>=2.0\r\n" = 12 bytes
        assert_eq!(findings[0].line, 2);
        assert_eq!(findings[0].column, 1);
        // end_column should span "python-rsa==4.9" (15 chars) → column 16
        assert_eq!(findings[0].end_column, 16);
    }

    #[test]
    fn pip_empty_input_returns_empty() {
        let tree = dummy_tree("");
        assert!(RequirementsTxtPqCrypto.check("", &tree).is_empty());
    }

    #[test]
    fn cargo_k256_seed_flagged() {
        let src = "\
[[package]]\n\
name = \"wallet\"\n\
version = \"0.1.0\"\n\
dependencies = [\"k256\"]\n\
\n\
[[package]]\n\
name = \"k256\"\n\
version = \"0.13.0\"\n";
        let tree = dummy_tree(src);
        let findings = CargoLockPqCrypto.check(src, &tree);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].dep_name.as_deref(), Some("wallet"));
        assert_eq!(findings[0].crypto_algorithm.as_deref(), Some("ECDSA"));
    }

    #[test]
    fn pip_jwt_lib_flagged() {
        let src = "pyjwt>=2.0\n";
        let tree = dummy_tree(src);
        let findings = RequirementsTxtPqCrypto.check(src, &tree);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].dep_name.as_deref(), Some("pyjwt"));
        assert!(findings[0].crypto_algorithm.is_none());
        assert_eq!(findings[0].confidence, 0.8);
    }

    #[test]
    fn pip_fabric_no_algorithm() {
        let src = "fabric>=3.0\n";
        let tree = dummy_tree(src);
        let findings = RequirementsTxtPqCrypto.check(src, &tree);
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].crypto_algorithm.is_none(),
            "fabric should not attribute RSA"
        );
    }

    // ─── PoetryLockPqCrypto::check ────────────────────────────────────

    #[test]
    fn poetry_detects_known_packages() {
        let src = "\
[[package]]\n\
name = \"flask\"\n\
version = \"3.0.0\"\n\
\n\
[[package]]\n\
name = \"cryptography\"\n\
version = \"41.0.7\"\n\
\n\
[[package]]\n\
name = \"python-rsa\"\n\
version = \"4.9\"\n\
\n\
[[package]]\n\
name = \"requests\"\n\
version = \"2.31.0\"\n";
        let tree = dummy_tree(src);
        let findings = PoetryLockPqCrypto.check(src, &tree);
        let names: Vec<_> = findings
            .iter()
            .filter_map(|f| f.dep_name.as_deref())
            .collect();
        assert!(names.contains(&"python-rsa"), "expected python-rsa");
        assert!(names.contains(&"cryptography"), "expected cryptography");
        assert!(!names.contains(&"flask"), "flask is not crypto");
        assert!(!names.contains(&"requests"), "requests is not crypto");
    }

    #[test]
    fn poetry_high_confidence_has_algorithm() {
        let src = "\
[[package]]\n\
name = \"python-rsa\"\n\
version = \"4.9\"\n";
        let tree = dummy_tree(src);
        let findings = PoetryLockPqCrypto.check(src, &tree);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].crypto_algorithm.as_deref(), Some("RSA"));
        assert_eq!(findings[0].confidence, 0.95);
    }

    #[test]
    fn poetry_low_confidence_has_fix_suggestion() {
        let src = "\
[[package]]\n\
name = \"cryptography\"\n\
version = \"41.0.7\"\n";
        let tree = dummy_tree(src);
        let findings = PoetryLockPqCrypto.check(src, &tree);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].fix_suggestion.is_some());
    }

    #[test]
    fn poetry_invalid_toml_returns_empty() {
        let src = "this is not valid toml {{{";
        let tree = dummy_tree(src);
        assert!(PoetryLockPqCrypto.check(src, &tree).is_empty());
    }

    #[test]
    fn poetry_no_findings_for_clean_lockfile() {
        let src = "\
[[package]]\n\
name = \"flask\"\n\
version = \"3.0.0\"\n\
\n\
[[package]]\n\
name = \"requests\"\n\
version = \"2.31.0\"\n";
        let tree = dummy_tree(src);
        assert!(PoetryLockPqCrypto.check(src, &tree).is_empty());
    }

    // ─── PipfileLockPqCrypto::check ───────────────────────────────────

    #[test]
    fn pipfile_detects_default_and_develop_deps() {
        let src = r#"{
    "default": {
        "cryptography": {"version": "==41.0.7"},
        "flask": {"version": "==3.0.0"}
    },
    "develop": {
        "paramiko": {"version": "==3.4.0"},
        "pytest": {"version": "==7.4.0"}
    }
}"#;
        let tree = dummy_tree(src);
        let findings = PipfileLockPqCrypto.check(src, &tree);
        let names: Vec<_> = findings
            .iter()
            .filter_map(|f| f.dep_name.as_deref())
            .collect();
        assert!(names.contains(&"cryptography"), "expected cryptography");
        assert!(
            names.contains(&"paramiko"),
            "expected paramiko from develop"
        );
        assert!(!names.contains(&"flask"), "flask is not crypto");
        assert!(!names.contains(&"pytest"), "pytest is not crypto");
    }

    #[test]
    fn pipfile_high_confidence_has_algorithm() {
        let src = r#"{
    "default": {
        "python-rsa": {"version": "==4.9"}
    },
    "develop": {}
}"#;
        let tree = dummy_tree(src);
        let findings = PipfileLockPqCrypto.check(src, &tree);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].crypto_algorithm.as_deref(), Some("RSA"));
        assert_eq!(findings[0].confidence, 0.95);
    }

    #[test]
    fn pipfile_invalid_json_returns_empty() {
        let src = "this is not valid json {{{";
        let tree = dummy_tree(src);
        assert!(PipfileLockPqCrypto.check(src, &tree).is_empty());
    }

    #[test]
    fn pipfile_no_findings_for_clean_lockfile() {
        let src = r#"{
    "default": {
        "flask": {"version": "==3.0.0"},
        "requests": {"version": "==2.31.0"}
    },
    "develop": {}
}"#;
        let tree = dummy_tree(src);
        assert!(PipfileLockPqCrypto.check(src, &tree).is_empty());
    }

    // ─── PnpmLockPqCrypto::check ──────────────────────────────────────

    #[test]
    fn pnpm_detects_known_packages() {
        let src = "lockfileVersion: '9.0'\n\npackages:\n  elliptic@6.5.4:\n    resolution: {integrity: sha512-abc}\n  express@4.18.2:\n    resolution: {integrity: sha512-def}\n  jsonwebtoken@9.0.2:\n    resolution: {integrity: sha512-ghi}\n  lodash@4.17.21:\n    resolution: {integrity: sha512-jkl}\n";
        let tree = dummy_tree(src);
        let findings = PnpmLockPqCrypto.check(src, &tree);
        let names: Vec<_> = findings
            .iter()
            .filter_map(|f| f.dep_name.as_deref())
            .collect();
        assert!(names.contains(&"elliptic"), "expected elliptic");
        assert!(names.contains(&"jsonwebtoken"), "expected jsonwebtoken");
        assert!(!names.contains(&"express"), "express is not crypto");
        assert!(!names.contains(&"lodash"), "lodash is not crypto");
    }

    #[test]
    fn pnpm_v6_slash_prefix_format() {
        // pnpm v6-v8 uses /pkg@version format
        let src = "lockfileVersion: '6.0'\n\npackages:\n  /elliptic@6.5.4:\n    resolution: {integrity: sha512-abc}\n  /express@4.18.2:\n    resolution: {integrity: sha512-def}\n";
        let tree = dummy_tree(src);
        let findings = PnpmLockPqCrypto.check(src, &tree);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].dep_name.as_deref(), Some("elliptic"));
        assert_eq!(findings[0].crypto_algorithm.as_deref(), Some("ECDSA"));
    }

    #[test]
    fn pnpm_high_confidence_has_algorithm() {
        let src = "lockfileVersion: '9.0'\n\npackages:\n  elliptic@6.5.4:\n    resolution: {integrity: sha512-abc}\n";
        let tree = dummy_tree(src);
        let findings = PnpmLockPqCrypto.check(src, &tree);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].crypto_algorithm.as_deref(), Some("ECDSA"));
        assert_eq!(findings[0].confidence, 0.95);
    }

    #[test]
    fn pnpm_invalid_yaml_returns_empty() {
        let src = "{{{{this is not valid yaml";
        let tree = dummy_tree(src);
        assert!(PnpmLockPqCrypto.check(src, &tree).is_empty());
    }

    #[test]
    fn pnpm_no_findings_for_clean_lockfile() {
        let src = "lockfileVersion: '9.0'\n\npackages:\n  express@4.18.2:\n    resolution: {integrity: sha512-def}\n  lodash@4.17.21:\n    resolution: {integrity: sha512-jkl}\n";
        let tree = dummy_tree(src);
        assert!(PnpmLockPqCrypto.check(src, &tree).is_empty());
    }

    // ─── PackageLockPqCrypto::check ───────────────────────────────────

    #[test]
    fn npm_detects_known_packages() {
        let src = r#"{
  "name": "my-app",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "my-app", "version": "1.0.0"},
    "node_modules/elliptic": {"version": "6.5.4"},
    "node_modules/express": {"version": "4.18.2"},
    "node_modules/jsonwebtoken": {"version": "9.0.2"},
    "node_modules/lodash": {"version": "4.17.21"}
  }
}"#;
        let tree = dummy_tree(src);
        let findings = PackageLockPqCrypto.check(src, &tree);
        let names: Vec<_> = findings
            .iter()
            .filter_map(|f| f.dep_name.as_deref())
            .collect();
        assert!(names.contains(&"elliptic"), "expected elliptic");
        assert!(names.contains(&"jsonwebtoken"), "expected jsonwebtoken");
        assert!(!names.contains(&"express"), "express is not crypto");
        assert!(!names.contains(&"lodash"), "lodash is not crypto");
    }

    #[test]
    fn npm_high_confidence_has_algorithm() {
        let src = r#"{
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "app"},
    "node_modules/elliptic": {"version": "6.5.4"}
  }
}"#;
        let tree = dummy_tree(src);
        let findings = PackageLockPqCrypto.check(src, &tree);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].crypto_algorithm.as_deref(), Some("ECDSA"));
        assert_eq!(findings[0].confidence, 0.95);
    }

    #[test]
    fn npm_v1_dependencies_fallback() {
        let src = r#"{
  "name": "my-app",
  "lockfileVersion": 1,
  "dependencies": {
    "elliptic": {"version": "6.5.4"},
    "express": {"version": "4.18.2"}
  }
}"#;
        let tree = dummy_tree(src);
        let findings = PackageLockPqCrypto.check(src, &tree);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].dep_name.as_deref(), Some("elliptic"));
    }

    #[test]
    fn npm_invalid_json_returns_empty() {
        let src = "this is not valid json {{{";
        let tree = dummy_tree(src);
        assert!(PackageLockPqCrypto.check(src, &tree).is_empty());
    }

    #[test]
    fn npm_no_findings_for_clean_lockfile() {
        let src = r#"{
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "app"},
    "node_modules/express": {"version": "4.18.2"},
    "node_modules/lodash": {"version": "4.17.21"}
  }
}"#;
        let tree = dummy_tree(src);
        assert!(PackageLockPqCrypto.check(src, &tree).is_empty());
    }

    #[test]
    fn npm_tags_and_metadata_correct() {
        let src = r#"{
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "app"},
    "node_modules/elliptic": {"version": "6.5.4"}
  }
}"#;
        let tree = dummy_tree(src);
        let findings = PackageLockPqCrypto.check(src, &tree);
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert!(f.tags.contains(&"PQ".to_string()));
        assert_eq!(f.dep_name.as_deref(), Some("elliptic"));
        assert_eq!(f.rule_id, "manifest/npm-pq-vulnerable-dep");
    }
}
