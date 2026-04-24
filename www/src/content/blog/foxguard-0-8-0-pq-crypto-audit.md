---
title: "foxguard 0.8 — post-quantum crypto audit in your terminal"
date: "2026-04-21"
description: "foxguard v0.8.0 bakes PQ-vulnerable-crypto rules and CNSA 2.0 migration deadlines into the default scan, and emits a CycloneDX 1.6 CBOM where each entry ties back to a source location and severity."
readTime: "6 min read"
---

NSA's CNSA 2.0 suite says federal software- and firmware-signing systems must stop using RSA and ECC by the end of 2030. Traditional networking equipment has the same 2030 deadline. Web browsers, web servers, cloud services, and operating systems trail through 2033. If you maintain a codebase that touches any of that, someone is going to ask you which calls in your tree are the problem — and your existing SAST won't tell you. Semgrep, Snyk, Bandit, and gosec ship no post-quantum rules out of the box.

We wrote foxguard 0.8 for that question.

## What 0.8 does

`foxguard pqc .` runs the PQ-vulnerable-crypto rules across a repository and prints the migration deadline alongside every hit:

```
src/tls/client.go
  42:14  HIGH      go/pq-vulnerable-crypto (CWE-327)
         ECDH P-256 is not post-quantum safe. CNSA 2.0 mandates ML-KEM-1024
         for NSS; ML-KEM-768 is the NIST default for commercial use.
         CNSA 2.0 deadline: traditional networking equipment, 2030.

WARNING  1 PQ finding in 18 files (0.04s): 1 high, 0 medium, 0 low
CNSA 2.0 migration: at-risk (1 finding with an NSA transition deadline)
```

Rules ship for Python, JavaScript/TypeScript, Go, Java, and Rust; TLS configuration files (OpenSSL, nginx, Apache) are also scanned for non-PQ cipher suites. Each finding carries a CNSA 2.0 deadline derived from rule metadata — not from substring matching on rule IDs — and the remediation text splits cleanly: **ML-KEM-1024 / ML-DSA-87** for NSS workloads, **ML-KEM-768 / ML-DSA-65** for commercial use, per the CNSA 2.0 algorithm table. Getting that split right mattered: `--cnsa2` mode would have otherwise contradicted itself ([#256](https://github.com/PwnKit-Labs/foxguard/pull/256)).

The rules file under CWE-327. We flag the caveat once and move on: CWE-327's canonical examples are already-broken ciphers like DES and MD5, and RSA/ECDSA aren't broken yet — they're quantum-vulnerable. The industry tags PQ findings under CWE-327 anyway; we follow the convention.

`foxguard --format cbom .` emits a CycloneDX 1.6 cryptographic bill of materials where every component links back to a file, a line, and the severity of any finding attached to it. The scan and the inventory are one artifact.

And the dependencies: `foxguard pqc .` now also walks `Cargo.lock` and `requirements.txt` (closes [#221](https://github.com/PwnKit-Labs/foxguard/issues/221)). For Rust, a BFS over the transitive graph flags crates whose PQ-vulnerability is seed-confidence (`rsa`, `ed25519-dalek`, `p256` at 0.9) or review-required (`ring`, `aws-lc-rs` at 0.6 — both ship PQ-safe AEADs alongside Ed25519/ECDSA, so a bare hit warrants a look rather than a panic). For Python, membership is matched against a curated list of ~11 packages with per-package confidence. Each manifest finding carries a `dep_name` field so downstream tooling can attribute the hit to the lockfile entry rather than the source tree. Combined with the source-code rules, the single `pqc` pass answers both "which of my own calls?" and "which of my dependencies?"

## Prior art, honestly

CBOM is a young standard and it already has tooling. IBM's [CBOMkit](https://github.com/IBM/cbomkit), [sonar-cryptography](https://github.com/PQCA/sonar-cryptography), and [cdxgen](https://github.com/CycloneDX/cdxgen) all produce CycloneDX CBOM output; the [CycloneDX Tool Center](https://cyclonedx.org/tool-center/) lists more. Most are import-graph or dependency-focused. foxguard's contribution is narrower and more specific: the scan and the inventory come out of one pass, each CBOM component ties back to a source location and severity, and crypto-agility scoring plus CNSA 2.0 annotations travel with the BOM.

On PQ rules specifically: GitHub has shipped [advanced-security/cbom-action](https://github.com/advanced-security/cbom-action) and experimental CodeQL queries under `cpp/ql/src/experimental/cryptography` in [`github/codeql`](https://github.com/github/codeql) ([announcement](https://github.blog/security/vulnerability-research/addressing-post-quantum-cryptography-with-codeql/)). If you're on GitHub and willing to run a separate action with research-grade queries against a built database, CodeQL covers a lot of ground. foxguard bakes PQ-vulnerable-crypto rules into the default scan, runs locally as a single binary, and annotates each hit with a CNSA 2.0 deadline in the default output. As far as we can tell, foxguard is the first OSS source-code scanner that annotates each PQ finding with its CNSA 2.0 migration deadline — a narrow claim, but one we actually checked.

## How it works

The detection is tree-sitter-based. For each supported language, PQ-vulnerable primitives are identified through the same matcher infrastructure that backs the rest of foxguard's rules: syntactic patterns over parsed ASTs, plus language-specific alias resolution so that `crypto/rsa`, an aliased `rsa as r`, and a re-exported `r.GenerateKey` all resolve to the same primitive.

Two pieces are PQ-specific. First, PQ-safe allowlists: calls through the `ml_kem`, `ml_dsa`, `slh_dsa`, `fn_dsa`, and `hqc` crates (and their analogues in other ecosystems) are explicitly marked safe, so a repo that has already migrated doesn't get dinged. FN-DSA (FIPS 206) and HQC were added in [#243](https://github.com/PwnKit-Labs/foxguard/pull/243) as NIST continues to standardize. Second, the CNSA 2.0 deadline is declarative rule metadata — a `cnsa2_deadline` field on the rule itself — consulted through the rule registry at scan time. Renaming a rule cannot silently drop its annotation, and the deadline string is never derived from a rule ID heuristic.

## The part we got wrong first

Our first pass at CNSA 2.0 annotations had unsourced dates. A review caught it. We rewrote `src/compliance.rs` so that every deadline constant carries an inline NSA citation — the FAQ v2.1 transition-timeline table, cross-referenced with the May 2025 CSA *CNSA 2.0 Algorithms* publication — and added a module-level design note explaining why we don't substring-match rule IDs. The [module-level doc comment](https://github.com/PwnKit-Labs/foxguard/blob/main/src/compliance.rs) is the canonical source for any date the tool prints. If you want to audit our claims, that's the file to start at.

## Try it

```sh
npx foxguard@latest pqc .
curl -fsSL https://foxguard.dev/install.sh | sh
cargo install foxguard
```

## What's next

More lockfile formats — `Pipfile.lock`, `poetry.lock`, `uv.lock`, `package-lock.json`, `pnpm-lock.yaml` — so the dependency story covers modern Python and Node projects end to end ([#262](https://github.com/PwnKit-Labs/foxguard/issues/262)). A GitHub App for one-click install on any repo is on the roadmap. Cloudflare reports over half of human TLS traffic on their edge is already post-quantum ([Cloudflare, 2025](https://blog.cloudflare.com/pq-2025/)); application code is catching up slower. We'd like to make that migration less painful.

---

*foxguard is an open-source security scanner written in Rust. [GitHub](https://github.com/PwnKit-Labs/foxguard) · [foxguard.dev](https://foxguard.dev).*
