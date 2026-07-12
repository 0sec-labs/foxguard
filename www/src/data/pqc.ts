// Data for the /post-quantum page.
//
// Every claim here is verified against the foxguard Rust source:
//   - src/compliance.rs       — CNSA 2.0 deadline constants + MigrationLevel
//                               (clean / on-track / at-risk) scoring, plus the
//                               post-quantum readiness percentage.
//   - src/rules/pq.rs         — post-quantum algorithm table (ML-KEM, ML-DSA,
//                               SLH-DSA, FN-DSA, HQC, hybrids, liboqs) and the
//                               shared spelling matcher (`pq-ready-crypto`).
//   - src/report/cbom.rs      — CycloneDX 1.6 CBOM output. Vulnerable primitives
//                               (RSA, ECDSA/DSA, ECDH/DH) mapped to crypto asset
//                               properties + a vulnerability entry; post-quantum
//                               algorithms emitted as quantum-resistant assets
//                               with NO vulnerability entry.
//   - src/cli.rs (PqcArgs)    — `foxguard pqc .` subcommand and flags.
//   - src/rules/manifest.rs   — 6 lockfile formats parsed for PQ-vulnerable deps.
//
// The audit is now a two-sided SCORECARD: it detects both the quantum-VULNERABLE
// inventory AND the post-quantum migration TARGETS already in use, and reports a
// readiness percentage.
//
// - Quantum-vulnerable detection: 5 source languages (Python, JavaScript, Go,
//   Java, Rust) + web-server configs + 6 lockfile formats.
// - Post-quantum-ready detection (informational, never flagged as insecure):
//   the same 5 source languages, nginx/apache/haproxy TLS configs, and the
//   Cargo.lock + requirements.txt manifests. These rules are opt-in and run
//   only under `foxguard pqc`. Do NOT widen this beyond what src/rules/pq.rs
//   and the `pq-ready-crypto` rules actually implement.

// ---------------------------------------------------------------------------
// Quantum-vulnerable primitives that foxguard flags
// ---------------------------------------------------------------------------

export interface Primitive {
  /** Algorithm name as it appears in findings / the CBOM. */
  name: string;
  /** What the algorithm is used for. */
  role: string;
  /** One-line note on why it is quantum-vulnerable. */
  risk: string;
}

export const primitives: Primitive[] = [
  {
    name: 'RSA',
    role: 'Public-key encryption & signatures',
    risk: "Shor's algorithm factors the modulus, breaking RSA outright.",
  },
  {
    name: 'ECDSA',
    role: 'Elliptic-curve signatures',
    risk: 'Elliptic-curve discrete log falls to Shor, so signatures can be forged.',
  },
  {
    name: 'ECDH',
    role: 'Elliptic-curve key agreement',
    risk: 'Shared secrets are recoverable, exposing every derived session key.',
  },
  {
    name: 'DH',
    role: 'Finite-field key agreement',
    risk: 'Relies on discrete log, which a quantum computer solves efficiently.',
  },
  {
    name: 'DSA',
    role: 'Finite-field signatures',
    risk: 'Same discrete-log foundation as DH, so signatures can be forged.',
  },
];

// ---------------------------------------------------------------------------
// Post-quantum migration TARGETS that foxguard recognises as already-in-use.
//
// Mirrors the table in src/rules/pq.rs. Detection is informational: a repo
// using these is AHEAD on migration, never flagged as insecure. They appear in
// the CBOM as quantum-resistant assets and count toward the readiness score.
// ---------------------------------------------------------------------------

export interface PqTarget {
  /** Canonical NIST/FIPS name as it appears in findings / the CBOM. */
  name: string;
  /** Standardisation identity. */
  standard: string;
  /** Legacy / common name, or '' when there is none. */
  aka: string;
  /** What the algorithm is used for. */
  role: string;
}

export const pqTargets: PqTarget[] = [
  {
    name: 'ML-KEM',
    standard: 'FIPS 203',
    aka: 'Kyber',
    role: 'Key encapsulation (KEM)',
  },
  {
    name: 'ML-DSA',
    standard: 'FIPS 204',
    aka: 'Dilithium',
    role: 'Digital signatures',
  },
  {
    name: 'SLH-DSA',
    standard: 'FIPS 205',
    aka: 'SPHINCS+',
    role: 'Stateless hash-based signatures',
  },
  {
    name: 'FN-DSA',
    standard: 'FIPS 206 (draft)',
    aka: 'Falcon',
    role: 'Lattice signatures',
  },
  {
    name: 'HQC',
    standard: 'NIST 5th selection (draft)',
    aka: '',
    role: 'Code-based key encapsulation',
  },
  {
    name: 'X25519MLKEM768',
    standard: 'FIPS 203 hybrid (RFC 9370)',
    aka: 'X25519 + ML-KEM-768',
    role: 'Hybrid TLS key exchange',
  },
];

// ---------------------------------------------------------------------------
// CNSA 2.0 transition milestones (deadlines per equipment / algorithm class)
//
// Years are the *exclusive-use* drop-dead dates from the NSA CNSA 2.0 FAQ
// (Dec 2024, v2.1) as encoded in src/compliance.rs::deadlines. Findings are
// annotated with the year for their class.
// ---------------------------------------------------------------------------

export interface Milestone {
  /** Exclusive-use deadline year. */
  year: string;
  /** Short label for the class of systems. */
  label: string;
  /** What this milestone covers. */
  covers: string;
}

export const milestones: Milestone[] = [
  {
    year: '2030',
    label: 'Networking & firmware',
    covers:
      'Software/firmware signing and networking gear (VPNs, routers) go CNSA 2.0 first. Hash-based and ML-DSA signatures are already fieldable.',
  },
  {
    year: '2033',
    label: 'Web, cloud & operating systems',
    covers:
      'Browsers, web servers, cloud services, operating systems, and legacy/custom apps must finish migrating to quantum-resistant algorithms.',
  },
  {
    year: '2035',
    label: 'National security systems',
    covers:
      'The NSM-10 outer limit: all National Security Systems fully quantum-resistant. foxguard falls back to this year when a finding has no more specific class.',
  },
];

// ---------------------------------------------------------------------------
// Migration-readiness levels emitted by the scan (src/compliance.rs)
// ---------------------------------------------------------------------------

export interface ReadinessLevel {
  /** Literal level string the CLI prints. */
  level: string;
  /** What it means. */
  meaning: string;
}

export const readinessLevels: ReadinessLevel[] = [
  {
    level: 'clean',
    meaning:
      'No CNSA-relevant findings. Either no quantum-vulnerable crypto is in use, or no PQ rules matched.',
  },
  {
    level: 'on-track',
    meaning:
      'A minority of post-quantum findings carry an unmet CNSA 2.0 deadline.',
  },
  {
    level: 'at-risk',
    meaning:
      'A majority (≥ 50%) of post-quantum findings carry an unmet CNSA 2.0 deadline. Migration has not begun.',
  },
];
