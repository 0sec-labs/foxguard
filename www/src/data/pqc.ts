// Data for the /post-quantum page.
//
// Every claim here is verified against the foxguard Rust source:
//   - src/compliance.rs       — CNSA 2.0 deadline constants + MigrationLevel
//                               (clean / on-track / at-risk) scoring.
//   - src/report/cbom.rs      — CycloneDX 1.6 CBOM output; flagged primitives
//                               (RSA, ECDSA/DSA, ECDH/DH) mapped to crypto
//                               asset properties.
//   - src/cli.rs (PqcArgs)    — `foxguard pqc .` subcommand and flags.
//   - src/rules/manifest.rs   — 6 lockfile formats parsed for PQ-vulnerable deps.
//
// PQ source-code detection covers 5 languages (Python, JavaScript, Go, Java,
// Rust) plus web-server configs, plus 6 lockfile formats. Do NOT widen this.

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
