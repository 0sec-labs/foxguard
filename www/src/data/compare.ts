// Data for the /compare page.
//
// foxguard ground truth is verified against the Rust source:
//   196 built-in rules; 10 programming languages (JS/TS, Python, Go, Ruby, Java,
//   PHP, Rust, C#, Swift, Kotlin) plus config/infra targets; cross-file taint for
//   Python, JavaScript, and Go only; loads Semgrep/OpenGrep YAML via --rules;
//   MIT OR Apache-2.0, free forever.
//
// Competitor facts were gathered from each vendor's official docs (2024-2026) and
// are deliberately limited to widely-documented, defensible claims. Where a tier
// or specific is uncertain we use a short qualifier rather than a hard yes/no.
// Capabilities and pricing change — the page footnotes tell readers to verify.

// ---------------------------------------------------------------------------
// Tools (columns) shared by the matrix and the core-attributes table
// ---------------------------------------------------------------------------

export type ToolKey =
  | 'foxguard'
  | 'semgrep'
  | 'opengrep'
  | 'codeql'
  | 'snyk'
  | 'sonarqube';

export interface MatrixTool {
  key: ToolKey;
  label: string;
  /** Short tagline shown under the column header. */
  tagline: string;
}

export const matrixTools: MatrixTool[] = [
  { key: 'foxguard', label: 'foxguard', tagline: 'Rust CLI' },
  { key: 'semgrep', label: 'Semgrep', tagline: 'OSS + SaaS' },
  { key: 'opengrep', label: 'OpenGrep', tagline: 'Semgrep fork' },
  { key: 'codeql', label: 'CodeQL', tagline: 'GitHub' },
  { key: 'snyk', label: 'Snyk Code', tagline: 'SaaS' },
  { key: 'sonarqube', label: 'SonarQube', tagline: 'Server' },
];

// Cell value:
//   'yes'  -> green check
//   'no'   -> em-dash
//   string -> rendered verbatim (short qualifier text)
export type Cell = 'yes' | 'no' | string;

export interface MatrixRow {
  capability: string;
  note?: string;
  cells: Record<ToolKey, Cell>;
}

// ---------------------------------------------------------------------------
// Section 01 — Capability matrix
// ---------------------------------------------------------------------------

export const matrixRows: MatrixRow[] = [
  {
    capability: 'Free, no account required',
    note: 'Can you run a full scan locally with no login, token, or paid tier?',
    cells: {
      foxguard: 'yes',
      semgrep: 'yes',
      opengrep: 'yes',
      codeql: 'OSS / public',
      snyk: 'no',
      sonarqube: 'Community ed.',
    },
  },
  {
    capability: 'Single static binary',
    cells: {
      foxguard: 'yes',
      semgrep: 'no',
      opengrep: 'Release binary',
      codeql: 'CLI bundle',
      snyk: 'no',
      sonarqube: 'no',
    },
  },
  {
    capability: 'Sub-second local scans',
    note: 'On small-to-medium repos; see the performance section for measured numbers.',
    cells: {
      foxguard: 'yes',
      semgrep: 'no',
      opengrep: 'no',
      codeql: 'no',
      snyk: 'no',
      sonarqube: 'no',
    },
  },
  {
    capability: 'Runs fully offline',
    note: 'A default scan with no data leaving the machine. SaaS tools upload code or require an account.',
    cells: {
      foxguard: 'yes',
      semgrep: 'yes',
      opengrep: 'yes',
      codeql: 'yes',
      snyk: 'no',
      sonarqube: 'Self-host',
    },
  },
  {
    capability: 'Intra-file taint / dataflow',
    cells: {
      foxguard: 'yes',
      semgrep: 'yes',
      opengrep: 'yes',
      codeql: 'yes',
      snyk: 'yes',
      sonarqube: 'yes',
    },
  },
  {
    capability: 'Cross-file taint on the free tier',
    note: 'foxguard: Python, JS, Go. Semgrep cross-file needs Pro; SonarQube needs Developer ed.; OpenGrep is per-file today.',
    cells: {
      foxguard: 'yes',
      semgrep: 'Paid (Pro)',
      opengrep: 'Per-file',
      codeql: 'yes',
      snyk: 'yes',
      sonarqube: 'Paid (Dev+)',
    },
  },
  {
    capability: 'Autofix / remediation',
    cells: {
      foxguard: 'yes',
      semgrep: 'yes',
      opengrep: 'yes',
      codeql: 'Copilot',
      snyk: 'DeepCode AI',
      sonarqube: 'AI CodeFix',
    },
  },
  {
    capability: 'Custom rules',
    note: "foxguard runs Semgrep-style YAML today; its own native rule DSL is on the roadmap.",
    cells: {
      foxguard: 'Semgrep YAML',
      semgrep: 'YAML DSL',
      opengrep: 'YAML DSL',
      codeql: 'QL',
      snyk: 'no',
      sonarqube: 'Plugins / XPath',
    },
  },
  {
    capability: 'Loads Semgrep / OpenGrep YAML',
    note: 'foxguard ingests a focused, parity-tested subset of Semgrep/OpenGrep YAML via --rules.',
    cells: {
      foxguard: 'yes',
      semgrep: 'yes',
      opengrep: 'yes',
      codeql: 'no',
      snyk: 'no',
      sonarqube: 'no',
    },
  },
  {
    capability: 'Secrets detection',
    cells: {
      foxguard: 'yes',
      semgrep: 'Paid product',
      opengrep: 'no',
      codeql: 'GitHub sep.',
      snyk: 'Limited',
      sonarqube: 'yes',
    },
  },
  {
    capability: 'Post-quantum crypto audit',
    note: 'CNSA 2.0 readiness — flags pre-quantum primitives (RSA, ECDSA, ECDH, DH, DSA).',
    cells: {
      foxguard: 'yes',
      semgrep: 'no',
      opengrep: 'no',
      codeql: 'no',
      snyk: 'no',
      sonarqube: 'no',
    },
  },
  {
    capability: 'CBOM generation',
    note: 'Cryptographic Bill of Materials — inventory of every crypto primitive in the codebase.',
    cells: {
      foxguard: 'yes',
      semgrep: 'no',
      opengrep: 'no',
      codeql: 'no',
      snyk: 'no',
      sonarqube: 'no',
    },
  },
  {
    capability: 'SARIF output',
    cells: {
      foxguard: 'yes',
      semgrep: 'yes',
      opengrep: 'yes',
      codeql: 'yes',
      snyk: 'yes',
      sonarqube: 'Import',
    },
  },
  {
    capability: 'IDE extension',
    cells: {
      foxguard: 'VS Code',
      semgrep: 'yes',
      opengrep: 'LSP',
      codeql: 'VS Code',
      snyk: 'yes',
      sonarqube: 'SonarLint',
    },
  },
  {
    capability: 'GitHub PR comments',
    cells: {
      foxguard: 'yes',
      semgrep: 'yes',
      opengrep: 'CI-based',
      codeql: 'yes',
      snyk: 'yes',
      sonarqube: 'yes',
    },
  },
  {
    capability: 'Managed SaaS dashboard',
    cells: {
      foxguard: 'no',
      semgrep: 'yes',
      opengrep: 'no',
      codeql: 'via GitHub',
      snyk: 'yes',
      sonarqube: 'SonarCloud',
    },
  },
];

// ---------------------------------------------------------------------------
// Section 02 — Core attributes (what each tool is)
// ---------------------------------------------------------------------------

export const coreRows: MatrixRow[] = [
  {
    capability: 'Written in',
    cells: {
      foxguard: 'Rust',
      semgrep: 'OCaml + Python',
      opengrep: 'OCaml',
      codeql: 'Proprietary engine',
      snyk: 'Proprietary (DeepCode AI)',
      sonarqube: 'Java',
    },
  },
  {
    capability: 'License',
    cells: {
      foxguard: 'MIT OR Apache-2.0',
      semgrep: 'LGPL-2.1 (engine)',
      opengrep: 'LGPL-2.1',
      codeql: 'MIT queries / proprietary CLI',
      snyk: 'Proprietary',
      sonarqube: 'LGPLv3 (Community) + commercial',
    },
  },
  {
    capability: 'Distribution',
    cells: {
      foxguard: 'Single static binary',
      semgrep: 'Python wheel + runtime',
      opengrep: 'Signed release binaries',
      codeql: 'CLI bundle + DB build step',
      snyk: 'CLI + cloud',
      sonarqube: 'Server + scanner',
    },
  },
  {
    capability: 'Install',
    cells: {
      foxguard: 'npx, curl, cargo, brew',
      semgrep: 'pip, brew, Docker',
      opengrep: 'install script',
      codeql: 'download / GitHub Action',
      snyk: 'CLI, IDE, SaaS',
      sonarqube: 'Docker / self-host',
    },
  },
  {
    capability: 'Languages',
    note: 'foxguard: 10 programming languages plus config/infra targets. Counts vary by edition/version.',
    cells: {
      foxguard: '10 + config',
      semgrep: '30+',
      opengrep: '30+',
      codeql: '~11',
      snyk: '~10',
      sonarqube: '~30',
    },
  },
  {
    capability: 'Rule model',
    cells: {
      foxguard: '196 built-in (CWE-mapped) + YAML',
      semgrep: 'YAML registry + Pro packs',
      opengrep: 'Semgrep-compatible YAML',
      codeql: 'QL query packs',
      snyk: 'Vendor-maintained',
      sonarqube: 'Built-in + plugins',
    },
  },
];

// ---------------------------------------------------------------------------
// Section 03 — Performance (measured: foxguard vs Semgrep; OpenGrep tracks Semgrep)
// ---------------------------------------------------------------------------

export interface Row {
  feature: string;
  foxguard: string;
  semgrep: string;
  note?: string;
}

export const performanceFeatures: Row[] = [
  { feature: 'Typical scan time (medium repo)', foxguard: '< 1 second', semgrep: '10-30 seconds' },
  { feature: 'Cold start (no cache)', foxguard: '< 1 second', semgrep: '5-15 seconds' },
  { feature: 'Memory usage', foxguard: '~50 MB', semgrep: '~500 MB+' },
  { feature: 'Parallel execution', foxguard: 'Rayon (work-stealing)', semgrep: 'Multiprocess' },
];

// ---------------------------------------------------------------------------
// Section 04 — Unique to foxguard (no direct equivalent in the others)
// ---------------------------------------------------------------------------

export interface UniqueFeature {
  feature: string;
  note: string;
}

export const uniqueFeatures: UniqueFeature[] = [
  {
    feature: 'Post-quantum crypto audit (CNSA 2.0)',
    note: 'foxguard pqc . flags RSA, ECDSA, ECDH, DH, and DSA against NSA CNSA 2.0 migration timelines.',
  },
  {
    feature: 'CBOM generation',
    note: 'foxguard pqc . --format cbom inventories every crypto primitive for compliance and supply-chain reporting.',
  },
  {
    feature: 'TUI triage mode',
    note: 'foxguard tui . opens an interactive terminal UI to review findings, read dataflow traces, and suppress inline.',
  },
  {
    feature: 'Sub-second scans from a single binary',
    note: 'No runtime, no database build, no server — one Rust binary that finishes before your editor saves.',
  },
];

// ---------------------------------------------------------------------------
// Section 05 — Pricing & licensing model
// ---------------------------------------------------------------------------

export interface PricingRow {
  tool: string;
  license: string;
  cost: string;
  note: string;
}

export const pricingRows: PricingRow[] = [
  {
    tool: 'foxguard',
    license: 'MIT OR Apache-2.0',
    cost: 'Free, forever',
    note: 'Fully open source. No accounts, no token limits, no paid tier gating engine features.',
  },
  {
    tool: 'Semgrep',
    license: 'LGPL-2.1 (OSS engine)',
    cost: 'Free OSS + Team ~$35/contributor/mo',
    note: 'CLI engine is open source; cross-file (Pro) analysis, Secrets, and the AppSec Platform are paid.',
  },
  {
    tool: 'OpenGrep',
    license: 'LGPL-2.1 (community fork)',
    cost: 'Free',
    note: 'Vendor-neutral fork of the Semgrep engine, created in 2025; no paid tier or hosted platform.',
  },
  {
    tool: 'CodeQL',
    license: 'MIT queries / proprietary CLI',
    cost: 'Free for OSS; paid for private',
    note: 'Free on public repos and for research; private use is licensed via GitHub Advanced Security.',
  },
  {
    tool: 'Snyk Code',
    license: 'Proprietary SaaS',
    cost: 'Free tier + Team from ~$25/dev/mo',
    note: 'Cloud-based; code is uploaded for analysis by default. Limited free tier, paid team/enterprise plans.',
  },
  {
    tool: 'SonarQube',
    license: 'LGPLv3 (Community) + commercial',
    cost: 'Community free; Developer/Enterprise by LOC',
    note: 'Self-hosted Community Build is free; cross-file taint and many languages need Developer Edition or higher.',
  },
];
