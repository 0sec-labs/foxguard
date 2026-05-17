---
description: Post-quantum cryptography audit — find legacy RSA/ECDSA/ECDH usage with CNSA 2.0 deadlines
disable-model-invocation: true
---

Run a post-quantum readiness audit.

1. Take an optional path from `$ARGUMENTS`, default to `.`.
2. Run `foxguard --help` first. If the active binary does not list the `pqc`
   subcommand, stop and tell the user their foxguard binary is too old for
   `/foxguard:pq-audit`; recommend upgrading foxguard, then rerunning
   `/foxguard:setup`. Do not fall back to a generic scan and call it a PQ
   audit.
3. Run via Bash: `foxguard pqc "$PATH_OR_DOT" --format json --severity medium`.
4. Parse the JSON. Each finding may include a `cnsa2Deadline` field — surface that prominently. CNSA 2.0 mandates deprecation of classical asymmetric crypto in security-sensitive paths by specific dates; findings nearer those deadlines are higher priority.
5. Report:
   - Total PQ-vulnerable call sites
   - Breakdown by primitive (RSA, ECDSA, ECDH, etc.) — derive from `rule_id` or `description`
   - For each finding: `file:line`, the legacy primitive, the recommended PQ replacement (e.g., ML-KEM, ML-DSA, hybrid suites)
6. Note that classical primitives may still be acceptable in non-security paths (test fixtures, signed-binary verification of trusted releases). Ask the user about context before recommending wholesale rewrites.
