// tests/fixtures/safe_pq_draft.js
//
// Positive non-match fixture for js/pq-vulnerable-crypto.
// generateKeyPair('ml-dsa'|'fn-dsa'|'hqc') must NOT fire: the rule matches
// on the literal algorithm argument, and draft NIST PQC names (FN-DSA /
// FIPS 206, HQC — selected March 2025) are not in the quantum-vulnerable
// table.

const crypto = require("crypto");

// PQ-safe KEMs/signatures — no findings expected
crypto.generateKeyPair("ml-dsa", {});
crypto.generateKeyPair("ml-kem", {});
crypto.generateKeyPair("fn-dsa", {});
crypto.generateKeyPair("hqc", {});

// crypto.sign with a PQ-safe algorithm name must also stay quiet
crypto.sign("ml-dsa-65", Buffer.from("msg"), privateKey);
crypto.sign("fn-dsa", Buffer.from("msg"), privateKey);
