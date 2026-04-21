// tests/fixtures/safe_pq_draft.rs
//
// Positive non-match fixture for rs/pq-vulnerable-crypto.
// Early adopters of draft NIST PQC standards (FN-DSA / FIPS 206 and HQC,
// selected March 2025 as the 5th NIST PQC algorithm) should NOT be flagged
// alongside existing PQ-safe crates (ml_dsa, ml_kem, slh_dsa).

fn pq_safe() {
    // Already PQ-safe — expected not to fire
    let _ = ml_dsa::MlDsa65::keygen();
    let _ = ml_kem::MlKem768::keygen();
    let _ = slh_dsa::Sha2_128s::keygen();

    // Draft NIST standards — should also be ignored by the allowlist
    let _ = fn_dsa::FnDsa512::keygen();
    let _ = hqc::Hqc128::keygen();
}
