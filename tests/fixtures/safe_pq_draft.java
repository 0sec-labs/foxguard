// tests/fixtures/safe_pq_draft.java
//
// Positive non-match fixture for java/pq-vulnerable-crypto.
// KeyPairGenerator/Signature.getInstance with PQ-safe names — including the
// draft NIST standards FN-DSA (FIPS 206) and HQC (5th NIST PQC algorithm,
// selected March 2025) — must NOT fire. classify_java_pq_algo excludes
// FN-DSA/HQC from the WITHDSA fallback explicitly.
import java.security.KeyPairGenerator;
import java.security.Signature;

public class SafePqDraft {
    public void pqSafe() throws Exception {
        // Already PQ-safe — no findings expected
        KeyPairGenerator.getInstance("ML-DSA");
        KeyPairGenerator.getInstance("ML-KEM");
        KeyPairGenerator.getInstance("SLH-DSA");

        // Draft NIST standards — must also be ignored
        KeyPairGenerator.getInstance("FN-DSA");
        KeyPairGenerator.getInstance("HQC");

        Signature.getInstance("SHA256withFN-DSA");
        Signature.getInstance("SHA256withML-DSA");
    }
}
