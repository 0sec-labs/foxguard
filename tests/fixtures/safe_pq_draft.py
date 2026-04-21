# tests/fixtures/safe_pq_draft.py
#
# Positive non-match fixture for py/pq-vulnerable-crypto.
# Draft NIST PQC standards (FN-DSA / FIPS 206 and HQC, selected March 2025)
# live outside the cryptography.hazmat.primitives.asymmetric.{rsa,ec,dsa,
# ed25519,x25519} module tree and therefore must not fire.

from cryptography.hazmat.primitives.asymmetric import ml_dsa, ml_kem
from pqc import fn_dsa, hqc


def pq_safe() -> None:
    ml_dsa.generate_private_key()
    ml_kem.generate_private_key()
    fn_dsa.generate_private_key()
    hqc.generate_private_key()
