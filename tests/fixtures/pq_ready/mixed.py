# Mixed fixture: quantum-vulnerable RSA + post-quantum ML-KEM.
from cryptography.hazmat.primitives.asymmetric import rsa
from kyber_py.ml_kem import ML_KEM_768


def make_rsa():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def make_pq():
    pk, sk = ML_KEM_768.keygen()
    return pk, sk
