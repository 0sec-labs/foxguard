package main

// Positive non-match fixture for go/pq-vulnerable-crypto.
// Imports of draft NIST PQC standards (FN-DSA / FIPS 206 and HQC, selected
// March 2025 as the 5th NIST PQC algorithm) should NOT trigger the rule.
// Package-prefix matching on rsa./ecdsa./ecdh./dsa./elliptic./ed25519.
// already excludes these; this fixture locks that in.

import (
	"example.com/fndsa"
	"example.com/hqc"
	"example.com/mlkem"
)

func safePq() {
	_ = mlkem.GenerateKey()
	_ = fndsa.GenerateKey()
	_ = hqc.Encapsulate(nil)
}
