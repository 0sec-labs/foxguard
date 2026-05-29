---
title: "Why we ship a CBOM: making CNSA 2.0 deadlines machine-readable"
date: "2026-05-28"
description: "Knowing which of your calls are quantum-vulnerable is only half the answer. The other half is which deadline they miss — and a Cryptographic Bill of Materials is how you make that tracking automatable instead of a spreadsheet someone forgets to update."
readTime: "7 min read"
---

A store-now-decrypt-later attacker doesn't need a quantum computer today. They need your encrypted traffic today and a quantum computer eventually. Anything you protect with RSA or elliptic-curve crypto right now — TLS sessions, signed firmware, key exchanges — can be captured, archived, and decrypted the day a cryptanalytically-relevant quantum computer exists. The data with a long secrecy lifetime is already at risk, whether or not the hardware has arrived.

That threat has been hanging around for years as a "someday" problem. What changed is that CNSA 2.0 put dates on it. NSA's transition timeline turns "we should migrate off RSA eventually" into "national security systems in this equipment class must be on CNSA 2.0 exclusively by this specific year." Once there's a deadline, the engineering question stops being *whether* and becomes *which of my code, against which date.*

Most scanners can't answer that question. We built foxguard's PQ audit and CBOM output to answer both halves of it.

## The gap

Run a typical SAST pass over a repository and it will happily find SQL injection, hardcoded secrets, and unsafe deserialization. Ask it where your quantum-vulnerable crypto lives and it shrugs — post-quantum rules aren't in the default rule set for most of the common scanners. And even the tools that *can* surface crypto usage rarely tie a finding to a compliance deadline. You end up with two disconnected artifacts: a pile of grep hits for `rsa` somewhere, and a CNSA 2.0 timeline PDF somewhere else, and a human in the middle trying to reconcile them in a spreadsheet that goes stale the next time someone adds a dependency.

The inventory and the deadline want to be the same artifact. That's the whole idea behind shipping a CBOM.

## What `foxguard pqc .` flags

```
foxguard pqc .
```

The `pqc` subcommand runs foxguard's PQ-vulnerable-crypto rules and prints the migration deadline alongside every hit. It flags the quantum-vulnerable primitives — **RSA, ECDSA, ECDH, DH, and DSA** — across **five source languages: Python, JavaScript/TypeScript, Go, Java, and Rust.** Web-server and TLS configuration files (OpenSSL, nginx, Apache) are scanned for non-PQ cipher suites, and the dependency side walks **six lockfile formats**: `Cargo.lock`, `requirements.txt`, `poetry.lock`, `Pipfile.lock`, `pnpm-lock.yaml`, and `package-lock.json`. One pass answers both "which of my own calls?" and "which of my dependencies?"

Every finding is deadline-annotated. The deadline is not a guess and not a substring match on the rule name — it's declarative metadata on the rule, consulted through the registry, with each date pinned to NSA guidance in [`src/compliance.rs`](https://github.com/0sec-labs/foxguard/blob/main/src/compliance.rs). The three milestones foxguard surfaces:

- **2030** — software and firmware signing, and traditional networking equipment.
- **2033** — web browsers, web servers, cloud services, and operating systems.
- **2035** — the NSS-wide outer limit from NSM-10, used as the fallback when no more specific class applies.

A scan rolls those per-finding deadlines up into a migration-readiness level: **clean** when nothing PQ-vulnerable fired, **on-track** when only a minority of PQ-relevant findings are still outstanding, and **at-risk** when a majority are. The level is the one-line answer to "how exposed are we right now?" — but it's a summary, and a summary isn't something a pipeline can act on. For that you need the inventory in a structured form.

## Why a CBOM

A Cryptographic Bill of Materials is an SBOM for your crypto. foxguard emits one in [CycloneDX 1.6](https://cyclonedx.org/) — the same standard your dependency SBOM already uses, so a CBOM drops into the same supply-chain tooling:

```
foxguard pqc . --format cbom --output cbom.json
```

The point of writing the inventory to a machine-readable file is that the deadline tracking becomes automatable. Instead of a human eyeballing terminal output once and forgetting about it, you get a CycloneDX document that a CI job can diff, a compliance dashboard can ingest, and an auditor can query. Each crypto asset comes through as a `cryptographic-asset` component with `cryptoProperties` — the primitive (signature, key-agreement, public-key encryption), the crypto functions, and the asset type — and an `evidence.occurrences` block that pins every use back to a `file:line:column` location plus the source snippet. Vulnerable dependencies come through as `library` components carrying their package manager, lockfile context, and resolved version text. The scan and the inventory are one artifact: every component links back to where it actually lives in your tree and the severity of the finding attached to it.

Because the output is CycloneDX rather than a foxguard-specific format, the deadline tracking isn't locked inside our tool. You can:

- diff today's `cbom.json` against last release's in CI and fail the build if a 2030-class finding reappears,
- feed the CBOM into a dependency-track or supply-chain platform that already speaks CycloneDX,
- attach it to a release as a compliance artifact that an auditor can verify without re-running the scan.

Shipping PQ rules in the default scan and emitting a deadline-annotated CBOM out of the same pass is still rare in open source. That's the differentiator: the inventory and the deadline are the same machine-readable thing.

## A realistic example

Say a Go service does its TLS key exchange over P-256:

```go
// src/tls/client.go
import "crypto/ecdh"

func newSession() (*ecdh.PrivateKey, error) {
    return ecdh.P256().GenerateKey(rand.Reader)
}
```

`foxguard pqc .` flags it in the terminal with the deadline inline:

```
src/tls/client.go
  6:12  HIGH      go/pq-vulnerable-crypto (CWE-327)
        ECDH P-256 is not post-quantum safe. CNSA 2.0 mandates ML-KEM-1024
        for NSS; ML-KEM-768 is the NIST default for commercial use.
        CNSA 2.0 deadline: traditional networking equipment, 2030.

WARNING  1 PQ finding in 1 file (0.01s): 1 high, 0 medium, 0 low
CNSA 2.0 migration: at-risk (1 finding with an NSA transition deadline)
```

The same finding, in the CBOM, is a structured component your tooling can read (illustrative shape):

```json
{
  "type": "cryptographic-asset",
  "bom-ref": "crypto:ECDH",
  "name": "ECDH",
  "cryptoProperties": {
    "assetType": "algorithm",
    "algorithmProperties": {
      "primitive": "key-agree",
      "cryptoFunctions": ["keyagree"]
    }
  },
  "evidence": {
    "occurrences": [
      {
        "location": "src/tls/client.go:6:12",
        "additionalContext": "ecdh.P256().GenerateKey(rand.Reader)"
      }
    ]
  }
}
```

The terminal output is for the developer reading it now. The CBOM is for everything downstream that needs to track the same fact over time without a human in the loop.

## Honest scope

A CBOM is an inventory, not a migration. foxguard tells you where your quantum-vulnerable crypto is and which deadline it falls under; it doesn't rewrite your key exchange for you. The PQ rules cover five source languages plus configs and six lockfiles — broad, but not every ecosystem. And NSA's per-class timeline has more nuance than a single annotation can hold: a file that touches both networking equipment (2030) and a web service (2033) has a real ambiguity we resolve by rule, not by surrounding context. The CNSA 2.0 dates and the parameter-set split (ML-KEM-1024 / ML-DSA-87 for NSS, ML-KEM-768 / ML-DSA-65 for commercial) are pinned to primary NSA sources in [`src/compliance.rs`](https://github.com/0sec-labs/foxguard/blob/main/src/compliance.rs); if a date or class looks wrong, that file is the audit surface, and [an issue](https://github.com/0sec-labs/foxguard/issues/new) is the fix path.

The deal is the same as the rest of foxguard: the answer should be fast to get, scoped enough to act on, and structured enough that you only have to compute it once.

---

*foxguard is an open-source security scanner written in Rust. 196 built-in rules, 10 languages, post-quantum crypto audit with CNSA 2.0 deadline annotations and CycloneDX 1.6 CBOM output. [Try it](https://github.com/0sec-labs/foxguard): `npx foxguard pqc .`*
