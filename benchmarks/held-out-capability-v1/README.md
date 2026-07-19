# Held-out capability evidence v1

This producer compares exact Foxguard binaries against a private, independently
reviewed known-positive corpus. It is deliberately separate from the fixed
negative-control lanes: positive evidence measures newly detected capability,
while the existing lanes continue to gate false positives and regressions.

Promotion evidence requires all of the following:

- a root-owned manifest with no group/other write bit (normally `0640`) and
  root-owned fixtures that the evaluator cannot modify;
- at least four sorted, content-addressed, known-positive cases;
- exact normalized expected findings and an independent oracle digest per case;
- a non-calibration corpus; and
- non-overlapping 95% Wilson intervals favoring the challenger.

The public precision fixtures may be used to test this evaluator only when the
manifest is marked `calibration: true`. Calibration evidence can never pass the
capability gate.

This artifact is evidence only: its draft-PR, merge, and publication authority
flags are always false. Only the 0brain composite gate may later authorize a
private draft PR after it also verifies both negative lanes, the exact executed
source change, trusted controller/build receipts, and the exact CI check set.

Direct binary execution in this module is deliberately calibration-only and
must use a public/non-secret corpus. A non-calibration run is refused: real
held-out execution belongs to the controller's dedicated unprivileged sandbox
broker, where the candidate cannot read the manifest/oracle, mutate fixtures,
reach the network, or access sibling/controller state. Retain its manifest,
fixtures, raw reports, evidence, executed-change descriptor, and signatures in
the private evidence root. Nothing here publishes, discloses, or uploads them.

The native verifier captures artifact bytes once and derives both validation
and the printed reference from that same bounded snapshot. Fixture traversal is
descriptor-relative and capped by total files, bytes, entries, and depth before
content is retained. Calibration executes owner-private, read-only copies made
from that captured fixture and binary byte view, and checks their complete
byte/identity seals before and after every scan. These controls are
prerequisites for the private
`foxguard-held-out-provenance-v2` custody package; the v1 evidence JSON is not
itself self-contained, signed, or eligible for a global training corpus.

`source_change.py` separately binds the candidate to clean base/head commits,
Git tree OIDs, content-tree digests, canonical full-index binary patch bytes,
the allowed changed paths (`src/rules/**` plus tests), both executed binaries,
the exact build argv and Rust inputs, and a successful CI receipt for the exact
head. Verification reapplies the retained patch to an isolated temporary Git
index and requires the resulting tree to equal the recorded head tree.

The descriptor records the supplied CI receipt and binary/build claims but
marks both `ciVerified` and `buildVerified` false. It proves their identities,
not their truth. Only 0brain may upgrade those provenance gates after checking
signed controller build receipts and the exact GitHub check set.

```sh
python3 held_out.py calibrate \
  --candidate-id "$CANDIDATE_ID" \
  --champion-binary "$CHAMPION_BINARY" \
  --challenger-binary "$CHALLENGER_BINARY" \
  --champion-source-root "$CHAMPION_SOURCE" \
  --challenger-source-root "$CHALLENGER_SOURCE" \
  --manifest "$PRIVATE_MANIFEST" \
  --results-dir "$PRIVATE_OUTPUT/raw" \
  --output "$PRIVATE_OUTPUT/evidence.json"
```
