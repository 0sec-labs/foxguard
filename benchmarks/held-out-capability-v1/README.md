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

## Private provenance custody v2

`provenance_v2.py` wraps the exact v1 capability and source-change artifacts
with every retained replay preimage: the private manifest, fixtures, oracle
preimages, raw reports, champion and challenger binaries, Foxguard Git bundle,
evaluator and build-input bytes, toolchain output, receipts, signatures, and
historical allowed-signers policies. Every payload path, type, size, and digest
is included in one canonical tree manifest signed under the distinct
`foxguard-held-out-provenance-v2:package-root` SSH namespace.

Verification requires a caller-supplied allowed-signers policy whose captured
bytes exactly match the retained evidence policy. A policy stored only inside
the package is never a trust root. The verifier captures and bounds the entire
package once, validates cross-artifact candidate, corpus, oracle, report,
binary, evaluator, source, and policy bindings, and returns an immutable byte
view; consumers do not reopen package paths. It uses fixed trusted local Git to
verify and unbundle into a bounded bare repository without fetching or checking
out a worktree. Before Git runs, a streaming pack preflight bounds object count,
declared and delta-result sizes, and aggregate expansion on both Linux and
Darwin; a second Git inventory runs under process/output limits. All replay
commands use a fixed minimal environment, then check the exact base and head
objects and reapply the retained patch to reproduce the head tree. It never
executes retained binaries, scripts, evaluators, controller material, or build
commands.

The package is a private quarantined evidence vault. Its exact authority allows
private retention and offline audit only. Execution, provider access, spend,
promotion, training, global-corpus eligibility, model or GitHub writes, draft
PRs, merge, deployment, publication, and disclosure are all false. Presence of
an opaque controller receipt is recorded as presence, while the exact raw CI
receipt is descriptor-bound but remains explicitly not independently verified.
Neither becomes a verified external claim without a separately caller-trusted
role policy.
Private fixture, oracle, and report bytes must never enter the global training
corpus or leave the evidence root without a separate disclosure decision.

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
