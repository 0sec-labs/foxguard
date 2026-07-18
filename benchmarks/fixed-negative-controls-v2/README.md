# Fixed negative controls v2

This is Foxguard's sealed, local negative-control lane for 0research promotion
decisions. It is deliberately separate from `benchmarks/precision`: the
networked OSS precision corpus remains a nightly diagnostic and backlog, while
these cases exist independently of scanner output and therefore remain
gradable when a false positive disappears.

Each case is a pinned, known-safe fixture with an expected empty finding set.
The runner executes the same ordered case set against champion and challenger,
retains exact normalized findings, recomputes both scores from those findings,
and binds the artifact to the manifest bytes, fixture bytes, evaluator bytes,
source commit/tree identities, and executed binary bytes. Output is canonical
JSON; the printed `foxguard-negative-controls-v2:sha256:...` reference hashes
the exact retained bytes.

Example after building both variants:

```sh
python3 benchmarks/fixed-negative-controls-v2/fixed_controls.py run \
  --candidate-id foxguard_candidate_1 \
  --champion-binary /path/to/champion/foxguard \
  --challenger-binary /path/to/challenger/foxguard \
  --champion-source-root /path/to/champion/source \
  --challenger-source-root /path/to/challenger/source \
  --results-dir /tmp/foxguard-controls/raw \
  --output /tmp/foxguard-controls/evidence.json
```

Offline structural replay checks the sealed corpus, exact case coverage,
per-case verdicts, recomputed scores, and optionally the retained-byte ref:

```sh
python3 benchmarks/fixed-negative-controls-v2/fixed_controls.py verify \
  --artifact /tmp/foxguard-controls/evidence.json \
  --ref "foxguard-negative-controls-v2:sha256:..."
```

The command fails when the challenger false-positive rate exceeds the champion
rate. It does not claim vulnerability-discovery success; held-out vulnerable
cases remain a separate 0research lane.
