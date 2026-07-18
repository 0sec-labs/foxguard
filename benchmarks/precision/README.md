# Labeled precision corpus

This directory is foxguard's reviewed precision corpus. It scans pinned OSS
repositories, joins each emitted finding to a reviewed label, and reports
aggregate plus per-rule precision/noise metrics.

## Quick start

```sh
cargo build --release
./benchmarks/precision/run.sh --check
```

Reports are written to `benchmarks/precision/results/`:

- `summary.md` - dashboard table for aggregate, per-rule, and per-repo metrics.
- `summary.json` - machine-readable metrics used for drift checks.
- `findings.json` - normalized finding rows with labels and justifications.
- `<repo>.foxguard.json` - raw foxguard JSON output for each corpus repo.

## Corpus

`corpus.toml` is the manifest. Every repo is pinned to a full commit SHA and
may specify a `scan_subdir` plus `exclude` patterns. The current seed corpus
is deliberately small enough for local and scheduled CI runs:

| Repo | Language | Scan scope | Purpose |
|------|----------|------------|---------|
| express | JavaScript | `lib` | Reference production framework code |
| flask | Python | `src/flask` | Reference production framework code |
| echo | Go | `.` excluding `*_test.go` | Production framework code with Go rules |
| juice-shop | JavaScript | `routes` | Intentionally vulnerable route handlers |

The current blessed snapshot covers 36 findings: 16 true positives,
20 false positives, and 0 unsure labels. Reviewed precision is 44.4%;
reviewed noise is 55.6%. Treat this as a regression baseline and backlog map,
not as a global precision claim.

## 0research fixed negative cases

`negative-controls-v2.json` selects the 20 reviewed false-positive identities
as immutable negative cases. `fixed_cases_v2.py` grades each selected case even
when its old finding disappears, retains exact per-case evidence, rejects new
unreviewed findings, recomputes metrics, and binds both executed variants to
their source-tree and binary digests. This schema-v2 evidence is suitable for
a future Foxguard-specific 0brain consumer; it must not be disguised as the
currently pwnkit-specific tournament contract.

The small sealed fixture corpus in `../fixed-negative-controls-v2/` runs in PR
CI as a reliable local smoke lane. The 20-case pinned OSS lane remains a
nightly or candidate-evaluation lane because it requires networked checkouts.
Its `project` command executes both bound binaries itself; caller-supplied
findings are not accepted. Each arm retains a scan receipt binding the exact
precision runner, executed binary, and canonical findings:

```sh
python3 benchmarks/precision/fixed_cases_v2.py project \
  --candidate-id foxguard_candidate_1 \
  --champion-source-root /path/to/champion/source \
  --challenger-source-root /path/to/challenger/source \
  --champion-binary /path/to/champion/foxguard \
  --challenger-binary /path/to/challenger/foxguard \
  --workdir /path/to/pinned-corpus-clones \
  --results-dir /tmp/foxguard-reviewed-controls/raw \
  --output /tmp/foxguard-reviewed-controls/evidence.json
```

The reviewed OSS pair uses contract discriminator
`foxguard-reviewed-negative-controls-v2`; the bounded local smoke artifact uses
`foxguard-fixed-negative-controls-v2`. Consumers must select the exact contract,
not dispatch on `schemaVersion` alone.

## Labels

`labels.jsonl` stores one reviewed label per emitted finding. Labels are:

- `true_positive` - the finding identifies a real issue or intentionally
  vulnerable code path.
- `false_positive` - the finding is not actionable for this code location.
- `unsure` - the finding needs deeper maintainer or domain review.

Each row must include a one-line `justification`. If foxguard starts emitting
a new finding, `./benchmarks/precision/run.sh --check` fails with a missing
label. To refresh a review skeleton:

```sh
./benchmarks/precision/run.sh --write-label-skeleton /tmp/labels.jsonl
```

Review the new rows, update `labels.jsonl`, then refresh the blessed snapshot:

```sh
./benchmarks/precision/run.sh --update-expected
```

## CI

The main CI validates the corpus metadata without cloning. The nightly
precision workflow builds foxguard, runs the full corpus, uploads the dashboard
artifact, and fails when reviewed precision drops or reviewed noise rises past
the thresholds in `corpus.toml`.
