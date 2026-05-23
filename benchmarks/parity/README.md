# Semgrep parity harness

What this is:

> A diff harness, not a leaderboard.

It runs both foxguard and Semgrep against a pinned corpus of real OSS repos
and emits a Markdown report showing which findings overlap, which are foxguard-only,
and which are semgrep-only. The point is to surface coverage gaps and lexical
divergence in rule families so we can decide what to do about them on purpose
rather than by accident.

This is the real-repo counterpart to `tests/semgrep_parity.rs`, which exercises
6 synthetic Python micro-patterns. Closes #376.

## Quick start

```sh
# Build foxguard first.
cargo build --release

# Run the harness. Clones go to a temp dir and are cleaned up afterwards.
./benchmarks/parity/run.sh

# Cache clones between runs (faster on re-runs, takes ~200MB on disk).
KEEP_CLONES=1 ./benchmarks/parity/run.sh

# One repo at a time.
./benchmarks/parity/run.sh --only flask

# Overwrite expected.json with the current results (snapshot bump).
UPDATE_SNAPSHOT=1 ./benchmarks/parity/run.sh
```

Reports land in `benchmarks/parity/results/`:

- `summary.md` — top-level table across all repos
- `report-<name>.md` — per-repo detail (top 10 foxguard-only, top 10 semgrep-only, per-family counts)

The harness re-runs idempotently. `KEEP_CLONES=1` reuses cached clones at the
pinned ref. Without it, clones go to a system temp dir and are removed on exit.

## Corpus

`repos.toml` is the manifest. Each entry pins a SHA so re-runs are reproducible.
The default corpus (as of this PR) is:

| Repo | Language | Semgrep ruleset | Scan subdir | Why |
|------|----------|------------------|-------------|-----|
| express | javascript | `p/javascript` | `lib` | Reference JS web framework |
| flask | python | `p/python` | `src/flask` | Reference Python web framework |
| echo | go | `p/golang` | `.` | Small Go HTTP framework, avoids Gin's test-heavy tree |
| juice-shop | javascript | `p/owasp-top-ten` | `routes` | Intentionally-vulnerable app, high-signal route handlers |
| libssh-rs | rust | `p/rust` | `.` | Rust unsafe-block target, currently `skip = true` |

To add a repo: append a `[[repos]]` block to `repos.toml`. Pin to a SHA, not a
branch, so the diff is stable. The script falls back to a default-branch fetch
if the SHA isn't reachable via `fetch --depth 1 <sha>`, but pinning to a tag
or full SHA keeps re-runs honest.

## Output format

### Site parity vs. family parity

The harness reports two numbers per repo:

- **Site parity** = `|sites_both| / |sites_either|`, where a "site" is `(file, line)`.
  Did both tools flag the same code location at all? Ignores rule IDs entirely.
- **Family parity** = `|matches_both| / |matches_either|`, where a "match" is
  `(file, line, rule_family)`. `rule_family` is the rule_id with namespace
  prefixes stripped — so foxguard's `py/no-eval` and Semgrep's
  `python.lang.security.audit.eval-detected.eval-detected` both collapse to
  their leaf token. In practice the leaves still don't always match (`no-eval`
  vs `eval-detected`), so site parity is usually the more honest number.

Family parity is the stricter metric and is what we'd want to track over time.
Site parity is the looser "do we even notice this code?" metric.

### Top 10 lists

Each per-repo report shows:

- Top 10 foxguard-only findings — could be differentiation (foxguard catches
  something Semgrep doesn't) or could be false positives. Triage required.
- Top 10 semgrep-only findings — straight-up coverage gaps to triage.
- Per-rule-family counts — useful for spotting "I have a rule for X but Semgrep
  is also flagging X with a different leaf token".

## Snapshot tracking

`expected.json` is a JSON snapshot of the last "blessed" parity numbers. Bump
it with `UPDATE_SNAPSHOT=1 ./benchmarks/parity/run.sh` after intentional rule
changes. The next non-update run prints a delta:

```
snapshot delta: family parity 14.8% -> 18.2% (+3.4 pp)
```

This makes parity-rate drift visible without being a hard CI gate.

## CI integration

**This PR does not wire the harness into CI.** Real-repo cloning + Semgrep runs
are too slow + flaky to gate every push on. The intent is:

- **Now:** developers run this locally before/after rule changes
- **Follow-up (not in this PR):** nightly GitHub Action that runs the harness,
  uploads `summary.md` + `report-*.md` as artifacts, and opens an issue if
  family parity drops by more than (say) 5 pp week-over-week. See the "Open
  follow-ups" section below.

## Constraints / design choices

- **No Cargo deps.** The harness is pure Python 3.11+ (stdlib only). Matches
  the precedent in `benchmarks/run.sh` and `benchmarks/compare_versions.py`.
  Python 3.9/3.10 will run if `pip install tomli` is available.
- **Semgrep is optional.** If `semgrep` isn't on PATH, foxguard still runs and
  the per-repo Semgrep columns surface a clear error. The script never fails
  the run because of missing Semgrep.
- **No CI gate.** See the section above. The harness is documentation-grade
  tooling, not a check.
- **No fixing of gaps.** The point of this harness is to make gaps visible.
  Acting on them is a separate workstream — open follow-up issues, don't
  silently expand the corpus until the deltas look better.

## Known limitations

- **Rule-family normalization is heuristic.** Real-world rule IDs diverge
  semantically more than lexically. `no-weak-crypto` vs
  `insecure-hash-algorithm-sha1` is the same finding semantically but doesn't
  collapse to the same family token. Site parity covers most of these cases;
  for the rest, eyeballing the per-rule-family table is currently required.
- **Semgrep version drift.** `repos.toml` declares an expected Semgrep version
  but the harness does not enforce it. We rely on the CI-side pin from #374.
- **No Rust coverage yet.** `libssh-rs` is in the manifest but `skip = true`
  pending broader Rust rule coverage on both sides. See "Open follow-ups".

## Open follow-ups (filed separately, not in this PR)

1. **Nightly parity workflow.** GitHub Action that runs this on a cron,
   uploads reports as artifacts, and opens an issue on >5 pp parity drop.
2. **Rule-family mapping table.** Maintain an explicit `foxguard_id -> semgrep_id`
   alias map so semantically-equivalent rules collapse for parity even when
   their lexical leaves diverge (`no-weak-crypto` vs `insecure-hash-algorithm-sha1`).
3. **Rust corpus.** Once foxguard's Rust rule set is wider, unskip `libssh-rs`
   and add a second Rust target.
4. **`semgrep_version` enforcement.** Honor the version pin in `repos.toml` —
   warn or skip when the local Semgrep is older/newer than expected.
