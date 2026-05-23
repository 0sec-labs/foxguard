#!/usr/bin/env bash
# Wrapper around benchmarks/parity/parity.py.
#
# Usage:
#   ./benchmarks/parity/run.sh              # full run, temp clones, cleanup on exit
#   ./benchmarks/parity/run.sh --only flask # one repo
#   KEEP_CLONES=1 ./benchmarks/parity/run.sh
#   UPDATE_SNAPSHOT=1 ./benchmarks/parity/run.sh
#
# Honored env:
#   FOXGUARD          path to foxguard binary (default: ./target/release/foxguard)
#   SEMGREP           path to semgrep binary (default: $(command -v semgrep))
#   KEEP_CLONES=1     reuse clones in benchmarks/parity/clones across runs
#   UPDATE_SNAPSHOT=1 overwrite benchmarks/parity/expected.json with current results
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FOXGUARD="${FOXGUARD:-$REPO_ROOT/target/release/foxguard}"

if [ ! -x "$FOXGUARD" ]; then
  echo "foxguard binary not found at $FOXGUARD"
  echo "building (cargo build --release)..."
  (cd "$REPO_ROOT" && cargo build --release)
fi

ARGS=("--foxguard" "$FOXGUARD")
if [ -n "${SEMGREP:-}" ]; then
  ARGS+=("--semgrep" "$SEMGREP")
fi
if [ "${KEEP_CLONES:-0}" = "1" ]; then
  ARGS+=("--keep-clones")
fi
if [ "${UPDATE_SNAPSHOT:-0}" = "1" ]; then
  ARGS+=("--update-snapshot")
fi

exec python3 "$SCRIPT_DIR/parity.py" "${ARGS[@]}" "$@"
