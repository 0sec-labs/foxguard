#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

if [ -z "${FOXGUARD:-}" ]; then
  FOXGUARD="$REPO_ROOT/target/release/foxguard"
  cargo build --release
elif [ ! -x "$FOXGUARD" ]; then
  echo "FOXGUARD does not point to an executable: $FOXGUARD" >&2
  exit 2
fi

python3 "$SCRIPT_DIR/precision.py" run --foxguard "$FOXGUARD" "$@"
