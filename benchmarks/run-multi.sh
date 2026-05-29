#!/usr/bin/env bash
# Multi-tool speed benchmark: foxguard vs Semgrep, OpenGrep (all repos) plus the
# language-native security scanner for each repo (njsscan / bandit / gosec).
# Times wall-clock over N runs and emits parseable "repo tool run seconds findings"
# lines. Tool paths are overridable via env so this is reproducible elsewhere.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPOS="$ROOT/benchmarks/repos"
RUNS="${RUNS:-3}"

FOX="${FOXGUARD:-$ROOT/target/release/foxguard}"
SEMGREP="${SEMGREP:-$(command -v semgrep || true)}"
OPENGREP="${OPENGREP:-$ROOT/.bench-tools/opengrep_osx_arm64}"
NJSSCAN="${NJSSCAN:-$(command -v njsscan || true)}"
BANDIT="${BANDIT:-$(command -v bandit || true)}"
GOSEC="${GOSEC:-$ROOT/.bench-tools/gosec}"

now() { perl -MTime::HiRes=time -e 'printf "%.3f\n", time'; }
elapsed() { perl -e "printf '%.3f', $2 - $1"; }

# time_tool <repo> <tool> <command...>
time_tool() {
  local repo="$1" tool="$2"; shift 2
  for r in $(seq 1 "$RUNS"); do
    local s e t
    s=$(now); "$@" >/dev/null 2>&1 || true; e=$(now); t=$(elapsed "$s" "$e")
    echo "$repo $tool $r $t"
  done
}

run_repo() {
  local repo="$1" lang="$2"; local path="$REPOS/$repo"
  echo "### $repo ($lang)" >&2
  time_tool "$repo" foxguard "$FOX" "$path" --format json
  [ -n "$SEMGREP" ]  && time_tool "$repo" semgrep  "$SEMGREP" --config auto --json --quiet "$path"
  [ -n "$OPENGREP" ] && time_tool "$repo" opengrep "$OPENGREP" scan --config auto --json --quiet "$path"
  case "$lang" in
    javascript) [ -n "$NJSSCAN" ] && time_tool "$repo" njsscan "$NJSSCAN" --json "$path" ;;
    python)     [ -n "$BANDIT" ]  && time_tool "$repo" bandit  "$BANDIT" -r "$path" -f json -q ;;
    go)
      if [ -x "$GOSEC" ]; then
        ( cd "$path" && "$GOSEC" -fmt=json -quiet ./... >/dev/null 2>&1 || true )  # warm-up: resolve deps
        for r in $(seq 1 "$RUNS"); do
          local s e t
          s=$(now); ( cd "$path" && "$GOSEC" -fmt=json -quiet ./... >/dev/null 2>&1 || true ); e=$(now); t=$(elapsed "$s" "$e")
          echo "$repo gosec $r $t"
        done
      fi
      ;;
  esac
}

run_repo express javascript
run_repo flask python
run_repo gin go
