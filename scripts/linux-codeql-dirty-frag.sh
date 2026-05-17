#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

kernel_ref="${KERNEL_REF:-14acf9652e5690de3c7486c6db5fb8dafd0a32a3}"
linux_repo="${LINUX_REPO:-https://github.com/torvalds/linux.git}"
workdir="${WORKDIR:-${RUNNER_TEMP:-/tmp}/foxguard-linux-codeql-${kernel_ref}}"
out_dir="${OUT_DIR:-${repo_root}/.omx/codeql-linux-calibration/${kernel_ref}}"
codeql_bin="${CODEQL:-codeql}"
query_path="${FOXGUARD_QUERY:-${repo_root}/rules/kernel/dirty-frag-class/queries/kernel/dirty-frag-esp-shared-frag-decrypt-guard.ql}"
targets="${TARGETS:-net/ipv4/esp4.o net/ipv6/esp6.o net/ipv4/ip_output.o net/ipv6/ip6_output.o}"
make_args="${MAKE_ARGS:-ARCH=x86_64 LLVM=1}"
jobs="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)}"
read -r -a make_args_array <<<"$make_args"

kernel_tree="${workdir}/linux"
database_dir="${workdir}/linux-codeql-db"
query_pack_dir="${repo_root}/rules/kernel/dirty-frag-class/queries"
scratch_dir="${query_pack_dir}/.scratch-${kernel_ref}"
sarif_path="${out_dir}/dirty-frag-${kernel_ref}.sarif"

log() {
  printf '[linux-codeql] %s\n' "$*"
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'missing required command: %s\n' "$1" >&2
    exit 127
  fi
}

count_query_rows() {
  local ql_file="$1"
  local bqrs_file="$2"
  local csv_file="$3"

  "$codeql_bin" query run --database "$database_dir" --output "$bqrs_file" "$ql_file" >/dev/null
  "$codeql_bin" bqrs decode --format=csv --output "$csv_file" "$bqrs_file" >/dev/null
  tail -n +2 "$csv_file" | sed '/^[[:space:]]*$/d' | wc -l | tr -d '[:space:]'
}

result_count() {
  python3 - "$sarif_path" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)

print(sum(len(run.get("results", [])) for run in data.get("runs", [])))
PY
}

collect_diagnostics() {
  if [ -d "$database_dir/log" ]; then
    mkdir -p "${out_dir}/database-log"
    cp -R "$database_dir/log/." "${out_dir}/database-log/"
  fi

  if [ -d "$database_dir/diagnostic" ]; then
    mkdir -p "${out_dir}/database-diagnostic"
    cp -R "$database_dir/diagnostic/." "${out_dir}/database-diagnostic/"
  fi
}

write_summary() {
  local findings="${1:-unknown}"

  cat >"${out_dir}/summary.txt" <<EOF
kernel_ref=${kernel_ref}
linux_repo=${linux_repo}
database=${database_dir}
query=${query_path}
sarif=${sarif_path}
files=${files_count:-unknown}
functions=${functions_count:-unknown}
calls=${calls_count:-unknown}
findings=${findings}
targets=${targets}
make_args=${make_args}
EOF
}

require_cmd git
require_cmd make
require_cmd python3
require_cmd "$codeql_bin"

cleanup() {
  rm -rf "$scratch_dir"
}

trap cleanup EXIT

mkdir -p "$workdir" "$out_dir" "$scratch_dir"

if [ ! -d "$kernel_tree/.git" ]; then
  log "cloning Linux into ${kernel_tree}"
  git clone --filter=blob:none "$linux_repo" "$kernel_tree"
else
  log "reusing Linux tree ${kernel_tree}"
fi

log "checking out ${kernel_ref}"
git -C "$kernel_tree" fetch --filter=blob:none origin "$kernel_ref"
git -C "$kernel_tree" checkout --force FETCH_HEAD
git -C "$kernel_tree" clean -ffdqx

log "preparing minimal x86_64 kernel build state"
make -C "$kernel_tree" "${make_args_array[@]}" defconfig
make -C "$kernel_tree" "${make_args_array[@]}" -j"$jobs" prepare scripts

rm -rf "$database_dir"

log "creating CodeQL database for targets: ${targets}"
"$codeql_bin" database create "$database_dir" \
  --language=cpp \
  --source-root "$kernel_tree" \
  --command "make ${make_args} -j${jobs} ${targets}"

cat >"${scratch_dir}/files.ql" <<'QL'
import cpp

from File f
select f, f.getRelativePath()
QL

cat >"${scratch_dir}/functions.ql" <<'QL'
import cpp

from Function f
select f, f.getName()
QL

cat >"${scratch_dir}/calls.ql" <<'QL'
import cpp

from FunctionCall c
select c, c.toString()
QL

files_count="$(count_query_rows "${scratch_dir}/files.ql" "${scratch_dir}/files.bqrs" "${scratch_dir}/files.csv")"
functions_count="$(count_query_rows "${scratch_dir}/functions.ql" "${scratch_dir}/functions.bqrs" "${scratch_dir}/functions.csv")"
calls_count="$(count_query_rows "${scratch_dir}/calls.ql" "${scratch_dir}/calls.bqrs" "${scratch_dir}/calls.csv")"

log "database inventory: files=${files_count} functions=${functions_count} calls=${calls_count}"

if [ "$functions_count" -eq 0 ] || [ "$calls_count" -eq 0 ]; then
  collect_diagnostics
  write_summary "not-run"
  printf 'CodeQL database has no usable function/call AST records; refusing to calibrate.\n' >&2
  exit 1
fi

log "analyzing ${query_path}"
"$codeql_bin" database analyze "$database_dir" "$query_path" \
  --format=sarif-latest \
  --output "$sarif_path"

findings="$(result_count)"
log "SARIF findings: ${findings}"

collect_diagnostics
write_summary "$findings"

log "wrote ${out_dir}/summary.txt"

if [ "${KEEP_WORKDIR:-0}" != "1" ]; then
  log "removing workdir ${workdir}"
  rm -rf "$workdir"
fi
