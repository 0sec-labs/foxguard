#!/usr/bin/env bash
set -euo pipefail

root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd -P)
scan_hook="$root/plugins/claude-code/scripts/scan-edited-file.sh"
restore_hook="$root/plugins/claude-code/scripts/restore-unresolved-findings.sh"
state_helper="$root/plugins/claude-code/scripts/finding-state.sh"
lock_wrapper="$root/plugins/claude-code/scripts/with-state-lock.pl"
hooks_json="$root/plugins/claude-code/hooks/hooks.json"
fixture="$root/tests/fixtures/safe.py"
session_id="compaction-test-588"
tmp_dir=$(mktemp -d)
cache_dir="$tmp_dir/cache"
fake_bin="$tmp_dir/bin"
pause_bin="$tmp_dir/pause-bin"
no_perl_bin="$tmp_dir/no-perl-bin"
no_scanner_bin="$tmp_dir/no-scanner-bin"
state_root="$cache_dir/foxguard/claude-code"

cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

assert_status() {
  [ "$1" = "$2" ] || fail "expected exit $2, got $1"
}

assert_contains() {
  case "$1" in
    *"$2"*) ;;
    *) fail "expected output containing $2" ;;
  esac
}

assert_not_contains() {
  case "$1" in
    *"$2"*) fail "unexpected output containing $2" ;;
    *) ;;
  esac
}

assert_line() {
  case $'\n'"$1"$'\n' in
    *$'\n'"$2"$'\n'*) ;;
    *) fail "expected exact line $2" ;;
  esac
}
file_mtime() {
  perl -e 'print((stat $ARGV[0])[9])' "$1"
}

file_links() {
  perl -e 'print((stat $ARGV[0])[3])' "$1"
}

file_mode() {
  perl -e 'printf "%04o", (stat $ARGV[0])[2] & 0777' "$1"
}


hash_for_test() {
  if command -v shasum >/dev/null 2>&1; then
    printf '%s\0' "$@" | shasum -a 256 | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then
    printf '%s\0' "$@" | sha256sum | awk '{print $1}'
  else
    printf '%s\0' "$@" | openssl dgst -sha256 | awk '{print $NF}'
  fi
}

fingerprint_for_test() {
  hash_for_test "$@"
}

workspace_key_for_test() {
  hash_for_test "foxguard-claude-code-workspace-v1" "$1"
}

session_key_for_test() {
  hash_for_test "foxguard-claude-code-session-v1" "$1"
}

state_for_path() {
  jq -cn --arg path "$1" '
    {
      version: 3,
      overflow: 0,
      omitted: [],
      files: {
        ($path): {
          threshold: "medium",
          total: 1,
          truncated: false,
          findings: [{
            fingerprint: ([range(0;64) | "a"] | join("")),
            rule_id: "test/no-danger",
            severity: "high",
            line: 1,
            column: 1
          }]
        }
      }
    }
  '
}
record_for_rule() {
  jq -cn --arg rule_id "$1" '
    {
      total: 1,
      truncated: false,
      findings: [{
        fingerprint: ([range(0;64) | "b"] | join("")),
        rule_id: $rule_id,
        severity: "high",
        line: 7,
        column: 3
      }]
    }
  '
}

mkdir -p "$fake_bin" "$pause_bin" "$no_perl_bin" "$no_scanner_bin"
cat > "$fake_bin/foxguard" <<'EOF'
#!/usr/bin/env bash
case "${FOXGUARD_TEST_MODE:-finding}" in
  finding)
    printf '%s\n' '{"findings":[{"rule_id":"test/no-danger","severity":"high","line":7,"column":3,"description":"FINDING_SECRET","cwe":"CWE-79","snippet":"SOURCE_SNIPPET_SECRET"}]}'
    exit 1
    ;;
  alternate)
    printf '%s\n' '{"findings":[{"rule_id":"test/no-danger","severity":"high","line":7,"column":3,"description":"OTHER_FINDING_SECRET","cwe":"CWE-79","snippet":"OTHER_SOURCE_SNIPPET_SECRET"}]}'
    exit 1
    ;;
  other)
    printf '%s\n' '{"findings":[{"rule_id":"test/other-danger","severity":"high","line":7,"column":3,"description":"OTHER_FINDING_SECRET","cwe":"CWE-79","snippet":"OTHER_SOURCE_SNIPPET_SECRET"}]}'
    exit 1
    ;;
  hostile)
    printf '%s\n' '{"findings":[{"rule_id":"test/hostile-rule","severity":"high","line":7,"column":3,"description":"HOSTILE_FINDING_SECRET","cwe":"CWE-79","snippet":"HOSTILE_SOURCE_SECRET"}]}'
    exit 1
    ;;
  clean)
    printf '%s\n' '{"findings":[]}'
    exit 0
    ;;
  invalid)
    printf '%s\n' 'not-json'
    exit 2
    ;;
  empty_error)
    printf '%s\n' '{"findings":[]}'
    exit 2
    ;;
  error)
    printf '%s\n' '{"error":"scanner failure"}'
    exit 2
    ;;
  many)
    jq -n '[range(0;90) | {rule_id:("test/rule-" + tostring), severity:"high", line:(. + 1), column:1, description:"FINDING_SECRET", snippet:"SOURCE_SNIPPET_SECRET"}]'
    exit 1
    ;;
  *)
    exit 2
    ;;
esac
EOF
chmod +x "$fake_bin/foxguard"
# State helpers must not rely on `sh` being Bash; CI commonly uses dash.
cat > "$fake_bin/sh" <<'EOF'
#!/usr/bin/env bash
exit 99
EOF
chmod +x "$fake_bin/sh"
cat > "$no_perl_bin/perl" <<'EOF'
#!/usr/bin/env bash
exit 99
EOF
chmod +x "$no_perl_bin/perl"
cat > "$pause_bin/mv" <<'EOF'
#!/usr/bin/env bash
if [ "${FG_STATE_TEST_PAUSE_MV:-}" = "1" ]; then
  : > "$FG_STATE_TEST_MV_READY"
  while [ ! -f "$FG_STATE_TEST_MV_RELEASE" ]; do sleep 0.05; done
fi
exec /bin/mv "$@"
EOF
chmod +x "$pause_bin/mv"
jq_path=$(command -v jq)
case "$jq_path" in
  /*) ;;
  *) fail "jq command is not an absolute path" ;;
esac
ln -s "$jq_path" "$no_scanner_bin/jq"
cat > "$no_scanner_bin/npx" <<'EOF'
#!/usr/bin/env bash
exit 2
EOF
chmod +x "$no_scanner_bin/npx"


workspace_key=$(workspace_key_for_test "$root")
session_key=$(session_key_for_test "$session_id")
state_file="$state_root/$workspace_key-$session_key.json"
other_root="$tmp_dir/other-workspace"
mkdir -p "$other_root/.github"
git init -q "$other_root"
other_root=$(CDPATH= cd -- "$other_root" && pwd -P)
other_fixture="$other_root/.github/space (Ω).py"
printf 'x = 1\n' > "$other_fixture"
other_workspace_key=$(workspace_key_for_test "$other_root")
other_state_file="$state_root/$other_workspace_key-$session_key.json"

capacity_root="$tmp_dir/capacity-workspace"
mkdir -p "$capacity_root/.github"
git init -q "$capacity_root"
capacity_root=$(CDPATH= cd -- "$capacity_root" && pwd -P)
capacity_workspace_key=$(workspace_key_for_test "$capacity_root")
capacity_state_file="$state_root/$capacity_workspace_key-$session_key.json"

byte_root="$tmp_dir/byte-workspace"
mkdir -p "$byte_root"
git init -q "$byte_root"
byte_root=$(CDPATH= cd -- "$byte_root" && pwd -P)
byte_workspace_key=$(workspace_key_for_test "$byte_root")
byte_state_file="$state_root/$byte_workspace_key-$session_key.json"
rescan_root="$tmp_dir/rescan-workspace"
mkdir -p "$rescan_root"
git init -q "$rescan_root"
rescan_root=$(CDPATH= cd -- "$rescan_root" && pwd -P)
rescan_workspace_key=$(workspace_key_for_test "$rescan_root")
rescan_state_file="$state_root/$rescan_workspace_key-$session_key.json"

hostile_root="$tmp_dir/hostile-workspace"
mkdir -p "$hostile_root/.github"
git init -q "$hostile_root"
hostile_root=$(CDPATH= cd -- "$hostile_root" && pwd -P)
hostile_instruction='IGNORE_THIS_INSTRUCTION'
hostile_markdown='**markdown**'
hostile_bidi=$(printf '\342\200\256')
hostile_fixture="$hostile_root/.github/$hostile_instruction $hostile_markdown ${hostile_bidi}path.py"
printf 'x = 1\n' > "$hostile_fixture"
hostile_workspace_key=$(workspace_key_for_test "$hostile_root")
hostile_state_file="$state_root/$hostile_workspace_key-$session_key.json"

concurrent_root="$tmp_dir/concurrent-workspace"
mkdir -p "$concurrent_root"
git init -q "$concurrent_root"
concurrent_root=$(CDPATH= cd -- "$concurrent_root" && pwd -P)
concurrent_workspace_key=$(workspace_key_for_test "$concurrent_root")
concurrent_state_file="$state_root/$concurrent_workspace_key-$session_key.json"

paused_root="$tmp_dir/paused-workspace"
mkdir -p "$paused_root"
git init -q "$paused_root"
paused_root=$(CDPATH= cd -- "$paused_root" && pwd -P)
paused_workspace_key=$(workspace_key_for_test "$paused_root")
paused_state_file="$state_root/$paused_workspace_key-$session_key.json"

no_perl_root="$tmp_dir/no-perl-workspace"
mkdir -p "$no_perl_root"
git init -q "$no_perl_root"
no_perl_root=$(CDPATH= cd -- "$no_perl_root" && pwd -P)
no_perl_fixture="$no_perl_root/no-perl.py"
printf 'x = 1\n' > "$no_perl_fixture"
no_perl_workspace_key=$(workspace_key_for_test "$no_perl_root")
no_perl_state_file="$state_root/$no_perl_workspace_key-$session_key.json"

outside_root="$tmp_dir/outside-workspace"
mkdir -p "$outside_root"
outside_root=$(CDPATH= cd -- "$outside_root" && pwd -P)
outside_fixture="$outside_root/outside.py"
printf 'x = 1\n' > "$outside_fixture"

untracked_root="$tmp_dir/untracked-workspace"
mkdir -p "$untracked_root"
git init -q "$untracked_root"
untracked_root=$(CDPATH= cd -- "$untracked_root" && pwd -P)
untracked_workspace_key=$(workspace_key_for_test "$untracked_root")
untracked_state_file="$state_root/$untracked_workspace_key-$session_key.json"

forged_locked_root="$tmp_dir/forged-locked-workspace"
mkdir -p "$forged_locked_root"
git init -q "$forged_locked_root"
forged_locked_root=$(CDPATH= cd -- "$forged_locked_root" && pwd -P)
forged_locked_session_id='forged-locked-session'
forged_locked_workspace_key=$(workspace_key_for_test "$forged_locked_root")
forged_locked_session_key=$(session_key_for_test "$forged_locked_session_id")
forged_locked_state_file="$state_root/$forged_locked_workspace_key-$forged_locked_session_key.json"

plugin_root_with_spaces="$tmp_dir/plugin root"
mkdir -p "$plugin_root_with_spaces"
ln -s "$root/plugins/claude-code/scripts" "$plugin_root_with_spaces/scripts"

containment_root="$tmp_dir/containment-workspace"
mkdir -p "$containment_root"
git init -q "$containment_root"
containment_root=$(CDPATH= cd -- "$containment_root" && pwd -P)
containment_alias_name=$(printf '%s' "${containment_root##*/}" | tr '[:lower:]' '[:upper:]')
containment_alias="${containment_root%/*}/$containment_alias_name"

edit_payload=$(jq -cn --arg session "$session_id" --arg cwd "$root" --arg path "$fixture" \
  '{session_id:$session, cwd:$cwd, tool_input:{file_path:$path}}')
relative_edit_payload=$(jq -cn --arg session "$session_id" --arg cwd "$root" --arg path 'tests/fixtures/safe.py' \
  '{session_id:$session, cwd:$cwd, tool_input:{file_path:$path}}')
compact_payload=$(jq -cn --arg session "$session_id" --arg cwd "$root" \
  '{session_id:$session, cwd:$cwd, source:"compact"}')
other_edit_payload=$(jq -cn --arg session "$session_id" --arg cwd "$other_root" --arg path "$other_fixture" \
  '{session_id:$session, cwd:$cwd, tool_input:{file_path:$path}}')
other_compact_payload=$(jq -cn --arg session "$session_id" --arg cwd "$other_root" \
  '{session_id:$session, cwd:$cwd, source:"compact"}')
capacity_compact_payload=$(jq -cn --arg session "$session_id" --arg cwd "$capacity_root" \
  '{session_id:$session, cwd:$cwd, source:"compact"}')
byte_compact_payload=$(jq -cn --arg session "$session_id" --arg cwd "$byte_root" \
  '{session_id:$session, cwd:$cwd, source:"compact"}')
rescan_compact_payload=$(jq -cn --arg session "$session_id" --arg cwd "$rescan_root" \
  '{session_id:$session, cwd:$cwd, source:"compact"}')
hostile_edit_payload=$(jq -cn --arg session "$session_id" --arg cwd "$hostile_root" --arg path "$hostile_fixture" \
  '{session_id:$session, cwd:$cwd, tool_input:{file_path:$path}}')
hostile_compact_payload=$(jq -cn --arg session "$session_id" --arg cwd "$hostile_root" \
  '{session_id:$session, cwd:$cwd, source:"compact"}')
other_session_compact_payload=$(jq -cn --arg session 'prune-test-session' --arg cwd "$capacity_root" \
  '{session_id:$session, cwd:$cwd, source:"compact"}')
foo_compact_payload=$(jq -cn --arg session 'foo' --arg cwd "$root" \
  '{session_id:$session, cwd:$cwd, source:"compact"}')
old_foo_session_key=$(session_key_for_test 'old-foo')
old_foo_state_file="$state_root/$workspace_key-$old_foo_session_key.json"
startup_payload=$(jq -cn --arg session "$session_id" --arg cwd "$root" \
  '{session_id:$session, cwd:$cwd, source:"startup"}')
no_perl_payload=$(jq -cn --arg session "$session_id" --arg cwd "$no_perl_root" --arg path "$no_perl_fixture" \
  '{session_id:$session, cwd:$cwd, tool_input:{file_path:$path}}')
outside_payload=$(jq -cn --arg session "$session_id" --arg cwd "$outside_root" --arg path "$outside_fixture" \
  '{session_id:$session, cwd:$cwd, tool_input:{file_path:$path}}')
missing_payload=$(jq -cn --arg session "$session_id" --arg cwd "$root" --arg path "$root/does-not-exist.py" \
  '{session_id:$session, cwd:$cwd, tool_input:{file_path:$path}}')

run_scan() {
  local mode=$1 payload

  payload=${2:-"$edit_payload"}
  set +e
  scan_output=$(printf '%s' "$payload" | \
    FOXGUARD_TEST_MODE="$mode" XDG_CACHE_HOME="$cache_dir" PATH="$fake_bin:$PATH" \
      "$scan_hook" 2>&1)
  scan_status=$?
  set -e
}

run_scan_without_perl() {
  local mode=$1 payload=$2

  set +e
  scan_output=$(printf '%s' "$payload" | \
    FOXGUARD_TEST_MODE="$mode" XDG_CACHE_HOME="$cache_dir" PATH="$no_perl_bin:$fake_bin:$PATH" \
      "$scan_hook" 2>&1)
  scan_status=$?
  set -e
}

run_scan_without_scanner() {
  local payload=$1

  set +e
  scan_output=$(printf '%s' "$payload" | \
    XDG_CACHE_HOME="$cache_dir" PATH="$no_scanner_bin:/usr/bin:/bin" "$scan_hook" 2>&1)
  scan_status=$?
  set -e
}

run_restore_with_cache() {
  local payload=$1 cache_home=$2

  set +e
  restore_output=$(printf '%s' "$payload" | \
    XDG_CACHE_HOME="$cache_home" PATH="$fake_bin:$PATH" "$restore_hook" 2>&1)
  restore_status=$?
  set -e
}

run_restore() {
  run_restore_with_cache "$1" "$cache_dir"
}

run_state_root() {
  local cache_home=$1 repo_root=$2

  set +e
  state_root_output=$(
    (
      XDG_CACHE_HOME="$cache_home"
      . "$state_helper"
      fg_state_root "$repo_root"
    ) 2>&1
  )
  state_root_status=$?
  set -e
}
run_state_update() {
  local repo_root=$1 relative_path=$2 record=$3 state_session=${4:-$session_id}

  (
    XDG_CACHE_HOME="$cache_dir"
    PATH="$fake_bin:$PATH"
    . "$state_helper"
    fg_state_update_file "$state_session" "$repo_root" "$relative_path" medium "$record"
  )
}

run_locked_action() {
  set +e
  locked_action_output=$(XDG_CACHE_HOME="$cache_dir" PATH="$fake_bin:$PATH" "$state_helper" "$@" 2>&1)
  locked_action_status=$?
  set -e
}


run_paused_state_update() {
  local repo_root=$1 relative_path=$2 record=$3 ready_file=$4 release_file=$5

  (
    export XDG_CACHE_HOME="$cache_dir"
    export PATH="$pause_bin:$fake_bin:$PATH"
    export FG_STATE_TEST_PAUSE_MV=1
    export FG_STATE_TEST_MV_READY="$ready_file"
    export FG_STATE_TEST_MV_RELEASE="$release_file"
    . "$state_helper"
    fg_state_update_file "$session_id" "$repo_root" "$relative_path" medium "$record"
  )
}

run_state_update_with_limit() {
  local limit=$1 repo_root=$2 relative_path=$3 record=$4 state_session=${5:-$session_id}

  (
    XDG_CACHE_HOME="$cache_dir"
    PATH="$fake_bin:$PATH"
    . "$state_helper"
    export FG_STATE_MAX_BYTES=$limit
    fg_state_update_file "$state_session" "$repo_root" "$relative_path" medium "$record"
  )
}


run_state_update_with_limits() {
  local byte_limit=$1 omitted_limit=$2 repo_root=$3 relative_path=$4 record=$5

  (
    XDG_CACHE_HOME="$cache_dir"
    PATH="$fake_bin:$PATH"
    . "$state_helper"
    export FG_STATE_MAX_BYTES=$byte_limit
    export FG_STATE_MAX_OMITTED=$omitted_limit
    fg_state_update_file "$session_id" "$repo_root" "$relative_path" medium "$record"
  )
}
run_configured_post_hook() {
  set +e
  configured_post_output=$(printf '%s' "$edit_payload" | \
    CLAUDE_PLUGIN_ROOT="$plugin_root_with_spaces" FOXGUARD_TEST_MODE=finding \
      XDG_CACHE_HOME="$cache_dir" PATH="$fake_bin:$PATH" bash -c "$post_hook_command" 2>&1)
  configured_post_status=$?
  set -e
}

run_configured_restore_hook() {
  set +e
  configured_restore_output=$(printf '%s' "$compact_payload" | \
    CLAUDE_PLUGIN_ROOT="$plugin_root_with_spaces" XDG_CACHE_HOME="$cache_dir" PATH="$fake_bin:$PATH" \
      bash -c "$restore_hook_command" 2>&1)
  configured_restore_status=$?
  set -e
}
jq -e '
  ([.hooks.PostToolUse[] | .hooks[] |
    select(.command == "\"${CLAUDE_PLUGIN_ROOT}/scripts/scan-edited-file.sh\"")
  ] | length) == 1
  and
  ([.hooks.SessionStart[] |
    select(.hooks | any(.[]; .command == "cat \"${CLAUDE_PLUGIN_ROOT}/scripts/secure-defaults.txt\""))
  ] | length) == 1
  and
  ([.hooks.SessionStart[] |
    select(.matcher == "compact"
      and (.hooks | any(.[]; .command == "\"${CLAUDE_PLUGIN_ROOT}/scripts/restore-unresolved-findings.sh\"")))
  ] | length) == 1
' "$hooks_json" >/dev/null
post_hook_command=$(jq -r '.hooks.PostToolUse[0].hooks[0].command' "$hooks_json")
restore_hook_command=$(jq -r '.hooks.SessionStart[] | select(.matcher == "compact") | .hooks[0].command' "$hooks_json")

bash -n "$scan_hook"
bash -n "$state_helper"
bash -n "$restore_hook"
perl -c "$lock_wrapper" >/dev/null
jq empty "$hooks_json"
for unsafe_path in '/absolute.py' 'C:/absolute.py' 'dir//empty.py' './dot.py' 'dir/../up.py' \
  $'control\001path.py' 'dir\backslash.py'; do
  if state_for_path "$unsafe_path" | ( . "$state_helper"; fg_state_validate >/dev/null 2>&1 ); then
    fail "unsafe relative path was accepted"
  fi
done

run_state_root "$containment_root/.cache" "$containment_root"
[ "$state_root_status" -ne 0 ] || fail "repository cache path was accepted"
[ -z "$state_root_output" ] || fail "repository cache path emitted diagnostics"
[ ! -e "$containment_root/.cache" ] || fail "state landed in checkout"
if [[ "$containment_alias" -ef "$containment_root" ]]; then
  run_state_root "$containment_alias/.case-cache" "$containment_root"
  [ "$state_root_status" -ne 0 ] || fail "case-folded repository cache path was accepted"
  [ -z "$state_root_output" ] || fail "case-folded repository cache path emitted diagnostics"
  [ ! -e "$containment_root/.case-cache" ] || fail "case-folded state landed in checkout"
fi
run_configured_post_hook
assert_status "$configured_post_status" 2
assert_contains "$configured_post_output" FINDING_SECRET

run_scan finding
assert_status "$scan_status" 2
assert_contains "$scan_output" FINDING_SECRET
assert_contains "$scan_output" SOURCE_SNIPPET_SECRET
[ -f "$state_file" ] || fail "finding scan did not create state"
jq -e --arg path 'tests/fixtures/safe.py' '
  .version == 3
  and .overflow == 0
  and .omitted == []
  and (.files | keys == [$path])
  and (.files[$path].threshold == "medium")
  and (.files[$path].total == 1)
  and (.files[$path].truncated == false)
  and ((.files[$path].findings[0] | keys | sort) == ["column", "fingerprint", "line", "rule_id", "severity"])
' "$state_file" >/dev/null || fail "state schema is not metadata-only"
if jq -e '.. | objects | select(has("description") or has("snippet") or has("cwe") or has("dataflow"))' "$state_file" >/dev/null; then
  fail "state retained a forbidden finding field"
fi
state_content=$(cat "$state_file")
assert_not_contains "$state_content" FINDING_SECRET
assert_not_contains "$state_content" SOURCE_SNIPPET_SECRET
assert_not_contains "$state_content" "$root"
assert_not_contains "$(basename "$state_file")" "$session_id"
direct_locked_record=$(record_for_rule test/direct-locked)
locked_update_sentinel="$forged_locked_root/update-sentinel"
printf 'sentinel\n' > "$locked_update_sentinel"
run_locked_action --locked-update 131072 64 "$forged_locked_root" "$forged_locked_session_id" \
  'direct.py' medium "$direct_locked_record"
assert_status "$locked_action_status" 0
[ "$(cat "$locked_update_sentinel")" = "sentinel" ] \
  || fail "direct locked update modified an out-of-cache sentinel"
[ -f "$forged_locked_state_file" ] || fail "direct locked update did not write its derived state file"
forged_locked_state_content=$(cat "$forged_locked_state_file")
run_locked_action --locked-update 131072 64 "$forged_locked_root" "$forged_locked_session_id" \
  "$locked_update_sentinel" medium "$direct_locked_record"
[ "$locked_action_status" -ne 0 ] || fail "hostile direct locked update was accepted"
[ "$(cat "$locked_update_sentinel")" = "sentinel" ] \
  || fail "hostile direct locked update modified an out-of-cache sentinel"
[ "$(cat "$forged_locked_state_file")" = "$forged_locked_state_content" ] \
  || fail "hostile direct locked update changed derived state"

locked_remove_sentinel="$forged_locked_root/remove-sentinel"
printf 'sentinel\n' > "$locked_remove_sentinel"
run_locked_action --locked-remove 131072 64 "$forged_locked_root" "$forged_locked_session_id" \
  "$locked_remove_sentinel"
assert_status "$locked_action_status" 0
[ "$(cat "$locked_remove_sentinel")" = "sentinel" ] \
  || fail "hostile direct locked remove modified an out-of-cache sentinel"
[ "$(cat "$forged_locked_state_file")" = "$forged_locked_state_content" ] \
  || fail "hostile direct locked remove changed derived state"
run_locked_action --locked-remove 131072 64 "$forged_locked_root" "$forged_locked_session_id" 'direct.py'
assert_status "$locked_action_status" 0
[ ! -e "$forged_locked_state_file" ] || fail "direct locked remove did not remove its derived state file"
[ "$(cat "$locked_remove_sentinel")" = "sentinel" ] \
  || fail "direct locked remove modified an out-of-cache sentinel"

locked_state_symlink_sentinel="$forged_locked_root/state-symlink-sentinel"
printf 'sentinel\n' > "$locked_state_symlink_sentinel"
ln -s "$locked_state_symlink_sentinel" "$forged_locked_state_file"
run_locked_action --locked-update 131072 64 "$forged_locked_root" "$forged_locked_session_id" \
  'direct.py' medium "$direct_locked_record"
[ "$locked_action_status" -ne 0 ] || fail "symlinked derived state file was accepted"
[ "$(cat "$locked_state_symlink_sentinel")" = "sentinel" ] \
  || fail "direct locked update followed a state-file symlink"
[ -L "$forged_locked_state_file" ] || fail "state-file symlink was replaced"
rm -f "$forged_locked_state_file"
nested_locked_root="$state_root/nested-locked-workspace"
mkdir -p "$nested_locked_root"
git init -q "$nested_locked_root"
nested_locked_root=$(CDPATH= cd -- "$nested_locked_root" && pwd -P)
nested_locked_session_id='nested-locked-session'
nested_locked_session_key=$(session_key_for_test "$nested_locked_session_id")
nested_locked_workspace_key=$(workspace_key_for_test "$nested_locked_root")
nested_locked_state_file="$state_root/$nested_locked_workspace_key-$nested_locked_session_key.json"
nested_locked_active_sentinel="$nested_locked_root/active-${nested_locked_session_key}.json"
nested_locked_stale_sentinel="$nested_locked_root/stale.json"
nested_locked_temp_sentinel="$nested_locked_root/.state.stale"
printf 'sentinel\n' > "$nested_locked_active_sentinel"
printf 'sentinel\n' > "$nested_locked_stale_sentinel"
printf 'sentinel\n' > "$nested_locked_temp_sentinel"
touch -t 200001010000 "$nested_locked_active_sentinel" "$nested_locked_stale_sentinel" "$nested_locked_temp_sentinel"
nested_locked_active_mtime=$(file_mtime "$nested_locked_active_sentinel")
run_locked_action --locked-update 131072 64 "$nested_locked_root" "$nested_locked_session_id" \
  'direct.py' medium "$direct_locked_record"
[ "$locked_action_status" -ne 0 ] || fail "nested cache repository direct locked update was accepted"
run_locked_action --locked-remove 131072 64 "$nested_locked_root" "$nested_locked_session_id" 'direct.py'
[ "$locked_action_status" -ne 0 ] || fail "nested cache repository direct locked remove was accepted"
run_locked_action --locked-summary 131072 64 "$nested_locked_root" "$nested_locked_session_id"
[ "$locked_action_status" -ne 0 ] || fail "nested cache repository direct locked summary was accepted"
[ "$(cat "$nested_locked_active_sentinel")" = "sentinel" ] \
  || fail "nested cache repository active JSON sentinel changed"
[ "$(file_mtime "$nested_locked_active_sentinel")" = "$nested_locked_active_mtime" ] \
  || fail "nested cache repository active JSON sentinel was touched"
[ "$(cat "$nested_locked_stale_sentinel")" = "sentinel" ] \
  || fail "nested cache repository stale JSON sentinel changed"
[ "$(cat "$nested_locked_temp_sentinel")" = "sentinel" ] \
  || fail "nested cache repository temporary sentinel changed"
[ ! -e "$nested_locked_state_file" ] || fail "nested cache repository derived state was written"
rm -rf "$nested_locked_root"

locked_state_hardlink_sentinel="$tmp_dir/locked-state-hardlink-sentinel"
state_for_path 'hard-link.py' > "$locked_state_hardlink_sentinel"
chmod 600 "$locked_state_hardlink_sentinel"
touch -t 200001010000 "$locked_state_hardlink_sentinel"
locked_state_hardlink_content=$(cat "$locked_state_hardlink_sentinel")
locked_state_hardlink_mtime=$(file_mtime "$locked_state_hardlink_sentinel")
ln "$locked_state_hardlink_sentinel" "$forged_locked_state_file"
locked_state_hardlink_links=$(file_links "$locked_state_hardlink_sentinel")
run_locked_action --locked-summary 131072 64 "$forged_locked_root" "$forged_locked_session_id"
[ "$locked_action_status" -ne 0 ] || fail "hard-linked direct summary state was accepted"
[ "$(cat "$locked_state_hardlink_sentinel")" = "$locked_state_hardlink_content" ] \
  || fail "direct locked summary changed an outside hard-linked state"
[ "$(file_mtime "$locked_state_hardlink_sentinel")" = "$locked_state_hardlink_mtime" ] \
  || fail "direct locked summary touched an outside hard-linked state"
[ "$(file_links "$locked_state_hardlink_sentinel")" = "$locked_state_hardlink_links" ] \
  || fail "direct locked summary changed an outside hard-linked state link count"
rm -f "$forged_locked_state_file"

hardlink_prune_root="$tmp_dir/hardlink-prune-workspace"
mkdir -p "$hardlink_prune_root"
git init -q "$hardlink_prune_root"
hardlink_prune_root=$(CDPATH= cd -- "$hardlink_prune_root" && pwd -P)
hardlink_prune_session_id='hardlink-prune-session'
hardlink_prune_workspace_key=$(workspace_key_for_test "$hardlink_prune_root")
hardlink_prune_session_key=$(session_key_for_test "$hardlink_prune_session_id")
hardlink_prune_state_file="$state_root/$hardlink_prune_workspace_key-$hardlink_prune_session_key.json"
state_for_path 'summary.py' > "$hardlink_prune_state_file"
chmod 600 "$hardlink_prune_state_file"
hardlink_prune_sentinel="$tmp_dir/hardlink-prune-sentinel"
state_for_path 'stale.py' > "$hardlink_prune_sentinel"
chmod 600 "$hardlink_prune_sentinel"
touch -t 200001010000 "$hardlink_prune_sentinel"
hardlink_prune_content=$(cat "$hardlink_prune_sentinel")
hardlink_prune_mtime=$(file_mtime "$hardlink_prune_sentinel")
ln "$hardlink_prune_sentinel" "$state_root/hardlink-prune.json"
hardlink_prune_links=$(file_links "$hardlink_prune_sentinel")
run_locked_action --locked-summary 131072 64 "$hardlink_prune_root" "$hardlink_prune_session_id"
[ "$locked_action_status" -ne 0 ] || fail "hard-linked stale prune candidate was accepted"
[ "$(cat "$hardlink_prune_sentinel")" = "$hardlink_prune_content" ] \
  || fail "state prune changed an outside hard-linked candidate"
[ "$(file_mtime "$hardlink_prune_sentinel")" = "$hardlink_prune_mtime" ] \
  || fail "state prune touched an outside hard-linked candidate"
[ "$(file_links "$hardlink_prune_sentinel")" = "$hardlink_prune_links" ] \
  || fail "state prune changed an outside hard-linked candidate link count"
rm -f "$state_root/hardlink-prune.json" "$hardlink_prune_state_file"


forged_prune_root="$forged_locked_root/forged-prune-root"
mkdir -p "$forged_prune_root"
forged_json_sentinel="$forged_prune_root/stale.json"
forged_temp_sentinel="$forged_prune_root/.state.stale"
printf 'sentinel\n' > "$forged_json_sentinel"
printf 'sentinel\n' > "$forged_temp_sentinel"
touch -t 200001010000 "$forged_json_sentinel" "$forged_temp_sentinel"
run_locked_action --locked-summary 131072 64 "$forged_locked_root" "$forged_locked_session_id"
[ "$locked_action_status" -ne 0 ] || fail "missing direct locked summary state was accepted"
[ "$(cat "$forged_json_sentinel")" = "sentinel" ] \
  || fail "direct locked summary pruned a forged-root JSON sentinel"
[ "$(cat "$forged_temp_sentinel")" = "sentinel" ] \
  || fail "direct locked summary pruned a forged-root temporary sentinel"


run_scan_without_perl finding "$no_perl_payload"
assert_status "$scan_status" 2
assert_contains "$scan_output" FINDING_SECRET
[ ! -e "$no_perl_state_file" ] || fail "missing Perl persisted state"

run_scan finding '{}'
assert_status "$scan_status" 0
[ -z "$scan_output" ] || fail "missing hook input produced feedback"
run_scan finding "$missing_payload"
assert_status "$scan_status" 0
[ -z "$scan_output" ] || fail "missing file produced feedback"
run_scan_without_scanner "$edit_payload"
assert_status "$scan_status" 0
[ -z "$scan_output" ] || fail "missing scanner produced feedback"
[ "$(cat "$state_file")" = "$state_content" ] || fail "failed hook machinery changed state"

run_scan finding "$outside_payload"
assert_status "$scan_status" 2
assert_contains "$scan_output" FINDING_SECRET

finding_fingerprint=$(jq -r --arg path 'tests/fixtures/safe.py' '.files[$path].findings[0].fingerprint' "$state_file")
expected_fingerprint=$(fingerprint_for_test 'tests/fixtures/safe.py' test/no-danger high 7 3)
[ "$finding_fingerprint" = "$expected_fingerprint" ] || fail "fingerprint used non-metadata input"
finding_identifier=${finding_fingerprint:0:12}
run_configured_restore_hook
assert_status "$configured_restore_status" 0
assert_contains "$configured_restore_output" "finding $finding_identifier"
assert_not_contains "$configured_restore_output" 'tests/fixtures/safe.py'
assert_not_contains "$configured_restore_output" 'test/no-danger'
run_scan clean "$relative_edit_payload"
assert_status "$scan_status" 0
[ ! -e "$state_file" ] || fail "relative clean re-scan did not clear an absolute finding"
run_scan finding "$relative_edit_payload"
assert_status "$scan_status" 2
[ -f "$state_file" ] || fail "relative finding scan did not create state"
run_scan alternate
assert_status "$scan_status" 2
[ "$(jq -r --arg path 'tests/fixtures/safe.py' '.files[$path].findings[0].fingerprint' "$state_file")" = "$finding_fingerprint" ] \
  || fail "fingerprint was not stable across source-only changes"
alternate_content=$(cat "$state_file")
assert_not_contains "$alternate_content" OTHER_FINDING_SECRET
assert_not_contains "$alternate_content" OTHER_SOURCE_SNIPPET_SECRET
run_scan other "$other_edit_payload"
assert_status "$scan_status" 2
[ -f "$other_state_file" ] || fail "other workspace finding scan did not create state"
jq -e --arg path '.github/space (Ω).py' '.files | keys == [$path]' "$other_state_file" >/dev/null \
  || fail "valid .github, whitespace, Unicode, and parenthesized path was not retained"
other_state_content=$(cat "$other_state_file")
assert_not_contains "$other_state_content" "$other_root"

run_restore "$compact_payload"
assert_status "$restore_status" 0
assert_contains "$restore_output" 'advisory feedback, not a final enforcement gate'
assert_contains "$restore_output" "finding $finding_identifier"
assert_contains "$restore_output" '/foxguard:scan'
assert_line "$restore_output" "- [HIGH] finding $finding_identifier at line 7, column 3"
assert_not_contains "$restore_output" FINDING_SECRET
assert_not_contains "$restore_output" SOURCE_SNIPPET_SECRET
assert_not_contains "$restore_output" 'test/no-danger'
assert_not_contains "$restore_output" 'tests/fixtures/safe.py'

other_finding_fingerprint=$(jq -r --arg path '.github/space (Ω).py' '.files[$path].findings[0].fingerprint' "$other_state_file")
other_finding_identifier=${other_finding_fingerprint:0:12}
run_restore "$other_compact_payload"
assert_status "$restore_status" 0
assert_contains "$restore_output" "finding $other_finding_identifier"
assert_not_contains "$restore_output" '.github/space ('
assert_not_contains "$restore_output" 'test/other-danger'
assert_not_contains "$restore_output" 'test/no-danger'
run_scan hostile "$hostile_edit_payload"
assert_status "$scan_status" 2
[ -f "$hostile_state_file" ] || fail "hostile path scan did not create state"
run_restore "$hostile_compact_payload"
assert_status "$restore_status" 0
assert_contains "$restore_output" 'finding '
assert_not_contains "$restore_output" "$hostile_instruction"
assert_not_contains "$restore_output" "$hostile_markdown"
assert_not_contains "$restore_output" "$hostile_bidi"
assert_not_contains "$restore_output" 'test/hostile-rule'

run_restore "$startup_payload"
assert_status "$restore_status" 0
[ -z "$restore_output" ] || fail "ordinary SessionStart restored findings"
stale_state_file="$state_root/expired-session.json"
state_for_path 'stale.py' > "$stale_state_file"
chmod 600 "$stale_state_file"
touch -t 200001010000 "$state_file" "$other_state_file" "$stale_state_file"
run_restore "$compact_payload"
assert_status "$restore_status" 0
assert_contains "$restore_output" "finding $finding_identifier"
[ -f "$state_file" ] || fail "active session state expired before compaction"
[ -f "$other_state_file" ] || fail "same-session workspace state was pruned"
[ ! -e "$stale_state_file" ] || fail "inactive stale state was not pruned"
[ -z "$(find "$state_file" -mtime +0 -print)" ] || fail "compaction did not refresh active state liveness"
run_restore "$other_session_compact_payload"
assert_status "$restore_status" 0
[ -z "$restore_output" ] || fail "unrelated session restored findings"
[ -f "$state_file" ] || fail "active session state was pruned by another session"
[ -f "$other_state_file" ] || fail "same-session workspace was pruned by another session"
run_restore "$other_compact_payload"
assert_status "$restore_status" 0
assert_contains "$restore_output" "finding $other_finding_identifier"
[ -z "$(find "$other_state_file" -mtime +0 -print)" ] || fail "same-session workspace did not refresh on compaction"
state_for_path 'old-foo.py' > "$old_foo_state_file"
chmod 600 "$old_foo_state_file"
touch -t 200001010000 "$old_foo_state_file"
run_restore "$foo_compact_payload"
assert_status "$restore_status" 0
[ -z "$restore_output" ] || fail "foo session restored another session's findings"
[ ! -e "$old_foo_state_file" ] || fail "old-foo state matched foo session namespace"
printf 'orphan\n' > "$state_root/.state.orphan-dead-owner"
run_scan alternate
assert_status "$scan_status" 2
[ ! -e "$state_root/.state.orphan-dead-owner" ] || fail "orphan state temp was not pruned"

lock_sentinel="$tmp_dir/lock-sentinel"
printf 'sentinel\n' > "$lock_sentinel"
rm -f "$state_root/.lock"
ln -s "$lock_sentinel" "$state_root/.lock"
if run_state_update "$concurrent_root" 'symlink.py' "$(record_for_rule test/symlink)"; then
  fail "symlinked lock was accepted"
fi
[ "$(cat "$lock_sentinel")" = "sentinel" ] || fail "lock wrapper followed a symlink"
rm -f "$state_root/.lock"
lock_hardlink_sentinel="$tmp_dir/lock-hardlink-sentinel"
printf 'sentinel\n' > "$lock_hardlink_sentinel"
chmod 0644 "$lock_hardlink_sentinel"
lock_hardlink_content=$(cat "$lock_hardlink_sentinel")
lock_hardlink_mode=$(file_mode "$lock_hardlink_sentinel")
rm -f "$state_root/.lock"
ln "$lock_hardlink_sentinel" "$state_root/.lock"
lock_hardlink_links=$(file_links "$lock_hardlink_sentinel")
if perl "$lock_wrapper" "$state_root/.lock" /usr/bin/true; then
  fail "hard-linked lock was accepted"
fi
[ "$(cat "$lock_hardlink_sentinel")" = "$lock_hardlink_content" ] \
  || fail "lock wrapper changed an outside hard-linked lock"
[ "$(file_mode "$lock_hardlink_sentinel")" = "$lock_hardlink_mode" ] \
  || fail "lock wrapper changed an outside hard-linked lock mode"
[ "$(file_links "$lock_hardlink_sentinel")" = "$lock_hardlink_links" ] \
  || fail "lock wrapper changed an outside hard-linked lock link count"
rm -f "$state_root/.lock"
perl "$lock_wrapper" "$state_root/.lock" /usr/bin/true \
  || fail "lock wrapper did not create a normal lock"
[ "$(file_mode "$state_root/.lock")" = "0600" ] || fail "normal lock mode is not 0600"


kernel_lock_ready="$tmp_dir/kernel-lock-ready"
perl -MFcntl=:flock -e '
  open my $lock, ">>", $ARGV[0] or die $!;
  flock($lock, LOCK_EX) or die $!;
  open my $ready, ">", $ARGV[1] or die $!;
  print {$ready} "ready\n";
  close $ready or die $!;
  sleep 30;
' "$state_root/.lock" "$kernel_lock_ready" &
kernel_lock_holder_pid=$!
for _ in $(seq 1 80); do
  [ -f "$kernel_lock_ready" ] && break
  sleep 0.05
done
[ -f "$kernel_lock_ready" ] || fail "kernel lock holder did not start"
run_state_update "$concurrent_root" 'kernel-lock.py' "$(record_for_rule test/kernel-lock)" &
kernel_lock_update_pid=$!
sleep 0.1
kill -0 "$kernel_lock_update_pid" 2>/dev/null || fail "kernel lock did not exclude an update"
kill -KILL "$kernel_lock_holder_pid"
set +e
wait "$kernel_lock_holder_pid"
kernel_lock_holder_status=$?
set -e
[ "$kernel_lock_holder_status" -ne 0 ] || fail "crashed kernel lock holder exited cleanly"
wait "$kernel_lock_update_pid"
jq -e '.files | has("kernel-lock.py")' "$concurrent_state_file" >/dev/null \
  || fail "state update did not recover after a crashed lock holder"
[ -f "$state_root/.lock" ] && [ ! -L "$state_root/.lock" ] \
  || fail "state lock is not a regular persistent file"
atomic_ready="$tmp_dir/atomic-write-ready"
atomic_session_id='atomic-write-interrupt'
atomic_session_key=$(session_key_for_test "$atomic_session_id")
atomic_target="$state_root/$workspace_key-$atomic_session_key.json"

(
  XDG_CACHE_HOME="$cache_dir"
  PATH="$fake_bin:$PATH"
  . "$state_helper"
  mv() {
    bash -c 'printf "%s\n" "$PPID"' > "$atomic_ready"
    while :; do sleep 1; done
  }
  fg_state_atomic_write "$root" "$atomic_session_id" '{"metadata":"only"}'
) &
atomic_holder_pid=$!
for _ in $(seq 1 80); do
  [ -f "$atomic_ready" ] && break
  sleep 0.05
done
[ -f "$atomic_ready" ] || fail "atomic write did not reach move"
atomic_owner_pid=$(cat "$atomic_ready")
kill -0 "$atomic_owner_pid" 2>/dev/null || fail "atomic write owner was not live"
kill -TERM "$atomic_owner_pid"
set +e
wait "$atomic_holder_pid"
atomic_holder_status=$?
set -e
[ "$atomic_holder_status" -ne 0 ] || fail "interrupted atomic write exited cleanly"
[ ! -e "$atomic_target" ] || fail "interrupted atomic write reached its destination"
[ -z "$(find "$state_root" -type f -name '.state.*' -print)" ] \
  || fail "interrupted atomic write left a state temp"

concurrent_record=$(record_for_rule test/concurrent)
stale_concurrent_state="$state_root/expired-concurrent.json"
state_for_path 'expired-concurrent.py' > "$stale_concurrent_state"
chmod 600 "$stale_concurrent_state"
touch -t 200001010000 "$stale_concurrent_state"
run_state_update "$concurrent_root" 'one.py' "$concurrent_record" &
concurrent_one_pid=$!
run_state_update "$concurrent_root" 'two.py' "$concurrent_record" &
concurrent_two_pid=$!
wait "$concurrent_one_pid"
wait "$concurrent_two_pid"
[ ! -e "$stale_concurrent_state" ] || fail "serialized prune retained stale state"
jq -e '(.files | keys | sort) == ["kernel-lock.py", "one.py", "two.py"]' "$concurrent_state_file" >/dev/null \
  || fail "concurrent state updates lost an entry"
[ -f "$state_root/.lock" ] && [ ! -L "$state_root/.lock" ] \
  || fail "concurrent updates did not retain a regular lock file"

paused_record=$(record_for_rule test/paused)
paused_ready="$tmp_dir/paused-mv-ready"
paused_release="$tmp_dir/paused-mv-release"
run_paused_state_update "$paused_root" 'one.py' "$paused_record" "$paused_ready" "$paused_release" &
paused_one_pid=$!
for _ in $(seq 1 80); do
  [ -f "$paused_ready" ] && break
  sleep 0.05
done
[ -f "$paused_ready" ] || fail "paused update did not reach rename"
run_state_update "$paused_root" 'two.py' "$paused_record" &
paused_two_pid=$!
sleep 0.1
kill -0 "$paused_two_pid" 2>/dev/null || fail "second update bypassed the paused writer"
touch "$paused_release"
wait "$paused_one_pid"
wait "$paused_two_pid"
jq -e '(.files | keys | sort) == ["one.py", "two.py"]' "$paused_state_file" >/dev/null \
  || fail "paused concurrent updates lost an entry"

run_scan clean
assert_status "$scan_status" 0
[ ! -e "$state_file" ] || fail "clean scan did not remove state"
[ -f "$other_state_file" ] || fail "clean scan removed another workspace state"
run_restore "$other_compact_payload"
assert_status "$restore_status" 0
assert_contains "$restore_output" "finding $other_finding_identifier"

run_scan finding
assert_status "$scan_status" 2
state_content=$(cat "$state_file")
run_scan invalid
assert_status "$scan_status" 0
[ "$(cat "$state_file")" = "$state_content" ] || fail "invalid scanner output cleared state"
run_scan error
assert_status "$scan_status" 0
[ "$(cat "$state_file")" = "$state_content" ] || fail "scanner error cleared state"
run_scan empty_error
assert_status "$scan_status" 0
[ "$(cat "$state_file")" = "$state_content" ] || fail "empty scanner error cleared state"

for index in $(seq 1 65); do
  capacity_fixture="$capacity_root/.github/capacity-$index.py"
  printf 'x = %s\n' "$index" > "$capacity_fixture"
  capacity_payload=$(jq -cn --arg session "$session_id" --arg cwd "$capacity_root" --arg path "$capacity_fixture" \
    '{session_id:$session, cwd:$cwd, tool_input:{file_path:$path}}')
  run_scan finding "$capacity_payload"
  assert_status "$scan_status" 2
done
[ -f "$capacity_state_file" ] || fail "capacity test did not create state"
omitted_capacity_key=$(fingerprint_for_test "foxguard-claude-code-omitted-path-v1" '.github/capacity-65.py')
jq -e --arg omitted "$omitted_capacity_key" \
  '.version == 3 and .overflow == 0 and .omitted == [$omitted] and (.files | length) == 64' "$capacity_state_file" >/dev/null \
  || fail "65th successful scan did not record its omitted path"
run_restore "$capacity_compact_payload"
assert_status "$restore_status" 0
assert_contains "$restore_output" 'Some successful scan results were omitted because the local continuity cache reached capacity.'

capacity_unrelated_fixture="$capacity_root/.github/unrelated.py"
printf 'x = 0\n' > "$capacity_unrelated_fixture"
capacity_unrelated_payload=$(jq -cn --arg session "$session_id" --arg cwd "$capacity_root" --arg path "$capacity_unrelated_fixture" \
  '{session_id:$session, cwd:$cwd, tool_input:{file_path:$path}}')
run_scan clean "$capacity_unrelated_payload"
assert_status "$scan_status" 0
jq -e --arg omitted "$omitted_capacity_key" '.omitted == [$omitted]' "$capacity_state_file" >/dev/null \
  || fail "unrelated clean scan cleared an omitted-path marker"

capacity_first_fixture="$capacity_root/.github/capacity-1.py"
capacity_first_payload=$(jq -cn --arg session "$session_id" --arg cwd "$capacity_root" --arg path "$capacity_first_fixture" \
  '{session_id:$session, cwd:$cwd, tool_input:{file_path:$path}}')
run_scan clean "$capacity_first_payload"
assert_status "$scan_status" 0
capacity_last_fixture="$capacity_root/.github/capacity-65.py"
capacity_last_payload=$(jq -cn --arg session "$session_id" --arg cwd "$capacity_root" --arg path "$capacity_last_fixture" \
  '{session_id:$session, cwd:$cwd, tool_input:{file_path:$path}}')
run_scan finding "$capacity_last_payload"
assert_status "$scan_status" 2
jq -e --arg path '.github/capacity-65.py' \
  '.overflow == 0 and .omitted == [] and (.files | length) == 64 and (.files | has($path))' "$capacity_state_file" >/dev/null \
  || fail "freed capacity did not retain the formerly omitted path"
run_restore "$capacity_compact_payload"
assert_status "$restore_status" 0
assert_not_contains "$restore_output" 'Some successful scan results were omitted because the local continuity cache reached capacity.'
for index in $(seq 1 65); do
  capacity_fixture="$capacity_root/.github/capacity-$index.py"
  capacity_payload=$(jq -cn --arg session "$session_id" --arg cwd "$capacity_root" --arg path "$capacity_fixture" \
    '{session_id:$session, cwd:$cwd, tool_input:{file_path:$path}}')
  run_scan clean "$capacity_payload"
  assert_status "$scan_status" 0
done
[ ! -e "$capacity_state_file" ] || fail "clean scans did not remove all capacity state"
run_restore "$capacity_compact_payload"
assert_status "$restore_status" 0
[ -z "$restore_output" ] || fail "cleared capacity state still emitted a warning"

large_record=$(jq -cn '
  [range(0;64) |
    . as $index |
    {
      fingerprint: ([range(0;64) | "f"] | join("")),
      rule_id: ("test/" + ([range(0;115) | "a"] | join("")) + "-" + ($index | tostring)),
      severity: "high",
      line: ($index + 1),
      column: 1
    }
  ] | {total: length, truncated: false, findings: .}
')

run_state_update_with_limits 2048 0 "$untracked_root" 'untracked.py' "$large_record"
jq -e '.version == 3 and .overflow == 1 and .omitted == [] and .files == {}' "$untracked_state_file" >/dev/null \
  || fail "untrackable capacity overflow was not retained"
untracked_other_fixture="$untracked_root/other.py"
printf 'x = 0\n' > "$untracked_other_fixture"
untracked_other_payload=$(jq -cn --arg session "$session_id" --arg cwd "$untracked_root" --arg path "$untracked_other_fixture" \
  '{session_id:$session, cwd:$cwd, tool_input:{file_path:$path}}')
run_scan clean "$untracked_other_payload"
assert_status "$scan_status" 0
jq -e '.overflow == 1 and .omitted == []' "$untracked_state_file" >/dev/null \
  || fail "unrelated clean scan cleared untracked overflow"
untracked_compact_payload=$(jq -cn --arg session "$session_id" --arg cwd "$untracked_root" \
  '{session_id:$session, cwd:$cwd, source:"compact"}')
run_restore "$untracked_compact_payload"
assert_status "$restore_status" 0
assert_contains "$restore_output" 'Some successful scan results were omitted because the local continuity cache reached capacity.'
for index in $(seq 1 20); do
  run_state_update "$byte_root" ".github/large-$index.py" "$large_record"
  if [ -f "$byte_state_file" ] && jq -e '(.overflow > 0 or (.omitted | length) > 0)' "$byte_state_file" >/dev/null; then
    break
  fi
done
jq -e '.version == 3 and (.overflow > 0 or (.omitted | length) > 0) and (.files | length) < 64' "$byte_state_file" >/dev/null \
  || fail "state byte limit did not record cache overflow"
run_restore "$byte_compact_payload"
assert_status "$restore_status" 0
assert_contains "$restore_output" 'Some successful scan results were omitted because the local continuity cache reached capacity.'
old_rescan_record=$(record_for_rule test/old-rule)
run_state_update "$rescan_root" 'rescan.py' "$old_rescan_record"
[ -f "$rescan_state_file" ] || fail "rescan state did not create old finding"
run_state_update_with_limit 2048 "$rescan_root" 'rescan.py' "$large_record"
jq -e '(.overflow > 0 or (.omitted | length) > 0) and (.files | has("rescan.py") | not)' "$rescan_state_file" >/dev/null \
  || fail "byte-cap rescan retained stale finding"
assert_not_contains "$(cat "$rescan_state_file")" 'test/old-rule'
run_restore "$rescan_compact_payload"
assert_status "$restore_status" 0
assert_contains "$restore_output" 'Some successful scan results were omitted because the local continuity cache reached capacity.'
assert_not_contains "$restore_output" 'test/old-rule'

rm -f "$state_file"
run_restore "$compact_payload"
assert_status "$restore_status" 0
[ -z "$restore_output" ] || fail "missing state produced a summary"
printf '{not-json\n' > "$state_file"
run_restore "$compact_payload"
assert_status "$restore_status" 0
[ -z "$restore_output" ] || fail "corrupt state produced a summary"

restore_sentinel='RAW_PROMPT_INJECTION_SHOULD_NOT_REACH_SESSIONSTART'
restore_bad_cache="$tmp_dir/$restore_sentinel"
printf '%s\n' "$restore_sentinel" > "$restore_bad_cache"
run_restore_with_cache "$compact_payload" "$restore_bad_cache"
assert_status "$restore_status" 0
[ -z "$restore_output" ] || fail "unusable cache emitted SessionStart output"

run_scan many
assert_status "$scan_status" 2
jq -n '
  [range(0;7) |
    . as $index |
    {
      key: ("dir-" + ($index | tostring) + "/" + ([range(0;210) | "p"] | join("")) + ".py"),
      value: {
        threshold: "medium",
        total: 2,
        truncated: false,
        findings: [
          {
            fingerprint: ([range(0;64) | "f"] | join("")),
            rule_id: ("test/" + ([range(0;100) | "a"] | join("")) + "-" + ($index | tostring)),
            severity: "critical",
            line: 1,
            column: 1
          },
          {
            fingerprint: ([range(0;64) | "e"] | join("")),
            rule_id: ("test/" + ([range(0;100) | "b"] | join("")) + "-" + ($index | tostring)),
            severity: "high",
            line: 2,
            column: 2
          }
        ]
      }
    }
  ] | from_entries | {version: 1, files: .}
' > "$state_file"
chmod 600 "$state_file"
run_restore "$compact_payload"
assert_status "$restore_status" 0
summary_bytes=$(printf '%s\n' "$restore_output" | wc -c | tr -d ' ')
[ "$summary_bytes" -le 3072 ] || fail "summary exceeded byte bound"
assert_contains "$restore_output" 'Additional finding details omitted.'
assert_not_contains "$restore_output" FINDING_SECRET
assert_not_contains "$restore_output" SOURCE_SNIPPET_SECRET

printf 'ok: Claude Code compaction state hooks\n'
