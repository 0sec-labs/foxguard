#!/usr/bin/env bash
# Metadata-only state helpers for Claude Code hook continuity.

FG_STATE_MAX_FILES=64
FG_STATE_MAX_FINDINGS=64
FG_STATE_MAX_OMITTED=64
FG_STATE_MAX_TOTAL=10000
FG_STATE_MAX_BYTES=131072
# Reserve space for a bounded omitted-path marker when a normal record reaches capacity.
FG_STATE_OVERFLOW_RESERVE=128
FG_STATE_MAX_SUMMARY_FILES=6
FG_STATE_MAX_SUMMARY_FINDINGS=2
FG_STATE_SUMMARY_MAX_BYTES=3072

fg_state_repository_root() {
  local cwd=$1 root

  [ -n "$cwd" ] || return 1
  root=$(git -C "$cwd" rev-parse --show-toplevel 2>/dev/null) || return 1
  (cd -P "$root" 2>/dev/null && pwd -P)
}

fg_state_normalize_file_path() {
  local cwd=$1 file_path=$2 repo_root=$3 resolved_cwd candidate file_dir file_name resolved_dir resolved_path

  case "$cwd" in
    /*) ;;
    *) return 1 ;;
  esac
  case "$repo_root" in
    /*) ;;
    *) return 1 ;;
  esac
  resolved_cwd=$(cd -P "$cwd" 2>/dev/null && pwd -P) || return 1
  case "$file_path" in
    /*) candidate=$file_path ;;
    *) candidate="$resolved_cwd/$file_path" ;;
  esac
  file_dir=${candidate%/*}
  file_name=${candidate##*/}
  [ "$file_dir" != "$candidate" ] && [ -n "$file_name" ] || return 1
  [ -n "$file_dir" ] || file_dir=/
  resolved_dir=$(cd -P "$file_dir" 2>/dev/null && pwd -P) || return 1
  resolved_path="$resolved_dir/$file_name"
  [ ! -L "$resolved_path" ] || return 1

  case "$resolved_path" in
    "$repo_root"/*) printf '%s\n' "$resolved_path" ;;
    *) return 1 ;;
  esac
}

fg_state_relative_path() {
  local file_path=$1 repo_root=$2 file_dir file_name resolved_path

  case "$file_path" in
    /*) ;;
    *) return 1 ;;
  esac

  file_dir=${file_path%/*}
  file_name=${file_path##*/}
  [ "$file_dir" != "$file_path" ] && [ -n "$file_name" ] || return 1
  [ -n "$file_dir" ] || file_dir=/
  file_dir=$(cd -P "$file_dir" 2>/dev/null && pwd -P) || return 1
  resolved_path="$file_dir/$file_name"

  case "$resolved_path" in
    "$repo_root"/*) printf '%s\n' "${resolved_path#"$repo_root"/}" ;;
    *) return 1 ;;
  esac
}

fg_state_cache_path_outside_repository() {
  local candidate=$1 repo_root=$2 probe=$1 parent physical candidate_physical

  # Start at the nearest existing ancestor, then compare physical filesystem
  # identities while walking upward so case-folding aliases cannot bypass this.
  while [ ! -e "$probe" ] && [ ! -L "$probe" ]; do
    parent=${probe%/*}
    [ "$parent" != "$probe" ] || return 1
    [ -n "$parent" ] || parent=/
    probe=$parent
  done
  [ -d "$probe" ] || return 1
  physical=$(cd -P "$probe" 2>/dev/null && pwd -P) || return 1

  while :; do
    [[ "$physical" -ef "$repo_root" ]] && return 1
    [ "$physical" = / ] && break
    parent=$(cd -P "$physical/.." 2>/dev/null && pwd -P) || return 1
    [ "$parent" != "$physical" ] || return 1
    physical=$parent
  done

  if [ -d "$candidate" ] && [ ! -L "$candidate" ]; then
    candidate_physical=$(cd -P "$candidate" 2>/dev/null && pwd -P) || return 1
    physical=$(cd -P "$repo_root" 2>/dev/null && pwd -P) || return 1
    while :; do
      [[ "$physical" -ef "$candidate_physical" ]] && return 1
      [ "$physical" = / ] && break
      parent=$(cd -P "$physical/.." 2>/dev/null && pwd -P) || return 1
      [ "$parent" != "$physical" ] || return 1
      physical=$parent
    done
  fi
}


fg_state_root() {
  local repo_root=$1 cache_home state_root resolved_state resolved_repo

  resolved_repo=$(cd -P "$repo_root" 2>/dev/null && pwd -P) || return 1

  if [ -n "${XDG_CACHE_HOME:-}" ]; then
    cache_home=$XDG_CACHE_HOME
  elif [ "$(uname -s)" = "Darwin" ]; then
    cache_home="${HOME:-}/Library/Caches"
  else
    cache_home="${HOME:-}/.cache"
  fi

  case "$cache_home" in
    /*) ;;
    *) return 1 ;;
  esac

  state_root="$cache_home/foxguard/claude-code"
  fg_state_cache_path_outside_repository "$state_root" "$resolved_repo" || return 1
  (umask 077; mkdir -p "$state_root" >/dev/null 2>&1) || return 1
  [ -d "$state_root" ] && [ ! -L "$state_root" ] || return 1
  fg_state_cache_path_outside_repository "$state_root" "$resolved_repo" || return 1

  resolved_state=$(cd -P "$state_root" 2>/dev/null && pwd -P) || return 1
  fg_state_cache_path_outside_repository "$resolved_state" "$resolved_repo" || return 1
  printf '%s\n' "$resolved_state"
}

fg_state_session_key() {
  [[ "$1" =~ ^[A-Za-z0-9_-]{1,128}$ ]] || return 1
  fg_state_sha256 "foxguard-claude-code-session-v1" "$1"
}

fg_state_session_file() {
  local state_root=$1 repo_root=$2 session_id=$3 workspace_key session_key

  workspace_key=$(fg_state_workspace_key "$repo_root") || return 1
  session_key=$(fg_state_session_key "$session_id") || return 1
  printf '%s/%s-%s.json\n' "$state_root" "$workspace_key" "$session_key"
}

fg_state_valid_threshold() {
  case "$1" in
    low|medium|high|critical) return 0 ;;
    *) return 1 ;;
  esac
}

fg_state_sha256() {
  local digest

  if command -v shasum >/dev/null 2>&1; then
    digest=$(printf '%s\0' "$@" | shasum -a 256 | awk '{print $1}')
  elif command -v sha256sum >/dev/null 2>&1; then
    digest=$(printf '%s\0' "$@" | sha256sum | awk '{print $1}')
  elif command -v openssl >/dev/null 2>&1; then
    digest=$(printf '%s\0' "$@" | openssl dgst -sha256 | awk '{print $NF}')
  else
    return 1
  fi

  [[ "$digest" =~ ^[a-f0-9]{64}$ ]] || return 1
  printf '%s\n' "$digest"
}

fg_state_workspace_key() {
  fg_state_sha256 "foxguard-claude-code-workspace-v1" "$1"
}

fg_state_file_operation_path() {
  local state_script

  state_script=$(fg_state_script_path) || return 1
  [ -r "${state_script%/*}/state-file-operation.pl" ] \
    && [ ! -L "${state_script%/*}/state-file-operation.pl" ] || return 1
  printf '%s/state-file-operation.pl\n' "${state_script%/*}"
}

fg_state_file_operation() {
  local action=$1 helper
  shift

  command -v perl >/dev/null 2>&1 || return 1
  helper=$(fg_state_file_operation_path) || return 1
  if [[ "${FG_STATE_LOCK_DIR_FD:-}" =~ ^[0-9]+$ ]]; then
    perl "$helper" --fd "$FG_STATE_LOCK_DIR_FD" "$action" "$@"
  else
    [ -n "${FG_STATE_LOCKED_ROOT:-}" ] || return 1
    perl "$helper" --root "$FG_STATE_LOCKED_ROOT" "$action" "$@"
  fi
}


fg_state_prepare_locked_state() {
  local repo_identity=$1 session_id=$2 repo_root state_root workspace_key session_key state_file
  # Locked actions are executable; re-derive every filesystem path from identity.
  unset FG_STATE_LOCKED_REPOSITORY FG_STATE_LOCKED_SESSION_ID \
    FG_STATE_LOCKED_SESSION_KEY FG_STATE_LOCKED_ROOT FG_STATE_LOCKED_FILE
  repo_root=$(fg_state_repository_root "$repo_identity") || return 1
  state_root=$(fg_state_root "$repo_root") || return 1
  workspace_key=$(fg_state_workspace_key "$repo_root") || return 1
  session_key=$(fg_state_session_key "$session_id") || return 1
  state_file="$workspace_key-$session_key.json"
  [[ "$state_file" =~ ^[a-f0-9]{64}-[a-f0-9]{64}\.json$ ]] || return 1

  FG_STATE_LOCKED_REPOSITORY=$repo_root
  FG_STATE_LOCKED_SESSION_ID=$session_id
  FG_STATE_LOCKED_SESSION_KEY=$session_key
  FG_STATE_LOCKED_ROOT=$state_root
  FG_STATE_LOCKED_FILE=$state_file
}


fg_state_fingerprint() {
  # The fingerprint input is limited to the metadata that is retained in state.
  fg_state_sha256 "$@"
}

fg_state_omitted_path_key() {
  fg_state_fingerprint "foxguard-claude-code-omitted-path-v1" "$1"
}

fg_state_add_omitted_path() {
  local state=$1 relative_path=$2 omitted_key

  omitted_key=$(fg_state_omitted_path_key "$relative_path") || return 1
  printf '%s' "$state" | jq -ce --arg key "$omitted_key" --argjson max_omitted "$FG_STATE_MAX_OMITTED" '
    if (.omitted | index($key)) then .
    elif (.omitted | length) < $max_omitted then .omitted += [$key]
    else .overflow = 1
    end
  '
}

fg_state_remove_omitted_path() {
  local state=$1 relative_path=$2 omitted_key

  omitted_key=$(fg_state_omitted_path_key "$relative_path") || return 1
  printf '%s' "$state" | jq -ce --arg key "$omitted_key" '.omitted |= map(select(. != $key))'
}

fg_state_mark_untracked_overflow() {
  printf '%s' "$1" | jq -ce '.overflow = 1'
}

fg_state_is_empty() {
  printf '%s' "$1" | jq -e '(.files | length) == 0 and (.omitted | length) == 0 and .overflow == 0' >/dev/null 2>&1
}

fg_state_validate() {
  jq -ce --argjson max_omitted "$FG_STATE_MAX_OMITTED" '
    def valid_path:
      type == "string"
      and length > 0
      and length <= 240
      and (startswith("/") | not)
      and (test("^[A-Za-z]:[\\\\/]") | not)
      and (contains("\\") | not)
      and (test("[\\x00-\\x1F\\x7F]") | not)
      and (split("/") | all(. != "" and . != "." and . != ".."));
    def valid_rule:
      type == "string"
      and length > 0
      and length <= 128
      and test("^[A-Za-z0-9][A-Za-z0-9._/@:+-]*$");
    def valid_severity:
      type == "string"
      and (. == "low" or . == "medium" or . == "high" or . == "critical");
    def valid_position:
      type == "number"
      and floor == .
      and . >= 1
      and . <= 2147483647;
    def valid_count:
      type == "number"
      and floor == .
      and . >= 1
      and . <= 10000;
    def valid_overflow:
      type == "number"
      and floor == .
      and (. == 0 or . == 1);
    def valid_omitted:
      type == "array"
      and length <= $max_omitted
      and all(.[]; type == "string" and test("^[a-f0-9]{64}$"))
      and (length == (unique | length));
    def valid_finding:
      type == "object"
      and ((keys | sort) == ["column", "fingerprint", "line", "rule_id", "severity"])
      and (.fingerprint | type == "string" and test("^[a-f0-9]{64}$"))
      and (.rule_id | valid_rule)
      and (.severity | valid_severity)
      and (.line | valid_position)
      and (.column | valid_position);
    def valid_entry:
      type == "object"
      and ((keys | sort) == ["findings", "threshold", "total", "truncated"])
      and (.threshold | valid_severity)
      and (.total | valid_count)
      and (.truncated | type == "boolean")
      and (.findings | type == "array" and length > 0 and length <= 64 and all(.[]; valid_finding))
      and ((.findings | length) as $count |
        .total >= $count
        and (if .truncated then .total > $count else .total == $count end));
    if type != "object" then
      error("invalid foxguard Claude Code state")
    elif .version == 1
      and ((keys | sort) == ["files", "version"])
      and (.files | type == "object" and length <= 64)
      and (.files | all(to_entries[]; (.key | valid_path) and (.value | valid_entry)))
    then
      {version: 3, overflow: 0, omitted: [], files: .files}
    elif .version == 2
      and ((keys | sort) == ["files", "overflow", "version"])
      and (.overflow | type == "number" and floor == . and . >= 0 and . <= 10000)
      and (.files | type == "object" and length <= 64)
      and (.files | all(to_entries[]; (.key | valid_path) and (.value | valid_entry)))
    then
      {version: 3, overflow: (if .overflow > 0 then 1 else 0 end), omitted: [], files: .files}
    elif .version == 3
      and ((keys | sort) == ["files", "omitted", "overflow", "version"])
      and (.overflow | valid_overflow)
      and (.omitted | valid_omitted)
      and (.files | type == "object" and length <= 64)
      and (.files | all(to_entries[]; (.key | valid_path) and (.value | valid_entry)))
    then .
    else
      error("invalid foxguard Claude Code state")
    end
  '
}

fg_state_normalize_findings() {
  jq -ce --argjson max_findings "$FG_STATE_MAX_FINDINGS" --argjson max_total "$FG_STATE_MAX_TOTAL" '
    def valid_rule:
      type == "string"
      and length > 0
      and length <= 128
      and test("^[A-Za-z0-9][A-Za-z0-9._/@:+-]*$");
    def valid_severity:
      type == "string"
      and (. == "low" or . == "medium" or . == "high" or . == "critical");
    def valid_position:
      type == "number"
      and floor == .
      and . >= 1
      and . <= 2147483647;
    def valid_finding:
      type == "object"
      and (.rule_id | valid_rule)
      and (.severity | valid_severity)
      and (.line | valid_position)
      and (.column | valid_position);
    if type != "array" or (all(.[]; valid_finding) | not) then
      error("invalid scanner finding metadata")
    else
      [ .[] | {rule_id, severity, line, column} ]
      | sort_by(.severity, .rule_id, .line, .column)
      | unique_by([.rule_id, .severity, .line, .column])
      | . as $findings
      | ($findings | length) as $count
      | {
          total: (if $count > $max_total then $max_total else $count end),
          truncated: ($count > $max_findings or $count > $max_total),
          findings: $findings[0:$max_findings]
        }
    end
  '
}

fg_state_add_fingerprints() {
  local relative_path=$1 record=$2
  local total truncated entries= rule_id severity line column fingerprint entry status=0

  total=$(printf '%s' "$record" | jq -er '.total' 2>/dev/null) || return 1
  truncated=$(printf '%s' "$record" | jq -r '.truncated' 2>/dev/null) || return 1

  while IFS=$'\t' read -r rule_id severity line column; do
    fingerprint=$(fg_state_fingerprint "$relative_path" "$rule_id" "$severity" "$line" "$column") || {
      status=1
      break
    }
    entry=$(jq -cn \
      --arg fingerprint "$fingerprint" \
      --arg rule_id "$rule_id" \
      --arg severity "$severity" \
      --argjson line "$line" \
      --argjson column "$column" \
      '{fingerprint: $fingerprint, rule_id: $rule_id, severity: $severity, line: $line, column: $column}') || {
      status=1
      break
    }
    entries="${entries}${entries:+$'\n'}${entry}"
  done < <(printf '%s' "$record" | jq -r '.findings[] | [.rule_id, .severity, (.line | tostring), (.column | tostring)] | @tsv')

  [ "$status" = "0" ] && [ -n "$entries" ] || return 1
  printf '%s\n' "$entries" | jq -sce \
    --argjson total "$total" \
    --argjson truncated "$truncated" \
    '{total: $total, truncated: $truncated, findings: .}'
}

fg_state_prune_locked() {
  local repo_identity=$1 session_id=$2

  [ "$repo_identity" = "${FG_STATE_LOCKED_REPOSITORY:-}" ] || return 1
  [ "$session_id" = "${FG_STATE_LOCKED_SESSION_ID:-}" ] || return 1
  fg_state_file_operation prune "$FG_STATE_LOCKED_FILE" "$FG_STATE_LOCKED_SESSION_KEY"
}


fg_state_script_path() {
  local script_path=${BASH_SOURCE[0]} script_dir

  script_dir=$(CDPATH= cd -- "$(dirname -- "$script_path")" 2>/dev/null && pwd -P) || return 1
  [ -f "$script_dir/finding-state.sh" ] && [ ! -L "$script_dir/finding-state.sh" ] || return 1
  printf '%s/finding-state.sh\n' "$script_dir"
}

fg_state_lock_wrapper_path() {
  local state_script

  state_script=$(fg_state_script_path) || return 1
  [ -r "${state_script%/*}/with-state-lock.pl" ] || return 1
  printf '%s/with-state-lock.pl\n' "${state_script%/*}"
}

fg_state_apply_lock_limits() {
  local max_bytes=$1 max_omitted=$2

  [[ "$max_bytes" =~ ^[0-9]{1,6}$ ]] || return 1
  [[ "$max_omitted" =~ ^[0-9]{1,2}$ ]] || return 1
  [ "$max_bytes" -ge "$FG_STATE_OVERFLOW_RESERVE" ] && [ "$max_bytes" -le 131072 ] || return 1
  [ "$max_omitted" -le 64 ] || return 1
  FG_STATE_MAX_BYTES=$max_bytes
  FG_STATE_MAX_OMITTED=$max_omitted
}

fg_state_with_root_lock() {
  local repo_identity=$1 session_id=$2 callback=$3 action state_script lock_wrapper cache_home
  shift 3

  case "$callback" in
    fg_state_update_file_locked) action=--locked-update ;;
    fg_state_remove_file_locked) action=--locked-remove ;;
    fg_state_emit_compact_summary_locked) action=--locked-summary ;;
    *) return 1 ;;
  esac
  fg_state_prepare_locked_state "$repo_identity" "$session_id" || return 1
  command -v perl >/dev/null 2>&1 || return 1
  state_script=$(fg_state_script_path) || return 1
  lock_wrapper=$(fg_state_lock_wrapper_path) || return 1
  [ -x "$state_script" ] || return 1
  cache_home=${FG_STATE_LOCKED_ROOT%/foxguard/claude-code}
  [ -n "$cache_home" ] || cache_home=/

  # The wrapper holds an inherited flock through the self-invoked action.
  XDG_CACHE_HOME="$cache_home" perl "$lock_wrapper" "$FG_STATE_LOCKED_ROOT" .lock "$state_script" "$action" \
    "$FG_STATE_MAX_BYTES" "$FG_STATE_MAX_OMITTED" "$FG_STATE_LOCKED_REPOSITORY" \
    "$FG_STATE_LOCKED_SESSION_ID" "$@"
}


fg_state_atomic_write() {
  local repo_identity=$1 session_id=$2 content=$3 allow_overflow_reserve=${4:-0} limit

  [ "$repo_identity" = "${FG_STATE_LOCKED_REPOSITORY:-}" ] || return 1
  [ "$session_id" = "${FG_STATE_LOCKED_SESSION_ID:-}" ] || return 1
  case "$allow_overflow_reserve" in
    0) limit=$((FG_STATE_MAX_BYTES - FG_STATE_OVERFLOW_RESERVE)) ;;
    1) limit=$FG_STATE_MAX_BYTES ;;
    *) return 1 ;;
  esac

  printf '%s\n' "$content" | fg_state_file_operation write "$FG_STATE_LOCKED_FILE" "$limit"
}


fg_state_write_omitted_fallback() {
  local repo_identity=$1 session_id=$2 state=$3 relative_path=$4 next write_status

  next=$(fg_state_add_omitted_path "$state" "$relative_path") || return 1
  printf '%s' "$next" | fg_state_validate >/dev/null 2>&1 || return 1
  if fg_state_atomic_write "$repo_identity" "$session_id" "$next" 1; then
    return 0
  else
    write_status=$?
  fi
  [ "$write_status" = "2" ] || return 1

  next=$(fg_state_mark_untracked_overflow "$state") || return 1
  printf '%s' "$next" | fg_state_validate >/dev/null 2>&1 || return 1
  fg_state_atomic_write "$repo_identity" "$session_id" "$next" 1
}


fg_state_update_file_locked() {
  local repo_identity=$1 session_id=$2 relative_path=$3 threshold=$4 record=$5
  local current entry next fallback_state write_status read_status can_store=0 existing=0

  fg_state_prune_locked "$repo_identity" "$session_id" || return 1
  if current=$(fg_state_file_operation touch-read "$FG_STATE_LOCKED_FILE" "$FG_STATE_MAX_BYTES"); then
    current=$(printf '%s' "$current" | fg_state_validate 2>/dev/null) || current='{"version":3,"overflow":0,"omitted":[],"files":{}}'
  else
    read_status=$?
    [ "$read_status" = "3" ] || return 1
    current='{"version":3,"overflow":0,"omitted":[],"files":{}}'
  fi

  entry=$(printf '%s' "$record" | jq -ce --arg threshold "$threshold" '. + {threshold: $threshold}' 2>/dev/null) || return 1
  if printf '%s' "$current" | jq -e --arg path "$relative_path" '.files | has($path)' >/dev/null 2>&1; then
    existing=1
  fi
  if [ "$existing" = "1" ] || printf '%s' "$current" | jq -e \
    --argjson max_files "$FG_STATE_MAX_FILES" '(.files | length) < $max_files' >/dev/null 2>&1; then
    can_store=1
  fi

  if [ "$can_store" != "1" ]; then
    fg_state_write_omitted_fallback "$FG_STATE_LOCKED_REPOSITORY" "$FG_STATE_LOCKED_SESSION_ID" \
      "$current" "$relative_path"
    return $?
  fi

  next=$(printf '%s' "$current" | jq -ce \
    --arg path "$relative_path" \
    --argjson entry "$entry" '.files[$path] = $entry' 2>/dev/null) || return 1
  next=$(fg_state_remove_omitted_path "$next" "$relative_path") || return 1
  printf '%s' "$next" | fg_state_validate >/dev/null 2>&1 || return 1
  if fg_state_atomic_write "$FG_STATE_LOCKED_REPOSITORY" "$FG_STATE_LOCKED_SESSION_ID" "$next" 0; then
    return 0
  else
    write_status=$?
  fi
  [ "$write_status" = "2" ] || return 1

  fallback_state=$current
  if [ "$existing" = "1" ]; then
    fallback_state=$(printf '%s' "$fallback_state" | jq -ce --arg path "$relative_path" 'del(.files[$path])' 2>/dev/null) || return 1
  fi
  fg_state_write_omitted_fallback "$FG_STATE_LOCKED_REPOSITORY" "$FG_STATE_LOCKED_SESSION_ID" \
    "$fallback_state" "$relative_path"
}


fg_state_update_file() {
  local session_id=$1 repo_root=$2 relative_path=$3 threshold=$4 record=$5

  fg_state_valid_threshold "$threshold" || return 1
  fg_state_with_root_lock "$repo_root" "$session_id" fg_state_update_file_locked \
    "$relative_path" "$threshold" "$record"
}


fg_state_remove_file_locked() {
  local repo_identity=$1 session_id=$2 relative_path=$3
  local current next read_status status=1

  fg_state_prune_locked "$repo_identity" "$session_id" || return 1
  if current=$(fg_state_file_operation touch-read "$FG_STATE_LOCKED_FILE" "$FG_STATE_MAX_BYTES"); then
    :
  else
    read_status=$?
    [ "$read_status" = "3" ] && return 0
    return 1
  fi
  current=$(printf '%s' "$current" | fg_state_validate 2>/dev/null) || return 1

  next=$(printf '%s' "$current" | jq -ce --arg path "$relative_path" 'del(.files[$path])' 2>/dev/null) || return 1
  next=$(fg_state_remove_omitted_path "$next" "$relative_path") || return 1
  if fg_state_is_empty "$next"; then
    fg_state_file_operation remove "$FG_STATE_LOCKED_FILE" && status=0
  elif printf '%s' "$next" | fg_state_validate >/dev/null 2>&1 \
    && fg_state_atomic_write "$FG_STATE_LOCKED_REPOSITORY" "$FG_STATE_LOCKED_SESSION_ID" "$next"; then
    status=0
  fi
  return "$status"
}


fg_state_remove_file() {
  local session_id=$1 repo_root=$2 relative_path=$3

  fg_state_with_root_lock "$repo_root" "$session_id" fg_state_remove_file_locked "$relative_path"
}


fg_state_record_findings() {
  local session_id=$1 cwd=$2 file_path=$3 threshold=$4 findings=$5
  local repo_root relative_path record

  repo_root=$(fg_state_repository_root "$cwd") || return 1
  file_path=$(fg_state_normalize_file_path "$cwd" "$file_path" "$repo_root") || return 1
  relative_path=$(fg_state_relative_path "$file_path" "$repo_root") || return 1
  record=$(printf '%s' "$findings" | fg_state_normalize_findings 2>/dev/null) || return 1
  record=$(fg_state_add_fingerprints "$relative_path" "$record" 2>/dev/null) || return 1
  fg_state_update_file "$session_id" "$repo_root" "$relative_path" "$threshold" "$record"
}

fg_state_clear_findings() {
  local session_id=$1 cwd=$2 file_path=$3
  local repo_root relative_path

  repo_root=$(fg_state_repository_root "$cwd") || return 1
  file_path=$(fg_state_normalize_file_path "$cwd" "$file_path" "$repo_root") || return 1
  relative_path=$(fg_state_relative_path "$file_path" "$repo_root") || return 1
  fg_state_remove_file "$session_id" "$repo_root" "$relative_path"
}

fg_state_emit_compact_summary_locked() {
  local repo_identity=$1 session_id=$2
  local state details header footer truncated_footer body detail_limit

  fg_state_prune_locked "$repo_identity" "$session_id" || return 1
  state=$(fg_state_file_operation touch-read "$FG_STATE_LOCKED_FILE" "$FG_STATE_MAX_BYTES") || return 1
  state=$(printf '%s' "$state" | fg_state_validate 2>/dev/null) || return 1

  details=$(printf '%s' "$state" | jq -r \
    --argjson max_files "$FG_STATE_MAX_SUMMARY_FILES" \
    --argjson max_findings "$FG_STATE_MAX_SUMMARY_FINDINGS" '
      [.files | to_entries[] |
        {
          total: .value.total,
          truncated: .value.truncated,
          findings: (.value.findings | sort_by(.severity, .fingerprint, .line, .column) | .[0:$max_findings])
        }
      ] as $files
      | ($files | sort_by(.findings[0].fingerprint) | .[0:$max_files]) as $shown
      | (if .overflow > 0 or (.omitted | length) > 0
         then "- Some successful scan results were omitted because the local continuity cache reached capacity."
         else empty
         end),
        ($shown[] | .findings[] |
          "- [\(.severity | ascii_upcase)] finding \(.fingerprint[0:12]) at line \(.line), column \(.column)"
        ),
        (if (($files | length) > ($shown | length))
          or ($shown | any(.[]; .truncated or (.total > (.findings | length))))
         then "- Additional finding details omitted."
         else empty
         end)
    ' 2>/dev/null) || return 1
  [ -n "$details" ] || return 1

  header='foxguard unresolved findings from this session are advisory feedback, not a final enforcement gate. Finding IDs are opaque; run `/foxguard:scan` to review current findings.'
  footer='Run `/foxguard:scan` to review current findings.'
  truncated_footer='Additional finding details omitted. Run `/foxguard:scan` to review current findings.'
  body="$header"$'\n'"$details"$'\n'"$footer"

  if [ $(( ${#body} + 1 )) -gt "$FG_STATE_SUMMARY_MAX_BYTES" ]; then
    detail_limit=$((FG_STATE_SUMMARY_MAX_BYTES - ${#header} - ${#truncated_footer} - 3))
    [ "$detail_limit" -gt 0 ] || return 1
    details="${details:0:$detail_limit}"
    body="$header"$'\n'"$details"$'\n'"$truncated_footer"
  fi

  printf '%s\n' "$body"
}


fg_state_emit_compact_summary() {
  local session_id=$1 cwd=$2
  local repo_root

  repo_root=$(fg_state_repository_root "$cwd") || return 1
  fg_state_with_root_lock "$repo_root" "$session_id" fg_state_emit_compact_summary_locked
}


fg_state_run_locked_action() {
  local action=${1:-}
  local repo_identity session_id
  shift || return 1

  case "$action" in
    --locked-update)
      [ "$#" -eq 7 ] || return 1
      fg_state_apply_lock_limits "$1" "$2" || return 1
      shift 2
      repo_identity=$1
      session_id=$2
      fg_state_prepare_locked_state "$repo_identity" "$session_id" || return 1
      shift 2
      fg_state_update_file_locked "$FG_STATE_LOCKED_REPOSITORY" "$FG_STATE_LOCKED_SESSION_ID" "$@"
      ;;
    --locked-remove)
      [ "$#" -eq 5 ] || return 1
      fg_state_apply_lock_limits "$1" "$2" || return 1
      shift 2
      repo_identity=$1
      session_id=$2
      fg_state_prepare_locked_state "$repo_identity" "$session_id" || return 1
      shift 2
      fg_state_remove_file_locked "$FG_STATE_LOCKED_REPOSITORY" "$FG_STATE_LOCKED_SESSION_ID" "$@"
      ;;
    --locked-summary)
      [ "$#" -eq 4 ] || return 1
      fg_state_apply_lock_limits "$1" "$2" || return 1
      shift 2
      repo_identity=$1
      session_id=$2
      fg_state_prepare_locked_state "$repo_identity" "$session_id" || return 1
      fg_state_emit_compact_summary_locked "$FG_STATE_LOCKED_REPOSITORY" "$FG_STATE_LOCKED_SESSION_ID"
      ;;
    *) return 1 ;;
  esac
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  fg_state_run_locked_action "$@"
fi
