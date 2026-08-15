#!/usr/bin/env bash
# SessionStart hook: restore metadata-only finding reminders after compaction.

set -uo pipefail

input=$(cat)
source=$(printf '%s' "$input" | jq -r '.source // empty' 2>/dev/null)
[ "$source" = "compact" ] || exit 0

session_id=$(printf '%s' "$input" | jq -r '.session_id // empty' 2>/dev/null)
cwd=$(printf '%s' "$input" | jq -r '.cwd // empty' 2>/dev/null)
[ -n "$session_id" ] && [ -n "$cwd" ] || exit 0

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" 2>/dev/null && pwd -P)
if [ -n "$script_dir" ] && [ -r "$script_dir/finding-state.sh" ] \
  && . "$script_dir/finding-state.sh" >/dev/null 2>&1; then
  fg_state_emit_compact_summary "$session_id" "$cwd" 2>/dev/null || :
fi

exit 0
