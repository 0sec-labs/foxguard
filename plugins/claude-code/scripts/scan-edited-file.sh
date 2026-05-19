#!/usr/bin/env bash
# PostToolUse hook: scan the file Claude just wrote/edited and feed findings back.
#
# Reads the Claude Code hook input JSON from stdin, extracts the edited path from
# common Write/Edit/NotebookEdit schemas, runs `foxguard --format json` on it,
# and emits a compact summary on stderr with exit 2 when medium+ findings exist
# so Claude treats it as actionable feedback.
# Stays silent (exit 0) on clean files, missing tools, or unreadable inputs — a
# scanner hook should never block Claude on its own machinery.

set -uo pipefail

input=$(cat)

file_path=$(printf '%s' "$input" | jq -r '
  .tool_input.file_path
  // .tool_input.path
  // .tool_input.notebook_path
  // .tool_response.filePath
  // .tool_response.file_path
  // empty
' 2>/dev/null)

[ -z "$file_path" ] && exit 0
[ ! -f "$file_path" ] && exit 0

# Resolve foxguard binary: prefer PATH, fall back to npx.
if command -v foxguard >/dev/null 2>&1; then
  fg=(foxguard)
elif command -v npx >/dev/null 2>&1; then
  fg=(npx --yes foxguard)
else
  exit 0
fi

min_severity="${FOXGUARD_HOOK_SEVERITY:-medium}"

scan_output=$("${fg[@]}" --format json --severity "$min_severity" -- "$file_path" 2>/dev/null) || true

[ -z "$scan_output" ] && exit 0

findings=$(printf '%s' "$scan_output" | jq -c '
  if type == "array" then
    .
  elif type == "object" and (.findings | type == "array") then
    .findings
  else
    []
  end
' 2>/dev/null)

[ -z "$findings" ] && exit 0
[ "$findings" = "[]" ] && exit 0

count=$(printf '%s' "$findings" | jq 'length' 2>/dev/null)
if [ -z "$count" ] || [ "$count" = "0" ]; then
  exit 0
fi

{
  printf 'foxguard found %s issue(s) in %s (severity >= %s):\n\n' "$count" "$file_path" "$min_severity"
  printf '%s' "$findings" | jq -r '
    .[] |
    "  [\(.severity // "unknown" | tostring | ascii_upcase)] \(.rule_id // "unknown-rule") at line \(.line // "?")\n" +
    "    \(.description // "No description")\n" +
    "    \(.cwe // "")\n" +
    "    > \(.snippet // "" | tostring)\n"
  '
  printf '\nFix these before continuing. Run `/foxguard:scan` for the full repo or `/foxguard:triage` for the interactive TUI.\n'
} >&2

exit 2
