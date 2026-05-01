---
description: Open the foxguard interactive TUI for triaging findings
disable-model-invocation: true
---

Launch the foxguard TUI for interactive triage.

1. Tell the user the TUI is an interactive terminal app and Claude cannot drive it — they need to interact with it directly in their terminal.
2. Suggest they run one of these in their own terminal (NOT via your Bash tool, which can't render a TUI):
   - `foxguard tui` — full repo
   - `foxguard tui --changed` — staged/unstaged files only
   - `foxguard tui --diff main` — diff vs main
   - `foxguard tui --secrets` — secrets mode
   - `foxguard tui --explain` — show dataflow traces in the detail pane
3. Pass through any path or flags from `$ARGUMENTS`.
4. After they finish triaging, offer to follow up with `/foxguard:scan` to re-verify the codebase is clean.
