#!/usr/bin/env bash
# Optional. Installs the my-error watchdog and prints the settings.json snippet
# to wire it up. It deliberately does NOT edit settings.json for you: that file
# is yours, and a hook is something you should add with your eyes open.
set -euo pipefail

DEST="${MY_ERROR_WATCHDOG_DIR:-$HOME/.claude/watchdogs}"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/my-error-watchdog.cjs"

command -v node >/dev/null 2>&1 || { echo "ERROR: node is required." >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 is required." >&2; exit 1; }

mkdir -p "$DEST"
cp "$SRC" "$DEST/my-error-watchdog.cjs"
chmod +x "$DEST/my-error-watchdog.cjs"
echo "Installed: $DEST/my-error-watchdog.cjs"
echo
echo "Verify it can see your installation:"
echo "  echo '{\"session_id\":\"probe\",\"cwd\":\"\$PWD\"}' | node \"$DEST/my-error-watchdog.cjs\" --probe"
echo
echo "Then add ONE UserPromptSubmit hook to ~/.claude/settings.json:"
cat <<JSON

  "hooks": {
    "UserPromptSubmit": [
      { "hooks": [ {
          "type": "command",
          "timeout": 10000,
          "command": "sh -c 'exec node \"\${HOME}/.claude/watchdogs/my-error-watchdog.cjs\"'"
      } ] }
    ]
  }

JSON
echo "Already have a UserPromptSubmit hook? Do not add a second one - wrap yours:"
echo "  sh -c 'MY_ERROR_WRAP_COMMAND=\"<your existing command>\" exec node \"\${HOME}/.claude/watchdogs/my-error-watchdog.cjs\"'"
