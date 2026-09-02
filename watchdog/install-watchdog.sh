#!/usr/bin/env bash
# Optional. Installs the my-error watchdog and status line segment, then prints
# the settings.json snippets to wire them up. It deliberately does NOT edit
# settings.json for you: that file is yours, and a hook is something you should
# add with your eyes open.
set -euo pipefail

DEST="${MY_ERROR_WATCHDOG_DIR:-$HOME/.claude/watchdogs}"
SRCDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

command -v node >/dev/null 2>&1 || { echo "ERROR: node is required." >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 is required." >&2; exit 1; }

mkdir -p "$DEST"
# my-error-state.cjs is required by both of the others: health, freshness and
# the data directory are decided in exactly one place. Copying only one file
# leaves a wrapper that reports ❌ instead of metrics.
for f in my-error-state.cjs my-error-watchdog.cjs my-error-statusline.cjs; do
  cp "$SRCDIR/$f" "$DEST/$f"
  chmod +x "$DEST/$f"
  echo "Installed: $DEST/$f"
done

echo
echo "Verify the watchdog can see your installation:"
echo "  echo '{\"session_id\":\"probe\",\"cwd\":\"\$PWD\"}' | node \"$DEST/my-error-watchdog.cjs\" --probe"
echo
echo "1) Watchdog - ONE UserPromptSubmit hook in ~/.claude/settings.json."
echo "   NOTE: hook timeouts are in SECONDS. 10 means ten seconds; 10000 means"
echo "   almost three hours and is always a units bug."
cat <<'JSON'

  "hooks": {
    "UserPromptSubmit": [
      { "hooks": [ {
          "type": "command",
          "timeout": 10,
          "command": "sh -c 'exec node \"${HOME}/.claude/watchdogs/my-error-watchdog.cjs\"'"
      } ] }
    ]
  }

JSON
echo "Already have a UserPromptSubmit hook? Do not add a second one - wrap yours:"
echo "  sh -c 'MY_ERROR_WRAP_COMMAND=\"<your existing command>\" exec node \"\${HOME}/.claude/watchdogs/my-error-watchdog.cjs\"'"
echo
echo "2) Status line - Claude Code runs exactly ONE statusLine command, so if you"
echo "   already have one, wrap it rather than replacing it. Put your existing"
echo "   command in MY_ERROR_STATUSLINE_WRAP:"
cat <<'JSON'

  "statusLine": {
    "type": "command",
    "command": "sh -c 'MY_ERROR_STATUSLINE_WRAP=\"<your existing command>\" exec node \"${HOME}/.claude/watchdogs/my-error-statusline.cjs\"'"
  }

JSON
echo "   With no existing bar, drop MY_ERROR_STATUSLINE_WRAP and it prints the"
echo "   my-error segment alone. statusLine takes no timeout field."
echo
echo "   After restarting Claude Code, this file proves the LIVE bar ran it -"
echo "   a manual run of the script does not:"
echo "     cat \"$DEST/.my-error-statusline.json\""
