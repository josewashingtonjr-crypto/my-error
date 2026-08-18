---
name: forget
description: Supersede an obsolete or incorrect my-error lesson and disable its guards.
allowed-tools: Bash
argument-hint: [ERR-id]
---
Run `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/my_error.py" forget "$ARGUMENTS"`. Confirm that the lesson is superseded and any associated guard is disabled.
