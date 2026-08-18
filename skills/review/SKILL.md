---
name: review
description: Review pending error candidates and active learned rules from my-error without changing them.
allowed-tools: Bash
---
Run `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/my_error.py" review --limit 30`. Distinguish pending failures from verified lessons. Do not promote anything automatically during a review-only request.
