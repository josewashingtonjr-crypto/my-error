---
name: learn
description: Review a recently fixed mistake and persist a verified lesson in my-error. Use only after the correction has been tested or otherwise verified.
allowed-tools: Bash, Read, Grep, Glob
argument-hint: [candidate-id]
---

Review the pending my-error candidate `$ARGUMENTS` and learn from it only if the root cause and correction are verified.

Run:
`python3 "${CLAUDE_PLUGIN_ROOT}/scripts/my_error.py" review --limit 20`

Then follow the evidence-gated workflow in the `my-error` skill. Store a concise causal lesson. Do not add a blocking guard unless the forbidden tool action is precise and safe to reject deterministically.
