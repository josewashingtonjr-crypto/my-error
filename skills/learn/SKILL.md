---
name: learn
description: Review a recently fixed mistake and persist a verified lesson in my-error. Use only after the correction has been tested or otherwise verified. Works both for a captured candidate and for a mistake found by investigation, which has no candidate.
allowed-tools: Bash, Read, Grep, Glob
argument-hint: [candidate-id]
---

Learn from the mistake described in `$ARGUMENTS`, and only if its root cause and its
correction are verified.

There are two paths, and both are first class:

**A captured candidate.** Run
`python3 "${CLAUDE_PLUGIN_ROOT}/scripts/my_error.py" review --limit 20`,
find the candidate matching the failure, and pass it as `--candidate-id`.

**No candidate.** A logic defect, a wrong assumption, a badly sized task or any mistake
found by reading and reasoning never produces a candidate, because capture fires on tool
exit codes. Do not go looking for one and do not treat its absence as a reason to skip:
omit `--candidate-id` entirely. Verification still applies — a test that fails against the
old code and passes against the new one, or a concrete before/after measurement.

Then follow the evidence-gated workflow in the `my-error:workflow` skill: check the four
admission criteria, choose `--scope global` when the rule is not specific to this
repository, and store a concise causal lesson. Do not add a blocking guard unless the
forbidden tool action is precise and safe to reject deterministically.
