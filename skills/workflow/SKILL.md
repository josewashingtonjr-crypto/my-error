---
name: workflow
description: Use when Claude has made a coding or tool-use mistake, diagnosed the root cause, applied a correction, and verified that the correction works. Converts verified mistakes into durable project lessons so they are not repeated.
allowed-tools: Bash, Read, Grep, Glob
---

# My Error — verified learning workflow

Use this skill only after an error has a credible root cause and a verified correction. A failure by itself is not a lesson.

## Procedure

1. Inspect pending candidates:
   `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/my_error.py" review --limit 20`
2. Identify the candidate that corresponds to the error just fixed.
3. Confirm evidence: the corrected command/test/build/behavior must have succeeded, or there must be another concrete verification.
4. Generalize narrowly. Record the causal rule that would have prevented the mistake, not a vague instruction such as "be careful".
5. Save it:
   `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/my_error.py" learn --candidate-id <N> --title "<short title>" --cause "<root cause>" --rule "<future rule>" --confidence verified --tags "<comma,separated,tags>"`
6. Add a deterministic guard only when the forbidden action can be identified precisely and blocking it is safe. Example for an exact Bash command:
   `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/my_error.py" learn --candidate-id <N> --title "..." --cause "..." --rule "..." --confidence verified --guard-tool Bash --guard-field command --guard-match exact --guard-pattern "<bad command>" --replacement "<good command>" --guard-reason "<why blocked>"`
7. Do not create broad regex guards from a single ambiguous incident.

## Boundary with the host's other memory systems

my-error stores **only verified operational failures** — a command or tool action that
failed, with a correction that passed verification. It must not duplicate content into
the host's general memory (project notes, session memory, or any other memory plugin),
and those systems must not automatically copy my-error's lessons back.

The reason is that the two kinds of knowledge have different truth conditions. A my-error
lesson is falsifiable by re-running a command. A design decision or project preference is
not, and it decays on a different schedule. Merging them produces a store where nothing
can be safely expired, and where the same claim can be asserted twice and later disagree
with itself.

If a failure turns out to carry a durable design lesson, write the operational half here
and the design half in the host's own memory, deliberately and by hand — never both
automatically.

## Never learn from

- transient network/service failures;
- user interrupts;
- failures whose root cause is still uncertain;
- tests known to have been broken before Claude's change;
- behavior that succeeded only accidentally;
- secrets, tokens, passwords, or raw credentials.

## Quality bar

A good lesson is causal, reusable, scoped to the project unless truly universal, and falsifiable. Prefer one precise rule over several speculative rules.
