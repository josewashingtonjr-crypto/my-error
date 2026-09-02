---
name: workflow
description: Use when a mistake of any kind — a failed command, a logic or design defect, a wrong assumption, bad task sizing, an unsafe judgment call — has been diagnosed to a root cause and its correction verified. Converts verified mistakes into durable lessons so they are not repeated. How the mistake was discovered does not matter; whether it is verified does.
allowed-tools: Bash, Read, Grep, Glob
---

# My Error — verified learning workflow

Use this skill only after a mistake has a credible root cause and a verified correction. A failure by itself is not a lesson.

## What counts as an error

**A non-zero exit code is evidence of a mistake. It is not the definition of one.**

The automatic capture path can only see failed tool calls, because that is the only thing
`PostToolUseFailure` fires on. Reading that mechanism as the scope of this plugin is the
single most likely way to throw away its most valuable lessons: the defect found by reading
code, the assumption that was wrong, the work that was sized badly. Those produce no failing
command, so nothing captures them, so they must be recorded deliberately — and they are
exactly the mistakes an experienced engineer has already paid for once and does not repeat.

A lesson may come from any of these:

- a failed command or tool call;
- a coding or logic defect;
- an architectural or design error;
- an assumption that turned out to be false;
- bad task decomposition or sizing;
- an unsafe operational judgment;
- a repeated inefficiency;
- a mistake caused by not having done this before.

**Admission criteria — all four, regardless of how it was found:**

1. something actually went wrong, or would reproducibly go wrong;
2. the causal mechanism is understood, not guessed;
3. the rule is falsifiable — a test, a command, or concrete measured evidence could show it
   false;
4. remembering it can prevent a recurrence.

Criterion 3 is what keeps the store honest, and it is met by far more than commands. "A
`.catch()` around a query inside one Postgres transaction does not prevent the abort" is
checkable in thirty seconds. "Splitting a large document across a shared extraction context
collapses its output" was measured at 164 nodes against 23. Neither began as a failed
command; both are falsifiable.

**Reject, however it was found:**

- preferences and style opinions;
- vague suspicion or unverified speculation;
- project state with no reusable rule attached;
- a decision that worked out, with no failure mechanism behind it.

## Procedure

1. Inspect pending candidates:
   `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/my_error.py" review --limit 20`
2. Identify the candidate that corresponds to the error just fixed — **if there is one**. A
   mistake found by investigation has no candidate, and that is normal, not a gap. Skip to
   step 3 and omit `--candidate-id` in step 5.
3. Confirm evidence: the corrected command/test/build/behavior must have succeeded, or there
   must be another concrete verification — a regression test that fails against the old code
   and passes against the new one, a measurement before and after, an observed production
   state. Verification is the bar; a failed command is only one way to clear it.
4. Generalize narrowly. Record the causal rule that would have prevented the mistake, not a
   vague instruction such as "be careful".
5. Save it — with a candidate when one exists:
   `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/my_error.py" learn --candidate-id <N> --title "<short title>" --cause "<root cause>" --rule "<future rule>" --confidence verified --tags "<comma,separated,tags>"`

   or without one, for a mistake discovered by reading, reasoning or measuring:
   `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/my_error.py" learn --title "<short title>" --cause "<root cause>" --rule "<future rule>" --confidence verified --scope <project|global> --tags "<comma,separated,tags>"`

   `--candidate-id` is optional and always has been. This step spells it out because a
   workflow that only ever shows the candidate form teaches, by omission, that a lesson
   requires a captured failure.
6. Add a deterministic guard only when the forbidden action can be identified precisely and blocking it is safe. Example for an exact Bash command:
   `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/my_error.py" learn --candidate-id <N> --title "..." --cause "..." --rule "..." --confidence verified --guard-tool Bash --guard-field command --guard-match exact --guard-pattern "<bad command>" --replacement "<good command>" --guard-reason "<why blocked>"`
7. Do not create broad regex guards from a single ambiguous incident.

## Boundary with the host's other memory systems

The split is by **kind of claim**, not by how the mistake was discovered.

- **my-error** holds the *reusable prevention rule*: the causal mechanism and what to do
  differently next time. It is falsifiable — a test, a command or a measurement could show
  it wrong — and it stays true after the project that produced it is finished.
- **The host's project memory** holds *what happened*: state, dates, commits, decisions and
  facts specific to this codebase. It is not falsifiable by re-running anything, and it
  decays on a different schedule.

An earlier version of this section drew the line at "operational failures — a command or
tool action that failed", and routed everything else to project memory. That was wrong, and
wrong in the expensive direction: it excluded precisely the logic, design and judgment
mistakes that are worth remembering longest, on the incorrect grounds that they are not
falsifiable. Many are. The test is criterion 3 above, not the presence of an exit code.

The two systems may reference the same incident from their own side, and often should:
the rule here, the state there. What must never happen is blind duplication in either
direction, or one system automatically copying the other. Write each half deliberately.

Worked example. A collector silently wrote nothing for 37 hours because seven queries ran
inside one Postgres transaction, each with a `.catch()` that could not prevent the
transaction abort:

- **my-error** gets: *a per-query `catch` inside one PG transaction does not degrade, it
  aborts everything — move the reads out of the transaction, or use a SAVEPOINT per read.*
  Reusable in any project, on any codebase, provable in a test.
- **Project memory** gets: *which collector, which table, which dates it was dead, the
  commit that fixed it, that the SLI above it read HEALTHY the whole time.* Useful here,
  meaningless elsewhere.

## Reflection — the errors nothing captures

At the end of a session my-error asks, once, whether anything went wrong for a reason that
was *not* a failed command. That prompt exists because the capture path is blind to exactly
the class of mistake this skill most wants: it fires on exit codes, and a wrong assumption
has none.

The prompt only asks. It never creates a lesson, and "nothing went wrong" is the expected
answer most of the time. When the answer is yes, the mistake goes through the same four
admission criteria as everything else — a reflection is not a shortcut past the quality bar,
it is a way of noticing that the bar should be applied at all.

## Never learn from

- transient network/service failures;
- user interrupts;
- failures whose root cause is still uncertain;
- tests known to have been broken before Claude's change;
- behavior that succeeded only accidentally;
- a suspicion that something *might* be wrong, with no verification;
- a preference, convention or style choice, however strongly held;
- secrets, tokens, passwords, or raw credentials.

## Quality bar

A good lesson is causal, reusable, scoped to the project unless truly universal, and
falsifiable. Prefer one precise rule over several speculative rules.

Scope is a real decision, not a default. A rule that follows from a language, a database or
a protocol is `global` — it will be true in the next project too. A rule that depends on this
repository's layout, tooling or conventions is `project`. Marking a universal rule as
project-scoped quietly throws away most of its value.
