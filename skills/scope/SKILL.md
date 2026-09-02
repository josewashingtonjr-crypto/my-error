---
name: scope
description: Move a stored my-error lesson between project and global reach, preserving its identity and recording an audit trail. Use when a lesson turns out to generalise beyond the repository it was learned in, or when a rule believed universal proves to depend on one repository's specifics.
allowed-tools: Bash, Read, Grep
argument-hint: ERR-0012 global [--reason "..."]
---

# Change a lesson's reach

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/my_error.py" scope <ERR-id> <project|global> --reason "<why>"
```

The lesson keeps its id, title, cause, rule, confidence, source, provenance, creation date
and accumulated `use_count`. Only reach changes, and the change is written to
`lesson_scope_changes` with the old scope, the new scope, a timestamp and the reason.

Do **not** reach for a direct `UPDATE` on the database, and do not use `forget` plus a fresh
`learn`. The first leaves no trace that a rule's reach was widened; the second mints a new
id and discards the history that shows the lesson has been earning its place.

## Which way to move it

**Promote to `global`** when the failure mechanism does not depend on this repository — it
follows from a language, a database, a protocol, or a general engineering principle, and
would be just as true in the next project. "A caught query error still aborts a Postgres
transaction." "A metric derived from the collector it is judging cannot prove its own
health." "Readiness is not the same as bootstrap being finished."

**Demote to `project`** when the rule turns out to depend on this repository's paths, script
names, services, internal APIs or particular configuration. "The deploy helper here is
`scripts/deploy-x.sh`" must never travel; in another repository it is simply wrong.

Demotion returns the lesson to the project it was **learned** in, not to whichever project
happens to be running the command — `origin_project_id` is the anchor, and it survives every
promotion.

## What not to promote

Automatically learned command corrections (`git sttaus` → `git status`) stay `project`. They
are keystroke-level and local by nature, and auto-capture is not authorised to produce
global knowledge — that is what keeps the shared store from filling with one environment's
typing habits.
