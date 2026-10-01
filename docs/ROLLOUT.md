# Rollout — 0.4.5 (installed) → 0.6.0

NOT AUTHORIZED. This is the plan, written to be executed only on the user's
explicit go-ahead, one stage at a time, with a stop condition at each.

## Starting state, measured 2026-10-01

| | |
|---|---|
| Installed plugin | **0.4.5** at `~/.claude/plugins/cache/my-error-local/my-error/0.4.5` |
| Repo `main` | 0.5.0 |
| This branch | 0.6.0 (`feat/active-prevention`) |
| Live database | `~/.claude/plugins/data/my-error/my-error.db`, `user_version` **6** |
| Live mode | SHADOW |
| Active guards | **0** |
| Active lessons | 20 (16 project, 4 global) |
| Hook timeout | `UserPromptSubmit.timeout = 10000` — units bug, contract is seconds |

Three independent versions are in play. That incoherence is what `release_coherence_check()`
exists to refuse, and it must be resolved *before* a new measurement window opens,
not after.

## Stage 0 — baseline, before touching anything

```bash
cp ~/.claude/plugins/data/my-error/my-error.db \
   ~/.claude/plugins/data/my-error/my-error.db.pre-0.6.0
```

Then record, from the **installed 0.4.5**, not from the repo:

```bash
python3 ~/.claude/plugins/cache/my-error-local/my-error/0.4.5/scripts/my_error.py doctor
```

Keep the output. It is the only before-picture that exists.

**Why from the installed copy:** running the repo's newer code against the live
database is not a read. It already migrated it 5→6 and opened SHADOW v3 once
today. 0.6.0 fixes that (read-only commands no longer migrate, verified on real
v5 and v6 fixtures), but stage 0 happens before 0.6.0 is installed.

## Stage 1 — fix the hook timeout

In `~/.claude/settings.json`, `UserPromptSubmit.timeout`: `10000` → `10`.

Independent of everything else, reversible, and worth doing alone first so its
effect is attributable. `10000` is not a long timeout — it is nearly three hours,
so the hook currently has no effective timeout at all.

**Verify:** a new session's prompt still gets lesson injection, and the status
line still renders.

## Stage 2 — install 0.6.0, WARN off, mode SHADOW

Merge `feat/active-prevention` and let the plugin cache pick up 0.6.0.

At this point the behaviour must be **indistinguishable from 0.5.0**: the WARN
channel ships off, so contextual recall and every `severity=warn` guard are
silent, and there are no guards at all. This is deliberate — it separates
"the new code is installed and stable" from "the new behaviour is on".

**Verify, and stop if any of these fail:**

```bash
# the four must name the same release
python3 <plugin_root>/scripts/my_error.py doctor    # expect coherent: YES
```

- `doctor` exits 0 and reports `coherent: YES`. While the installed copy is
  0.4.5 and the db is v6, it will report `NO` and name the disagreeing pair —
  that is the gate working, not a failure to ignore.
- `user_version` reaches 7 only via a **hook** (the write path), never via a
  read. Confirm with `PRAGMA user_version`.
- All 20 lessons and every `recall_events` row survive. Count them against
  stage 0.
- The statusline beacon reports 0.6.0, matching the installed path.

**Rollback:** restore `my-error.db.pre-0.6.0` and re-point the plugin at 0.4.5.
0.4.5 and 0.5.0 both operate correctly against a v7 database — verified, not
assumed: the `_user_version(db) >= SCHEMA_VERSION` fast path plus additive-only
columns, tested by running both unmodified against a v7 fixture. What is lost on
rollback is the *meaning* of the v7 columns (severity, condition, exceptions,
prevention_class) and the three new tables; the rows themselves are preserved and
unread. No lesson, candidate, guard or recall event is lost in either direction.

## Stage 3 — annotate the contaminated window, do not erase it

`shadow_v3_started_at` and `shadow_v3_baseline_snapshot` are stamped
2026-10-01T17:45:46 with `code_version: 0.5.0`, written by an out-of-band CLI run
while 0.4.5 was the installed runtime. So v3's clock has been counting hours of
0.4.5 behaviour labelled as v3.

The keys stay. `annotate_shadow_v3_contamination()` records what happened, when,
by which code version, against which installed version. A new window then opens
on top of the annotated history — gated by `release_coherence_check()`, so it
cannot open until stage 2's four-way agreement holds.

Deleting those keys to get a clean baseline is the one thing this stage must not
do. This experiment has already been declared inconclusive twice; a third
generation starting from a silently-cleaned slate would be unfalsifiable.

## Stage 4 — WARN on, still no guards

Turn the WARN channel on. Contextual recall begins injecting at PreToolUse;
nothing can block, because no guard exists.

**This is the stage that needs patience.** What to watch, for at least a few
days of ordinary work:

- How often a lesson is injected per session, and whether the ones injected are
  the ones that mattered. Measured, not recalled from impression:
  `recall-audit` separates deliveries by phase, and `pretooluse` near-misses are
  sampled into `recall_misses`.
- Whether any lesson is injected on plainly unrelated actions. One delivery
  spent on noise costs the session's one slot for that lesson.

**Stop condition:** if the channel is noisy, turn it off and fix the selection
before going further. A channel that is learned to be ignored is worse than
silence, because it looks like coverage.

## Stage 5 — seed guards, `severity=warn` first

The three specified in `seed-guards.md` (ERR-0003, ERR-0001, ERR-0017), seeded as
`warn`, with a TTL. They match and warn but cannot deny. This measures the false
positive rate against real work with nothing at risk.

Note what the seed spec already corrected: the first draft's exception patterns
were bypassable by appending `# grep`. Exceptions are now evaluated in command
position only. The anti-bypass cases are tested, and were re-verified
independently through `hook guard`, not only through the suite.

**Stop condition:** any guard that fires on a legitimate operation goes back to
the drawing board. Not "tune the pattern" — re-examine whether the lesson is
mechanically verifiable at all.

## Stage 6 — selective ENFORCE

Only after stage 5 has produced a real false-positive rate. Promote
guard-by-guard, `warn` → `deny`, never a global switch. ERR-0017 only with
`condition=cwd_not_git_repo`; it is a false-positive factory without it, since
`git status` from inside a repo is correct and the deciding fact is not in the
command text.

Auto-learned guards stay `warn` by the user's decision of 2026-10-01. The
`MY_ERROR_AUTO_GUARD_SEVERITY` opt-in exists so the benchmarks can still measure
blocking; it is not meant to be set in the live installation.

## What would make this a success, and what would only look like one

Success is a controlled recurrence blocked before execution, recorded as
`actually_blocked` with a confirmed causal outcome, plus a false-positive count
that is a real measured number rather than an absence of complaints.

Not success: green tests, a non-zero guard count, or a zero in any prevention
metric. With `guards_active == 0` those metrics now read `NOT_MEASURABLE`, and on
a pre-v7 database `SCHEMA_INSUFFICIENT` — two different reasons, deliberately
never collapsed into the same `0` that started this whole investigation.
