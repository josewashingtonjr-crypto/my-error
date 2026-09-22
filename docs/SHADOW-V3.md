# SHADOW v3

## Why v2 was closed 11 days early

SHADOW v2 ran **2026-09-02T17:01:05Z → 2026-09-22**, day 19 of 30. Its final
status is:

```
INCONCLUSIVE_DUE_TO_MEASUREMENT_DEFECTS
```

Neither a success nor a failure, and for a different reason than v1. v1 closed
because the *system* changed mid-window. v2 closes because the *instrument*
could not support the claim its verdict would have made.

Four defects, each independently sufficient, all found by auditing the stored
rows rather than by waiting for day 30.

### 1. The verdict depended on the working directory

`collect_metrics` counted guard events through a helper that filtered
`project_id = <the cwd's project>`. The pre-committed rule therefore returned a
different answer depending on where the doctor ran — same database, same
instant:

| doctor run from | confirmed | refuted | rule says |
|---|---|---|---|
| `/home/w-jr` | 2 | 1 | EXTEND |
| `/home/w-jr/fidren` | 0 | 1 | **REMOVE** (`confirmed == 0`) |

A verdict that moves when you `cd` is not a verdict. v2's reported dataset was
also incomplete: it showed 3 natural firings where the database held 4.

### 2. `command failed` was recorded as `the guard was right`

```python
outcome = "true_positive" if failed else "false_positive"
```

Nothing checked that the failure was *caused* by the guarded pattern. This is
correlation recorded under the name of confirmation.

### 3. Some guards predict harm an exit code cannot express

`git add -A` stages the wrong paths and exits 0. Under rule 2 that guard could
only ever be refuted, by construction, no matter how correct it was.

### 4. At least one recorded confirmation was demonstrably spurious

`guard_events` id=7: the guard matched `pkill -f` appearing **inside a quoted
lesson body**, and the command then died of an unrelated bash syntax error
(`exit 127`, on the `|` in the prose). Scored `true_positive`. Reclassifying
event 7 alone moves the canonical v2 outcome from EXTEND to REMOVE, which is
how little the old verdict was resting on.

Nothing was deleted and nothing was rescored. Every v2 row keeps its original
`outcome`; the causal columns added in 0.5.0 are stamped `not_evaluated` on
every pre-v3 row, because those rows were not evaluated under a model that did
not exist when they were recorded.

## What v3 changes

### The canonical dataset

`canonical_dataset()` selects on `experiment` and `origin` and applies **no
project filter**. `project_id` survives as a reported dimension — the doctor
prints a per-project breakdown — but it no longer decides which rows count.

Verified on a copy of the live database: the canonical block and the verdict
are identical from `/home/w-jr` and from `/home/w-jr/fidren`, while the
preserved legacy v2 series still shows the old asymmetry (2/1 vs 0/1).

### Causal outcomes

Four values instead of two:

| value | meaning |
|---|---|
| `causally_confirmed` | the guard's declared harm demonstrably occurred |
| `causally_refuted` | it demonstrably did not |
| `unverified` | it cannot be established either way |
| `not_evaluated` | the row predates this model |

`unverified` is the **default**, so silence can never read as success. Each
guard declares `eval_class` (which observable decides it) and optionally
`confirm_evidence` (a regex over the failure output that proves the harm).

- `execution_error` — the harm IS the command failing, and the failure must
  implicate the guarded token. A failure with another cause is `unverified`.
- `side_effect` — the harm happens while exiting 0. No probe exists, so rows
  are `unverified` and the guard is simply **not on trial**.
- `destructive` — never confirmed by proxy, never provoked for evidence.

### The pre-committed v3 rule

Frozen before any v3 row existed:

```
unverified > 2x(confirmed+refuted)  -> INSTRUMENT_INSUFFICIENT  (no guard verdict)
confirmed == 0 and refuted == 0     -> EXTEND   (absence of evidence)
confirmed == 0                      -> REMOVE
refuted > confirmed                 -> REMOVE
confirmed >= 3 and refuted == 0     -> PROMOTE to ENFORCE
anything else                       -> EXTEND
```

Two additions over v2. The instrument is judged **before** the guard, so a
window whose firings were mostly illegible reports that instead of a finding.
And zero-and-zero is now EXTEND rather than REMOVE: with a causal model it means
the guard never fired decisively, which is an absence of evidence rather than
evidence of absence.

`missed_relevant_recall` is deliberately **not** in this rule. It measures the
recall path; letting a guard verdict absorb it is what made the single v2
verdict unreadable.

### Baseline

- **start:** stamped in `meta.shadow_v3_started_at` when the migration runs
- **baseline version:** my-error 0.4.5 (the code v2 was measuring)
- **shipped in:** 0.5.0
- **mode:** SHADOW. Nothing is blocked.
- v1 and v2 rows are excluded by `experiment`, never by deletion.

## Guard 8 and guard 9

**Guard 8** (`pkill -f`) moves from `match_type=regex` to `shell_cmd`, a matcher
that fires only where the shell would actually run a command — quoted spans and
heredoc bodies are masked, command substitution stays code, and transparent
wrappers like `sudo` are stepped over. It also declares
`confirm_evidence = [Ee]xit code (137|143|144)\b`, the self-kill signature
ERR-0039 names.

Measured across all six real firings in the live database:

| event | v2 outcome | old matcher | new matcher |
|---|---|---|---|
| 7 | true_positive | fires | data_only (mention in a rule body) |
| 8 | false_positive | fires | data_only (mention in a heredoc) |
| 10 | true_positive | fires | **command_position** (exit 144, genuine) |
| 11, 12, 13 | false_positive | fires | data_only (heredocs written while fixing this) |

Old matcher: 6 firings. New matcher: 1 — and it is the real one. Events 11–13
were produced *by the investigation itself*, writing heredocs that mention the
token; the defect reproduced three more times while being diagnosed.

**Guard 9** (`git add -A`) keeps its regex **unchanged**. Loosening it to
improve a statistic would be fitting the guard to the instrument. It is
reclassified `side_effect` instead: the guard may be entirely correct while this
experiment remains unable to judge it, and that is what the row now says.

## Retired fixtures

`retire-fixtures` retires controlled-test scaffolding by a **structural
criterion** — `source` in `AUTO_LESSON_SOURCES` and `origin = controlled_test` —
not by an id list, which would be wrong for any other installation. Dry run is
the default. Rows are preserved with `status = retired_fixture`, guards are
deactivated, and `lesson_retirements` records the previous status, the reason
and how many guards were disabled.

The doctor reports three totals separately, because one "lessons: N" invites
reading the historical total as the amount of useful knowledge:

```
lessons ever recorded / lessons active / fixtures retired
```

## Measuring recall

`missed_relevant_recall` records that a **provably** relevant lesson was not in
front of the agent before the action. The basis is a guard match — a
deterministic pattern, not a similarity score — so it is a measurement, not an
inference.

The case it exists for, from the live database: on 2026-09-21 at 11:39:56 a
guard matched `pkill -f "port=2202"`; the command died with exit 144, the exact
harm ERR-0039 describes. ERR-0039 reached the agent at **11:39:57**, from the
*failure* hook — one second after the command it would have prevented. The
recalls before the action (11:21:05, 11:27:18, 11:29:12) carried other lessons.

The structural cause is worth stating plainly: in SHADOW the `PreToolUse` hook is
the only one that sees an action before it runs, and it deliberately emits
nothing so as not to contaminate the measurement. So pre-action recall is keyed
on the **user's prompt text** and never on the **command about to run**. A lesson
whose relevance is only visible from the command cannot arrive in time. v3
measures that gap rather than fixing it by guess.

`recall_events` now records `session_id`, `rank`, `phase`, `top_k` and
`pool_size`, and every delivery path writes through one function — including
SessionStart, which previously injected lessons while recording nothing, making
them look to the audit as though they had never arrived. `phase` separates
`prompt` / `session-start` (before the action) from `failure` (after, and
therefore incapable of prevention).

Nothing here claims a delivered lesson helped. `recall_events` counts what was
put in front of the agent, and that is all it counts.

## The top-5 question, and why it is not yet answerable

The cut is **unchanged at 5**. Raising it would be a guess, and the instrument to
judge it did not exist until 0.5.0.

What the data does already show is that the cut was not the binding constraint
for the seven project-scoped lessons with zero recalls. All eight project-scope
lessons in the live database have `source = auto-verified-recovery`, and
`lesson_rows()` excludes that source from recall entirely. They were never
candidates at any `k`: they never competed and lost, they never entered. Raising
`top_k` would have changed nothing for them.

`recall_misses` now samples up to five just-below-the-cut lessons per recall, so
the question becomes answerable from real traffic. Until it has data, a reported
`0` means *no evidence*, and the doctor says so rather than letting 0 read as
"top-5 is fine".

Ranking changes wait for that evidence.
