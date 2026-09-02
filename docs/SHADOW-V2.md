# SHADOW v2

## Why v1 was closed instead of extended

SHADOW v1 ran **2026-08-18T14:24:26Z → 2026-09-02**. Its final status is:

```
INCONCLUSIVE_DUE_TO_MATERIAL_SYSTEM_CHANGES
```

This is **not** a success and **not** a failure. It is a statement that the
window cannot answer the question it was opened to answer.

During those 15 days the system underneath the experiment changed materially:
canonical database location, the SQLite concurrency fix that was silently
losing captures, project identity, project/global scope, provenance,
cross-project recall, the controlled/natural split, learning doctrine,
instrumentation, watchdog and doctor, runtime/version verification, and
storage and metrics. Comparing the first half of that window against the
current system as though they were one experiment would be a category error,
so the honest move is to declare the window inconclusive and restart from a
known, frozen baseline.

Silently letting the old clock keep running would have produced a verdict on
2026-09-17 computed from two different systems. That verdict would have looked
exactly as legitimate as a real one.

## v2

| | |
|---|---|
| Start | **2026-09-02** (`meta.shadow_v2_started_at`, stamped by the migration) |
| Duration | 30 days |
| Decision due | **2026-10-02** |
| Baseline code | **my-error 0.4.4**, published at commit `001245d` |
| Verdict dataset | `natural_usage` **and** `created_at >= shadow_v2_started_at` |

Both filters are required. A row must be natural usage *and* inside the
window. Controlled tests are excluded regardless of date; v1 natural usage is
excluded regardless of origin.

An **absent** v2 stamp admits nothing rather than everything. Failing open
there would silently promote every historical row into the verdict — the exact
failure this split exists to prevent.

## The pre-committed rule — unchanged

Frozen before the first measurement of v1, and not touched by this release:

```
confirmed == 0                  -> REMOVE the auto-guard from the code
refuted > confirmed             -> REMOVE
confirmed >= 3 and refuted == 0 -> PROMOTE to ENFORCE
anything else                   -> EXTEND another 30 days
```

Threshold stays **3**. `SHADOW_EXPERIMENT_DAYS` stays **30**. Neither may be
adjusted after seeing data — doing so would invalidate the experiment rather
than improve it. A test asserts the rule's behaviour is byte-identical.

## What the verdict judges

**Only the deterministic auto-guard for operational recurrence.**

It does **not** judge:

- the value of my-error as a whole
- semantic lessons
- recall
- cross-project transfer
- global knowledge
- prevention of engineering mistakes between projects

Those are measured in the doctor's separate *Knowledge transfer* section and
never feed `shadow_verdict()`. They answer a broader thesis that no exit code
can settle: *an experience paid for in one project can stop another project
paying for it again.*

## History is preserved

Nothing is deleted: not candidates, lessons, guards, guard_events,
recall_events, controlled tests, old natural usage, historical metrics or
provenance. The generation change is **metadata only** — the migration to
schema 5 writes `meta` keys and touches no row of any other table. A test
snapshots `guard_events` before and after and asserts byte equality.

v1's rows stay queryable and are reported under `v1_*` in the doctor.

## Freeze, 2026-09-02 → 2026-10-02

Do not change without a real bug: SHADOW threshold, verdict, families, guard
matching, automatic heuristics, confirmed/refuted classification,
natural/controlled classification, causal verification criteria.

Infrastructure bugs may be fixed. If one is: document the version, timestamp,
potential impact, preserve the data, and **do not restart the experiment
without asking the owner.**

## Baseline snapshot

The database half is captured atomically by the migration, inside the same
transaction that opens v2, and stored in `meta.shadow_v2_baseline_snapshot`.
It is the state at the boundary instant, not a reading taken afterwards.
`doctor --json` returns it under `shadow_v2_baseline_snapshot`.

The repo commit and the live runtime version are recorded here rather than in
the snapshot, because a process cannot honestly attest to either from inside
itself (see ERR-0016).
