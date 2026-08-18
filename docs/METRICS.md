# Metrics

Every counter here is a count of rows that exist in the database. Nothing is estimated,
nothing is derived from a model's opinion, and a metric that cannot be computed is reported
as unavailable rather than as zero.

Read this before quoting a number. Several of them are easy to misread in a flattering
direction, and the whole point of the project is not to do that.

## The counters

| Name | Definition |
|---|---|
| `failures_captured` | Distinct failure signatures for this project. A signature is `(tool, exact action, normalized error)`. |
| `failure_events` | Total occurrences, including repeats of the same signature. `failures_captured` is the denominator you usually want; this is how many times they actually happened. |
| `verified_corrections` | Candidates in status `learned` — the correction passed the verification gate. |
| `unverified_recoveries` | Candidates in status `evidence` or `review_requested`: a later success was observed but the cause is **not** proven. **These are not corrections.** |
| `lessons_active` | Lessons with status `active`. Excludes superseded ones. |
| `guards_active` | Active guards attached to active lessons and not expired. |
| `guard_matches_total` | Times a guard pattern matched an attempted action — the repeat opportunities. |
| `would_block_shadow` | Matches that occurred in SHADOW. **Nothing was prevented.** |
| `actual_blocks_enforce` | Matches that occurred in ENFORCE, where the tool call was actually denied. |
| `predictions_confirmed` | Shadow let the command run and it **failed again**. The guard was right. |
| `predictions_refuted` | Shadow let the command run and it **succeeded**. The guard was wrong — a measured false positive. |
| `predictions_pending` | Matched, but the outcome has not been observed yet. |
| `mode` | `SHADOW` or `ENFORCE`. |
| `shadow_started_at` / `shadow_day` | When the experiment clock started, and how far into the 30 days it is. `null` until the first hook runs. |

## Language that would be wrong

**`would_block_shadow` is not "errors prevented".** In SHADOW nothing is prevented. The
correct phrasing is "repetitions detected" or "would have blocked". If you see a report
calling this number *prevented*, the report is wrong.

**`unverified_recoveries` is not a correction.** A command failed, something later
succeeded, and that is all that is known. Counting it as a fix is exactly the superstition
this project refuses.

**`verified_corrections / failures_captured` is not a success rate.** The denominator
includes failures that are legitimately unlearnable — flaky tests, ambiguous errors,
transient conditions. A plugin that "learned" from all of them would be worse, not better.

**`failure_events` is not a count of distinct mistakes.** One typo retried five times is
one `failures_captured` and five `failure_events`.

## `predictions_refuted` is the one that matters

`confirmed` tells you the guard would have been useful. `refuted` tells you it would have
been *harmful* — it would have blocked a command that was going to work.

Only shadow mode can measure this. An enforcing guard blocks the command, so you never
learn whether it would have succeeded; the counterfactual is destroyed by the act of
blocking. This is the entire reason the plugin ships in SHADOW.

Watch `refuted` more closely than `confirmed`. A single false positive in real use is worth
more attention than several correct predictions, because a false block is an interruption
the user cannot easily diagnose.

## Metrics that do not exist

There is no `false_matches` counter, and no `errors_prevented`. If you need the
false-positive count, it is `predictions_refuted`. If you want to know how much harm the
guard has done in SHADOW, the answer is structurally zero — it has blocked nothing.

## Namespacing

Metrics are per project. A project is identified by its Git common directory when inside a
repository (so every worktree of one repo shares a namespace), and by absolute path
otherwise. Moving or renaming a repository changes its identity and orphans its history —
a known limit, documented in [ARCHITECTURE.md](ARCHITECTURE.md).

`/my-error:doctor` prints the namespace it resolved. If a number looks wrong, check that
first: you may be reading a different project's history, or an empty one.

## Where they come from

`collect_metrics()` in `scripts/my_error.py` is the single implementation. The watchdog
line, `/my-error:doctor`, `/my-error:status` and `metrics --json` all render the same
function's output, so they cannot disagree.
