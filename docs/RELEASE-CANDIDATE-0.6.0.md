# Release candidate 0.6.0 — evidence record

Frozen 2026-10-01. Tag `v0.6.0-rc1`, commit `34eb40143161a91a41c6a5e447b221e55082ff16`, branch `feat/active-prevention`,
schema **v9**.

This file exists so the evidence behind the rollout decision cannot drift. Every
number here was measured first-hand against this commit, not carried over from a
report. Re-running any of them should reproduce these values; if one does not,
that divergence is itself the finding.

## Scope of the claim

These numbers show the machinery behaves as specified. **They are not evidence of
preventive efficacy.** No guard is seeded in any real database, the WARN channel
ships off, and the mode is SHADOW. Real prevention requires a recurrence of a
recorded mistake denied before execution in genuine work, with a confirmed causal
outcome — see `docs/ROLLOUT.md`.

## 1. Unit suite — 187 tests, OK

```bash
MY_ERROR_DATA_DIR=<scratch> python3 -m unittest discover -s tests
```

## 2. Independent adversarial harness — 9/9

```bash
python3 benchmarks/review_adversarial.py
```

Deliberately outside `tests/`: a check inside the suite it judges can be made to
pass by editing that suite. The nine:

| Check | Proves |
|---|---|
| observing an older database does not migrate or rotate it | the live incident cannot recur |
| read-only commands exit 0 on a v5 database | the fix did not trade migration for a crash |
| 0.4.5 operates on a v9 database | additive schema, rollback path intact |
| `NOT_MEASURABLE` with no guards | a structurally impossible 0 is not rendered as a result |
| WARN off emits nothing | the freeze guarantee |
| exception cannot be disarmed by a comment | 4 bypass variants still deny; `grep` still allowed |
| a condition separates the mistake from its twin | same `git log` denies outside a repo, allowed inside |
| editing a guard does not change a past metric | `actually_blocked` 1 → 1 across an edit |
| the edit is still detectable | live fingerprint ≠ the event's frozen one |

## 3. Benchmarks

| Benchmark | Result |
|---|---|
| `ab_benchmark.py` | pass |
| `fuzz_live_benchmark.py` | `pass_100: true` |
| `heldout_live_benchmark.py` | **93.9% — `pass_100: false`** |

### The 93.9%, recorded permanently and not adjusted

Measured first-hand at this commit:

```
valid_pairs                                33
baseline.mistakes_prevented                 0
with_my_error.repeat_mistakes_prevented    31   (93.94%)
with_my_error.false_blocks                  0
with_my_error.semantic_recall_hits      10/10
anti_superstition_false_lessons             0
pass_100                                False
skipped                                     3
```

Cause, established by extracting `main` (0.5.0, pre-review) and running the
identical benchmark in isolation — the same gap, the same two commands, so it is
pre-existing and unrelated to any 0.6.0 change:

1. three pairs skip because this host has no `pytest` binary at all;
2. `npm rn build` and `npm lss` are never classified into an auto-eligible
   failure family by `classify_failure()`.

**The threshold was not lowered.** It stays at 100% and the benchmark exits
non-zero. A passing number manufactured by moving the bar would be worth less
than an honest failing one, and this project has already been declared
inconclusive twice over measurement defects.

Note: running this benchmark rewrites `benchmarks/v0.3-heldout-result.json` in
the working tree as a side effect, regardless of `MY_ERROR_DATA_DIR`. That file
was reverted after measurement and is unchanged at this commit.

## 4. Fingerprint completeness — verified field by field

`guard_fingerprint()` covers eight fields, each confirmed by mutation to change
the fingerprint: `tool_name`, `field_name`, `match_type`, `pattern`,
**`condition`**, **`exceptions`**, **`severity`**, `replacement`. The three in
bold were required explicitly and are covered.

Deliberately excluded, with reasons:

| Column | Why excluded |
|---|---|
| `project_id` | scope, not rule. `guard_events.project_id` records where it fired |
| `active`, `expires_at` | lifecycle. A guard that does not fire produces no event to compare |
| `eval_class`, `confirm_evidence` | post-hoc scoring; `guard_events.guard_class` freezes the former separately |
| `id`, `created_at`, `hit_count`, `last_hit`, `origin` | bookkeeping |

### Known gap, deliberately not fixed

The DENY payload is built from `guards.reason` + `guards.replacement` +
`lessons.rule_text`. `replacement` is in `guard_fingerprint`, `rule_text` is in
`rule_fingerprint`, and **`reason` is in neither** — so editing it changes what a
past block appears to have said, with no trace. That is the same argument used to
justify `rule_fingerprint` in v8, so it is a consistency gap.

Not fixed, on purpose: `reason` is prose and does not change whether or how a
guard fires, so the behavioural definition is complete without it, and the
standing instruction is not to bump the schema again without a concrete blocking
defect. Recorded here so the limit is known rather than discovered later.

## 5. Live installation at the time of freezing

Untouched, and must stay so until 2026-10-02:

```
installed plugin   0.4.5
live database      user_version 6, 20 lessons, 0 guards
mode               SHADOW
hook timeout       UserPromptSubmit 10000 (units bug, contract is seconds)
```

The three-way version disagreement (installed 0.4.5 / repo main 0.5.0 / this
candidate 0.6.0) is what `release_coherence_check()` refuses, and resolving it is
stage 2 of the rollout.

## 6. rc2 correction: `hooks_evidence()` was reading a declaration as proof of firing

Frozen 2026-10-01 (same day, after rc1). Tag `v0.6.0-rc2`. Scope: this defect only,
no schema change, version stays at **0.6.0** (this is rc2 of the same release, not
a new one).

### The defect

`hooks_evidence()`/`release_coherence_check()` claimed to report hooks "ACTUALLY
LOADED (not merely declared)". It did not. Its second source, the external
watchdog's `.my-error-health.json` (`health.hooks`), is itself computed from
`watchdog/my-error-state.cjs`'s `structuralHealth()`:

```js
const manifest = readJson(path.join(health.install_path, 'hooks', 'hooks.json'));
const events = manifest && manifest.hooks ? Object.keys(manifest.hooks) : [];
const required = ['PreToolUse', 'PostToolUseFailure', 'PostToolUse', 'SessionStart'];
health.hooks = Object.fromEntries(required.map((e) => [e, events.includes(e)]));
```

That reads the MANIFEST and reports which of a hardcoded four events are
DECLARED — a second declaration, not evidence of anything firing. Consequences:

- the four hooks rc1 called "evidenced" were, in fact, only declared twice over;
- `SessionEnd`, `Stop`, `UserPromptSubmit` could never appear in that map (not in
  the hardcoded four), so rc1's `coherent: YES` was structurally unreachable for
  any installation, forever;
- measured live: `doctor` reported `UserPromptSubmit` unverified while the real
  database held `recall_events` rows with `phase='prompt'`, the most recent 2
  minutes old. The hook demonstrably fired; the checker said otherwise.

### The fix

Replaced the binary evidenced/unverified split with four states — `DECLARED`
(appears in `hooks/hooks.json`), `OBSERVED` (current, strong, release-attributable
evidence), `UNOBSERVED` (declared, nothing proven yet — **not a fault**), `MISMATCH`
(concrete evidence contradicting the manifest). `health.hooks` is now read ONLY for
its two honest uses: cross-checking the installed version it separately records
(`health.version`), and its own availability/freshness — never as firing evidence.

New evidence sources, each causally traced to one hook kind via `_dispatch_hook`:
`recall_events.phase` ('prompt'→UserPromptSubmit, 'session-start'→SessionStart,
'pretooluse'→PreToolUse, written only when the WARN channel is on), `guard_events`
rows (PreToolUse, via `run_guard`), and the beacon's `last_hook`/`last_seen`
(exactly one hook, mapped through `KIND_TO_EVENT`). `candidates` rows are accepted
only as **weak** evidence (created by the failure hook, but the row carries no
release/version marker) and are never, alone, upgraded to `OBSERVED`.

`coherent` is redefined: version/schema/manifest agreement plus genuine
`MISMATCH`es only. A hook that has not fired yet is `UNOBSERVED`, reported in a
separate coverage breakdown (`hooks_loaded.coverage`), and never drags `coherent`
down — this is why `Stop`/`SessionEnd` can now be `UNOBSERVED` in every live
session without the installation ever reading as incoherent for it, which was
rc1's structural dead end.

### Verification

```bash
MY_ERROR_DATA_DIR=<scratch> python3 -m unittest discover -s tests   # 197 tests, OK
MY_ERROR_DATA_DIR=<scratch> python3 benchmarks/review_adversarial.py # 6/9 in a sandbox
                                                                      # missing the 0.4.5
                                                                      # cache extract; the
                                                                      # 3 failures are the
                                                                      # SAME 3 that fail
                                                                      # identically on rc1
                                                                      # (confirmed via
                                                                      # `git stash`) and are
                                                                      # environment-only,
                                                                      # not this defect.
```

`heldout_live_benchmark.py` still reports **93.9%**, unchanged, as expected and
documented in section 3 above. `benchmarks/v0.3-heldout-result.json` was reverted
after measurement.
