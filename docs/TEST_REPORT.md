# Test report — v0.3.1

Measured 2026-08-18 on Linux, Python 3.12.3, locale `pt_BR.UTF-8`.

## What is being measured

**Prevention of exact recurrence after a verified correction.** A baseline without the
plugin cannot block a repeated mistake, so its prevention rate is 0% by construction.

The benchmarks run with `MY_ERROR_MODE=ENFORCE`, because they measure blocking. The product
default is `SHADOW`, which blocks nothing. A benchmark that ran in the default mode would
be measuring nothing.

## Results

| Benchmark | Cases | Learned | Recurrences blocked | False blocks |
|---|---:|---:|---:|---:|
| Live held-out A/B | 33 valid of 36 attempted | 33 | **33 (100%)** | 0 |
| Generated typo fuzz | 30 | 30 | **30 (100%)** | 0 |
| Deterministic A/B | 8 | 8 | **8 (100%)** | 0 |

Semantic recall: 10/10 expected lessons ranked #1 for differently worded prompts on the
held-out benchmark, 4/4 on the deterministic one. Anti-superstition false lessons: 0.
Guard hot path, in-process p95: 0.138 ms.

Under `LC_ALL=C`, held-out and fuzz both reach 100% as well.

Raw results: [`../benchmarks/v0.3-heldout-result.json`](../benchmarks/v0.3-heldout-result.json),
[`../benchmarks/v0.3-fuzz-result.json`](../benchmarks/v0.3-fuzz-result.json),
[`../benchmarks/last_result.json`](../benchmarks/last_result.json).

Three of the 36 held-out cases are skipped when the tool they need is absent from the
environment; they are reported as skipped rather than counted as passes.

## Automated suite

53 tests, no third-party dependencies. Coverage includes the learning gate, secret
redaction, project isolation, guard expiry, forgetting, concurrency, locale handling,
shadow scoring, storage resolution, legacy adoption, and each anti-superstition rule.

## Live verification

The pipeline was exercised end to end through the installed plugin's real hooks in Claude
Code, in SHADOW mode, in Portuguese. Five deterministic failure/correction pairs plus one
repeat each:

- 7 failures captured (13 events), 6 verified corrections, 6 lessons, 6 guard matches.
- 6 `predictions_confirmed`, 0 `predictions_refuted`, **0 actual blocks** — SHADOW blocked
  nothing, as designed.
- Anti-superstition: `git sttaus` followed by a *successful but unrelated*
  `git log -1 --oneline` produced no association. The candidate stayed `captured`.

The Portuguese run matters: it is what validates the localized patterns in production
rather than in a fixture.

## Why the earlier 100% was not trustworthy

v1.1.0 reported 100% on both live benchmarks. Those numbers came from an English-locale
host. Re-running the *unmodified* v1.1.0 benchmarks on `pt_BR.UTF-8`:

| Benchmark | v1.1.0 on pt_BR |
|---|---|
| Live held-out | 23/33 (69.7%) |
| Generated typo fuzz | 21/30 (70%) |

Every family regex matched English message text only, so on a non-English host most
deterministic failures classified as `other` and were never learned. The published figure
was a property of the test environment, not of the algorithm.

This is the reason the report now states its locale, and reports both.

## What these numbers do not mean

**They are not evidence that Claude makes fewer mistakes.** They measure one workflow:

```
deterministic mistake → observed failure → narrow verified correction
  → persistent lesson and guard → exact recurrence blocked
```

That is close to tautological — the benchmark trains the mechanism and then tests the
mechanism. It shows the machinery works and does not misfire; it says nothing about how
often the machinery is *needed*.

**The base rate is unmeasured.** How often does the same exact failing command actually
recur in real use? Nobody knows yet. If it is near zero, the automatic guard is expensive
machinery for a problem that does not occur, and the value of the plugin lies entirely in
the manually reviewed lessons. That question is what the 30-day SHADOW experiment exists to
answer, with a decision rule fixed in advance.

**No model-level A/B has been run.** Comparing the same authenticated model solving tasks
with and without the plugin needs a controlled harness that was not available.

Semantic and logic failures still require causal review before promotion. The plugin
deliberately refuses to auto-learn ambiguous test failures, transient failures, interrupts,
and unrelated nearby successes.
