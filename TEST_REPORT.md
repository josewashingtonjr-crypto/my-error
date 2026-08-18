# my-error v1.2.0 Test Report

Date: 2026-08-18

## Goal

Measure whether `my-error` improves operational memory after a verified mistake without
increasing false blocking or turning unrelated successes into false lessons.

The primary metric is **prevention of exact recurrence after a verified correction**. A
baseline without the plugin cannot block a repeated mistake, so its prevention rate is 0%.

## Why v1.2.0 exists

v1.1.0 reported 100% on both live benchmarks. Those numbers were produced on an
English-locale host. Re-running the *unmodified* v1.1.0 benchmarks on a `pt_BR.UTF-8`
machine gave:

| Benchmark | v1.1.0 on pt_BR | v1.2.0 on pt_BR | v1.2.0 on `LC_ALL=C` |
|---|---|---|---|
| Live held-out | 23/33 (69.7%) | **33/33 (100%)** | **33/33 (100%)** |
| Generated typo fuzz | 21/30 (70%) | **30/30 (100%)** | **30/30 (100%)** |
| Deterministic A/B | 8/8 | 8/8 | 8/8 |

Every family regex matched English message text only, so on a non-English host most
deterministic failures classified as `other` and were never auto-learned. The v1.1.0
figure was environment-specific, not a property of the algorithm.

## Results (v1.2.0, this machine)

### 1. Independent live held-out A/B

- 36 attempted pairs, 33 valid in this environment (3 skipped: tool not present).
- Baseline: 0/33 repeated mistakes prevented (0%).
- `my-error`: 33/33 verified corrections learned, 33/33 exact recurrences denied (100%).
- Semantic recall: 10/10 expected lessons ranked #1 for differently worded prompts.
- False blocks: 0. Anti-superstition false lessons: 0. Control commands checked: 32.

Raw result: `benchmarks/v1.2-heldout-result.json`

### 2. Generated typo fuzz A/B

Typo strings are generated after the implementation is loaded; they are not stored inside
the plugin.

- 30 generated valid pairs. Baseline repeated failures: 30/30.
- Learned 30/30, exact recurrences blocked 30/30 (100%), false blocks 0.

Raw result: `benchmarks/v1.2-fuzz-result.json`

### 3. Regression benchmark

- 8/8 known mistakes prevented, 4/4 semantic lessons recalled, 0 false blocks.
- Transient failure ignored.
- Guard hot path p95 in-process: ~0.11 ms.

Raw result: `benchmarks/last_result.json`

### 4. Unit/integration suite

27/27 tests pass. Beyond the v1.1.0 coverage, v1.2.0 adds:

- localized (pt/es/fr) failure messages auto-learn;
- an unrecognized language still learns via the blamed-token fallback;
- a stack frame naming the entrypoint does **not** create a lesson;
- a guard matches a command that carries a redacted credential;
- a `PostToolUse` carrying an error response is not treated as a recovery;
- a hook fed garbage stdin and an unwritable data dir exits 0 with no output;
- `ignore` with a malformed id exits 2 instead of raising.

Concurrency was additionally stress-tested outside the suite: 12 trials x 8 simultaneous
failure hooks against a fresh database. Before the fix ~30% of trials lost an event to a
`projects.id` UNIQUE race; after, 12/12 trials record all 8 occurrences, and under artificial
disk saturation (six parallel 300 MB direct-I/O writers) 11/12.

## Integration verified against Claude Code 2.1.179

- `claude plugin validate . --strict` passes.
- `PostToolUseFailure` exists and its payload carries `tool_name`, `tool_input`, `error`,
  and `is_interrupt`, as the plugin assumes.
- Exec-form hooks (`command` + `args`) with `${CLAUDE_PLUGIN_ROOT}` are substituted
  per-element as plain strings — the form the plugin uses.
- Every `hookSpecificOutput` shape the plugin emits is consumed: `additionalContext` for
  `SessionStart`, `UserPromptSubmit`, `PostToolUse`, `PostToolUseFailure`, and `Stop`;
  `permissionDecision`/`permissionDecisionReason` for `PreToolUse`.

## Important interpretation

100% is **not** a claim that Claude became 100% smarter or that every programming error is
prevented. It is the measured result for this workflow:

`deterministic mistake -> observed failure -> narrow verified correction -> persistent lesson/guard -> exact recurrence blocked`.

Semantic/code-logic failures still require causal review before promotion. The plugin
refuses to auto-learn ambiguous test failures, transient/network failures, interrupts, and
unrelated nearby successes.

A model-level A/B (the same authenticated model solving tasks with and without the plugin)
was not run; it requires a controlled authenticated Claude Code harness. These benchmarks
validate the learning/recall/guard mechanics independently of model variance.
