# my-error

Persistent, evidence-gated error memory for [Claude Code](https://claude.com/claude-code).

`my-error` remembers mistakes that were diagnosed and corrected, so they are not made
twice. It keeps them in a local SQLite database, recalls the relevant ones on later
prompts, and can block an exact action that was already proven wrong.

Failed commands are captured automatically: when Claude runs a command that fails and then
a corrected one that works, the pair is recorded — but only when the correction is
verifiable. That path is the *cheapest* source of evidence, not the definition of an error.
A logic defect, a wrong assumption, a badly sized task or an unsafe judgment produces no
failing command and is recorded deliberately, through the same verification bar.

> ### ⚠️ EXPERIMENTAL — v0.4.1
>
> Ships in **SHADOW mode**: the guard records what it *would* have blocked and **blocks
> nothing**. The automatic guard is on a 30-day probation while its real base rate is
> measured, and it may be **removed** if the data does not justify it. `0.x` is deliberate —
> interfaces may change. See [The experiment](#the-experiment).

## The core rule

**A failure is not a lesson. A mistake with a diagnosed cause and a verified correction
can become a lesson — however it was discovered.**

Everything else follows from that. A test that fails and later passes is not proof of
anything. A network timeout is not a lesson. A command that happened to succeed nearby is
not the correction for the one that failed. And a non-zero exit code is evidence that
something broke, never the boundary of what counts as breaking: the mistakes worth
remembering longest — the wrong assumption, the design that could not work — leave no exit
code at all.

## Install

Requires Claude Code, `python3`, and `git`. No third-party Python packages.

```bash
claude plugin marketplace add josewashingtonjr-crypto/my-error
```

```bash
claude plugin install my-error@my-error-local --scope user
```

`--scope user` makes it available in every project, with history kept separately per
project. Restart Claude Code, then run `/my-error:doctor`.

To update later:

```bash
claude plugin marketplace update my-error-local && claude plugin install my-error@my-error-local --scope user
```

## Try it in two minutes

In any project, ask Claude to run a command with a typo in it, let it fail, then let the
corrected one succeed:

```
git sttaus     →  fails
git status     →  succeeds
git sttaus     →  runs again (SHADOW blocks nothing) and fails again
```

Then run `/my-error:doctor`. You should see `failures captured: 1`,
`verified corrections: 1`, `would-block (SHADOW): 1`, `predictions confirmed: 1`.

That last number is the point: the guard predicted a repeat, shadow let it run, and the
prediction was borne out. For the full protocol, including the anti-superstition check,
see [docs/TESTING.md](docs/TESTING.md).

## Commands

| Skill | What it does |
|---|---|
| `/my-error:doctor` | Full health report: paths, hooks, locale, mode, metrics |
| `/my-error:status` | One-line counts for the current project |
| `/my-error:review` | Pending candidates and active lessons, changing nothing |
| `/my-error:learn` | Promote a reviewed candidate to a lesson (requires a stated cause) |
| `/my-error:forget` | Supersede a lesson and disable its guards |
| `/my-error:workflow` | The evidence-gated procedure Claude follows before promoting anything |

The same operations exist on the CLI — see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Modes

| Mode | Behaviour |
|---|---|
| **`SHADOW`** (default) | A matching guard is recorded and the command **runs**. Nothing is blocked, and nothing is injected into the model's context. |
| `ENFORCE` | A matching guard denies the tool call. |

Switching mode is a CLI operation. `MY_ERROR` below is the installed script — the path is
printed by `/my-error:doctor`:

```bash
MY_ERROR=$(ls -d ~/.claude/plugins/cache/*/my-error/*/scripts/my_error.py | tail -1)
```

```bash
python3 "$MY_ERROR" mode --set ENFORCE
```

Shadow is not "off". When it lets a command through, it scores its own prediction against
what actually happened: the command failed again (`predictions_confirmed`) or it
**succeeded** (`predictions_refuted` — a false positive *measured*, not estimated).

An enforcing guard cannot produce that evidence, because blocking destroys the
counterfactual. Nor does shadow warn the model: an instrument that announces itself changes
the behaviour it is measuring.

## The experiment

The automatic guard is on probation. The decision rule was fixed **before any data
existed**, and lives in the code as a constant marked `DO NOT EDIT BEFORE 2026-09-17`:

| Outcome | Verdict |
|---|---|
| `predictions_confirmed == 0` | **REMOVE** the auto-guard from the codebase |
| `refuted > confirmed` | **REMOVE** |
| `confirmed >= 3` and `refuted == 0` | **PROMOTE** to ENFORCE |
| anything else | **EXTEND** another 30 days |

`doctor` computes the verdict itself and refuses to state one before day 30. The rule is
written down in advance precisely so that the numbers cannot be argued with after the fact.

## What it does without asking

- Captures `Bash`, `Write` and `Edit` failures via `PostToolUseFailure`.
- Ignores transient/network failures and user interrupts.
- Redacts API keys, bearer tokens and passwords before anything is stored.
- After a **deterministic** failure — unknown subcommand, unknown option, path not found,
  missing npm script, git pathspec — if a closely related command succeeds next, promotes
  that exact correction to a lesson and a 90-day guard.
- Recalls reviewed lessons on `UserPromptSubmit`, and high-confidence ones at
  `SessionStart`.
- Recognizes failure messages in English, Portuguese, Spanish, French, German and Italian.

"Closely related" is strict: exactly one shell token may differ, and that token must itself
be similar. An unrelated nearby success is rejected.

## What it will not do without you

Semantic and logic failures are captured as *candidates* and never promoted automatically.
When a previously failing command later succeeds, a `Stop` hook asks Claude once to review
it via `/my-error:learn` — and the model still has to state a root cause. This is what keeps
flaky tests and misunderstood failures out of memory.

## Observability (optional)

`my-error` cannot credibly monitor itself: if it stops loading, its own hooks stop too and
its silence is indistinguishable from health. So it emits a liveness beacon, and a separate
watchdog judges it, printing one line before every response:

```
🧠 my-error: ✅ ATIVO GLOBAL | falhas: 7 | corrigidas: 6/7 (86%) | lições: 6 | repetições detectadas: 6 | modo: SHADOW
```

It reports degradation honestly — `DB INDISPONÍVEL`, `HOOKS INATIVOS`, `MÉTRICAS DEFASADAS`
— and never substitutes zeros for a failure. Install with `watchdog/install-watchdog.sh`;
it prints the settings snippet rather than editing your `settings.json` for you.

## Documentation

| | |
|---|---|
| [docs/TESTING.md](docs/TESTING.md) | Reproduce the controlled test, including the anti-superstition check |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Hooks, pipeline, storage, watchdog, CLI |
| [docs/METRICS.md](docs/METRICS.md) | Exact meaning of every counter — read before quoting one |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Real failure modes and how to diagnose them |
| [docs/TEST_REPORT.md](docs/TEST_REPORT.md) | Benchmark results and their limits |
| [CHANGELOG.md](CHANGELOG.md) | What changed and why |

## Verify the claims yourself

```bash
git clone https://github.com/josewashingtonjr-crypto/my-error && cd my-error
```

```bash
python3 -m unittest discover -s tests -v && python3 benchmarks/ab_benchmark.py && python3 benchmarks/heldout_live_benchmark.py && python3 benchmarks/fuzz_live_benchmark.py
```

53 tests, no third-party dependencies. The benchmarks run real commands in a temporary
project. Numbers and their limits are in [docs/TEST_REPORT.md](docs/TEST_REPORT.md).

## Limits

This does not retrain anything. It is external memory plus deterministic guards, and its
value is bounded by how often the same exact mistake actually recurs — which is precisely
the open question the shadow experiment exists to answer.

No model-level A/B test has been run. The benchmarks validate the learning, recall and
guard mechanics, not that Claude makes fewer mistakes overall.

## License

MIT. See [LICENSE](LICENSE).
