# Testing my-error

Two kinds of verification: the automated suite, which you can run without installing
anything, and a live protocol that exercises the real hook pipeline inside Claude Code.

## Automated

```bash
python3 -m unittest discover -s tests -v
```

186 tests, no third-party dependencies. They cover the learning gate, secret redaction,
project isolation, guard expiry, concurrency, locale handling, shadow scoring, storage
resolution, the anti-superstition rules, (0.6.0) active prevention: severity/
condition/exceptions, contextual recall at PreToolUse, read-only observability on an
older database, release coherence, and cross-version compatibility, and the 0.6.0 v8
correction: frozen fire-time facts (`severity_at_fire`/`decision`/`guard_fingerprint`),
`actually_blocked`'s immunity to a guard edited after it fired, unknown-at-fire reporting
for pre-v8 rows, and hooks-actually-loaded verification (fixtures only, never this
machine's real watchdog file).

```bash
python3 benchmarks/ab_benchmark.py && python3 benchmarks/heldout_live_benchmark.py && python3 benchmarks/fuzz_live_benchmark.py
```

The last two run **real commands** in a temporary project and measure whether a verified
correction prevents an exact recurrence. Each exits non-zero if it does not reach 100%.
Results and their limits: [TEST_REPORT.md](TEST_REPORT.md).

The benchmarks set `MY_ERROR_MODE=ENFORCE` explicitly, because they measure blocking and
the product default blocks nothing. Since 0.6.0 they ALSO set
`MY_ERROR_AUTO_GUARD_SEVERITY=deny` explicitly, for the same reason: the auto-learned
guard's own default changed to `warn` (a verified correction with no human in the loop
no longer blocks on its own), so a benchmark that measures blocking opts in to `deny`
the same way it already opts in to `ENFORCE`.

### `heldout_live_benchmark.py`: documented, standing result, 93.9% (31/33)

On this machine, `heldout_live_benchmark.py` reaches **93.9% (31/33)**, exits non-zero
(`pass_100: false`), and does **not** pass outright. This is recorded here permanently,
not fixed by lowering the bar: **the threshold stays 100%**, and this result is the
honest distance from it on this machine, not a manufactured pass.

Two established causes, both environmental, neither a defect in the prevention logic
under test:

1. **No `pytest` binary on this machine.** Three held-out pairs use `pytest` as the
   "good" command (e.g. `pytest tests/test_alpha.py -q` correcting
   `pytest test/test_alpha.py -q`); the good command itself fails with
   `/bin/sh: 1: pytest: not found`, so the pair cannot demonstrate a verified recovery
   and is skipped (`skipped`, each with `reason: "good command failed"`). This is a
   missing interpreter on this host, not a benchmark or product failure.
2. **`npm rn build` / `npm lss` are never classified into an auto-eligible failure
   family.** The auto-learning gate (`narrow_command_correction`) only promotes a
   correction when the failure is recognized as one of the deterministic families it
   covers; these two typo'd `npm` invocations fall outside that recognizer, so no
   lesson is ever learned for them to begin with, independent of whether `pytest` is
   installed.

3 skipped pairs out of 33 is exactly the gap between 31/33 (93.9%) and 100%. Installing
`pytest` on the host running the benchmark removes cause 1 and should close most of that
gap; cause 2 is a recognizer-coverage gap, tracked separately, not something this
benchmark run papers over.

## Live protocol

This is the one that proves the plugin works *as installed*, through Claude Code's own
hooks. Run it in a disposable project. Every command below is read-only or confined to
`/tmp`.

### 0. Baseline

Run `/my-error:doctor` and write down `failures captured`, `verified corrections`,
`would-block (SHADOW)` and `predictions confirmed`.

Confirm `Mode: SHADOW`. If the plugin is not active, stop and diagnose — see
[TROUBLESHOOTING.md](TROUBLESHOOTING.md). Do not continue past a broken baseline.

### 1. A complete cycle

Ask Claude to run each of these as a **separate** command. They must be separate: a
compound command is stored as one action, and the correction would no longer differ by a
single token.

| Step | Command | Expected |
|---|---|---|
| 1 | `cat /tmp/probe-fiel.txt` | fails; hook reports `Captured candidate CAND-nnnn (path_not_found)` |
| 2 | `touch /tmp/probe-file.txt` then `cat /tmp/probe-file.txt` | succeeds; hook reports `Verified recovery: CAND-nnnn became ERR-nnnn` |
| 3 | `cat /tmp/probe-fiel.txt` | **runs anyway** and fails again |

Step 3 is the one people get wrong. In SHADOW the command is *not* blocked. Seeing it fail
again is the expected, correct result.

Afterwards `/my-error:doctor` should show each counter up by one, including
`predictions confirmed`.

### 2. Repeat with other failure families

The same three-step pattern, to cover more of the recognizer:

| Bad | Good | Family |
|---|---|---|
| `git sttaus` | `git status` | `unknown_subcommand` |
| `git --verison` | `git --version` | `unknown_option` |
| `python3 --versoin` | `python3 --version` | `unknown_option` |
| `python3 /tmp/probe/sript.py` | `python3 /tmp/probe/script.py` | `path_not_found` |

`git status` needs a Git repository. Outside one it fails, and then the "correction" never
succeeds and the cycle cannot complete — use `git -C /path/to/a/repo status`, or run the
test inside a repo.

### 3. The anti-superstition check

This is the most important step, because it tests what the plugin **refuses** to do.

1. Run a failing command, e.g. `git sttaus`.
2. Run an unrelated command that succeeds, e.g. `git log -1 --oneline`.

The second command working does **not** make it the correction for the first.

Check `/my-error:review`. The candidate must still be `captured`, with no recovery
recorded, and no lesson may mention `git log`. If a lesson was created linking them, that
is a critical failure — please open an issue with the two commands and your locale.

### 4. Nothing unrelated is affected

Run a normal, valid command. It must not be flagged, and no candidate should appear.

## What "it worked" means

Not that the commands failed. The full chain has to hold:

```
real failure
  → captured
  → corrected command succeeds
  → lesson learned
  → same mistake retried
  → shadow recognizes it would have blocked
  → lets it execute
  → it really fails again
  → predictions_confirmed increases
```

If any link is missing, the interesting question is *which one*. `/my-error:doctor` shows
where the pipeline stopped: no candidate means capture did not fire; a candidate but no
lesson means the correction did not pass the gate; a lesson but no guard match means the
repeated action did not match the stored pattern.

## Cleaning up

Remove any temporary directory you created. To discard what a test taught:

```bash
MY_ERROR=$(ls -d ~/.claude/plugins/cache/*/my-error/*/scripts/my_error.py | tail -1)
```

```bash
python3 "$MY_ERROR" forget ERR-0001
```

`forget` supersedes the lesson and disables its guards; it does not delete history, so the
record of what happened stays auditable.
