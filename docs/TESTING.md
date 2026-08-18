# Testing my-error

Two kinds of verification: the automated suite, which you can run without installing
anything, and a live protocol that exercises the real hook pipeline inside Claude Code.

## Automated

```bash
python3 -m unittest discover -s tests -v
```

53 tests, no third-party dependencies. They cover the learning gate, secret redaction,
project isolation, guard expiry, concurrency, locale handling, shadow scoring, storage
resolution, and the anti-superstition rules.

```bash
python3 benchmarks/ab_benchmark.py && python3 benchmarks/heldout_live_benchmark.py && python3 benchmarks/fuzz_live_benchmark.py
```

The last two run **real commands** in a temporary project and measure whether a verified
correction prevents an exact recurrence. Each exits non-zero if it does not reach 100%.
Results and their limits: [TEST_REPORT.md](TEST_REPORT.md).

The benchmarks set `MY_ERROR_MODE=ENFORCE` explicitly, because they measure blocking and
the product default blocks nothing.

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
