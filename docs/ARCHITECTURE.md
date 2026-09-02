# Architecture

A single dependency-free Python script, driven by Claude Code hooks, writing to one SQLite
database, observed by a separate watchdog process.

```
                    ┌──────────────────────────────────────────┐
  PostToolUseFailure│  capture      failure → candidate        │
  PostToolUse       │  verify       candidate + narrow fix     │
  PreToolUse        │  guard        match → record (→ deny)    │──┐
  UserPromptSubmit  │  recall       reviewed lessons → context │  │
  SessionStart      │  recall       high-confidence lessons    │  │
  Stop              │  review       ask once, promote by hand  │  │
  SessionEnd        │  cleanup      expire guards, prune       │  │
                    └──────────────────────────────────────────┘  │
                                       │                          │
                              scripts/my_error.py                 │
                                       │                          │
                    ┌──────────────────▼───────────────────┐      │
                    │ ~/.claude/plugins/data/my-error/     │      │
                    │   my-error.db      (history)         │      │
                    │   runtime.json     (liveness beacon) │◄─────┘
                    └──────────────────┬───────────────────┘
                                       │ reads, never writes
                    ┌──────────────────▼───────────────────┐
                    │ watchdog/my-error-state.cjs          │
                    │ one reader: health, freshness, paths │
                    └────────┬────────────────────┬────────┘
                             │                    │
              ┌──────────────▼───────┐  ┌─────────▼──────────────┐
              │ my-error-watchdog.cjs│  │ my-error-statusline.cjs│
              │ systemMessage, long  │  │ status bar, 4 tokens   │
              └──────────────────────┘  └────────────────────────┘
```

## The pipeline

**Capture.** `PostToolUseFailure` receives `tool_name`, `tool_input`, `error` and
`is_interrupt`. Interrupts and transient failures (timeouts, connection resets, 5xx, rate
limits) are dropped immediately. The rest becomes a *candidate*, keyed by
`(project, tool, exact action, normalized error fingerprint)`, so a repeat increments a
counter instead of creating a row.

**Classify.** The error text is matched against failure families —
`shell_command_not_found`, `npm_missing_script`, `path_not_found`, `unknown_option`,
`unknown_subcommand`, `git_pathspec`. Only these are eligible for automatic learning.
`dependency_or_import`, `test_failure` and `other` are captured but never auto-promoted.

Patterns exist for English, Portuguese, Spanish, French, German and Italian, because
messages follow the machine locale. In any other locale a fallback applies: if the failure
output literally names the single token the correction changed, that is language-independent
evidence. It is gated to unrecognized locales only — where explicit patterns already work,
the heuristic adds false-positive surface for no measured gain.

**Verify.** On the next successful `Bash` call in the same session and within 15 minutes,
candidates are checked. Auto-promotion requires **exactly one differing shell token**, that
token to be similar to its replacement (≥ 0.70), and overall command similarity ≥ 0.75.
Anything looser stays a candidate. This is what rejects an unrelated nearby success.

**Guard.** `PreToolUse` compares the attempted action against active guard patterns, both
raw and redacted (patterns are stored redacted, so a command carrying a credential would
otherwise never match its own pattern). A match is always recorded. Whether it *blocks*
depends on the mode.

**Score.** In SHADOW the command runs, and the next failure or success for that same action
resolves the recorded event to `true_positive` or `false_positive`. This is the only way to
measure a false positive: blocking destroys the counterfactual.

**Recall.** `UserPromptSubmit` scores lessons against the prompt using token overlap plus a
small, dependency-free concept expansion. Selection is explicit — active, human-reviewed
source, confidence, recency — and automatically learned lessons are excluded: "do not run
`git sttaus`" is useless as context and already covered by its guard. Lessons unused for 90
days leave automatic recall but stay stored and listed by `review`.

## Storage

One canonical directory: `~/.claude/plugins/data/my-error/`.

`${CLAUDE_PLUGIN_DATA}` — the officially injected value — is deliberately **not** the
storage location, for two reasons found the hard way:

1. It reaches hook processes only. A skill runs as a plain command and never receives it,
   so every user-facing command resolved elsewhere. `doctor` reported an empty database
   while the hooks accumulated history, and `learn` would have written lessons the hooks
   could never read.
2. It is not stable. Claude Code derives it from the plugin id, which encodes the *load
   method* — `my-error@inline` for `--plugin-dir`, `my-error@<marketplace>` when installed.
   That had already produced two directories on one machine.

`data_dir()` in `scripts/my_error.py` is the only implementation. The watchdog calls
`my_error.py datadir` rather than reimplementing it, because a second copy would drift and
recreate the split. The injected value is still consulted, but only to *discover* a legacy
database to adopt. Two populated legacy databases are reported by `doctor`, never merged —
choosing one silently would discard the other's lessons.

### Project identity

Inside a Git repository, `git rev-parse --git-common-dir`; otherwise the absolute path.
The common directory, not `--show-toplevel`: the latter is the *worktree* root and differs
for every linked worktree, so it would split one repository's history across every branch
checked out beside it.

Known limit: moving or renaming a whole repository changes this path and orphans its
lessons. Surviving that needs a marker stored inside the repository.

### Safety

Command and error text is capped and redacted (API keys, bearer tokens, passwords, AWS
keys, `sk-`/`gh*_` tokens) before anything is written. The plugin root is treated as
read-only; nothing is written next to the code.

## Modes

`SHADOW` is the default and blocks nothing. It also emits nothing to the model — a warning
would change the behaviour being measured. `ENFORCE` denies the tool call via
`permissionDecision: "deny"`.

The experiment's decision rule lives in `shadow_verdict()` beside constants marked
`DO NOT EDIT BEFORE 2026-09-17`, so a result cannot retroactively rewrite the criterion.

## The watchdog

A plugin cannot credibly monitor itself: if it stops loading, its own hooks stop with it
and its silence is indistinguishable from health. So the plugin only emits evidence — a
beacon written after every hook, carrying version, mode, session, database mtime and
per-project metrics — and a separate process judges it.

The watchdog caches structural facts (installed, enabled, scope, hooks registered, resolved
data dir) for five minutes, invalidated by the mtime of the config files. Liveness and
freshness are never cached: it stats the database every time, and compares the beacon's
recorded mtime against the real one, reporting **stale metrics** rather than trusting them.
An unreadable database reports unavailable; it never degrades to zeros.

Cost is roughly 37 ms per prompt.

## The status line segment

`systemMessage` is not a persistent surface in every build of Claude Code, and observability
that is only shown once is not observability. The status bar is the surface the user keeps
looking at, so `watchdog/my-error-statusline.cjs` puts four tokens there.

It is a **wrapper**, not a replacement, because Claude Code runs exactly one `statusLine`
command and that command usually already belongs to something else — often a file its own
framework regenerates, where an edit survives until the next `init` and then vanishes with no
error. The existing command is run as a child with the same stdin, its stdout is taken
verbatim, and the segment is appended (on its own line if that output is multi-line, so a
long bar is not pushed past the terminal width).

**Survival is the design constraint.** Every combination was tested: both healthy, plugin
broken, wrapped bar broken, shared module missing, malformed stdin, empty stdin. The wrapped
bar's output is never withheld because of anything that happens in the segment, and a
failing bar that still wrote something has that partial output shown rather than discarded.

**It never spawns a process.** A status line redraws constantly, so it asks the shared module
for the no-spawn answer: the watchdog's cached data directory if there is one, otherwise the
canonical path — flagged as a guess so the segment can report degraded rather than assert a
location it did not verify. Measured cost: p50 0.19 ms, p95 0.38 ms in process.

**Responsibilities do not mix.** `statusLine` is persistent information for the *user*;
`additionalContext` is information for *Claude*; `systemMessage` is complementary, shown if
the surface chooses to. The long watchdog line stays where it was.

### The invocation beacon

Running the script by hand proves nothing about an editor that is already running — the
mistake recorded as ERR-0016. So each run stamps `~/.claude/watchdogs/.my-error-statusline.json`
(throttled to one write per five seconds) with the pid, the session, the segment, the runtime
and installed versions, and the measured cost. That file is the only evidence that the live
bar — not a shell — is executing this code.

### Hook timeouts are seconds

`"timeout": 10` means ten seconds. `10000` means nearly three hours, which is indistinguishable
from a hook that never returns. The installer once printed the millisecond form; two tests now
fail if either the manifest or the snippet drifts back into it.

## CLI

Every skill is a thin wrapper around the script. `MY_ERROR` is the installed path, printed
by `/my-error:doctor`:

```bash
MY_ERROR=$(ls -d ~/.claude/plugins/cache/*/my-error/*/scripts/my_error.py | tail -1)
```

| Command | Purpose |
|---|---|
| `doctor [--json]` | Full health report |
| `status` | Compact counts |
| `review [--limit N]` | Candidates and lessons |
| `metrics [--compact]` | Machine-readable counters |
| `datadir [--compact]` | The canonical resolution |
| `mode [--set SHADOW\|ENFORCE]` | Read or set the mode |
| `learn --title … --cause … --rule …` | Record a reviewed lesson, optionally with a guard |
| `forget ERR-nnnn` | Supersede a lesson, disable its guards |
| `ignore CAND-nnnn` | Dismiss a candidate |
| `hook <kind>` | Hook entry point; reads the event as JSON on stdin |

### Environment variables

| Variable | Effect |
|---|---|
| `MY_ERROR_DATA_DIR` | Override the storage directory. Used by the test suite. |
| `MY_ERROR_MODE` | Override the stored mode for one invocation. |
| `MY_ERROR_DEBUG` | Legacy: swallowed hook errors go to stderr unconditionally since 0.4.3. |
| `MY_ERROR_STATUSLINE_TRACE` | Where the status line writes its invocation beacon. Tests and benchmarks MUST set it. |
| `MY_ERROR_HEALTH_CACHE` | Where the shared health cache lives. Tests and benchmarks MUST set it. |
| `MY_ERROR_WRAP_COMMAND` | Watchdog only: an existing hook command to run and merge. |

## Releasing

**A published version is immutable.** Once a version number exists anywhere outside the
working tree — installed, tagged, pushed, or sitting in the plugin cache — the code that
carries that number is frozen. Any further change that will be distributed requires a new
number.

Not this:

```
0.4.3  (commit A)  →  0.4.3  (commit B)
```

This:

```
0.4.3  (commit A)  →  0.4.4  (commit B)
```

The reason is mechanical, not ceremonial. The updater is **version-gated**: it compares the
installed version against the marketplace version and skips when they match. Re-cutting the
same number therefore produces a state that cannot be detected from the outside —

```
updater says "latest"   ≠   the code is latest
```

— and the live runtime keeps executing the old bytes while every version indicator agrees
that it should not. That is the ERR-0016 failure with the evidence trail removed: the beacon
in `runtime.json` reports `0.4.3` and is telling the truth, but `0.4.3` no longer identifies
a single body of code. Nothing in the system can then answer the question this plugin exists
to answer — *is the fix actually running?*

The bump is part of the delivery, not paperwork after it. Concretely, one distributed change
means all of: `.claude-plugin/plugin.json` version bumped, `CHANGELOG.md` entry, commit, and
reinstall — then confirm the live instance by its own declaration (`runtime.json`, or the
`--plugin-dir` of the running process), never by a fresh CLI invocation.

The only edits that may keep a version number are ones that never leave the working tree.

## Failure containment

A hook must never break the session it observes. Any internal error — locked database,
read-only directory, malformed event — is swallowed: no output, exit 0, the tool call
proceeds untouched. Since 0.4.3 the swallow is never silent: the reason goes to stderr and
the occurrence is counted in `meta.dropped_events`, which `/my-error:doctor` reports. That
counter exists because a silent swallow is what turned a schema-upgrade race into invisible
capture loss -- hooks reported success while their events disappeared.

## Schema

`projects`, `candidates`, `lessons`, `guards`, `guard_events`, `meta`. Migrations are
forward-only and idempotent, tracked by `PRAGMA user_version` (currently 4). WAL is enabled
once, not on every connect — issuing `PRAGMA journal_mode` repeatedly caused lost writes,
because it needs an exclusive lock and does not honour `busy_timeout`.
