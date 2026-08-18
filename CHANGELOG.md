# Changelog

## Unreleased — observability + SHADOW mode

Positioning change: this is now an **experimental** plugin whose auto-guard is on a
30-day probation. Version number is still `1.2.0` pending the renumbering decision.

### Added

- **SHADOW mode, now the default.** Guards record what they *would* have blocked and
  let the command run. An enforcing guard destroys its own counterfactual: you cannot
  tell "never repeated" from "we blocked it". Shadow can. `mode --set ENFORCE` switches.
- **Shadow scoring.** When a shadow guard lets a command through, the outcome is scored:
  it failed again (`predictions_confirmed`) or it succeeded (`predictions_refuted` — a
  *measured* false positive, not an estimated one). This is what the 30-day experiment
  reads.
- `guard_events` table (schema v2, forward-only migration) recording every guard match
  with its mode and outcome.
- **Liveness beacon** (`runtime.json`) written after every hook, carrying mode, session,
  database mtime and per-project metrics. The plugin only emits evidence; an external
  watchdog judges it.
- `metrics [--compact]` and `mode [--set]` commands; `doctor` rewritten as a full report
  (`--json` for machines) covering hooks, beacon, locale recognition, mode and metrics.
- `skills/doctor` — `/my-error:doctor`.

### Fixed

- `connect()` rewrote `meta.schema_version` on every open, and `ensure_project` rewrote
  `last_seen` on every open. Every read-only command was therefore a write, which
  amplified lock contention and made it impossible for an observer to distinguish a real
  mutation from a routine open. Both are now conditional.

## 1.2.0 - 2026-08-18

Correctness and portability release. All three benchmarks now reach 100% on a
non-English host; v1.1.0 measured 70% there.

### Fixed

- **Locale-dependent failure recognition.** Every family regex was English-only, so on
  any host whose `LANG` is not English (e.g. `pt_BR.UTF-8`) most deterministic failures
  classified as `other` and were never auto-learned. Measured on a pt_BR machine:
  held-out 23/33 (69.7%), fuzz 21/30 (70%). Added pt/es/fr/de/it patterns for
  command-not-found, path-not-found, unknown-option, unknown-subcommand, git-pathspec,
  missing-module, and transient failures.
- **Secret redaction corrupted shell quoting.** `api_key=...` matched `[^\s]+`, which
  swallowed the closing quote. The stored command became unparseable by `shlex`, so
  `narrow_command_correction` returned `False` and *no* command containing a credential
  could ever be learned. The value class now excludes quotes.
- **Guards never matched a command containing a secret.** Patterns are stored redacted
  but `PreToolUse` compared against the raw command. Guard matching now tries both forms.
- **A failed `PostToolUse` could be read as a recovery.** Now short-circuits when
  `tool_response` reports an error.
- `dns` in the transient list matched any substring (e.g. a path containing `dnsmasq`);
  it is now `\bdns\b`.
- `ignore` raised an uncaught `ValueError` on a malformed id instead of exiting 2.
- **Concurrent hooks could lose a capture.** `ensure_project` did SELECT-then-INSERT, so two
  hooks firing at once (parallel tool calls, subagents) both saw an absent row, both inserted,
  and one lost its entire event to `UNIQUE constraint failed: projects.id`. Reproduced in
  ~30% of 8-way concurrent runs. Now an idempotent upsert, with bounded retry on lock
  contention around schema bootstrap and candidate upsert. `journal_mode=WAL` is also set
  unconditionally, so a database created by a racing process is not left in rollback-journal
  mode. Hook timeouts split: 5s for the latency-sensitive path (guard, prompt, session start),
  10s for the write-heavy background path.

### Added

- **Locale-independent auto-learning fallback.** When the message text is in an
  unrecognized language, a correction is still learned if the failure output literally
  names the single shell token that the correction changed — true in every locale,
  because the offending token is echoed verbatim. Stack-trace frames (`at …`, `File "…"`)
  are excluded, and `dependency_or_import` is excluded because it already has a stricter
  purpose-built gate, so the anti-superstition guarantee is preserved.
- **Hooks can no longer break a session.** Any internal failure (locked or corrupt DB,
  read-only data directory, malformed event) is swallowed: no output, exit 0, the tool
  call proceeds untouched. Set `MY_ERROR_DEBUG=1` to surface them.
- `doctor` reports the active locale and supported families.
- Recall query capped at 500 lessons.
- 7 new regression tests (27 total) covering localized messages, the fallback,
  stack-frame rejection, secret-bearing guards, failed-response rejection, hook
  crash-safety, and malformed ids.

## 1.1.0 - 2026-08-18

- Expanded deterministic error recognition for Node/Python missing entrypoints/modules, Pytest file/path errors, unknown options, shell command-not-found variants, and Git/npm unknown subcommands.
- Added evidence-aware missing-target checks so internal dependency failures are not mistaken for entrypoint typos.
- Added lightweight semantic concept expansion for more reliable lesson recall across different wording.
- Switched hook commands that use `${CLAUDE_PLUGIN_ROOT}` to exec-form `command` + `args`, following current Claude Code hook guidance.
- Added a 36-case independent live held-out A/B benchmark: 36/36 learned and blocked, 10/10 semantic top-1 recall, 0 false blocks, 0 false lessons.
- Added generated typo fuzz benchmark: 30/30 learned and blocked, 0 false blocks.
- Expanded regression suite to 20 tests.

## 1.0.0 - 2026-08-18

- Evidence-gated candidate capture.
- Automatic verified Bash correction learning for narrow deterministic failure families.
- Project-scoped SQLite persistence in `CLAUDE_PLUGIN_DATA`.
- Prompt/session recall of relevant lessons.
- `PreToolUse` deterministic guards.
- Secret redaction, transient-failure filtering, lesson supersession, and guard expiry.
- Stop-time review request for recovered semantic/test failures.
- Status, review, learn, workflow, and forget skills.
- Unit/integration tests and deterministic A/B benchmark.
