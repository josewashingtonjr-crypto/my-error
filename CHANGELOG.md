# Changelog

## 0.4.1 — a CLI-recorded lesson names its repository

`learn` runs without a hook payload, and identity resolution still let
`CLAUDE_PROJECT_DIR` win in that branch — so a lesson written while working inside a
repository recorded the *workspace* as its origin. The same defect 0.4.0 fixed for the hook
path, one level down, landing on exactly the field that makes "learned in one project, used
in another" answerable. Found by running the real cross-project proof, not by review.

A version bump is required to reach the installed plugin at all: `claude plugin update` is
gated on the version string, so a same-version code change never leaves the repository.

## 0.4.0 — knowledge that travels between projects

`0.4.0` rather than `0.3.4`: `learn --scope` is now **required**, which breaks every existing
invocation that relied on the default, there is a new `scope` command, a schema migration to
v4, and project identity resolves differently. In 0.x the minor is where a break belongs.

### The defect this fixes

Two of them, and they compounded.

**Project identity followed the session, not the work.** `canonical_root()` preferred
`CLAUDE_PROJECT_DIR`, which Claude Code sets to the directory the session was launched from
and never changes. Measured with a live hook trace on 2026-09-02: session at `/home/w-jr`,
Bash tool operating inside `/home/w-jr/PoolBet`, env var reading `/home/w-jr` and
`event["cwd"]` reading `/home/w-jr/PoolBet`. Every repository under the home directory was
therefore filed into a single namespace named "home" — three unrelated projects sharing one
lesson store. That resembles cross-project transfer and is its opposite: it is the absence of
separation, and it collapses the moment a session is opened inside one of those repositories.

**Scope defaulted to `project` in silence.** A rule that generalises — "a caught query error
still aborts a Postgres transaction" — was recorded reachable from one repository unless
somebody remembered a flag. ERR-0012, a general observability principle, was stranded that
way and nobody would have noticed for months.

### Added

- **`my_error.py scope <ERR-id> <project|global> [--reason]`.** Moves a lesson in place:
  id, title, cause, rule, confidence, source, origin, provenance, `created_at` and
  `use_count` all survive, and the change is written to a new `lesson_scope_changes` audit
  table with old scope, new scope, timestamp and reason. The alternatives were rejected as
  lossy — a direct `UPDATE` leaves no trace that a rule's reach was widened, and
  `forget` + `learn` mints a new id, discarding the evidence that the lesson has been
  earning its place.
- **`lessons.origin_project_id`** — provenance, separate from scope. Where a lesson was
  *learned* is not where it may be *used*, and promotion to global must not erase the
  birthplace. This is what makes "we paid for this in Fidren and it came back in Livara"
  answerable.
- **`recall_events`** — one row per recall, carrying lesson scope, origin project, consuming
  project and a recorded `cross_project` flag.
- **Knowledge-transfer metrics**, reported by `doctor` in their own section, deliberately
  apart from every guard number: active global vs project lessons, recalls by scope,
  cross-project recalls, and the learned-in → used-in pairs. `recalled` means placed in
  front of the agent; nothing here claims it helped.
- **`projects.kind`** — `git`, `directory` or `workspace`. A home directory holding several
  repositories is not a project, and is now labelled rather than silently treated as one.

### Changed

- **Project identity prefers `event["cwd"]`**, then `CLAUDE_PROJECT_DIR`, then the process
  directory — evidence first, the session's opinion second. Linked worktrees still share one
  identity through `git --git-common-dir`, unchanged.
- **`learn --scope` is required.** No default, with `--scope-reason` available to record why.

### Unchanged

The SHADOW experiment is untouched: `SHADOW_EXPERIMENT_DAYS`, `SHADOW_PROMOTE_THRESHOLD`,
the pre-committed decision rule, guard criteria, command families, prediction classification
and the `controlled_test`/`natural_usage` split are all exactly as frozen on 2026-08-18. The
17/09 verdict judges the deterministic auto-guard and nothing else — which is why the
transfer metrics above are reported separately rather than folded in beside it.

### Tests

75 (9 new), nine of them verified failing against 0.3.3. Benchmarks re-run: prevention rate
1.0, zero false blocks.

## 0.3.3 — an error is a verified mistake, not a non-zero exit code

A doctrine fix. The plugin's own workflow skill defined its scope as "**only** verified
operational failures — a command or tool action that failed", and routed everything else to
the host's project memory on the grounds that design lessons are not falsifiable. That was
wrong, and wrong in the expensive direction: it excluded exactly the logic, architecture and
judgment mistakes worth remembering longest. Many of them *are* falsifiable — "a `.catch()`
around a query inside one Postgres transaction does not prevent the abort" is checkable in
thirty seconds — they simply never produce an exit code.

Because that text is loaded into context whenever the skill is used, the written doctrine
beat every session-level instruction to the contrary. A lesson recorded by hand outside the
command path depended on an agent noticing that `--candidate-id` happens to be optional.

### Changed

- **Learning boundary rewritten** (`skills/workflow/SKILL.md`). A lesson may come from a
  failed command, a logic defect, a design error, a false assumption, bad task sizing, an
  unsafe judgment, a repeated inefficiency, or inexperience. Four admission criteria replace
  the exit-code test: something went wrong or would reproducibly go wrong; the mechanism is
  understood; the rule is falsifiable; remembering it prevents recurrence. Preferences,
  hunches, unverified speculation and bare project state are rejected as before.
- **Memory boundary redrawn by kind of claim**, not by how the mistake was found: my-error
  keeps the reusable prevention rule, project memory keeps what happened. Both may reference
  one incident from their own side; neither copies the other. A worked example is included.
- **`skills/learn`** documents the no-candidate path as first class instead of leaving it as
  an undocumented property of the CLI.
- **README** no longer opens by defining the plugin as the failed-command pair.

### Added

- **Reflection prompt at `Stop`.** Once per session, when no candidate carries recovery
  evidence, my-error asks whether anything went wrong for a reason that was *not* a failed
  command. Capture fires on exit codes, so the class of mistake this plugin most wants has
  no trigger at all; this is that trigger. It only asks — it never creates a lesson, the
  quality gate still decides, and a session that was already sent to `learn` for a candidate
  does not also get asked.
- Five tests, including two verified failing against the previous code.

### Unchanged

The SHADOW experiment is untouched: `SHADOW_EXPERIMENT_DAYS`, `SHADOW_PROMOTE_THRESHOLD`,
the pre-committed decision rule, `AUTO_LESSON_SOURCES` and the automatic guard path are all
exactly as frozen on 2026-08-18. This release changes what a human-reviewed lesson may be
about; it changes nothing the experiment measures.

## 0.3.2 — separate controlled_test from natural_usage (methodology fix)

A methodology correction, not a feature. The 6 `predictions_confirmed` on record so far were
produced by deliberately triggering `error → correction → repeat` to prove the pipeline
works — valid as a functional test, invalid as evidence for the 30-day SHADOW decision, which
asks a different question: *in unprompted use, how often does Claude try to repeat an
already-learned mistake?* Mixing the two would have let a hand-run test decide an experiment
about spontaneous behaviour.

### Added

- **`origin` column** on `candidates`, `lessons`, `guards`, `guard_events`: `natural_usage`
  (default) or `controlled_test`. See [METRICS.md](docs/METRICS.md#origin-controlled_test-vs-natural_usage)
  for exactly how it is set and propagated.
- **`MY_ERROR_EVENT_ORIGIN=controlled_test`** — the explicit, temporary marker for a
  deliberate test. Without it, every new event is `natural_usage`; nobody has to remember to
  flag ordinary use, only the rare intentional test. `learn --origin` overrides it manually.
- **`shadow_verdict_confirmed` / `shadow_verdict_refuted` / `shadow_verdict_pending` /
  `natural_would_block`** — `natural_usage`-only counters. `shadow_verdict()` now reads
  exactly these three (confirmed/refuted/day), never the combined totals. The pre-committed
  rule itself — threshold 3, 30 days, REMOVE/PROMOTE/EXTEND conditions, start date, decision
  date — is unchanged.
- **`controlled_confirmed` / `controlled_refuted` / `controlled_pending` /
  `controlled_would_block`** — `controlled_test`-only counters, kept as the auditable record
  that the pipeline works. Never read by `shadow_verdict()`.
- `/my-error:doctor` now prints a "Shadow experiment" section with `Natural usage:`,
  `Controlled tests:` and `Verdict dataset: NATURAL USAGE ONLY` shown separately, plus the
  origin-migration backfill timestamp when one occurred.

### Changed

- **Schema v3.** `predictions_confirmed` / `predictions_refuted` / `predictions_pending` were
  renamed `predictions_confirmed_total` / `predictions_refuted_total` /
  `predictions_pending_total` — they still mean "both populations combined" but the old names
  invited exactly the misreading this release exists to prevent.
- **Migration backfill.** Every `candidates` / `lessons` / `guards` / `guard_events` row that
  existed before schema v3 is stamped `origin='controlled_test'` in one explicit, auditable
  statement (timestamped in `meta.origin_migration_backfilled_at`) — not deleted, not reset.
  That data was produced while developing and testing my-error itself, so the natural-usage
  experiment now starts at a true, measured zero instead of an inherited six.

### Not changed

Threshold (3), experiment length (30 days), start date, decision date, the REMOVE / PROMOTE /
EXTEND classification rules, failure families, locale handling, and every other frozen
experiment parameter. This release only separates the population the rule is applied to.

## 0.3.1 — split-brain database (bugfix)

Two defects found by using the plugin, not by reading it. No experiment parameter,
learning criterion, guard rule, error family, heuristic, locale behaviour or recorded
metric was touched.

### Fixed

- **The plugin kept two databases and the readable one was not the written one.**
  `${CLAUDE_PLUGIN_DATA}` is injected into hook processes only, so every skill and CLI
  command — `doctor`, `status`, `review`, `learn`, `forget` — fell through to a different
  path. `/my-error:doctor` reported an empty database while the hooks accumulated history
  elsewhere, and `/my-error:learn` would have written lessons the hooks could never read.

  The injected value is also **not stable**: Claude Code derives the directory from the
  plugin id, which encodes the *load method* (`my-error@inline` for `--plugin-dir`,
  `my-error@<marketplace>` when installed). On the machine where this was found it had
  already produced two directories with the history in one and nothing in the other.

  Storage is now a fixed canonical directory that no load method can perturb, resolved by
  one function that hooks, skills, CLI and the external watchdog all call. The injected
  value is used only to *discover* legacy data to adopt. Adoption moves a single populated
  legacy database; it never merges two, because choosing one silently would discard the
  other's lessons — that case is reported by `doctor` instead.

- **Concurrent hooks lost captures (~20% of 8-way runs).** `PRAGMA journal_mode=WAL` was
  issued on every connect. That PRAGMA needs a brief exclusive lock and, unlike ordinary
  statements, does **not** honour `busy_timeout` — it returns `SQLITE_BUSY` immediately.
  A hook could therefore lose its entire event to a lock it was never given a chance to
  wait for. It is now set only when the file is not already in WAL. Separately, the retry
  helper did not roll back before retrying, so a retry re-entered a still-open failed
  transaction; it now rolls back and applies jitter. Measured after: 0 losses in 60 runs.

### Added

- `datadir` command exposing the canonical resolution, so the watchdog consumes it instead
  of reimplementing it.
- `doctor` now prints the resolved database path, its readability, whether an injected
  path was present and whether it matched, and any populated legacy database left alone.
- Regression tests A–F reproducing the defect: hook context, skill context, cross-visible
  hook writes, cross-visible manual lessons, reads from another project, and proof that no
  normal operation recreates the old fallback. Plus adoption and refuse-to-merge tests.

## 0.3.0 — experimental repositioning

Renumbered from 1.2.0 to 0.x on purpose: the automatic guard is on a 30-day probation
and may be removed, so a 1.x stability promise would be false.

### Added

- **SHADOW mode, now the default.** Guards record what they would have blocked and let the
  command run, emitting nothing to the model — an instrument that warns changes the
  behaviour it measures. Shadow then scores its own prediction against the real outcome:
  `predictions_confirmed` (failed again) vs `predictions_refuted` (**succeeded** — a
  measured false positive). An enforcing guard cannot produce this evidence.
- **Pre-committed decision rule in code**, fixed before any data existed:
  `confirmed == 0` or `refuted > confirmed` → remove the auto-guard; `confirmed >= 3` with
  no false positives → promote to ENFORCE; otherwise extend. `doctor` computes the verdict
  and refuses to state one before day 30.
- **External liveness beacon** so a watchdog outside the plugin can judge whether it is
  running. A plugin that monitors itself reports silence when it fails.
- `metrics`, `mode`, and a full `doctor` report (`--json` for machines).

### Changed

- **Heuristic fallback gated to unrecognized locales.** In the six covered languages the
  explicit patterns already reach 100% on both live benchmarks, so the heuristic there was
  false-positive surface for no measurable gain. Elsewhere it is the difference between
  learning and doing nothing. `doctor` reports `Fallback active` either way, so it never
  degrades silently.
- **Project identity is the Git common directory**, not the filesystem path.
  `--show-toplevel` is the *worktree* root and differs per linked worktree, which would
  split one repository's lessons across every branch checked out beside it.
  `--git-common-dir` resolves to the same shared area from every worktree. Outside a
  repository the absolute path is still used. Known limit: moving the whole repository
  still orphans its lessons.
- **Prompt recall excludes automatically learned lessons.** "Do not run `git sttaus`" is
  useless as context and already covered by its guard. Auto lessons feed prediction;
  reviewed lessons feed context.
- **Recall selection is explicit** — status, source, confidence, recency — and the row
  limit is a ceiling against a pathological table, not the retention policy it had
  silently become. Lessons unused for 90 days leave automatic recall but stay stored,
  stay listed by `review`, and return on first use. `use_count`/`last_used` were written
  and never read; now they decide.

### Fixed

- Every read-only command was a write: `schema_version`, `last_seen`, and the experiment
  stamp were rewritten on each open. This amplified lock contention and made a real
  mutation indistinguishable from a routine open.
- Benchmarks inserted lessons with invented `source` values, exercising a path the product
  does not have.

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
