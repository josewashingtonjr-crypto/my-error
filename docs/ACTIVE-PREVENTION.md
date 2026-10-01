# Active Prevention — design spec (0.6.0)

Status: DESIGN. Nothing here is authorized for the live installation.
Branch: `feat/active-prevention`. Experimental freeze respected: the WARN channel
and every new guard ship **off by default**, so the SHADOW v3 baseline keeps
measuring the same system it measured yesterday.

## 0. What the audit found

Measured on 2026-10-01 against a copy of the live DB (`schema_version` 5→6,
20 active lessons, 189 recall deliveries):

| Fact | Evidence |
|---|---|
| Nothing has ever been blocked | `guards` table empty: 0 rows, 0 hits, `guard_events` 0 |
| SHADOW suppresses even the warning | `run_guard` returns `None` before building any output when `mode == MODE_SHADOW` (`scripts/my_error.py:2025`) |
| Recall is anchored to the user's prompt | `_dispatch_hook` calls `recall()` only with `event["prompt"]`; the `guard` branch runs `run_guard` alone |
| Prevention metrics read as healthy while unmeasurable | `recall-audit` prints `MISSED_RELEVANT_RECALL: 0` and `would_block: 0` with zero guards — structurally impossible to be anything else |
| Hook timeout is a units bug | `~/.claude/settings.json` `UserPromptSubmit.timeout = 10000`; contract is seconds (`install-watchdog.sh` warns explicitly) |
| Running the CLI mutates the experiment | `mode`/`metrics` opened the live DB and advanced `shadow_v3_started_at` to today |

### The structural finding

`recall()` is **already generic** — it scores an arbitrary `query` string against
the lesson pool. It is not prompt-coupled by design, only by call site. So
context-aware recall is a new *call*, not a new engine.

The real gap is on the guard side: the model is `(tool, field, pattern)` and
**cannot express the lessons we most want enforced**. Proof, from the real
candidate rows that produced the lessons:

- **ERR-0017** (`rtk git log` with no `-C`, failed `not a git repository`).
  A pattern matching bare `git` would also match every legitimate `git status`
  run from inside a repo. The deciding fact is not in the command — it is
  whether `cwd` is a git repo. Pattern-only enforcement here is a false-positive
  factory.
- **ERR-0001** (`os.path.getpid`). The literal sits inside a `<<'PYTHON'`
  heredoc, so `shell_cmd` match type deliberately will **not** fire (it masks
  heredoc data). Must be `regex`. But then `grep -n "os.path.getpid" f.py` —
  a legitimate operation — also matches.

Both need something the schema does not have: a **context predicate** and an
**exception pattern**. That is the core of this change.

## 1. Lesson classification

| Class | Meaning | Gate |
|---|---|---|
| `BLOCKABLE` | Deterministic violation; a correct exception set exists | may reach DENY |
| `WARNABLE` | Depends on context or judgment | WARN only, never DENY |
| `INFORMATIONAL` | Procedural reference; no action trigger | contextual recall only |

Assigned from the real `bad_action`/`error_excerpt` rows, not from rule prose:

- **BLOCKABLE**: ERR-0001 (`os.path.getpid`, argparse/AttributeError, no legitimate
  call site), ERR-0003 (`--candidate-id CAND-`, argparse exit 2).
- **BLOCKABLE only with a context predicate**: ERR-0017 (bare `git` **and**
  `cwd_not_git_repo`).
- **WARNABLE**: ERR-0002, 0004, 0006, 0008, 0009, 0012, 0014, 0015, 0016,
  0018, 0019, 0020.
- **INFORMATIONAL**: ERR-0005, 0007, 0010, 0011, 0013 (long recipes — recall
  them contextually, never gate on them).

Classification is stored, reviewable and reversible. No free-text rule is ever
auto-converted into a blocking regex.

## 2. Schema additions (v7) — additive only

New nullable columns on `guards`; no table rewritten, no row rewritten, no
lesson or history lost.

| Column | Purpose |
|---|---|
| `severity` | `warn` \| `deny`. Default `warn`. Decouples "matched" from "blocked". |
| `condition` | Optional named predicate, ANDed with the pattern. Closed registry, never `eval`. |
| `exceptions` | Optional regex; if it matches the action, the guard is suppressed and the suppression is recorded. |

New column on `lessons`: `prevention_class` (`BLOCKABLE`/`WARNABLE`/`INFORMATIONAL`,
default `WARNABLE`).

### Condition registry (closed set)

| Name | True when |
|---|---|
| `cwd_not_git_repo` | no `.git` found from the event's `cwd` upward |
| `path_missing` | a path parsed out of the action does not exist on disk |
| `path_exists` | …exists |
| `always` | unconditional (equivalent to today's behaviour) |

Unknown condition name ⇒ guard treated as inert and reported by `doctor`,
never silently ignored, never fail-open into a block.

## 3. Execution gate

Recall and the block decision become separate stages:

```
PreToolUse
  ├─ stage A: contextual recall  → additionalContext (never denies)
  └─ stage B: guard evaluation   → WARN (context) | DENY (deny only)
```

- `severity=warn` never denies, in any mode.
- `severity=deny` denies only when `mode == ENFORCE` **and** the guard is
  explicitly authorized. No global switch flips every guard to blocking.
- A DENY must name the lesson, state the violation and give the correction.
- A DENY is recorded; a retry of the same action in the same session is recorded
  as `recurrence_after_deny`, so silently working around a block is visible.

## 4. Contextual recall at PreToolUse

New phase value `pretooluse`, counted as **before the action**.

Query built from `tool_name`, `extract_action(tool_name, tool_input)` (already
redacts secrets), `cwd`, and file paths parsed from the action.

PreToolUse fires on every Bash/Write/Edit, so the bar is strict — this is a
noise budget, not a ranking tweak:

- at most 2 lessons per injection;
- a lesson already delivered in this session is skipped (`lesson_seen_in_session`);
- `INFORMATIONAL` lessons are eligible for recall, `BLOCKABLE`/`WARNABLE` too,
  but a minimum relevance floor applies (exact-token overlap ≥ 2, or a tag hit);
- no LLM call, no network, no subprocess on the critical path.

## 5. Metrics — distinguishable, with denominators

Separate counters: `lesson_registered`, `recall_candidate`, `recall_delivered`,
`guard_matched`, `would_block`, `actually_blocked`, `recurrence_detected`,
`false_positive`, `suppressed_by_exception`.

**Hard rule:** when `guards_active == 0`, every prevention metric reports
`NOT_MEASURABLE` with the reason, never `0`. A zero that is structurally
impossible must never render as success. Same for `missed_relevant_recall`,
whose detector *is* the guard set.

## 6. Learning loop

Recurrence detection no longer depends on a guard having matched: a new failure
whose fingerprint equals an earlier candidate already promoted to a lesson is
`recurrence_detected` even if no guard and no recall existed. The report then
attributes it to exactly one of: recall failure, guard failure, classification
failure, or not-mechanically-verifiable.

## 7. Limits — stated, not discovered later

- A regex guard prevents **literal operational recurrence**. It does not prevent
  a judgment error. Guessing a file's location is not representable as a pattern;
  the only lever there is the `path_missing` checkpoint, which is partial.
- `INFORMATIONAL` lessons are not prevention and are not counted as such.
- Green tests and non-zero counters are not evidence of preventive efficacy.
  Efficacy requires a controlled recurrence blocked before execution, and that
  claim is made only from `actually_blocked` with `causal_outcome=confirmed`.

## 8. Mandatory review criteria (added 2026-10-01, by the user)

These are acceptance requirements, not advisory. Four of them change the
implementation; one of them corrects a flaw in section 2 of this document.

### 8.1 Observation must not mutate

`metrics`, `status`, `doctor`, `recall-audit`, `review`, `datadir`, and `mode`
without `--set` are strictly read-only: no migration, no experiment creation,
no experiment rotation, no state-advancing beacon write.

This is a present, demonstrated bug and not a hypothetical. Running
`my_error.py metrics` from the 0.5.0 repo against the live database closed
SHADOW v2 and opened v3 as a side effect of being *looked at*. A read-only
command meeting a database newer or older than its own `SCHEMA_VERSION` must
report that and degrade, never migrate.

### 8.2 An unverifiable condition can never deny

A condition predicate has three outcomes, not two: true, false, `unverifiable`.
`unverifiable` covers a missing or unreadable `cwd`, an `OSError` from a path
check, a permission error, and an unknown condition name. On `unverifiable` the
guard must neither deny nor silently pass as "no match": the state is recorded
explicitly and auditably, and `doctor` reports it. Invariant under test: no code
path converts an unevaluated condition into a block.

### 8.3 Exception precedence, and the bypass hole in section 2

Precedence is explicit: **an exception suppresses the guard even when the
pattern matches**, and the suppression is recorded as `suppressed_by_exception`,
never as a clean pass.

Section 2's exception examples were unsafe. `\b(grep|rg|sed|awk)\b` evaluated as
a free substring over the whole command is a bypass hole:

    python3 -c "os.path.getpid()"   # grep

disarms the guard with a comment. Corrected as a property of the mechanism:
**exceptions are evaluated in command position only**, reusing
`mask_shell_data` / `shell_cmd_match`, which already distinguish what the shell
would execute from quoted data and heredoc bodies. Anti-bypass tests are
required — `# grep`, `; : grep`, `"grep"`, `echo grep`, trailing comments — and
exception-bypass is treated as a security property. The likely attacker is not
an attacker: it is Claude appending an innocent comment and disarming its own
guard.

### 8.4 Cross-version compatibility and rollback, proven

0.4.5 (`SCHEMA_VERSION` 5) and 0.5.0 (6) must keep operating against a v7
database. The mechanism is the `_user_version(up) >= SCHEMA_VERSION` fast path
plus additive-only columns; it must be proven, including that no query in those
versions references a column they lack. This is the current real state, not a
hypothetical: the installed plugin is 0.4.5 while the repo is 0.5.0. Rollback to
0.5.0 on a v7 database must work, with what is lost and what is preserved stated
in writing.

### 8.5 Contaminated SHADOW v3 evidence is preserved

`shadow_v3_started_at` and `shadow_v3_baseline_snapshot` are stamped 2026-10-01
by an out-of-band 0.5.0 CLI run while 0.4.5 was the installed runtime. The fix
is **not** deletion. The contamination is recorded as an explicit auditable
annotation naming what happened, when, by which code version, against which
installed version; a new window may then open without destroying the old keys.
Erasing history to manufacture a clean baseline is the failure mode this project
has already died of twice.

### 8.6 A new window must prove release coherence before opening

A precondition check, surfaced in `doctor`: the executing code version, the
version reported in the beacon, the installed `plugin_root` version, the schema
version the code expects versus the database's `user_version`, and the registered
hook set must all name the same release. On any disagreement the window refuses
to open and names the disagreeing pair. The live state today — 0.5.0 code run
against a 0.4.5 install on a schema-6 database — is the fixture for this test.

### 8.7 Integration tests on the three historical errors

Through the real `hook guard` entry point with realistic event payloads, not
unit tests of the matcher. For each of ERR-0001, ERR-0003, ERR-0017 the recorded
historical action must be caught and the legitimate equivalents must not be,
including: `git status` with `cwd` inside a repo, `git -C /path log`,
`cd /repo && git log`, `git clone`, `git init`, `git --version`,
`grep -rn "os.path.getpid" .`, a heredoc using `os.getpid()`, and
`--candidate-id 1`.

## 9. Report structure required

The final report separates four things and does not blur them:

1. implementation completed;
2. tests passing;
3. preventive efficacy **not yet demonstrated**;
4. decisions pending rollout authorization.

Green tests mean the machinery behaves as specified. They are not evidence of
preventive efficacy, which requires a controlled recurrence blocked before
execution, measured as `actually_blocked` with a confirmed causal outcome.

## 10. Correction (schema v8): metrics must read fire-time facts, never a live join

Section 5's `actually_blocked` was specified, and implemented, as a join from
`guard_events` to `guards.severity`. That is a defect this document inherited, not
one it created: a guard's severity is mutable, so the join made a past event's
meaning depend on the guard's state at READ time rather than at FIRE time. Editing a
guard after it fired silently rewrote what every one of its past events meant.

The fix, detailed in `CHANGELOG.md`: `guard_events.severity_at_fire`/`decision`/
`guard_fingerprint`/`rule_fingerprint`, written once in `run_guard()` before the
output is decided, and `actually_blocked` now reads `decision='denied'` directly --
no join to `guards` for anything behavioural, ever. Pre-existing rows have none of
this and are reported `unknown-at-fire`, never backfilled and never silently folded
into either a "true" or "false" answer. `release_coherence_check()` also gained a
check for hooks actually LOADED (evidenced by the beacon and the external watchdog's
health file), not merely declared in the manifest, per the user's 2026-10-01
requirement that a new window confirm coherence between the installed version, the
hooks effectively loaded, the schema and the baseline before WARN is ever enabled.
