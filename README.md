# my-error for Claude Code

> **EXPERIMENTAL — v0.3.0.** Ships in **SHADOW mode**: the guard records what it *would*
> have blocked and blocks nothing. The automatic guard is on a 30-day probation while its
> base rate is measured, and may be removed in a later version if the data does not justify
> it. Interfaces may change; `0.x` is deliberate.

`my-error` is an evidence-gated learning plugin for Claude Code. It captures failures, recognizes a narrow set of deterministic command corrections automatically, recalls relevant prior lessons on future prompts, and blocks exact actions that were proven wrong.

## Modes

| Mode | Behaviour |
|---|---|
| `SHADOW` (default) | A matching guard is recorded as `would_block` and the command **runs**. Nothing is blocked and nothing is injected into the model's context — an instrument that warns changes the behaviour it is measuring. |
| `ENFORCE` | A matching guard denies the tool call, as originally designed. |

```bash
python3 scripts/my_error.py mode            # show
python3 scripts/my_error.py mode --set ENFORCE
```

Shadow is not merely "off". When it lets a command through it scores its own prediction:
the command failed again (`predictions_confirmed`) or it succeeded
(`predictions_refuted` — a **measured** false positive). That is the evidence the guard is
being judged on, and an enforcing guard cannot produce it, because blocking destroys the
counterfactual.

## Core rule

**A failure is not a lesson. A failure with a diagnosed cause and verified correction can become a lesson.**

## What it does automatically

- Captures `Bash`, `Write`, and `Edit` failures through `PostToolUseFailure`.
- Ignores common transient/network failures and interrupts.
- Redacts common credentials before persistent storage.
- Detects a closely related successful Bash command after deterministic failures such as command typos, missing npm scripts, wrong paths, Node/Python entrypoint-module typos, invalid options, and Git/npm subcommand mistakes.
- Promotes that verified exact correction to a project lesson and a 90-day exact-command guard.
- Injects relevant learned rules through `UserPromptSubmit` and prior high-confidence rules at `SessionStart`, with lightweight dependency-free concept expansion for common software-engineering terms.
- Blocks an active learned guard through `PreToolUse` before the repeated action executes.
- When a previously failing semantic/test command later succeeds, a `Stop` hook asks Claude once to review the recovery and invoke `/my-error:learn`; the model must still justify root cause before promotion.
- Keeps data in `${CLAUDE_PLUGIN_DATA}`, separated by project.
- Recognizes failure messages in English, Portuguese, Spanish, French, German, and Italian, and
  falls back to a locale-independent check for any other language.

## What requires judgment

Semantic code mistakes are captured as candidates but are **not** automatically promoted. After Claude fixes and verifies the problem, use `/my-error:learn <candidate-id>` or `/my-error` to record the causal lesson. This prevents test flakes, environmental failures, or misunderstood root causes from becoming bad memory.

## Local development / install

### Fast local test

Claude Code can load a plugin directly from either this directory or the release ZIP:

```bash
claude --plugin-dir /absolute/path/to/my-error-plugin
# or
claude --plugin-dir /absolute/path/to/my-error-plugin-v1.1.0.zip
```

Inside Claude Code, useful skills are namespaced by the plugin:

```text
/my-error:status
/my-error:review
/my-error:learn 12
/my-error:forget ERR-0012
```

### Permanent user install

Keep the extracted plugin directory in a stable location, then run:

```bash
./install-user.sh
```

The installer validates the plugin, adds its bundled local marketplace, and installs `my-error@my-error-local` at user scope. Equivalent manual commands are:

```bash
claude plugin validate /absolute/path/to/my-error-plugin --strict
claude plugin marketplace add /absolute/path/to/my-error-plugin --scope user
claude plugin install my-error@my-error-local --scope user
```

## Validation

```bash
claude plugin validate /absolute/path/to/my-error-plugin --strict
python3 -m unittest discover -s tests -v
python3 benchmarks/ab_benchmark.py
python3 benchmarks/heldout_live_benchmark.py
python3 benchmarks/fuzz_live_benchmark.py
```

The test suite has no third-party Python dependencies (27 tests). On this machine v1.2.0 reached
33/33 recurrence prevention on the independent live held-out benchmark and 30/30 on generated typo
fuzz, with zero false blocks — under both `pt_BR.UTF-8` and `LC_ALL=C`. See `TEST_REPORT.md` for
interpretation and limits.

## Storage and safety

The SQLite database is stored under `CLAUDE_PLUGIN_DATA`; the plugin root is treated as read-only/ephemeral. Project roots are hashed for database keys. Stored command/error text is capped and common API keys, bearer tokens, passwords, and secrets are redacted.

Automatic blocking is intentionally conservative: only exact Bash commands that were followed by a closely related successful correction are auto-guarded. Generalized or regex guards require explicit learning.

## Locale

Shell and tool error messages follow the machine locale. Family recognition covers en/pt/es/fr/de/it
directly; for any other locale the plugin falls back to a language-independent signal — the failure
output naming the exact shell token that the verified correction changed. Run
`python3 scripts/my_error.py doctor` to see the locale it detected.

## Limits

This plugin does not retrain Claude's model weights. It improves future behavior through persistent external memory, contextual retrieval, and deterministic guards. A live model A/B test requires a Claude Code installation with an authenticated Claude account; the included benchmark validates the plugin's learning/recall/guard mechanics independently of model variance.

## Live acceptance test

After installing into Claude Code, use a disposable test repository and run:

1. `/my-error:status`.
2. Ask Claude to run an intentionally invalid but harmless command such as `npm run buil` in a package that has a working `build` script.
3. Let the invalid command fail, then let `npm run build` succeed.
4. Ask Claude to run `npm run buil` again. `my-error` should deny it in `PreToolUse` and surface the learned correction.
5. Start a fresh Claude Code session in the same project and ask a related task. The stored lesson should be recalled.
6. Run an unrelated valid command and confirm it is not blocked.

Use only disposable, harmless examples for acceptance testing. Do not deliberately introduce destructive shell commands or production failures.
