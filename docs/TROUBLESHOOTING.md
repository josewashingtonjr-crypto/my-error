# Troubleshooting

Every entry here is a failure that actually happened, not a hypothetical.

## `/my-error:doctor` reports zeros while the plugin is clearly working

Check the `Project namespace` line first. History is per project, and the namespace is the
Git common directory when you are inside a repository. Running a command from a *different*
repository — including the plugin's own checkout — resolves to a different, legitimately
empty namespace.

```bash
CLAUDE_PROJECT_DIR=/path/to/the/project python3 "$MY_ERROR" metrics
```

If the namespace is right and the numbers are still zero, compare `Database:` in `doctor`
against the `db` field in the beacon:

```bash
cat ~/.claude/plugins/data/my-error/runtime.json
```

They must be the same file. If they differ, you are on a version older than 0.3.1, which
had two separate resolutions of the data directory — see the 0.3.1 entry in the
[changelog](../CHANGELOG.md).

## The status line says `HOOKS INATIVOS` / no beacon

The plugin is installed but no hook of it has run in this session. Usual causes:

- **Claude Code was not restarted** after installing. Hooks are registered at session start.
- **The plugin is disabled.** Check `enabledPlugins` in `~/.claude/settings.json`.
- **The session predates the install.** Start a new one.

Confirm with the probe, which reports each check separately:

```bash
echo '{"session_id":"probe","cwd":"'$PWD'"}' | node ~/.claude/watchdogs/my-error-watchdog.cjs --probe
```

## I updated the plugin but it still behaves like the old version

Updating mid-session does not move a running session's hooks. They resolved
`${CLAUDE_PLUGIN_ROOT}` at session start and keep executing the previous version, from a
directory that uninstall leaves behind.

Restart Claude Code. To confirm which version the live hooks are actually running:

```bash
python3 -c "import json;print(json.load(open('$HOME/.claude/plugins/data/my-error/runtime.json'))['version'])"
```

That reads the beacon, which is written by the hooks themselves — not by whatever
`claude plugin list` reports.

## Nothing is ever learned on my machine

Run `/my-error:doctor` and look at two lines:

```
Locale recognized:  no
Fallback active:    YES (emergency cover for an unrecognized locale)
```

Failure messages follow your locale. English, Portuguese, Spanish, French, German and
Italian are matched by explicit patterns. Any other language falls back to a weaker,
language-independent signal: the failure output naming the exact token the correction
changed. It covers less.

Two options: run Claude Code with `LC_ALL=C` so tools emit English, or open an issue with
sample error messages in your language so patterns can be added.

## Commands are being blocked and I did not expect it

Check the mode:

```bash
python3 "$MY_ERROR" mode
```

The default is `SHADOW`, which blocks nothing. If it says `ENFORCE`, someone switched it.
To find what blocked you, `/my-error:review` lists active lessons and their rules; disable
one with `forget ERR-nnnn`.

If a guard blocked something that would have worked, that is a false positive and worth
reporting — it is the number the whole experiment is watching.

## `doctor` reports legacy databases that were not merged

```
Legacy databases still holding data (NOT merged automatically):
  /home/you/.claude/plugins/data/my-error-inline
```

More than one populated database was found. The plugin adopts a single one automatically
but refuses to merge two, because silently picking one would discard the other's lessons.

Inspect them and decide:

```bash
python3 -c "
import sqlite3,sys
db=sqlite3.connect('file:'+sys.argv[1]+'/my-error.db?mode=ro',uri=True)
for t in ('candidates','lessons','guard_events'): print(t, db.execute('select count(*) from '+t).fetchone()[0])
" /path/to/the/legacy/dir
```

Keep the one you want as `~/.claude/plugins/data/my-error/my-error.db` and archive the
other. There is deliberately no automatic merge.

## Concurrency, locks, missing captures

Hooks fire in parallel and contend for the SQLite file. Versions before 0.3.1 could lose an
event that way, in roughly 20% of heavily concurrent runs. If you see captures going
missing on 0.3.1 or later, that is a bug worth reporting — include the output of:

```bash
MY_ERROR_DEBUG=1 python3 "$MY_ERROR" hook failure < /tmp/your-event.json
```

`MY_ERROR_DEBUG=1` surfaces errors that hooks otherwise swallow. They are swallowed by
design: a learning plugin must never be able to break the session it observes.

## Starting over

```bash
python3 "$MY_ERROR" datadir
```

Move or delete the directory it prints. The next run recreates it empty. This discards all
learned history, including the shadow experiment clock.
