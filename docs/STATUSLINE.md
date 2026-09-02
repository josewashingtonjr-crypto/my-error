# The status line: where it appears, and where it cannot

The `my-error` status bar segment is a wrapper around whatever `statusLine`
command you already have. Whether you ever see it does **not** depend on the
plugin. It depends on whether the client you are using invokes `statusLine` at
all.

## The two surfaces

| Surface | `settings.statusLine` | What you see |
|---|---|---|
| **Claude Code in a terminal** | Invoked on every redraw | The wrapper runs: your existing bar, verbatim, then `🧠 ME ✅ <version> · <mode> · L<n> · X<n>` |
| **Electron / `--output-format stream-json` harness** (e.g. `claude-desktop-unofficial`) | **Never invoked** | No bar at all — neither yours nor the segment |

This was measured, not assumed. In the stream-json harness the configured
`statusLine` command is never executed, so nothing the wrapper does can make a
bar appear there.

## What the absence of the bar does and does not mean

**It does not mean `my-error` is inactive.** The status line is one *display*
surface. It is not the mechanism, and it carries no state of its own — every
number in it is read from the beacon that the hooks themselves write.

In a client that does not render the bar, observability continues through:

- **hooks** — `SessionStart`, `UserPromptSubmit`, `PostToolUse*` and `Stop`
  still fire and still inject their text, which is the plugin actually working;
- **`/my-error:doctor`** — the full report, including the metrics the bar would
  have shown;
- **`/my-error:status`** — the short form;
- **the watchdog** — `watchdog/my-error-watchdog.cjs --probe`, and its
  `systemMessage` where that is rendered.

## This is not a plugin bug

There is no plugin-side fix, and none is being attempted. `statusLine` is a
client feature; a client that does not call it cannot be made to call it from
inside the command it never calls. The wrapper is kept because it works, today,
in terminal Claude Code.

## What `/my-error:doctor` reports

`doctor` prints a `Statusline surface:` line, derived only from artifacts that
either exist or do not — no client sniffing, no heuristic:

| Line | Meaning |
|---|---|
| `not configured in settings.json` | No `statusLine` key. Nothing would render anywhere. |
| `active - last rendered <timestamp>` | The invocation beacon exists: the live bar really did execute this code. |
| `configured, never observed running - unavailable in current client, or simply not drawn yet` | Configured, but no beacon has ever been written. |

The third line is deliberately two-sided. From inside this process, a client
that never invokes `statusLine` and a bar that has simply not been drawn yet are
**indistinguishable**, and inventing a confident answer between them would be
exactly the fragile detection this file exists to refuse.

## The invocation beacon

`~/.claude/watchdogs/.my-error-statusline.json` is written by the wrapper on
each (throttled) run. It is the *only* evidence that the live bar — as opposed
to a shell, a test, or a benchmark — executed this code (see ERR-0016).

Because it is evidence, no automated run may write it. Tests and benchmarks
must redirect it with `MY_ERROR_STATUSLINE_TRACE` (and the health cache with
`MY_ERROR_HEALTH_CACHE`); this is enforced by
`test_tests_never_touch_the_installations_invocation_beacon`. If the file is
absent, that is a real and meaningful answer: the live bar has not run this
code. Do not create it by hand.
