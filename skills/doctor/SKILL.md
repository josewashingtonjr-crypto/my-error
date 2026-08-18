---
name: doctor
description: Full health report for my-error — installation, hooks, database, locale support, mode, and measured metrics. Use for the expensive checks that the per-prompt watchdog deliberately skips.
allowed-tools: Bash
---
Run `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/my_error.py" doctor` and explain the result.

Read the numbers carefully rather than summarising them as "healthy":

- `verified corrections` counts only failures whose correction passed the plugin's verification gate. `unverified recoveries` are recoveries observed but not causally proven — they are not corrections.
- In `SHADOW` mode nothing is blocked. Report `would-block` as "repetitions detected", never as "errors prevented".
- `predictions refuted` is the important one: the guard said a command would fail, shadow let it run, and it succeeded. Each of those is a measured false positive.
- `Locale recognized` and `Fallback active` go together. In a covered language the plugin
  uses explicit message patterns only. In an unrecognized one it falls back to a heuristic
  (the failure output naming the token the correction changed) as emergency cover — report
  that state plainly, because it is a weaker form of evidence than a matched pattern.
- In SHADOW, `Shadow experiment: day N of 30` is the clock the auto-guard is being judged on.
