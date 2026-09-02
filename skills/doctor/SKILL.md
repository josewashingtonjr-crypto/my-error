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
- In SHADOW, `Shadow experiment: v2, day N of 30` is the clock the auto-guard is being judged on.
- There are two generations. **v1 is CLOSED as `INCONCLUSIVE_DUE_TO_MATERIAL_SYSTEM_CHANGES`** —
  report it as neither success nor failure, and never merge its numbers into v2. Its rows are
  preserved, not deleted. **v2** is the active experiment; only `natural_usage` on or after the
  v2 start reaches the verdict. Controlled tests inside the v2 window are printed so the
  exclusion is auditable — they are not evidence.
- The verdict judges ONLY the deterministic auto-guard for operational recurrence. It does not
  judge the value of my-error as a whole, semantic lessons, recall, cross-project transfer, or
  prevention of engineering mistakes between projects. Those live in the separate
  `Knowledge transfer` section and never feed the verdict. Do not let a verdict about the guard
  read as a verdict about the plugin.
