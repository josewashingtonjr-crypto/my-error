#!/usr/bin/env python3
"""Independent adversarial verification for my-error 0.6.0.

Black-box, through the real CLI and the real `hook` stdin contract. Written
during review by someone other than the implementer, and deliberately NOT in
`tests/`: a check that lives inside the suite it judges can be made to pass by
editing that suite. Keep it separate on purpose.

It exists because three of the four defects found during the 0.6.0 review
presented as SILENCE or as GREEN, not as failure:

  - `doctor`/`metrics` crashed on a pre-v7 database, and every test missed it
    because each fixture was built by the code under test, so the schema was
    always already current;
  - contextual recall could not match any path-shaped lesson, which read as
    "no relevant lesson" rather than "cannot match";
  - a lesson tagged with a tool name burned its one per-session delivery on an
    irrelevant command, immunising the session against delivering it later;
  - `guards.fingerprint` was a cache with no invalidator, so "has this rule
    changed since that event" answered "no" after two edits.

Every check states what it proves. None of them proves preventive efficacy.

Run:  python3 benchmarks/review_adversarial.py
      REVIEW_SCRIPT=/path/to/other/my_error.py python3 benchmarks/review_adversarial.py
"""
import importlib.util
import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = Path(os.environ.get("REVIEW_SCRIPT") or (ROOT / "scripts" / "my_error.py"))
def _older_binary() -> Path:
    """An older release to build version-skew fixtures with.

    The live cache is the first choice, but it only holds whatever version is
    currently installed -- uninstalling the plugin removes the old one, and
    these checks would then silently degrade to "cannot test" rather than
    failing honestly. The pre-upgrade backup is the fallback, since the whole
    point of keeping it was to preserve exactly this. Override with
    REVIEW_OLD_SCRIPT.
    """
    env = os.environ.get("REVIEW_OLD_SCRIPT")
    if env:
        return Path(env)
    cache = Path.home() / ".claude/plugins/cache/my-error-local/my-error"
    if cache.is_dir():
        for d in sorted(cache.iterdir()):
            cand = d / "scripts" / "my_error.py"
            if cand.exists() and d.name != "0.6.0":
                return cand
    backups = sorted((Path.home() / ".claude/plugins/data/my-error").glob(
        "backup-pre-*/plugin-*/scripts/my_error.py"), reverse=True)
    return backups[0] if backups else cache / "0.4.5" / "scripts" / "my_error.py"


INSTALLED_045 = _older_binary()

results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, bool(ok), detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail}" if detail else ""))


def run(script, args, data_dir, stdin=None, mode=None, warn=None, cwd=None):
    env = dict(os.environ, MY_ERROR_DATA_DIR=str(data_dir))
    for k in ("MY_ERROR_MODE", "MY_ERROR_WARN"):
        env.pop(k, None)
    if mode:
        env["MY_ERROR_MODE"] = mode
    if warn:
        env["MY_ERROR_WARN"] = warn
    return subprocess.run([sys.executable, str(script), *args], input=stdin,
                          capture_output=True, text=True, env=env,
                          cwd=str(cwd or ROOT), timeout=120)


def fresh(tag):
    d = Path(tempfile.mkdtemp(prefix=f"myerr-rev-{tag}-"))
    run(SCRIPT, ["status"], d)
    return d


def snapshot(d):
    con = sqlite3.connect(d / "my-error.db")
    try:
        return {
            "meta": dict(con.execute("select key,value from meta").fetchall()),
            "user_version": con.execute("PRAGMA user_version").fetchone()[0],
            "counts": {t: con.execute(f"select count(*) from {t}").fetchone()[0]
                       for t in ("lessons", "guards", "candidates", "recall_events")},
        }
    finally:
        con.close()


def fire(d, cwd, cmd, session="s", mode=None, warn=None):
    ev = json.dumps({"session_id": session, "cwd": str(cwd), "tool_name": "Bash",
                     "tool_input": {"command": cmd}})
    return run(SCRIPT, ["hook", "guard"], d, stdin=ev, mode=mode, warn=warn)


# --------------------------------------------------- observation must not mutate
def test_first_contact_observation_does_not_migrate():
    """The real incident: newer code LOOKING AT an older database migrated it.

    The fixture must be built by OLDER code. An earlier version of this check
    built it with the code under test, so the schema was already current and it
    passed while the bug was live -- a false pass, and the reason this file
    exists.
    """
    if not INSTALLED_045.exists():
        check("observing an older database does not migrate it", False,
              f"no older binary to build a fixture with: {INSTALLED_045}")
        return
    d = Path(tempfile.mkdtemp(prefix="myerr-rev-firstcontact-"))
    run(INSTALLED_045, ["status"], d)
    before = snapshot(d)
    run(SCRIPT, ["metrics"], d)
    after = snapshot(d)
    new_keys = sorted(set(after["meta"]) - set(before["meta"]))
    changed = sorted(k for k in set(before["meta"]) & set(after["meta"])
                     if before["meta"][k] != after["meta"][k])
    ok = after["user_version"] == before["user_version"] and not new_keys and not changed
    check("observing an older database does not migrate or rotate it", ok,
          f"user_version {before['user_version']}->{after['user_version']}; "
          f"new={new_keys}; changed={changed}" if not ok else
          f"stayed at v{before['user_version']}, no meta added or changed")


def test_read_only_commands_survive_older_schemas():
    """Not migrating is only half: they must also not crash on what they find."""
    if not INSTALLED_045.exists():
        check("read-only commands survive an older schema", False, "no older binary")
        return
    d = Path(tempfile.mkdtemp(prefix="myerr-rev-ro-"))
    run(INSTALLED_045, ["status"], d)
    uv = snapshot(d)["user_version"]
    bad = []
    for cmd in ("doctor", "metrics", "status", "recall-audit", "review"):
        p = run(SCRIPT, [cmd], d)
        if p.returncode != 0 or "Traceback" in (p.stderr or ""):
            bad.append(f"{cmd}(exit {p.returncode})")
    check(f"read-only commands exit 0 on a v{uv} database", not bad,
          f"failed: {', '.join(bad)}" if bad else
          f"doctor/metrics/status/recall-audit/review all clean, db still v{uv}")


def test_old_code_operates_on_the_current_schema():
    d = fresh("compat")
    uv = snapshot(d)["user_version"]
    if not INSTALLED_045.exists():
        check("older code operates on the current schema", False, "no older binary")
        return
    p = run(INSTALLED_045, ["status"], d)
    check(f"0.4.5 operates on a v{uv} database", p.returncode == 0,
          (p.stderr or "")[-300:] if p.returncode else f"exit 0, additive schema holds")


# ------------------------------------------------------- metrics must not lie
def test_not_measurable_when_no_guards():
    d = fresh("nm")
    blob = (run(SCRIPT, ["metrics"], d).stdout or "") + (run(SCRIPT, ["recall-audit"], d).stdout or "")
    check("prevention metrics say NOT_MEASURABLE when no guard exists",
          "NOT_MEASURABLE" in blob,
          "a structurally impossible 0 is being rendered as a result"
          if "NOT_MEASURABLE" not in blob else "present")


# ------------------------------------------------------------ freeze guarantee
def test_warn_off_is_silent():
    d = fresh("warnoff")
    p = fire(d, ROOT, "echo hello")
    check("WARN off emits nothing on the PreToolUse path",
          p.returncode == 0 and not p.stdout.strip(),
          f"exit={p.returncode} stdout={p.stdout[:200]!r}")


# ------------------------------------------------- exceptions must not be bypassable
def test_exception_cannot_be_disarmed_by_a_comment():
    """An unanchored exception is a hole: `# grep` would disarm the guard."""
    d = fresh("bypass")
    run(SCRIPT, ["learn", "--title", "t", "--cause", "c", "--rule", "use os.getpid()",
                 "--scope", "project", "--confidence", "95", "--guard-tool", "Bash",
                 "--guard-field", "command", "--guard-match", "regex",
                 "--guard-pattern", r"os\.path\.getpid\s*\(", "--severity", "deny",
                 "--exceptions", r"^(grep|rg|sed|awk)\b"], d, mode="ENFORCE")
    must_deny = [
        'python3 -c "os.path.getpid()"',
        'python3 -c "os.path.getpid()"   # grep',
        'python3 -c "os.path.getpid()" ; : grep',
        'echo "grep" && python3 -c "os.path.getpid()"',
    ]
    must_allow = ['grep -rn "os.path.getpid" .', 'python3 -c "os.getpid()"']
    bad = []
    for c in must_deny:
        if '"permissionDecision":"deny"' not in fire(d, ROOT, c, mode="ENFORCE").stdout:
            bad.append(f"NOT denied: {c}")
    for c in must_allow:
        if '"permissionDecision":"deny"' in fire(d, ROOT, c, mode="ENFORCE").stdout:
            bad.append(f"wrongly denied: {c}")
    check("an exception cannot be disarmed by a trailing comment or quoted text",
          not bad, "; ".join(bad) if bad else
          "4 bypass variants still deny; legitimate grep and os.getpid() allowed")


# ------------------------------- a condition separates the mistake from its twin
def test_condition_separates_identical_commands():
    """ERR-0017's whole point: the deciding fact is not in the command text."""
    d = fresh("cond")
    norepo = Path(tempfile.mkdtemp(prefix="myerr-rev-norepo-"))
    run(SCRIPT, ["learn", "--title", "t", "--cause", "c", "--rule", "use git -C",
                 "--scope", "global", "--confidence", "90", "--guard-tool", "Bash",
                 "--guard-field", "command", "--guard-match", "shell_cmd",
                 "--guard-pattern",
                 r"(?:rtk\s+)?git\s+(?!(?:-C|--git-dir|--work-tree|-c|clone|init|help|--version|--help)\b)",
                 "--severity", "deny", "--condition", "cwd_not_git_repo",
                 "--exceptions", r"^cd\b"], d, mode="ENFORCE")
    cases = [
        (True,  norepo, "rtk git log --oneline HEAD..origin/main"),
        (False, norepo, "git -C /tmp log"),
        (False, norepo, "cd /tmp && git log"),
        (False, norepo, "git clone https://example.com/x.git"),
        (False, norepo, "git init"),
        (False, norepo, "git --version"),
        (False, ROOT,   "git status"),
        (False, ROOT,   "rtk git log --oneline HEAD..origin/main"),
    ]
    bad = []
    for want_deny, cwd, cmd in cases:
        denied = '"permissionDecision":"deny"' in fire(d, cwd, cmd, mode="ENFORCE").stdout
        if denied != want_deny:
            bad.append(f"{'should deny' if want_deny else 'should allow'}: <{cmd}> in {cwd}")
    check("a context condition separates the historical mistake from its legitimate twin",
          not bad, "; ".join(bad) if bad else
          "the same `git log` denies outside a repo and is allowed inside one")


# ---------------------------------- history must not change when a guard is edited
def test_editing_a_guard_cannot_rewrite_history():
    d = fresh("frozen")
    run(SCRIPT, ["learn", "--title", "t", "--cause", "c", "--rule", "r",
                 "--scope", "project", "--confidence", "95", "--guard-tool", "Bash",
                 "--guard-field", "command", "--guard-match", "exact",
                 "--guard-pattern", "doit", "--severity", "deny"], d, mode="ENFORCE")
    fire(d, ROOT, "doit", mode="ENFORCE")

    def blocked():
        out = run(SCRIPT, ["metrics"], d, mode="ENFORCE").stdout
        return json.loads(out).get("prevention", {}).get("actually_blocked")

    before = blocked()
    con = sqlite3.connect(d / "my-error.db")
    try:
        con.execute("update guards set severity='warn', pattern='something-else'")
        con.commit()
        con.row_factory = sqlite3.Row
        guard = con.execute("select * from guards").fetchone()
        frozen = con.execute("select guard_fingerprint from guard_events").fetchone()[0]
    finally:
        con.close()
    after = blocked()
    check("editing a guard does not change what a past metric means",
          before == after == 1, f"actually_blocked {before} -> {after} (expected 1 -> 1)")

    spec = importlib.util.spec_from_file_location("me_rev", SCRIPT)
    me = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(me)
    live = me.live_guard_fingerprint(guard)
    check("the edit is still DETECTABLE against the past event's fingerprint",
          live != frozen,
          "live fingerprint equals the frozen one after two edits -- a stale cache"
          if live == frozen else f"live {live[:18]} != frozen {frozen[:18]}")


def main() -> int:
    for fn in (test_first_contact_observation_does_not_migrate,
               test_read_only_commands_survive_older_schemas,
               test_old_code_operates_on_the_current_schema,
               test_not_measurable_when_no_guards,
               test_warn_off_is_silent,
               test_exception_cannot_be_disarmed_by_a_comment,
               test_condition_separates_identical_commands,
               test_editing_a_guard_cannot_rewrite_history):
        try:
            fn()
        except Exception as e:  # a harness crash is a failure, not a skip
            check(fn.__name__, False, f"harness raised {type(e).__name__}: {e}")
    failed = [n for n, ok, _ in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    if failed:
        print("FAILED: " + "; ".join(failed))
    print("\nNone of this is evidence of preventive efficacy. It shows the machinery\n"
          "behaves as specified. Real prevention requires a recurrence of a recorded\n"
          "mistake denied before execution in genuine work, with a confirmed causal\n"
          "outcome -- see docs/ROLLOUT.md.")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
