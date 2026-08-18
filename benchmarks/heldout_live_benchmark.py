#!/usr/bin/env python3
"""Independent live-command benchmark for my-error v1.2.

Runs real failing commands in a temporary project, repeats them without protection
(baseline), then feeds the observed failure + successful narrow correction to
my-error and verifies the same mistake is blocked before a third execution.
"""
from __future__ import annotations
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("my_error", ROOT / "scripts" / "my_error.py")
me = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(me)


def run(cmd: str, cwd: Path) -> tuple[int, str]:
    p = subprocess.run(cmd, cwd=cwd, shell=True, text=True, capture_output=True, timeout=30)
    return p.returncode, (p.stderr + "\n" + p.stdout).strip()


def setup_project(project: Path) -> None:
    (project / "tests").mkdir(parents=True)
    (project / "script.py").write_text("print('ok')\n")
    (project / "worker.py").write_text("print('worker')\n")
    (project / "server.js").write_text("console.log('server')\n")
    (project / "worker.js").write_text("console.log('worker')\n")
    (project / "build.sh").write_text("#!/bin/sh\necho build\n")
    (project / "config.json").write_text('{"ok": true}\n')
    (project / "tests" / "test_alpha.py").write_text("def test_alpha():\n    assert True\n")
    (project / "tests" / "test_beta.py").write_text("def test_beta():\n    assert True\n")
    (project / "tests" / "test_unittest.py").write_text("import unittest\nclass Smoke(unittest.TestCase):\n    def test_ok(self):\n        self.assertTrue(True)\n")
    (project / "package.json").write_text(json.dumps({
        "name": "my-error-heldout", "version": "1.0.0", "scripts": {
            "build": "node -e \"process.exit(0)\"",
            "test": "node -e \"process.exit(0)\"",
            "lint": "node -e \"process.exit(0)\""
        }
    }))
    run("git init -q", project)
    run("git config user.email benchmark@example.invalid", project)
    run("git config user.name Benchmark", project)
    run("git add . && git commit -qm init", project)
    # Normalize default branch and add two held-out branches.
    run("git branch -M main", project)
    run("git branch develop", project)
    run("git branch feature", project)


def insert_lesson(db, pid, title, cause, rule, tags):
    now = me.utcnow()
    db.execute("""
      INSERT INTO lessons(project_id,scope,created_at,updated_at,title,cause,rule_text,confidence,status,source,tags)
      VALUES(?,?,?,?,?,?,?,?,?,?,?)
    """, (pid, "project", now, now, title, cause, rule, 0.98, "active", "heldout-verified", tags))
    db.commit()


def main() -> int:
    td = Path(tempfile.mkdtemp(prefix="my-error-v11-heldout-"))
    project, data = td / "project", td / "data"
    project.mkdir(); data.mkdir(); setup_project(project)
    # Benchmarks measure the guard, so they must state the mode; the
    # product default is SHADOW, which deliberately blocks nothing.
    os.environ["MY_ERROR_MODE"] = "ENFORCE"
    os.environ["MY_ERROR_DATA_DIR"] = str(data)
    os.environ["CLAUDE_PROJECT_DIR"] = str(project)
    db = me.connect(); pid = me.ensure_project(db, str(project.resolve()))

    pairs = [
        ("python3 sript.py", "python3 script.py"),
        ("python3 workre.py", "python3 worker.py"),
        ("node sever.js", "node server.js"),
        ("node wroker.js", "node worker.js"),
        ("bash biuld.sh", "bash build.sh"),
        ("cat confi.json", "cat config.json"),
        ("pytest test/test_alpha.py -q", "pytest tests/test_alpha.py -q"),
        ("pytest tests/test_btea.py -q", "pytest tests/test_beta.py -q"),
        ("npm run biuld", "npm run build"),
        ("npm run tets", "npm run test"),
        ("npm run lnit", "npm run lint"),
        ("git checkout mian", "git checkout main"),
        ("git checkout develpo", "git checkout develop"),
        ("git checkout featuer", "git checkout feature"),
        ("git show HEADD", "git show HEAD"),
        ("python3 --versoin", "python3 --version"),
        ("git --verison", "git --version"),
        ("pytest --versoin", "pytest --version"),
        ("node --versoin", "node --version"),
        ("ls --alll", "ls --all"),
        ("mkdir --parentss tmp/a", "mkdir --parents tmp/a"),
        ("grep --line-nubmer ok config.json", "grep --line-number ok config.json"),
        ("git chekout main", "git checkout main"),
        ("npm rn build", "npm run build"),
        ("git sttaus", "git status"),
        ("git shwo HEAD", "git show HEAD"),
        ("npm lss", "npm ls"),
        ("python3 -m unitest discover -s tests", "python3 -m unittest discover -s tests"),
        ("python3 -m json.toool config.json", "python3 -m json.tool config.json"),
        ("node --chekc server.js", "node --check server.js"),
        ("grep --colro=never ok config.json", "grep --color=never ok config.json"),
        ("ls --colro=never", "ls --color=never"),
        ("pythno3 --version", "python3 --version"),
        ("ndoe --version", "node --version"),
        ("npmm --version", "npm --version"),
        ("giit --version", "git --version"),
    ]

    details = []
    baseline_repeat_failures = 0
    learned = 0
    blocked = 0
    skipped = []

    for i, (bad, good) in enumerate(pairs):
        # Good command must actually work in this environment.
        good_rc, good_probe = run(good, project)
        if good_rc != 0:
            skipped.append({"bad": bad, "good": good, "reason": "good command failed", "output": good_probe[:400]})
            continue
        first_rc, err = run(bad, project)
        if first_rc == 0:
            skipped.append({"bad": bad, "good": good, "reason": "bad command unexpectedly succeeded"})
            continue
        retry_rc, _ = run(bad, project)
        if retry_rc != 0:
            baseline_repeat_failures += 1

        sid = f"heldout-{i}"
        fail_event = {"session_id": sid, "cwd": str(project), "tool_name": "Bash", "tool_input": {"command": bad}, "error": err, "is_interrupt": False}
        cid, family, eligible, ignored = me.upsert_candidate(db, pid, fail_event)
        success_event = {"session_id": sid, "cwd": str(project), "tool_name": "Bash", "tool_input": {"command": good}, "tool_response": {"stdout": "ok"}}
        got_cid, lid = me.observe_success(db, pid, success_event)
        is_learned = bool(got_cid and lid)
        if is_learned: learned += 1
        out = me.run_guard(db, pid, {"tool_name": "Bash", "tool_input": {"command": bad}})
        is_blocked = bool(out and out.get("hookSpecificOutput", {}).get("permissionDecision") == "deny")
        if is_blocked: blocked += 1
        details.append({
            "bad": bad, "good": good, "family": family, "auto_eligible": eligible,
            "baseline_retry_failed": retry_rc != 0, "learned": is_learned, "blocked_after": is_blocked,
        })

    valid_pairs = len(details)

    # Semantically worded held-out prompts. These are deliberately phrased differently
    # from the stored rules to exercise concept recall rather than exact word overlap.
    semantic_lessons = [
        ("Money precision", "Binary floating point corrupted money arithmetic", "Use decimal or integer minor units for monetary values; never binary float for money.", "money,decimal,precision"),
        ("Migration before use", "Code used a database column before schema migration", "Apply and verify the database migration before relying on a new column.", "database,migration,schema,column"),
        ("Generated source", "Generated client was edited directly", "Change the source schema and regenerate generated client output.", "generated,codegen,schema"),
        ("Secret logging", "Credentials were written to logs", "Redact tokens, passwords, and API credentials before logging.", "secret,token,credential,redact"),
        ("Atomic database writes", "Partial writes left inconsistent state", "Use a transaction for atomic database changes and rollback on failure.", "transaction,atomic,database"),
        ("Authorization", "Privileged action lacked a role check", "Verify authorization permissions and role before privileged operations.", "auth,authorization,permission,role"),
        ("Concurrent state", "A race condition corrupted shared state", "Use appropriate locking or concurrency control around shared writes.", "concurrency,race,lock"),
        ("Cache invalidation", "Stale cached data survived a write", "Invalidate or refresh stale cache entries after writes.", "cache,stale,invalidate"),
        ("UTC timestamps", "Local timezone timestamps were persisted", "Persist timestamps in UTC and convert only at presentation boundaries.", "time,timestamp,timezone,utc"),
        ("API response contract", "Endpoint returned an incompatible response", "Validate API response payloads against the endpoint contract.", "api,endpoint,response,http"),
    ]
    for x in semantic_lessons: insert_lesson(db, pid, *x)
    semantic_queries = [
        ("Compute invoice totals and payment amounts", "Money precision"),
        ("Reference a newly added SQL field safely", "Migration before use"),
        ("Modify codegen output after changing its schema", "Generated source"),
        ("Print API credentials into diagnostic logs", "Secret logging"),
        ("Make several DB updates all-or-nothing", "Atomic database writes"),
        ("Protect an admin endpoint with the right permissions", "Authorization"),
        ("Prevent a race during concurrent shared-state writes", "Concurrent state"),
        ("Refresh stale cached data after an update", "Cache invalidation"),
        ("Store dates correctly across multiple timezones", "UTC timestamps"),
        ("Check an endpoint payload returned over HTTP", "API response contract"),
    ]
    semantic_details=[]; semantic_hits=0
    for prompt, expected_title in semantic_queries:
        rows = me.recall(db, pid, prompt, 5)
        top_title = rows[0]["title"] if rows else None
        hit = top_title == expected_title
        semantic_hits += int(hit)
        semantic_details.append({"prompt": prompt, "expected_top_lesson": expected_title, "top_lesson": top_title, "hit": hit})

    # Controls: valid corrections + unrelated commands must never be blocked.
    controls = sorted(set([good for _, good in pairs] + [
        "git status", "npm run lint", "python3 script.py", "node server.js", "pytest -q",
        "cat config.json", "ls --all", "grep --line-number ok config.json", "git diff", "npm ls"
    ]))
    false_blocks=[]
    for cmd in controls:
        out = me.run_guard(db, pid, {"tool_name": "Bash", "tool_input": {"command": cmd}})
        if out and out.get("hookSpecificOutput", {}).get("permissionDecision") == "deny":
            false_blocks.append(cmd)

    # Explicit anti-superstition cases: similar success must not become a lesson.
    before_lessons = db.execute("SELECT COUNT(*) FROM lessons").fetchone()[0]
    anti = [
        ("npm run buil", "npm error Missing script: buil", "npm run lint"),
        ("node ap.js", "Error: Cannot find module 'express'\n at /project/ap.js", "node app.js"),
        ("pytest tests/test_alpha.py -q", "1 failed\nAssertionError: expected 1 got 2", "pytest tests/test_beta.py -q"),
    ]
    for i,(bad,err,good) in enumerate(anti):
        sid=f"anti-{i}"
        me.upsert_candidate(db,pid,{"session_id":sid,"cwd":str(project),"tool_name":"Bash","tool_input":{"command":bad},"error":err,"is_interrupt":False})
        me.observe_success(db,pid,{"session_id":sid,"cwd":str(project),"tool_name":"Bash","tool_input":{"command":good}})
    after_lessons = db.execute("SELECT COUNT(*) FROM lessons").fetchone()[0]
    anti_false_lessons = after_lessons - before_lessons

    db.close()
    result = {
        "benchmark": "my-error v1.2 independent live held-out A/B",
        "plugin_version": me.VERSION,
        "attempted_pairs": len(pairs), "valid_pairs": valid_pairs, "skipped": skipped,
        "baseline": {
            "repeat_failures": baseline_repeat_failures,
            "mistakes_prevented": 0,
            "prevention_rate": 0.0,
        },
        "with_my_error": {
            "trained_pairs": learned,
            "repeat_mistakes_prevented": blocked,
            "prevention_rate": (blocked / valid_pairs if valid_pairs else 0),
            "semantic_recall_hits": semantic_hits,
            "semantic_recall_total": len(semantic_queries),
            "semantic_recall_rate": semantic_hits / len(semantic_queries),
            "false_blocks": len(false_blocks),
            "control_commands": len(controls),
            "anti_superstition_false_lessons": anti_false_lessons,
        },
        "improvement": {
            "repeat_prevention_percentage_points": round((blocked / valid_pairs) * 100, 1) if valid_pairs else 0,
            "semantic_recall_percentage_points": round((semantic_hits / len(semantic_queries)) * 100, 1),
        },
        "pass_100": bool(valid_pairs and blocked == valid_pairs and learned == valid_pairs and semantic_hits == len(semantic_queries) and not false_blocks and anti_false_lessons == 0),
        "details": details,
        "semantic_details": semantic_details,
        "false_block_commands": false_blocks,
        "temp_project": str(project),
    }
    out_path = ROOT / "benchmarks" / "v1.2-heldout-result.json"
    out_path.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result["pass_100"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
