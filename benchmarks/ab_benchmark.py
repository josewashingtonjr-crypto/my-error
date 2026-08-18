#!/usr/bin/env python3
"""Deterministic before/after benchmark for my-error learning mechanics.

This benchmark tests the plugin's external memory, recall, and guard behavior.
It intentionally does not claim to retrain or alter Claude model weights.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import my_error as me  # noqa: E402

TRAINING = [
    ("npm run buil", "Exit code 1\nnpm ERR! Missing script: buil", "npm run build"),
    ("python app.py", "Exit code 127\npython: command not found", "python3 app.py"),
    ("pytest test/test_api.py", "Exit code 4\nNo such file or directory: test/test_api.py", "pytest tests/test_api.py"),
    ("git checkout mian", "Exit code 1\nerror: pathspec 'mian' did not match any file(s) known to git", "git checkout main"),
    ("ruff check --fixx .", "Exit code 2\nerror: unknown option '--fixx'", "ruff check --fix ."),
    ("node scrpt.js", "Exit code 1\nNo such file or directory: scrpt.js", "node script.js"),
    ("npm run tset", "Exit code 1\nnpm ERR! Missing script: tset", "npm run test"),
    ("git checkout develp", "Exit code 1\nerror: pathspec 'develp' did not match any file(s) known to git", "git checkout develop"),
]

SOFT = [
    ("Generated Prisma client", "Generated code was edited directly", "Edit prisma/schema.prisma and regenerate the Prisma client instead of editing generated client files.", "prisma,schema,generated", "Update the Prisma client after changing schema", "prisma/schema.prisma"),
    ("Money precision", "Floating-point arithmetic was used for money", "Use decimal or integer minor units for monetary values; do not use binary float for money.", "money,decimal,precision", "Implement payment amount arithmetic with precision", "binary float"),
    ("Migration before constraint", "Code assumed a new database column existed before migration", "Apply and verify the database migration before relying on the new column or constraint.", "database,migration,constraint", "Use the new database constraint in this migration", "Apply and verify"),
    ("Generated OpenAPI", "Generated OpenAPI output was edited by hand", "Change the source schema and regenerate OpenAPI output; do not patch generated OpenAPI files directly.", "openapi,generated,schema", "Change generated OpenAPI after schema update", "regenerate OpenAPI"),
]

UNRELATED = ["npm run lint", "git status", "python3 -m unittest", "ruff format .", "node --version", "git diff", "npm ci", "pytest -q"]


def insert_soft_lesson(db, pid, title, cause, rule, tags):
    now = me.utcnow()
    db.execute("""
      INSERT INTO lessons(project_id,scope,created_at,updated_at,title,cause,rule_text,confidence,status,source,tags)
      VALUES(?,?,?,?,?,?,?,?,?,?,?)
    """, (pid, "project", now, now, title, cause, rule, 0.98, "active", "manual-verified", tags))
    db.commit()


def main() -> int:
    td = tempfile.mkdtemp(prefix="my-error-bench-")
    project = Path(td) / "project"; data = Path(td) / "data"
    project.mkdir(); data.mkdir()
    # Benchmarks measure the guard, so they must state the mode; the
    # product default is SHADOW, which deliberately blocks nothing.
    os.environ["MY_ERROR_MODE"] = "ENFORCE"
    os.environ["MY_ERROR_DATA_DIR"] = str(data)
    os.environ["CLAUDE_PROJECT_DIR"] = str(project)

    db = me.connect(); pid = me.ensure_project(db, str(project.resolve()))

    baseline = {"known_mistakes_prevented": 0, "known_mistake_prevention_rate": 0.0, "semantic_recall_hits": 0, "semantic_recall_rate": 0.0}

    for i, (bad, error, good) in enumerate(TRAINING):
        fail = {"session_id":f"train-{i}","cwd":str(project),"tool_name":"Bash","tool_input":{"command":bad},"error":error,"is_interrupt":False}
        success = {"session_id":f"train-{i}","cwd":str(project),"tool_name":"Bash","tool_input":{"command":good},"tool_response":{"stdout":"ok"}}
        me.upsert_candidate(db, pid, fail)
        cid, lid = me.observe_success(db, pid, success)
        if not cid or not lid:
            raise RuntimeError(f"training pair did not promote: {bad} -> {good}")

    for title, cause, rule, tags, _, _ in SOFT:
        insert_soft_lesson(db, pid, title, cause, rule, tags)

    prevented = 0
    for bad, _, _ in TRAINING:
        out = me.run_guard(db, pid, {"tool_name":"Bash","tool_input":{"command":bad}})
        if out and out["hookSpecificOutput"].get("permissionDecision") == "deny": prevented += 1

    false_blocks = 0
    for cmd in UNRELATED + [x[2] for x in TRAINING]:
        out = me.run_guard(db, pid, {"tool_name":"Bash","tool_input":{"command":cmd}})
        if out and out["hookSpecificOutput"].get("permissionDecision") == "deny": false_blocks += 1

    recall_hits = 0
    for *_, prompt, expected in SOFT:
        rows = me.recall(db, pid, prompt, 5)
        text = me.format_lessons(rows)
        if expected.lower() in text.lower(): recall_hits += 1

    before = db.execute("SELECT COUNT(*) FROM candidates").fetchone()[0]
    transient = {"session_id":"transient","cwd":str(project),"tool_name":"Bash","tool_input":{"command":"curl https://service"},"error":"Exit code 1\nConnection reset by peer","is_interrupt":False}
    me.upsert_candidate(db, pid, transient)
    after = db.execute("SELECT COUNT(*) FROM candidates").fetchone()[0]

    # Hot-path guard latency, in process, across a mixture of allowed and denied calls.
    samples = []
    commands = [TRAINING[0][0], UNRELATED[0]] * 100
    for cmd in commands:
        t0 = time.perf_counter()
        me.run_guard(db, pid, {"tool_name":"Bash","tool_input":{"command":cmd}})
        samples.append((time.perf_counter() - t0) * 1000)
    samples.sort()
    p95 = samples[int(len(samples) * 0.95) - 1]

    active_lessons = db.execute("SELECT COUNT(*) FROM lessons WHERE status='active'").fetchone()[0]
    active_guards = db.execute("SELECT COUNT(*) FROM guards WHERE active=1").fetchone()[0]
    db.close()

    result = {
        "benchmark": "my-error deterministic A/B",
        "training_examples": len(TRAINING),
        "semantic_lessons": len(SOFT),
        "baseline": baseline,
        "with_my_error": {
            "known_mistakes_prevented": prevented,
            "known_mistake_prevention_rate": prevented / len(TRAINING),
            "semantic_recall_hits": recall_hits,
            "semantic_recall_rate": recall_hits / len(SOFT),
            "false_blocks": false_blocks,
            "transient_failure_ignored": before == after,
            "active_lessons": active_lessons,
            "active_guards": active_guards,
            "guard_hot_path_p95_ms": round(p95, 3)
        },
        "pass": prevented == len(TRAINING) and recall_hits == len(SOFT) and false_blocks == 0 and before == after
    }
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result["pass"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
