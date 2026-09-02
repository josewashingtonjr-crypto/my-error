import json
import re
import os
import sqlite3
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "my_error.py"


def me_version() -> str:
    src = (ROOT / 'scripts' / 'my_error.py').read_text()
    return re.search(r'VERSION = "([^"]+)"', src).group(1)


# Bumped with SCHEMA_VERSION in my_error.py; named so a schema bump touches one line.
SCHEMA_VERSION_EXPECTED = 4


class MyErrorTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.project = Path(self.tmp.name) / "project"
        self.data = Path(self.tmp.name) / "data"
        self.project.mkdir(); self.data.mkdir()
        self.env = os.environ.copy()
        self.env["MY_ERROR_DATA_DIR"] = str(self.data)
        self.env["CLAUDE_PROJECT_DIR"] = str(self.project)
        # Guard-behaviour tests must name the mode they exercise; the product
        # default is SHADOW and a test that silently depended on it would be
        # asserting a default rather than a behaviour.
        self.env["MY_ERROR_MODE"] = "ENFORCE"

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, *args, event=None, project=None, mode=None, locale=None, origin=None):
        env = self.env.copy()
        if locale is not None:
            env["LC_ALL"] = locale; env["LANG"] = locale; env.pop("LC_MESSAGES", None)
        if project is not None:
            env["CLAUDE_PROJECT_DIR"] = str(project)
        if mode is not None:
            env["MY_ERROR_MODE"] = mode
        if origin is not None:
            env["MY_ERROR_EVENT_ORIGIN"] = origin
        p = subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            input=(json.dumps(event) if event is not None else None),
            text=True, capture_output=True, env=env, cwd=str(project or self.project),
        )
        return p

    def hook(self, kind, event, project=None, mode=None, locale=None, origin=None):
        p = self.run_cli("hook", kind, event=event, project=project, mode=mode, locale=locale, origin=origin)
        self.assertEqual(p.returncode, 0, p.stderr)
        return json.loads(p.stdout) if p.stdout.strip() else None

    def candidate_count(self):
        db = sqlite3.connect(self.data / "my-error.db")
        try: return db.execute("select count(*) from candidates").fetchone()[0]
        finally: db.close()

    def lesson_count(self):
        db = sqlite3.connect(self.data / "my-error.db")
        try: return db.execute("select count(*) from lessons where status='active'").fetchone()[0]
        except sqlite3.OperationalError: return 0  # schema never created: nothing was written
        finally: db.close()

    def train_pair(self, bad, error, good, sid="s1", locale=None, origin=None):
        fail = {
            "session_id": sid, "cwd": str(self.project), "hook_event_name": "PostToolUseFailure",
            "tool_name": "Bash", "tool_input": {"command": bad}, "error": error, "is_interrupt": False
        }
        success = {
            "session_id": sid, "cwd": str(self.project), "hook_event_name": "PostToolUse",
            "tool_name": "Bash", "tool_input": {"command": good},
            "tool_response": {"stdout": "ok", "stderr": "", "interrupted": False, "isImage": False}
        }
        out1 = self.hook("failure", fail, locale=locale, origin=origin)
        out2 = self.hook("success", success, locale=locale, origin=origin)
        return out1, out2

    def confirm_prediction(self, bad, sid, origin=None, mode="SHADOW"):
        """Guard fires, then the same command fails again: a confirmed prediction."""
        repeat = {"session_id": sid, "cwd": str(self.project), "tool_name": "Bash", "tool_input": {"command": bad}}
        self.hook("guard", repeat, mode=mode, origin=origin)
        self.hook("failure", {**repeat, "error": "same failure again", "is_interrupt": False}, mode=mode, origin=origin)

    def refute_prediction(self, bad, sid, origin=None, mode="SHADOW"):
        """Guard fires, then the same command succeeds: a refuted (false-positive) prediction."""
        repeat = {"session_id": sid, "cwd": str(self.project), "tool_name": "Bash", "tool_input": {"command": bad}}
        self.hook("guard", repeat, mode=mode, origin=origin)
        self.hook("success", {**repeat, "tool_response": {"stdout": "ok"}}, mode=mode, origin=origin)

    def test_marketplace_shape(self):
        marketplace = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text())
        self.assertEqual(marketplace["name"], "my-error-local")
        self.assertEqual(len(marketplace["plugins"]), 1)
        entry = marketplace["plugins"][0]
        self.assertEqual(entry["name"], "my-error")
        self.assertEqual(entry["source"], ".")
        self.assertEqual(entry["version"], me_version())

    def test_manifest_and_hooks_shape(self):
        manifest = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text())
        hooks = json.loads((ROOT / "hooks" / "hooks.json").read_text())
        self.assertEqual(manifest["name"], "my-error")
        for name in ["SessionStart","UserPromptSubmit","PreToolUse","PostToolUseFailure","PostToolUse","Stop","SessionEnd"]:
            self.assertIn(name, hooks["hooks"])
        for path in ROOT.glob("skills/*/SKILL.md"):
            self.assertIn("name:", path.read_text())

    def test_transient_and_interrupt_are_not_learned(self):
        transient = {"session_id":"s","cwd":str(self.project),"tool_name":"Bash","tool_input":{"command":"curl https://x"},"error":"Exit code 1\nConnection reset by peer","is_interrupt":False}
        interrupted = {"session_id":"s","cwd":str(self.project),"tool_name":"Bash","tool_input":{"command":"sleep 10"},"error":"aborted","is_interrupt":True}
        self.assertIsNone(self.hook("failure", transient))
        self.assertIsNone(self.hook("failure", interrupted))
        self.assertEqual(self.candidate_count(), 0)

    def test_secret_redaction(self):
        event = {"session_id":"s","cwd":str(self.project),"tool_name":"Bash","tool_input":{"command":"deploy api_key=supersecret123 token=abcdefghijk"},"error":"Exit code 1\ncommand not found","is_interrupt":False}
        self.hook("failure", event)
        db = sqlite3.connect(self.data / "my-error.db")
        row = db.execute("select bad_action from candidates").fetchone()[0]
        db.close()
        self.assertNotIn("supersecret123", row)
        self.assertNotIn("abcdefghijk", row)
        self.assertIn("[REDACTED]", row)

    def test_auto_verified_recovery_learns_and_guards(self):
        _, out = self.train_pair("npm run buil", "Exit code 1\nnpm ERR! Missing script: buil", "npm run build")
        self.assertIn("Verified recovery", out["hookSpecificOutput"]["additionalContext"])
        self.assertEqual(self.lesson_count(), 1)
        pre = {"session_id":"s2","cwd":str(self.project),"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"npm run buil"}}
        blocked = self.hook("guard", pre)
        h = blocked["hookSpecificOutput"]
        self.assertEqual(h["permissionDecision"], "deny")
        self.assertIn("npm run build", h["permissionDecisionReason"])
        pre_good = dict(pre); pre_good["tool_input"] = {"command":"npm run build"}
        self.assertIsNone(self.hook("guard", pre_good))

    def test_multiple_auto_recovery_families(self):
        pairs = [
            ("python app.py", "Exit code 127\npython: command not found", "python3 app.py"),
            ("pytest test/test_api.py", "Exit code 4\nERROR: file or directory not found: test/test_api.py\nNo such file or directory", "pytest tests/test_api.py"),
            ("git checkout mian", "Exit code 1\nerror: pathspec 'mian' did not match any file(s) known to git", "git checkout main"),
            ("ruff check --fixx .", "Exit code 2\nerror: unknown option '--fixx'", "ruff check --fix ."),
            ("node scrpt.js", "Exit code 1\nError: No such file or directory: scrpt.js", "node script.js"),
        ]
        for i, (bad, err, good) in enumerate(pairs):
            self.train_pair(bad, err, good, sid=f"s{i}")
        self.assertEqual(self.lesson_count(), len(pairs))
        for bad, _, _ in pairs:
            pre = {"session_id":"repeat","cwd":str(self.project),"tool_name":"Bash","tool_input":{"command":bad}}
            out = self.hook("guard", pre)
            self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_ambiguous_test_failure_stays_candidate(self):
        fail = {"session_id":"s","cwd":str(self.project),"tool_name":"Bash","tool_input":{"command":"npm test"},"error":"Exit code 1\n2 tests failed\nAssertionError expected 2 got 3","is_interrupt":False}
        success = {"session_id":"s","cwd":str(self.project),"tool_name":"Bash","tool_input":{"command":"npm test"},"tool_response":{"stdout":"pass"}}
        self.hook("failure", fail); self.hook("success", success)
        self.assertEqual(self.candidate_count(), 1)
        self.assertEqual(self.lesson_count(), 0)

    def test_manual_lesson_is_recalled_by_prompt(self):
        p = self.run_cli("learn", "--scope", "project", "--title", "Generated Prisma client", "--cause", "Generated code was edited directly", "--rule", "Edit prisma/schema.prisma and regenerate the client instead of editing generated client files.", "--confidence", "verified", "--tags", "prisma,schema,generated")
        self.assertEqual(p.returncode, 0, p.stderr)
        event = {"session_id":"s","cwd":str(self.project),"prompt":"Update the Prisma generated client after changing the schema"}
        out = self.hook("prompt", event)
        self.assertIn("prisma/schema.prisma", out["hookSpecificOutput"]["additionalContext"])

    def test_manual_write_guard_blocks_precise_pattern(self):
        p = self.run_cli("learn", "--scope", "project", "--title", "Do not edit generated file", "--cause", "File is generated", "--rule", "Do not write generated/client.ts directly.", "--confidence", "verified", "--guard-tool", "Write", "--guard-field", "file_path", "--guard-match", "contains", "--guard-pattern", "generated/client.ts", "--guard-reason", "Generated file must be regenerated")
        self.assertEqual(p.returncode, 0, p.stderr)
        event = {"session_id":"s","cwd":str(self.project),"tool_name":"Write","tool_input":{"file_path":str(self.project / 'generated/client.ts'),"content":"x"}}
        out = self.hook("guard", event)
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_forget_disables_guard(self):
        self.train_pair("npm run buil", "Exit code 1\nMissing script: buil", "npm run build")
        p = self.run_cli("forget", "ERR-0001")
        self.assertEqual(p.returncode, 0, p.stderr)
        pre = {"session_id":"s","cwd":str(self.project),"tool_name":"Bash","tool_input":{"command":"npm run buil"}}
        self.assertIsNone(self.hook("guard", pre))

    def test_project_scope_isolation(self):
        self.train_pair("npm run buil", "Exit code 1\nMissing script: buil", "npm run build")
        other = Path(self.tmp.name) / "other"; other.mkdir()
        pre = {"session_id":"s","cwd":str(other),"tool_name":"Bash","tool_input":{"command":"npm run buil"}}
        self.assertIsNone(self.hook("guard", pre, project=other))

    def test_similar_but_unrelated_success_is_not_auto_learned(self):
        fail = {
            "session_id":"s-near","cwd":str(self.project),"tool_name":"Bash",
            "tool_input":{"command":"npm run buil"},
            "error":"Exit code 1\nMissing script: buil","is_interrupt":False
        }
        self.hook("failure", fail)
        unrelated_success = {
            "session_id":"s-near","cwd":str(self.project),"tool_name":"Bash",
            "tool_input":{"command":"npm run lint"}
        }
        self.hook("success", unrelated_success)
        self.assertEqual(self.lesson_count(), 0)
        repeated = {
            "session_id":"s-near","cwd":str(self.project),"tool_name":"Bash",
            "tool_input":{"command":"npm run buil"}
        }
        self.assertIsNone(self.hook("guard", repeated))

    def test_unrelated_command_not_blocked(self):
        self.train_pair("npm run buil", "Exit code 1\nMissing script: buil", "npm run build")
        pre = {"session_id":"s","cwd":str(self.project),"tool_name":"Bash","tool_input":{"command":"npm run lint"}}
        self.assertIsNone(self.hook("guard", pre))


    def test_semantic_recovery_requests_one_stop_review(self):
        fail = {"session_id":"sem","cwd":str(self.project),"tool_name":"Bash","tool_input":{"command":"npm test"},"error":"Exit code 1\n2 tests failed\nAssertionError expected 2 got 3","is_interrupt":False}
        success = {"session_id":"sem","cwd":str(self.project),"tool_name":"Bash","tool_input":{"command":"npm test"},"tool_response":{"stdout":"all tests passed"}}
        self.hook("failure", fail)
        self.hook("success", success)
        stop = {"session_id":"sem","cwd":str(self.project),"hook_event_name":"Stop","stop_hook_active":False}
        out = self.hook("stop", stop)
        self.assertIn("my-error:learn", out["hookSpecificOutput"]["additionalContext"])
        # Review request is one-shot to avoid a stop loop.
        self.assertIsNone(self.hook("stop", stop))

    # ------------------------------------------------------------------
    # Verified-mistake learning: the error classes no exit code can capture.
    # ------------------------------------------------------------------

    def test_stop_asks_the_reflection_question_when_no_candidate_has_evidence(self):
        """Scenario B/C: a session whose mistakes were logic or judgment errors.

        Nothing failed, so nothing was captured, so the candidate path has
        nothing to offer — which is precisely when the reflection prompt has to
        fire. Without it the most valuable class of lesson has no trigger at
        all.
        """
        stop = {"session_id": "quiet", "cwd": str(self.project), "hook_event_name": "Stop", "stop_hook_active": False}
        out = self.hook("stop", stop)
        self.assertIsNotNone(out)
        ctx = out["hookSpecificOutput"]["additionalContext"]
        self.assertIn("NOT", ctx)
        self.assertIn("failed command", ctx)
        # Names the manual path, so the escape hatch is not folklore.
        self.assertIn("--candidate-id", ctx)

    def test_reflection_is_asked_once_per_session_not_every_turn(self):
        """Stop fires at the end of every turn; an unthrottled prompt is noise."""
        stop = {"session_id": "once", "cwd": str(self.project), "hook_event_name": "Stop", "stop_hook_active": False}
        self.assertIsNotNone(self.hook("stop", stop))
        self.assertIsNone(self.hook("stop", stop))
        self.assertIsNone(self.hook("stop", stop))
        # A different session gets its own single ask.
        other = dict(stop, session_id="another")
        self.assertIsNotNone(self.hook("stop", other))

    def test_candidate_review_and_reflection_never_both_fire_in_one_session(self):
        """Two prompts competing for the same action train the reader to skim."""
        fail = {"session_id": "both", "cwd": str(self.project), "tool_name": "Bash",
                "tool_input": {"command": "npm test"}, "error": "Exit code 1\nAssertionError", "is_interrupt": False}
        success = {"session_id": "both", "cwd": str(self.project), "tool_name": "Bash",
                   "tool_input": {"command": "npm test"}, "tool_response": {"stdout": "all tests passed"}}
        self.hook("failure", fail)
        self.hook("success", success)
        stop = {"session_id": "both", "cwd": str(self.project), "hook_event_name": "Stop", "stop_hook_active": False}
        first = self.hook("stop", stop)
        self.assertIn("my-error:learn", first["hookSpecificOutput"]["additionalContext"])
        self.assertNotIn("NOT simply a failed command", first["hookSpecificOutput"]["additionalContext"])
        self.assertIsNone(self.hook("stop", stop))

    def test_lesson_without_candidate_is_stored_and_recalled(self):
        """Scenario B: a verified logic bug where every command exited zero.

        This is the ERR-0011/0013/0014 shape — found by reading code, verified
        by a regression test, never once producing a failed tool call. It must
        be a first-class lesson, and it must come back on a later prompt.
        """
        p = self.run_cli(
            "learn",
            "--title", "catch inside one PG transaction does not degrade",
            "--cause", "seven reads shared one transaction; a raise aborts it and the catch cannot undo that",
            "--rule", "move the reads out of the transaction, or use a SAVEPOINT per read",
            "--confidence", "verified", "--scope", "global", "--tags", "postgres,transaction",
        )
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("Learned ERR-", p.stdout)
        self.assertEqual(self.lesson_count(), 1)
        self.assertEqual(self.candidate_count(), 0, "a manual lesson must not invent a candidate")

        db = sqlite3.connect(self.data / "my-error.db")
        try:
            row = db.execute("select source, source_candidate_id, scope from lessons").fetchone()
        finally:
            db.close()
        self.assertEqual(row[0], "manual-verified")
        self.assertIsNone(row[1], "no candidate means no candidate id, not a fabricated one")
        self.assertEqual(row[2], "global")

        recalled = self.hook("prompt", {"session_id": "later", "cwd": str(self.project),
                                        "prompt": "wrap these postgres queries in a transaction"})
        self.assertIsNotNone(recalled, "a manually recorded lesson must be injectable like any other")
        self.assertIn("SAVEPOINT", recalled["hookSpecificOutput"]["additionalContext"])

    def test_learn_still_rejects_a_candidate_id_that_does_not_exist(self):
        """The manual path widens what may be learned, never what may be claimed."""
        p = self.run_cli("learn", "--scope", "project", "--candidate-id", "9999", "--title", "t",
                         "--cause", "c", "--rule", "r", "--confidence", "verified")
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("not found", p.stderr)
        self.assertEqual(self.lesson_count(), 0)

    # ------------------------------------------------------------------
    # Project identity. Measured from real hook payloads on 2026-09-02:
    # CLAUDE_PROJECT_DIR is the session's launch directory and never moves,
    # while event["cwd"] follows the tool. Preferring the env var filed every
    # repository under one home-directory namespace.
    # ------------------------------------------------------------------

    def _mkrepo(self, name):
        d = Path(self.tmp.name) / name
        d.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", "-q"], cwd=str(d), check=True)
        return d

    def _pid_of(self, root, event_cwd=None):
        """The namespace a hook would file work under, read back from the DB."""
        ev = {"session_id": "id", "cwd": str(event_cwd or root), "tool_name": "Bash",
              "tool_input": {"command": "true"}, "tool_response": {"stdout": "ok"}}
        self.hook("success", ev, project=root)
        db = sqlite3.connect(self.data / "my-error.db")
        try:
            rows = {r[1]: (r[0], r[2]) for r in db.execute("select id, root, kind from projects")}
        finally:
            db.close()
        return rows

    def test_two_repos_under_one_session_root_get_separate_namespaces(self):
        """Fidren and Livara must not share a lesson store by accident."""
        a, b = self._mkrepo("fidren"), self._mkrepo("livara")
        # Session launched at the shared parent, tools operating inside each repo.
        home = Path(self.tmp.name)
        self.env["CLAUDE_PROJECT_DIR"] = str(home)
        rows = self._pid_of(home, event_cwd=a)
        rows = self._pid_of(home, event_cwd=b)
        roots = set(rows)
        self.assertIn(str(a), roots, f"tool cwd inside the repo must win over the session root: {roots}")
        self.assertIn(str(b), roots)
        self.assertNotEqual(rows[str(a)][0], rows[str(b)][0], "two repos, two namespaces")
        self.assertEqual(rows[str(a)][1], "git")
        self.assertEqual(rows[str(b)][1], "git")

    def test_session_started_inside_the_repo_lands_in_the_same_namespace(self):
        """The namespace must not depend on where Claude Code happened to start."""
        a = self._mkrepo("fidren")
        home = Path(self.tmp.name)
        self.env["CLAUDE_PROJECT_DIR"] = str(home)
        from_home = self._pid_of(home, event_cwd=a)[str(a)][0]
        self.env["CLAUDE_PROJECT_DIR"] = str(a)
        from_repo = self._pid_of(a, event_cwd=a)[str(a)][0]
        self.assertEqual(from_home, from_repo,
                         "same repository, so same lessons, whichever directory the session opened in")

    def test_linked_worktree_shares_the_repository_identity(self):
        """Preserved from the earlier decision: worktrees are one repository."""
        a = self._mkrepo("fidren")
        (a / "f.txt").write_text("x")
        subprocess.run(["git", "add", "-A"], cwd=str(a), check=True)
        subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "i"],
                       cwd=str(a), check=True)
        wt = Path(self.tmp.name) / "fidren-wt"
        r = subprocess.run(["git", "worktree", "add", "-q", str(wt), "-b", "side"],
                           cwd=str(a), capture_output=True, text=True)
        if r.returncode != 0:
            self.skipTest("git worktree unavailable")
        rows = self._pid_of(a, event_cwd=a)
        main_pid = rows[str(a)][0]
        before = len(rows)
        rows = self._pid_of(a, event_cwd=wt)
        # The worktree resolves onto the repository's existing identity, so no
        # new namespace appears and the stored root stays the one first seen.
        # Counting rows is the assertion; looking the worktree path up by root
        # would find nothing precisely *because* the behaviour is correct.
        self.assertEqual(len(rows), before, f"a linked worktree must not mint a namespace: {rows}")
        self.assertIn(main_pid, {v[0] for v in rows.values()})

    def test_directory_without_git_is_marked_not_invented(self):
        """No repository means the identity is a path, and says so."""
        plain = Path(self.tmp.name) / "loose"
        plain.mkdir()
        rows = self._pid_of(plain, event_cwd=plain)
        self.assertIn(rows[str(plain)][1], ("directory", "workspace"))
        self.assertNotEqual(rows[str(plain)][1], "git")

    def test_cli_lesson_is_attributed_to_the_repo_it_was_written_in(self):
        """Provenance must name the repository that paid for the lesson.

        `learn` runs as a CLI call with no hook payload, so if the session's
        launch directory won here, a lesson written while working inside a
        repository would record the workspace as its origin — the same defect
        as the hook path, one level down. Caught by running the real
        cross-project proof, not by review.
        """
        repo = self._mkrepo("fidren")
        self.env["CLAUDE_PROJECT_DIR"] = str(Path(self.tmp.name))  # session opened at the parent
        p = self.run_cli("learn", "--scope", "global", "--title", "t", "--cause", "c",
                         "--rule", "r", "--confidence", "verified", project=repo)
        self.assertEqual(p.returncode, 0, p.stderr)
        db = sqlite3.connect(self.data / "my-error.db"); db.row_factory = sqlite3.Row
        try:
            origin = db.execute("select origin_project_id from lessons where id=1").fetchone()[0]
            root = db.execute("select root from projects where id=?", (origin,)).fetchone()[0]
        finally:
            db.close()
        self.assertEqual(root, str(repo), "origin must be the repository, not the session root")

    # ------------------------------------------------------------------
    # Scope: an audited, identity-preserving move.
    # ------------------------------------------------------------------

    def test_scope_promotion_preserves_identity_and_records_an_audit_row(self):
        self.run_cli("learn", "--scope", "project", "--title", "SLI measuring itself",
                     "--cause", "the metric was derived from the collector it was judging",
                     "--rule", "a stopped series must read as bad, never as healthy",
                     "--confidence", "verified", "--tags", "observability")
        db = sqlite3.connect(self.data / "my-error.db"); db.row_factory = sqlite3.Row
        before = dict(db.execute("select * from lessons where id=1").fetchone()); db.close()

        p = self.run_cli("scope", "ERR-0001", "global", "--reason", "observability principle, not Fidren's")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("PROJECT -> GLOBAL", p.stdout)

        db = sqlite3.connect(self.data / "my-error.db"); db.row_factory = sqlite3.Row
        after = dict(db.execute("select * from lessons where id=1").fetchone())
        audit = dict(db.execute("select * from lesson_scope_changes where lesson_id=1").fetchone())
        db.close()
        # Everything that identifies the lesson survives.
        for field in ("id", "title", "cause", "rule_text", "confidence", "source",
                      "created_at", "use_count", "origin", "origin_project_id", "tags"):
            self.assertEqual(before[field], after[field], f"{field} must survive a scope change")
        self.assertEqual(after["scope"], "global")
        self.assertIsNone(after["project_id"], "a global lesson belongs to no project")
        self.assertIsNotNone(after["origin_project_id"], "promotion must not erase where it was learned")
        self.assertEqual((audit["old_scope"], audit["new_scope"]), ("project", "global"))
        self.assertIn("Fidren", audit["reason"])

    def test_scope_is_idempotent_and_rejects_unknown_lessons(self):
        self.run_cli("learn", "--scope", "global", "--title", "t", "--cause", "c",
                     "--rule", "r", "--confidence", "verified")
        p = self.run_cli("scope", "ERR-0001", "global")
        self.assertEqual(p.returncode, 0)
        self.assertIn("already GLOBAL", p.stdout)
        db = sqlite3.connect(self.data / "my-error.db")
        try:
            self.assertEqual(db.execute("select count(*) from lesson_scope_changes").fetchone()[0], 0,
                             "a no-op must not write an audit row")
        finally:
            db.close()
        self.assertNotEqual(self.run_cli("scope", "ERR-9999", "global").returncode, 0)

    def test_learn_refuses_to_guess_the_scope(self):
        """The silent `project` default is how a universal rule gets stranded."""
        p = self.run_cli("learn", "--title", "t", "--cause", "c", "--rule", "r", "--confidence", "verified")
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("--scope", p.stderr)
        # argparse refuses before anything opens the database, so there may be
        # no schema at all -- which is the strongest form of "nothing was
        # written", not a reason to skip the check.
        self.assertEqual(self.lesson_count() if (self.data / "my-error.db").exists() else 0, 0)

    # ------------------------------------------------------------------
    # The thesis: knowledge paid for in one project, recovered in another.
    # ------------------------------------------------------------------

    def test_global_lesson_learned_in_one_repo_is_recalled_in_another(self):
        a, b = self._mkrepo("fidren"), self._mkrepo("livara")
        self.env["CLAUDE_PROJECT_DIR"] = str(a)
        p = self.run_cli("learn", "--scope", "global", "--title", "PG transaction abort",
                         "--cause", "a caught query error still aborts the transaction",
                         "--rule", "move the reads out of the transaction, or use a SAVEPOINT per read",
                         "--confidence", "verified", "--scope-reason", "PostgreSQL semantics, not this repo",
                         "--tags", "postgres,transaction", project=a)
        self.assertEqual(p.returncode, 0, p.stderr)

        # Now working in the *other* repository.
        out = self.hook("prompt", {"session_id": "x", "cwd": str(b),
                                   "prompt": "wrap these postgres queries in one transaction"}, project=b)
        self.assertIsNotNone(out, "a global lesson must cross the project boundary")
        self.assertIn("SAVEPOINT", out["hookSpecificOutput"]["additionalContext"])

        db = sqlite3.connect(self.data / "my-error.db"); db.row_factory = sqlite3.Row
        ev = dict(db.execute("select * from recall_events order by id desc limit 1").fetchone())
        roots = {r[0]: r[1] for r in db.execute("select id, root from projects")}
        db.close()
        self.assertEqual(ev["cross_project"], 1, "recalled somewhere other than where it was learned")
        self.assertEqual(roots[ev["origin_project_id"]], str(a))
        self.assertEqual(roots[ev["consuming_project_id"]], str(b))

    def test_project_lesson_does_not_leak_into_another_repo(self):
        """Transfer must be a decision, not the absence of separation."""
        a, b = self._mkrepo("fidren"), self._mkrepo("livara")
        self.env["CLAUDE_PROJECT_DIR"] = str(a)
        self.run_cli("learn", "--scope", "project", "--title", "local script path",
                     "--cause", "wrong helper invoked", "--rule",
                     "in this repository the deploy helper is scripts/deploy-fidren.sh",
                     "--confidence", "verified", "--tags", "deploy", project=a)
        out = self.hook("prompt", {"session_id": "y", "cwd": str(b),
                                   "prompt": "which deploy helper script should I run"}, project=b)
        self.assertIsNone(out, "a repository-specific rule must not travel")

    def test_expired_guard_fails_open(self):
        self.train_pair("npm run buil", "Exit code 1\nMissing script: buil", "npm run build")
        db = sqlite3.connect(self.data / "my-error.db")
        db.execute("update guards set expires_at='2000-01-01T00:00:00+00:00' where id=1")
        db.commit(); db.close()
        pre = {"session_id":"s","cwd":str(self.project),"tool_name":"Bash","tool_input":{"command":"npm run buil"}}
        self.assertIsNone(self.hook("guard", pre))

    def test_concurrent_duplicate_failure_capture_is_atomic(self):
        """Every racing hook must be counted, including the ones that arrive
        while the schema is still being built.

        This used to fail intermittently (7 of 8, 6 of 8). The counter was never
        the problem -- `occurrences=occurrences+1` runs in SQLite and is atomic.
        The loss was upstream, in `connect()`: each process read the schema
        state without holding a write lock, all of them concluded the migration
        was still pending, and the losers of the resulting
        `ALTER TABLE ... ADD COLUMN` race raised "duplicate column name", which
        is not a lock error and so was re-raised past `with_retry` and swallowed
        by the exit-0 catch-all in `main()`. A fresh data directory is therefore
        essential to this test: a warm database never reproduced it.
        """
        from concurrent.futures import ThreadPoolExecutor
        n = 8
        event = {"session_id":"parallel","cwd":str(self.project),"tool_name":"Bash","tool_input":{"command":"npm run buil"},"error":"Exit code 1\nMissing script: buil","is_interrupt":False}
        def one(_):
            p = self.run_cli("hook", "failure", event=event)
            return p.returncode, p.stderr
        # Every worker must be able to start at once; a pool narrower than the
        # task count serialises the very collision under test.
        with ThreadPoolExecutor(max_workers=n) as ex:
            results = list(ex.map(one, range(n)))
        self.assertTrue(all(code == 0 for code, _ in results), results)
        db = sqlite3.connect(self.data / "my-error.db")
        row = db.execute("select count(*), max(occurrences) from candidates").fetchone()
        # Exit 0 is not proof of capture -- that combination is exactly what made
        # this bug invisible -- so the swallow counter is part of the assertion.
        dropped = db.execute("select value from meta where key='dropped_events'").fetchone()
        db.close()
        self.assertEqual(row[0], 1)
        self.assertEqual(row[1], n)
        self.assertIsNone(dropped, f"hooks silently swallowed events: {dropped}")

    def test_concurrent_cold_start_across_the_shared_paths(self):
        """New failure, duplicate failure and recovery, all racing a cold store.

        They share `candidates`, `meta` and the same write lock, so a lock or
        transaction defect in one is a defect in all three.
        """
        from concurrent.futures import ThreadPoolExecutor
        jobs = []
        for i in range(4):
            jobs.append(("failure", {"session_id":f"n{i}","cwd":str(self.project),"tool_name":"Bash",
                                     "tool_input":{"command":f"cat nope{i}.txt"},
                                     "error":f"cat: nope{i}.txt: No such file or directory","is_interrupt":False}))
        dup = {"session_id":"d","cwd":str(self.project),"tool_name":"Bash",
               "tool_input":{"command":"npm run buil"},"error":"Exit code 1\nMissing script: buil","is_interrupt":False}
        jobs += [("failure", dup)] * 4
        for i in range(4):
            jobs.append(("success", {"session_id":f"r{i}","cwd":str(self.project),"tool_name":"Bash",
                                     "tool_input":{"command":f"cat ok{i}.txt"}}))
        with ThreadPoolExecutor(max_workers=len(jobs)) as ex:
            codes = list(ex.map(lambda j: self.run_cli("hook", j[0], event=j[1]).returncode, jobs))
        self.assertTrue(all(c == 0 for c in codes), codes)
        db = sqlite3.connect(self.data / "my-error.db")
        distinct = db.execute("select count(*) from candidates where bad_action like 'cat nope%'").fetchone()[0]
        dup_occ = db.execute("select occurrences from candidates where bad_action='npm run buil'").fetchone()[0]
        dropped = db.execute("select value from meta where key='dropped_events'").fetchone()
        db.close()
        self.assertEqual(distinct, 4)
        self.assertEqual(dup_occ, 4)
        self.assertIsNone(dropped)

    def test_v11_node_entrypoint_pytest_and_module_typos_auto_learn(self):
        pairs = [
            ("node sever.js", "Error: Cannot find module '/tmp/project/sever.js'\ncode: MODULE_NOT_FOUND", "node server.js"),
            ("pytest tests/test_utitls.py -q", "ERROR: file or directory not found: tests/test_utitls.py", "pytest tests/test_utils.py -q"),
            ("pytest --versoin", "pytest: error: unrecognized arguments: --versoin", "pytest --version"),
            ("python3 -m unitest discover -s tests", "python3: No module named unitest", "python3 -m unittest discover -s tests"),
            ("git chekout main", "git: 'chekout' is not a git command.", "git checkout main"),
        ]
        for i, (bad, err, good) in enumerate(pairs):
            self.train_pair(bad, err, good, sid=f"v11-{i}")
        self.assertEqual(self.lesson_count(), len(pairs))
        for bad, _, _ in pairs:
            out = self.hook("guard", {"session_id":"r","cwd":str(self.project),"tool_name":"Bash","tool_input":{"command":bad}})
            self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_v11_dependency_failure_does_not_mislearn_entrypoint(self):
        fail = {
            "session_id":"dep","cwd":str(self.project),"tool_name":"Bash",
            "tool_input":{"command":"node ap.js"},
            "error":"Error: Cannot find module 'express'\n    at /tmp/project/ap.js",
            "is_interrupt":False,
        }
        self.hook("failure", fail)
        self.hook("success", {"session_id":"dep","cwd":str(self.project),"tool_name":"Bash","tool_input":{"command":"node app.js"}})
        self.assertEqual(self.lesson_count(), 0)

    def test_v11_semantic_recall_ranks_money_rule_first(self):
        p = self.run_cli("learn", "--scope", "project", "--title", "Money precision", "--cause", "Binary floating point corrupted monetary values", "--rule", "Use decimal or integer minor units for money.", "--confidence", "verified", "--tags", "money,decimal,precision")
        self.assertEqual(p.returncode, 0, p.stderr)
        event = {"session_id":"sem2","cwd":str(self.project),"prompt":"Compute invoice totals and payment amounts"}
        out = self.hook("prompt", event)
        self.assertIn("Use decimal", out["hookSpecificOutput"]["additionalContext"])

    def test_doctor_and_status(self):
        d = self.run_cli("doctor", "--json"); s = self.run_cli("status")
        self.assertEqual(d.returncode, 0, d.stderr); self.assertEqual(s.returncode, 0, s.stderr)
        self.assertTrue(json.loads(d.stdout)["database_writable"])
        self.assertEqual(self.run_cli("doctor").returncode, 0)
        self.assertEqual(json.loads(s.stdout)["version"], me_version())

    # --- v1.2.0 regressions -------------------------------------------------

    def test_v12_localized_error_messages_auto_learn(self):
        """Family recognition must not depend on the machine locale."""
        pairs = [
            ("cat config.jon", "cat: config.jon: Arquivo ou diretorio inexistente", "cat config.json"),
            ("git sttaus", "git: 'sttaus' nao e um comando git. Veja 'git --help'.", "git status"),
            ("ls --colxr=never", 'ls: opcao nao reconhecida "--colxr=never"', "ls --color=never"),
            ("cat conf.jsn", "cat: conf.jsn: No existe el archivo o el directorio", "cat conf.json"),
            ("cat data.tx", "cat: data.tx: Aucun fichier ou dossier de ce type", "cat data.txt"),
        ]
        for i, (bad, err, good) in enumerate(pairs):
            self.train_pair(bad, err, good, sid=f"v12-loc-{i}")
        self.assertEqual(self.lesson_count(), len(pairs))
        for bad, _, _ in pairs:
            out = self.hook("guard", {"session_id": "r", "cwd": str(self.project),
                                      "tool_name": "Bash", "tool_input": {"command": bad}})
            self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_unknown_locale_falls_back_to_blamed_token(self):
        """Emergency cover: an untranslated message still learns when it names
        the changed token."""
        self.train_pair("cat rapport.tx",
                        "cat: rapport.tx: \u0424\u0430\u0439\u043b \u043d\u0435 \u043d\u0430\u0439\u0434\u0435\u043d",
                        "cat rapport.txt", sid="fb", locale="ru_RU.UTF-8")
        self.assertEqual(self.lesson_count(), 1)

    def test_recognized_locale_does_not_use_the_fallback(self):
        """In a covered language the heuristic must stay out of the way: an
        unrecognized message is left for human review, not guessed at."""
        self.train_pair("cat rapport.tx",
                        "cat: rapport.tx: \u0424\u0430\u0439\u043b \u043d\u0435 \u043d\u0430\u0439\u0434\u0435\u043d",
                        "cat rapport.txt", sid="nofb", locale="pt_BR.UTF-8")
        self.assertEqual(self.lesson_count(), 0)

    def test_doctor_reports_fallback_state_per_locale(self):
        d = json.loads(self.run_cli("doctor", "--json", locale="pt_BR.UTF-8").stdout)
        self.assertTrue(d["locale_recognized"]); self.assertFalse(d["fallback_active"])
        d = json.loads(self.run_cli("doctor", "--json", locale="ja_JP.UTF-8").stdout)
        self.assertFalse(d["locale_recognized"]); self.assertTrue(d["fallback_active"])

    def test_v12_fallback_ignores_stack_frames(self):
        """A traceback naming the entrypoint is not proof the entrypoint was wrong.
        Exercised in an unrecognized locale, where the fallback is actually live."""
        self.hook("failure", locale="ja_JP.UTF-8", event={
            "session_id": "v12-st", "cwd": str(self.project), "tool_name": "Bash",
            "tool_input": {"command": "python3 mai.py"},
            "error": "Traceback (most recent call last):\n  File \"mai.py\", line 1\nRuntimeError: boom",
            "is_interrupt": False,
        })
        self.hook("success", locale="ja_JP.UTF-8", event={"session_id": "v12-st", "cwd": str(self.project),
                              "tool_name": "Bash", "tool_input": {"command": "python3 main.py"}})
        self.assertEqual(self.lesson_count(), 0)

    def test_v12_guard_matches_command_containing_a_secret(self):
        bad = "curl -H 'api_key=abcdef123456' https://example.invalid/x"
        self.train_pair(bad, "curl: (6) Could not resolve host: no such file or directory",
                        "curl -H 'api_key=abcdef123456' https://example.invalid/y", sid="v12-sec")
        out = self.hook("guard", {"session_id": "r", "cwd": str(self.project),
                                  "tool_name": "Bash", "tool_input": {"command": bad}})
        self.assertIsNotNone(out)
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_v12_failed_posttooluse_is_not_a_success(self):
        self.hook("failure", {
            "session_id": "v12-err", "cwd": str(self.project), "tool_name": "Bash",
            "tool_input": {"command": "cat missng.txt"},
            "error": "cat: missng.txt: No such file or directory", "is_interrupt": False,
        })
        self.hook("success", {"session_id": "v12-err", "cwd": str(self.project),
                              "tool_name": "Bash", "tool_input": {"command": "cat missing.txt"},
                              "tool_response": {"is_error": True, "error": "still broken"}})
        self.assertEqual(self.lesson_count(), 0)

    def test_v12_hook_never_crashes_the_session(self):
        env = dict(os.environ, MY_ERROR_DATA_DIR="/proc/definitely/not/writable")
        p = subprocess.run([sys.executable, str(SCRIPT), "hook", "prompt"],
                           input="not json at all", text=True, capture_output=True, env=env)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.strip(), "")

    def test_v12_ignore_rejects_malformed_id(self):
        p = self.run_cli("ignore", "not-an-id")
        self.assertEqual(p.returncode, 2)

    # --- v0.3 watchdog / shadow-mode regressions ----------------------------

    def metrics(self, mode=None, origin=None):
        p = self.run_cli("metrics", mode=mode, origin=origin)
        self.assertEqual(p.returncode, 0, p.stderr)
        return json.loads(p.stdout)

    def test_shadow_is_the_default_mode(self):
        env = dict(self.env); env.pop("MY_ERROR_MODE", None)
        p = subprocess.run([sys.executable, str(SCRIPT), "mode"], text=True,
                           capture_output=True, env=env, cwd=str(self.project))
        self.assertEqual(p.stdout.strip(), "SHADOW")

    def test_shadow_records_but_does_not_block(self):
        self.train_pair("git sttaus", "git: 'sttaus' is not a git command.", "git status")
        repeat = {"session_id": "sh", "cwd": str(self.project), "tool_name": "Bash",
                  "tool_input": {"command": "git sttaus"}}
        self.assertIsNone(self.hook("guard", repeat, mode="SHADOW"))
        m = self.metrics(mode="SHADOW")
        self.assertEqual(m["mode"], "SHADOW")
        self.assertEqual(m["would_block_shadow"], 1)
        self.assertEqual(m["actual_blocks_enforce"], 0)

    def test_shadow_confirms_a_correct_prediction(self):
        self.train_pair("git sttaus", "git: 'sttaus' is not a git command.", "git status")
        repeat = {"session_id": "sh", "cwd": str(self.project), "tool_name": "Bash",
                  "tool_input": {"command": "git sttaus"}}
        self.hook("guard", repeat, mode="SHADOW")
        self.hook("failure", {**repeat, "error": "git: 'sttaus' is not a git command.",
                              "is_interrupt": False}, mode="SHADOW")
        m = self.metrics()
        self.assertEqual(m["predictions_confirmed_total"], 1)
        self.assertEqual(m["predictions_refuted_total"], 0)
        self.assertEqual(m["shadow_verdict_confirmed"], 1)   # natural_usage by default
        self.assertEqual(m["shadow_verdict_refuted"], 0)

    def test_shadow_measures_a_false_positive(self):
        """The point of SHADOW: a guard that lets a command run and sees it
        succeed has been proven wrong, rather than merely suspected."""
        self.train_pair("git sttaus", "git: 'sttaus' is not a git command.", "git status")
        repeat = {"session_id": "sh", "cwd": str(self.project), "tool_name": "Bash",
                  "tool_input": {"command": "git sttaus"}}
        self.hook("guard", repeat, mode="SHADOW")
        self.hook("success", {**repeat, "tool_response": {"stdout": "ok"}}, mode="SHADOW")
        m = self.metrics()
        self.assertEqual(m["predictions_refuted_total"], 1)
        self.assertEqual(m["predictions_confirmed_total"], 0)
        self.assertEqual(m["shadow_verdict_refuted"], 1)     # natural_usage by default
        self.assertEqual(m["shadow_verdict_confirmed"], 0)

    def test_enforce_blocks_and_is_counted_separately(self):
        self.train_pair("git sttaus", "git: 'sttaus' is not a git command.", "git status")
        repeat = {"session_id": "e", "cwd": str(self.project), "tool_name": "Bash",
                  "tool_input": {"command": "git sttaus"}}
        out = self.hook("guard", repeat, mode="ENFORCE")
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
        m = self.metrics()
        self.assertEqual(m["actual_blocks_enforce"], 1)
        self.assertEqual(m["would_block_shadow"], 0)

    def test_beacon_is_written_for_the_external_watchdog(self):
        self.hook("session-start", {"session_id": "beacon-1", "cwd": str(self.project)})
        beacon = json.loads((self.data / "runtime.json").read_text())
        self.assertEqual(beacon["session_id"], "beacon-1")
        self.assertEqual(beacon["last_hook"], "session-start")
        self.assertIn("mode", beacon)

    def test_verified_corrections_exclude_unproven_recoveries(self):
        """An observed recovery is not a verified correction."""
        self.hook("failure", {"session_id": "amb", "cwd": str(self.project), "tool_name": "Bash",
                              "tool_input": {"command": "pytest tests/"},
                              "error": "AssertionError: 1 != 2", "is_interrupt": False})
        self.hook("success", {"session_id": "amb", "cwd": str(self.project), "tool_name": "Bash",
                              "tool_input": {"command": "pytest tests/"}})
        m = self.metrics()
        self.assertEqual(m["failures_captured"], 1)
        self.assertEqual(m["verified_corrections"], 0)
        self.assertEqual(m["unverified_recoveries"], 1)

    def test_schema_migrates_from_v1_without_data_loss(self):
        self.train_pair("git sttaus", "git: 'sttaus' is not a git command.", "git status")
        db = sqlite3.connect(self.data / "my-error.db")
        db.execute("DROP TABLE guard_events")
        db.execute("PRAGMA user_version=1")
        db.commit(); db.close()
        m = self.metrics()          # reopening must migrate all the way to current
        self.assertEqual(m["lessons_active"], 1)
        db = sqlite3.connect(self.data / "my-error.db")
        try:
            self.assertEqual(int(db.execute("PRAGMA user_version").fetchone()[0]), SCHEMA_VERSION_EXPECTED)
            # Data present before the origin column existed is backfilled
            # controlled_test, never natural_usage, so it can't leak into the verdict.
            origin = db.execute("SELECT origin FROM lessons LIMIT 1").fetchone()[0]
            self.assertEqual(origin, "controlled_test")
        finally:
            db.close()

    def test_doctor_json_reports_locale_and_mode(self):
        d = json.loads(self.run_cli("doctor", "--json").stdout)
        self.assertIn("locale_recognized", d)
        self.assertIn("mode", d)
        self.assertTrue(d["hooks_declared"]["PostToolUseFailure"])

    # --- Q9-Q12 policy regressions -----------------------------------------

    def test_auto_lessons_are_excluded_from_prompt_recall(self):
        """Auto lessons feed the guard, not the context window."""
        self.train_pair("git sttaus", "git: 'sttaus' is not a git command.", "git status")
        self.assertEqual(self.lesson_count(), 1)
        out = self.hook("prompt", {"session_id": "r", "cwd": str(self.project),
                                   "prompt": "run git sttaus status for me"})
        self.assertIsNone(out)

    def test_auto_lesson_source_matches_the_recall_filter(self):
        """Guards the one coupling that would silently break Q10: creation and
        filtering must agree on what 'automatic' means."""
        self.train_pair("git sttaus", "git: 'sttaus' is not a git command.", "git status")
        db = sqlite3.connect(self.data / "my-error.db")
        try:
            src = db.execute("SELECT source FROM lessons").fetchone()[0]
        finally:
            db.close()
        out = self.run_cli("doctor", "--json")
        self.assertEqual(src, "auto-verified-recovery")

    def test_manual_lessons_are_still_recalled(self):
        self.run_cli("learn", "--scope", "project", "--title", "Money precision", "--cause", "float corrupted money",
                     "--rule", "Use decimal for money.", "--confidence", "verified", "--tags", "money")
        out = self.hook("prompt", {"session_id": "r", "cwd": str(self.project),
                                   "prompt": "compute invoice payment amounts"})
        self.assertIn("Use decimal", out["hookSpecificOutput"]["additionalContext"])

    def test_dormant_lessons_leave_recall_but_stay_stored(self):
        self.run_cli("learn", "--scope", "project", "--title", "Old rule", "--cause", "c", "--rule",
                     "Use decimal for money.", "--confidence", "verified", "--tags", "money")
        db = sqlite3.connect(self.data / "my-error.db")
        db.execute("UPDATE lessons SET updated_at='2020-01-01T00:00:00+00:00',"
                   " last_used='2020-01-01T00:00:00+00:00'")
        db.commit(); db.close()
        self.assertIsNone(self.hook("prompt", {"session_id": "r", "cwd": str(self.project),
                                               "prompt": "invoice payment amounts money"}))
        self.assertEqual(self.lesson_count(), 1)                     # stored
        self.assertIn("Old rule", self.run_cli("review").stdout)     # still auditable

    def test_worktrees_of_one_repo_share_a_namespace(self):
        import subprocess as sp
        repo = self.project / "repo"; repo.mkdir()
        run = lambda *a, cwd=repo: sp.run(a, cwd=str(cwd), capture_output=True, text=True)
        if run("git", "init", "-q").returncode != 0:
            self.skipTest("git unavailable")
        run("git", "config", "user.email", "t@t.invalid"); run("git", "config", "user.name", "T")
        (repo / "a.txt").write_text("x")
        run("git", "add", "-A"); run("git", "commit", "-qm", "init")
        wt = self.project / "wt"
        if run("git", "worktree", "add", "-q", str(wt), "-b", "feat").returncode != 0:
            self.skipTest("git worktree unavailable")
        a = json.loads(self.run_cli("metrics", project=repo).stdout)
        b = json.loads(self.run_cli("metrics", project=wt).stdout)
        self.assertEqual(a["project_id"], b["project_id"])       # same repository
        self.assertNotEqual(a["project_root"], b["project_root"])  # different directories

    def test_non_git_directory_falls_back_to_path_identity(self):
        m = json.loads(self.run_cli("metrics").stdout)
        self.assertEqual(m["project_identity"], m["project_root"])

    def test_shadow_verdict_is_precommitted_and_time_gated(self):
        d = json.loads(self.run_cli("doctor", "--json").stdout)
        self.assertIn(d["shadow_verdict"], ("NOT STARTED", "RUNNING"))

    # --- 0.3.1: one plugin, one database ------------------------------------

    def _isolated(self, **extra):
        """A HOME of our own, so canonical resolution can be exercised for real
        instead of being short-circuited by MY_ERROR_DATA_DIR."""
        home = Path(self.tmp.name) / "home"
        (home / ".claude" / "plugins" / "data").mkdir(parents=True, exist_ok=True)
        env = {k: v for k, v in self.env.items() if k != "MY_ERROR_DATA_DIR"}
        env["HOME"] = str(home)
        env.update(extra)
        return home, env

    def _run(self, env, *args, event=None, cwd=None):
        return subprocess.run([sys.executable, str(SCRIPT), *args],
                              input=(json.dumps(event) if event is not None else None),
                              text=True, capture_output=True, env=env,
                              cwd=str(cwd or self.project))

    def test_A_hook_context_resolves_to_canonical(self):
        """With CLAUDE_PLUGIN_DATA injected, the canonical path still wins."""
        home, env = self._isolated(CLAUDE_PLUGIN_DATA=str(Path(self.tmp.name) / "injected"))
        d = json.loads(self._run(env, "datadir").stdout)
        self.assertEqual(Path(d["data_dir"]),
                         home / ".claude" / "plugins" / "data" / "my-error")
        self.assertNotEqual(Path(d["data_dir"]), Path(self.tmp.name) / "injected")

    def test_B_skill_context_resolves_to_the_same_place(self):
        """Without CLAUDE_PLUGIN_DATA -- the skill/CLI case that was broken."""
        home, env = self._isolated()
        hook_env = dict(env, CLAUDE_PLUGIN_DATA=str(Path(self.tmp.name) / "injected"))
        a = json.loads(self._run(hook_env, "datadir").stdout)["data_dir"]
        b = json.loads(self._run(env, "datadir").stdout)["data_dir"]
        self.assertEqual(a, b)
        for cmd in ("status", "review", "doctor"):
            self.assertEqual(self._run(env, cmd).returncode, 0)

    def test_C_hook_writes_are_visible_to_status(self):
        home, env = self._isolated()
        hook_env = dict(env, CLAUDE_PLUGIN_DATA=str(Path(self.tmp.name) / "injected"),
                        MY_ERROR_MODE="ENFORCE")
        ev = {"session_id": "x", "cwd": str(self.project), "tool_name": "Bash",
              "tool_input": {"command": "cat nope.txt"},
              "error": "cat: nope.txt: No such file or directory", "is_interrupt": False}
        self.assertEqual(self._run(hook_env, "hook", "failure", event=ev).returncode, 0)
        m = json.loads(self._run(env, "metrics").stdout)   # skill context
        self.assertEqual(m["failures_captured"], 1)

    def test_D_manual_lesson_is_visible_to_the_hook_path(self):
        home, env = self._isolated()
        self.assertEqual(self._run(env, "learn", "--scope", "project", "--title", "T", "--cause", "C",
                                   "--rule", "Use decimal for money.",
                                   "--confidence", "verified", "--tags", "money").returncode, 0)
        hook_env = dict(env, CLAUDE_PLUGIN_DATA=str(Path(self.tmp.name) / "injected"))
        out = self._run(hook_env, "hook", "prompt",
                        event={"session_id": "x", "cwd": str(self.project),
                               "prompt": "invoice payment amounts money"})
        self.assertIn("Use decimal", out.stdout)

    def test_E_reading_from_another_project_hits_the_same_database(self):
        home, env = self._isolated()
        other = Path(self.tmp.name) / "other-project"; other.mkdir()
        a = json.loads(self._run(env, "datadir").stdout)["data_dir"]
        b = json.loads(self._run(dict(env, CLAUDE_PROJECT_DIR=str(other)),
                                 "datadir", cwd=other).stdout)
        self.assertEqual(a, b["data_dir"])                       # same installation database
        ma = json.loads(self._run(env, "metrics").stdout)
        mb = json.loads(self._run(dict(env, CLAUDE_PROJECT_DIR=str(other)),
                                  "metrics", cwd=other).stdout)
        self.assertNotEqual(ma["project_id"], mb["project_id"])   # separate namespaces

    def test_F_no_command_recreates_the_phantom_fallback(self):
        home, env = self._isolated()
        phantom = home / ".claude" / "my-error"
        for cmd in (("doctor",), ("status",), ("review",), ("metrics",), ("datadir",)):
            self._run(env, *cmd)
        self._run(dict(env, CLAUDE_PLUGIN_DATA=str(Path(self.tmp.name) / "injected")),
                  "hook", "session-start",
                  event={"session_id": "x", "cwd": str(self.project)})
        self.assertFalse(phantom.exists(), f"phantom database reappeared at {phantom}")

    def test_legacy_database_is_adopted_not_duplicated(self):
        home, env = self._isolated()
        legacy = home / ".claude" / "plugins" / "data" / "my-error-inline"
        legacy.mkdir(parents=True)
        seed = dict(env, MY_ERROR_DATA_DIR=str(legacy), MY_ERROR_MODE="ENFORCE")
        self._run(seed, "hook", "failure",
                  event={"session_id": "s", "cwd": str(self.project), "tool_name": "Bash",
                         "tool_input": {"command": "cat nope.txt"},
                         "error": "cat: nope.txt: No such file or directory",
                         "is_interrupt": False})
        self.assertEqual(json.loads(self._run(seed, "metrics").stdout)["failures_captured"], 1)
        m = json.loads(self._run(env, "metrics").stdout)          # canonical, first touch
        self.assertEqual(m["failures_captured"], 1, "legacy history was not adopted")
        self.assertFalse((legacy / "my-error.db").exists(), "legacy copy left behind")

    def test_two_populated_legacy_dirs_are_reported_not_merged(self):
        home, env = self._isolated()
        base = home / ".claude" / "plugins" / "data"
        for name in ("my-error-inline", "my-error-my-error-local"):
            d = base / name; d.mkdir(parents=True)
            self._run(dict(env, MY_ERROR_DATA_DIR=str(d), MY_ERROR_MODE="ENFORCE"),
                      "hook", "failure",
                      event={"session_id": "s", "cwd": str(self.project), "tool_name": "Bash",
                             "tool_input": {"command": f"cat {name}.txt"},
                             "error": f"cat: {name}.txt: No such file or directory",
                             "is_interrupt": False})
        d = json.loads(self._run(env, "datadir").stdout)
        self.assertEqual(len(d["unmerged_legacy"]), 2)            # both reported
        self.assertEqual(json.loads(self._run(env, "metrics").stdout)["failures_captured"], 0)

    # --- 0.3.2: controlled_test vs natural_usage separation -----------------

    def test_A_controlled_predictions_do_not_count_toward_natural_verdict(self):
        for i in range(5):
            sid = f"orig-a{i}"
            self.train_pair(f"git sttaus{i}", f"git: 'sttaus{i}' is not a git command.",
                             f"git status{i}", sid=sid, origin="controlled_test")
            self.confirm_prediction(f"git sttaus{i}", sid=sid, origin="controlled_test")
        m = self.metrics()
        self.assertEqual(m["shadow_verdict_confirmed"], 0)
        self.assertEqual(m["controlled_confirmed"], 5)
        self.assertEqual(m["predictions_confirmed_total"], 5)

    def test_B_natural_prediction_counts(self):
        self.train_pair("git sttaus", "git: 'sttaus' is not a git command.", "git status", sid="orig-b0")
        self.confirm_prediction("git sttaus", sid="orig-b0")  # no marker => natural_usage
        m = self.metrics()
        self.assertEqual(m["shadow_verdict_confirmed"], 1)
        self.assertEqual(m["controlled_confirmed"], 0)

    def test_C_mixed_population_verdict_sees_natural_only(self):
        for i in range(6):
            sid = f"orig-c{i}"
            self.train_pair(f"git sttaus{i}", f"git: 'sttaus{i}' is not a git command.",
                             f"git status{i}", sid=sid, origin="controlled_test")
            self.confirm_prediction(f"git sttaus{i}", sid=sid, origin="controlled_test")
        for i in range(2):
            sid = f"orig-cn{i}"
            self.train_pair(f"npm run buil{i}", f"Exit code 1\nnpm ERR! Missing script: buil{i}",
                             f"npm run build{i}", sid=sid)
            self.confirm_prediction(f"npm run buil{i}", sid=sid)
        m = self.metrics()
        self.assertEqual(m["shadow_verdict_confirmed"], 2)         # not 8
        self.assertEqual(m["controlled_confirmed"], 6)
        self.assertEqual(m["predictions_confirmed_total"], 8)

    def test_D_controlled_refuted_does_not_contaminate_natural_population(self):
        for i in range(10):
            sid = f"orig-d{i}"
            self.train_pair(f"git sttaus{i}", f"git: 'sttaus{i}' is not a git command.",
                             f"git status{i}", sid=sid, origin="controlled_test")
            self.refute_prediction(f"git sttaus{i}", sid=sid, origin="controlled_test")
        m = self.metrics()
        # The 10 controlled false positives are real and recorded...
        self.assertEqual(m["controlled_refuted"], 10)
        self.assertEqual(m["predictions_refuted_total"], 10)
        # ...but the natural population -- what REMOVE (refuted > confirmed)
        # actually reads -- stays exactly empty. Controlled data cannot trip
        # that rule for a population it never touched.
        self.assertEqual(m["shadow_verdict_refuted"], 0)
        self.assertEqual(m["shadow_verdict_confirmed"], 0)

    def test_E_propagation_controlled_candidate_flows_to_guard_and_prediction(self):
        self.train_pair("git sttaus", "git: 'sttaus' is not a git command.", "git status",
                         sid="orig-e0", origin="controlled_test")
        db = sqlite3.connect(self.data / "my-error.db")
        try:
            cand_origin = db.execute("SELECT origin FROM candidates").fetchone()[0]
            lesson_origin = db.execute("SELECT origin FROM lessons").fetchone()[0]
            guard_origin = db.execute("SELECT origin FROM guards").fetchone()[0]
        finally:
            db.close()
        self.assertEqual(cand_origin, "controlled_test")
        self.assertEqual(lesson_origin, "controlled_test")
        self.assertEqual(guard_origin, "controlled_test")
        self.confirm_prediction("git sttaus", sid="orig-e0", origin="controlled_test")
        m = self.metrics()
        self.assertEqual(m["controlled_confirmed"], 1)
        self.assertEqual(m["shadow_verdict_confirmed"], 0)

    def test_F_default_without_marker_is_natural_usage(self):
        self.train_pair("npm run buil", "Exit code 1\nnpm ERR! Missing script: buil", "npm run build",
                         sid="orig-f0")
        db = sqlite3.connect(self.data / "my-error.db")
        try:
            cand_origin = db.execute("SELECT origin FROM candidates").fetchone()[0]
            lesson_origin = db.execute("SELECT origin FROM lessons").fetchone()[0]
            guard_origin = db.execute("SELECT origin FROM guards").fetchone()[0]
        finally:
            db.close()
        self.assertEqual(cand_origin, "natural_usage")
        self.assertEqual(lesson_origin, "natural_usage")
        self.assertEqual(guard_origin, "natural_usage")
        self.confirm_prediction("npm run buil", sid="orig-f0")
        db = sqlite3.connect(self.data / "my-error.db")
        try:
            event_origin = db.execute(
                "SELECT origin FROM guard_events ORDER BY id DESC LIMIT 1").fetchone()[0]
        finally:
            db.close()
        self.assertEqual(event_origin, "natural_usage")

    def test_learn_origin_flag_overrides_inherited_origin(self):
        p = self.run_cli("learn", "--scope", "project", "--title", "T", "--cause", "C", "--rule", "Use decimal for money.",
                         "--confidence", "verified", "--tags", "money", "--origin", "controlled_test")
        self.assertEqual(p.returncode, 0, p.stderr)
        db = sqlite3.connect(self.data / "my-error.db")
        try:
            origin = db.execute("SELECT origin FROM lessons").fetchone()[0]
        finally:
            db.close()
        self.assertEqual(origin, "controlled_test")

    def test_doctor_reports_verdict_dataset_is_natural_only(self):
        d = json.loads(self.run_cli("doctor", "--json").stdout)
        self.assertEqual(d["verdict_dataset"], "NATURAL USAGE ONLY")
        self.assertIn("shadow_verdict_confirmed", d)
        self.assertIn("controlled_confirmed", d)


class ObservabilityWrapperTest(unittest.TestCase):
    """The watchdog and the status line segment.

    They run outside the plugin, in node, so nothing else in this suite would
    notice if they broke. Two classes of regression are worth a test: the units
    of a hook timeout, which are silent when wrong, and the survival rules of
    the status line, which are only visible when something else has already
    failed.
    """

    WATCHDOG_DIR = ROOT / "watchdog"
    STATUSLINE = WATCHDOG_DIR / "my-error-statusline.cjs"

    def setUp(self):
        if not shutil.which("node"):
            self.skipTest("node não encontrado")
        self.tmp = tempfile.TemporaryDirectory()
        self.data = Path(self.tmp.name) / "data"
        self.data.mkdir()
        self.artifacts = Path(self.tmp.name) / "artifacts"
        self.artifacts.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def isolated_env(self, **env_extra):
        """Environment for anything that may write an observability artifact.

        No automated run may touch the real installation's files. The invocation
        beacon is the sharp case: it is the only evidence that the *live* status
        bar ran this code, so a test that overwrites it destroys the signal it
        exists to provide, and does so invisibly. `MY_ERROR_STATUSLINE_TRACE`
        and `MY_ERROR_HEALTH_CACHE` redirect both artifacts into this test's
        temporary directory; the ambient `HOME` is deliberately left alone so
        these tests keep reading the real installation, which is what they are
        about.
        """
        env = os.environ.copy()
        env["MY_ERROR_STATUSLINE_TRACE"] = str(self.artifacts / ".my-error-statusline.json")
        env["MY_ERROR_HEALTH_CACHE"] = str(self.artifacts / ".my-error-health.json")
        env.update({k: v for k, v in env_extra.items() if v is not None})
        for k, v in env_extra.items():
            if v is None:
                env.pop(k, None)
        return env

    def run_statusline(self, stdin="{}", script=None, **env_extra):
        p = subprocess.run(["node", str(script or self.STATUSLINE)],
                           input=stdin, capture_output=True, text=True,
                           env=self.isolated_env(**env_extra), timeout=30)
        return p

    # --- units -------------------------------------------------------------

    def test_hook_timeouts_are_seconds_not_milliseconds(self):
        """A hook timeout is in seconds. 10000 is not a long timeout, it is a
        units bug that hides a wedged hook for almost three hours."""
        hooks = json.loads((ROOT / "hooks" / "hooks.json").read_text())
        found = 0
        for event, groups in hooks["hooks"].items():
            for group in groups:
                for hook in group["hooks"]:
                    if "timeout" not in hook:
                        continue
                    found += 1
                    self.assertLessEqual(
                        hook["timeout"], 60,
                        f"{event}: timeout={hook['timeout']} — segundos, não milissegundos")
                    self.assertGreaterEqual(hook["timeout"], 1, f"{event}: timeout inutilizável")
        self.assertGreater(found, 0, "nenhum timeout declarado — o teste deixou de cobrir algo")

    def test_installer_snippet_uses_seconds(self):
        """The snippet the installer prints is copied verbatim into settings.json,
        so a wrong unit there becomes a wrong unit in every installation."""
        text = (self.WATCHDOG_DIR / "install-watchdog.sh").read_text()
        for value in re.findall(r'"timeout"\s*:\s*(\d+)', text):
            self.assertLessEqual(int(value), 60, f"snippet do instalador com timeout={value}")

    # --- one implementation ------------------------------------------------

    def test_health_logic_is_not_duplicated(self):
        """Health, freshness and the data directory are decided once, in the
        shared module. A second definition is how two observers start disagreeing
        about whether the plugin is healthy."""
        shared = (self.WATCHDOG_DIR / "my-error-state.cjs").read_text()
        for fn in ("function structuralHealth", "function liveState", "function resolveDataDir"):
            self.assertIn(fn, shared)
        for name in ("my-error-watchdog.cjs", "my-error-statusline.cjs"):
            src = (self.WATCHDOG_DIR / name).read_text()
            self.assertIn("my-error-state.cjs", src, f"{name} não usa o módulo compartilhado")
            for fn in ("structuralHealth", "liveState", "resolveDataDir"):
                # \b so liveStateDeep, a genuinely different (expensive) query
                # that belongs to the watchdog, is not mistaken for a copy.
                self.assertIsNone(re.search(rf"function {fn}\b", src), f"{name} redefine {fn}")

    def test_installer_ships_every_file_the_wrapper_needs(self):
        installer = (self.WATCHDOG_DIR / "install-watchdog.sh").read_text()
        for name in ("my-error-state.cjs", "my-error-watchdog.cjs", "my-error-statusline.cjs"):
            self.assertIn(name, installer)

    # --- survival ----------------------------------------------------------

    def test_segment_alone_reports_healthy_installation(self):
        p = self.run_statusline('{"session_id":"t"}', MY_ERROR_STATUSLINE_WRAP=None)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("ME", p.stdout)
        self.assertRegex(p.stdout, r"ME (✅|⚠️|❌)")

    def test_wrapped_bar_survives_a_broken_segment(self):
        """The whole point of the wrapper: my-error failing must cost the user
        their metrics, never their status line."""
        p = self.run_statusline('{"session_id":"t"}',
                                MY_ERROR_STATUSLINE_WRAP="printf 'BARRA-EXISTENTE'",
                                MY_ERROR_DATA_DIR=str(self.data / "inexistente"))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("BARRA-EXISTENTE", p.stdout)
        self.assertIn("ME", p.stdout)
        self.assertNotIn("✅", p.stdout)

    def test_segment_survives_a_broken_bar(self):
        p = self.run_statusline('{"session_id":"t"}', MY_ERROR_STATUSLINE_WRAP="exit 7")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("ME", p.stdout)
        self.assertIn("⚠️", p.stdout)

    def test_partial_output_from_a_failing_bar_is_still_shown(self):
        p = self.run_statusline('{"session_id":"t"}',
                                MY_ERROR_STATUSLINE_WRAP="printf 'METADE'; exit 1")
        self.assertIn("METADE", p.stdout)
        self.assertIn("ME", p.stdout)

    def test_invalid_stdin_does_not_break_anything(self):
        p = self.run_statusline("isto-nao-e-json{{{",
                                MY_ERROR_STATUSLINE_WRAP="printf 'BARRA'")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("BARRA", p.stdout)
        self.assertIn("ME", p.stdout)

    def test_empty_stdin_does_not_break_anything(self):
        p = self.run_statusline("", MY_ERROR_STATUSLINE_WRAP="printf 'BARRA'")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("BARRA", p.stdout)

    def test_missing_shared_module_degrades_instead_of_crashing(self):
        """Someone copies one file instead of three. The bar must still work."""
        solo = Path(self.tmp.name) / "solo"
        solo.mkdir()
        shutil.copy(self.STATUSLINE, solo / "my-error-statusline.cjs")
        p = self.run_statusline('{"session_id":"t"}', script=solo / "my-error-statusline.cjs",
                                MY_ERROR_STATUSLINE_WRAP="printf 'BARRA'")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("BARRA", p.stdout)
        self.assertIn("❌", p.stdout)

    def test_a_multi_line_bar_keeps_the_segment_on_its_own_line(self):
        p = self.run_statusline('{"session_id":"t"}',
                                MY_ERROR_STATUSLINE_WRAP="printf 'L1\\nL2'")
        lines = p.stdout.split("\n")
        self.assertEqual(lines[0], "L1")
        self.assertEqual(lines[1], "L2")
        self.assertIn("ME", lines[2])

    def test_a_single_line_bar_stays_on_one_line(self):
        p = self.run_statusline('{"session_id":"t"}', MY_ERROR_STATUSLINE_WRAP="printf 'UMA'")
        self.assertNotIn("\n", p.stdout.strip())
        self.assertIn("UMA", p.stdout)

    def test_run_leaves_evidence_that_it_ran(self):
        """A manual run proves nothing about the live editor (ERR-0016), so the
        wrapper stamps who invoked it. Without this file there is no way to tell
        a status bar that is running this code from one that is not."""
        home = Path(self.tmp.name) / "home"
        (home / ".claude" / "watchdogs").mkdir(parents=True)
        env = os.environ.copy()
        env["HOME"] = str(home)
        env.pop("MY_ERROR_STATUSLINE_WRAP", None)
        # This test is about the *default* location, so the override must be off.
        env.pop("MY_ERROR_STATUSLINE_TRACE", None)
        subprocess.run(["node", str(self.STATUSLINE)], input='{"session_id":"prova","cwd":"/tmp"}',
                       capture_output=True, text=True, env=env, timeout=30)
        trace = home / ".claude" / "watchdogs" / ".my-error-statusline.json"
        self.assertTrue(trace.exists(), "sem beacon de invocação")
        rec = json.loads(trace.read_text())
        self.assertEqual(rec["session_id"], "prova")
        self.assertIn("segment", rec)
        self.assertIn("ms", rec)

    def test_tests_never_touch_the_installations_invocation_beacon(self):
        """The beacon is evidence, and a test that writes it is not a test.

        `~/.claude/watchdogs/.my-error-statusline.json` is the only artifact
        that distinguishes a status bar which really executed this code from one
        which never did. An automated run that writes it manufactures the
        evidence and destroys the answer, silently and permanently -- and the
        old module-level constant made that the default behaviour.

        Three steps, deliberately: plant a sentinel where a real installation
        keeps its beacon, drive the entire status line routine under the test
        environment, then prove the sentinel is byte-identical. No part of this
        touches the real HOME.
        """
        installed_home = Path(self.tmp.name) / "installed-home"
        beacon = installed_home / ".claude" / "watchdogs" / ".my-error-statusline.json"
        beacon.parent.mkdir(parents=True)
        sentinel = json.dumps({"at": "2020-01-01T00:00:00Z", "segment": "SENTINELA",
                               "pid": 1, "line": "prova de execução real"})
        beacon.write_text(sentinel)
        # Age it past the write throttle. A freshly written beacon is skipped by
        # the rate limiter, which would make this test pass for the wrong reason
        # -- it must be a beacon the routine *would* rewrite if it could.
        old_time = time.time() - 3600
        os.utime(beacon, (old_time, old_time))
        before = (sentinel, beacon.stat().st_mtime_ns)

        # The full routine, several times, through every branch a test drives:
        # bar present, bar broken, payload malformed, data dir absent.
        for kwargs in ({"MY_ERROR_STATUSLINE_WRAP": None},
                       {"MY_ERROR_STATUSLINE_WRAP": "printf 'BARRA'"},
                       {"MY_ERROR_STATUSLINE_WRAP": "exit 7"},
                       {"MY_ERROR_STATUSLINE_WRAP": "printf 'B'",
                        "MY_ERROR_DATA_DIR": str(self.data / "inexistente")}):
            env = self.isolated_env(**kwargs)
            # HOME points at the sentinel installation: if the trace path were
            # still resolved from HOME alone, every one of these would overwrite
            # it. Only the explicit override keeps it intact.
            env["HOME"] = str(installed_home)
            p = subprocess.run(["node", str(self.STATUSLINE)], input='{"session_id":"t"}',
                               capture_output=True, text=True, env=env, timeout=30)
            self.assertEqual(p.returncode, 0, p.stderr)

        self.assertEqual((beacon.read_text(), beacon.stat().st_mtime_ns), before,
                         "uma execução de teste sobrescreveu o probe da instalação")
        # And the redirected copy really was written, so the assertion above is
        # proof of isolation and not proof that tracing quietly stopped working.
        redirected = self.artifacts / ".my-error-statusline.json"
        self.assertTrue(redirected.exists(), "o trace não foi escrito em lugar nenhum")
        self.assertEqual(json.loads(redirected.read_text())["session_id"], "t")

    def test_watchdog_probe_never_touches_the_installations_health_cache(self):
        """Same rule, the other artifact: `--probe` writes a shared health cache."""
        installed_home = Path(self.tmp.name) / "wd-home"
        cache = installed_home / ".claude" / "watchdogs" / ".my-error-health.json"
        cache.parent.mkdir(parents=True)
        cache.write_text('{"stamp":"SENTINELA"}')
        before = (cache.read_text(), cache.stat().st_mtime_ns)
        env = self.isolated_env()
        env["HOME"] = str(installed_home)
        p = subprocess.run(["node", str(self.WATCHDOG_DIR / "my-error-watchdog.cjs"), "--probe"],
                           input='{"session_id":"probe","cwd":"/tmp"}',
                           capture_output=True, text=True, env=env, timeout=30)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual((cache.read_text(), cache.stat().st_mtime_ns), before)

    def _fake_install(self, lessons=8, cross=2, db_ahead=False):
        """A data directory shaped like a real one, so the segment can be driven
        through states that are hard to produce on demand in a live install."""
        db = self.data / "my-error.db"
        db.write_bytes(b"SQLite format 3\x00")
        beacon = {
            "version": me_version(), "mode": "SHADOW", "session_id": "s",
            "db_mtime": os.path.getmtime(db),
            "projects": {"p": {"mode": "SHADOW", "lessons_active": lessons,
                               "cross_project_recalls": cross}},
        }
        if db_ahead:
            beacon["db_mtime"] = os.path.getmtime(db) - 3600
        (self.data / "runtime.json").write_text(json.dumps(beacon))

    def test_segment_reports_the_metrics_the_beacon_carries(self):
        self._fake_install(lessons=42, cross=7)
        p = self.run_statusline('{"session_id":"t"}', MY_ERROR_DATA_DIR=str(self.data),
                                MY_ERROR_STATUSLINE_WRAP=None)
        self.assertIn("L42", p.stdout)
        self.assertIn("X7", p.stdout)
        self.assertIn("SHADOW", p.stdout)

    def test_a_beacon_older_than_its_database_is_reported_stale(self):
        """The one branch that must never be optimistic: only the plugin writes
        that database, so a beacon predating the last write is not merely old —
        the numbers in it describe a state that no longer exists."""
        self._fake_install(db_ahead=True)
        p = self.run_statusline('{"session_id":"t"}', MY_ERROR_DATA_DIR=str(self.data),
                                MY_ERROR_STATUSLINE_WRAP=None)
        self.assertIn("⚠️", p.stdout)
        self.assertIn("defasado", p.stdout)
        self.assertNotIn("✅", p.stdout)

    def test_a_runtime_version_that_differs_from_the_installed_one_is_flagged(self):
        """ERR-0016 in the bar: code on disk is not code in use. A restart is
        what closes the gap, and until then the segment must say so."""
        self._fake_install()
        beacon = json.loads((self.data / "runtime.json").read_text())
        beacon["version"] = "0.0.1-antiga"
        (self.data / "runtime.json").write_text(json.dumps(beacon))
        p = self.run_statusline('{"session_id":"t"}', MY_ERROR_DATA_DIR=str(self.data),
                                MY_ERROR_STATUSLINE_WRAP=None)
        self.assertIn("0.0.1-antiga", p.stdout)
        self.assertIn("inst", p.stdout)
        self.assertIn("⚠️", p.stdout)

    def test_watchdog_probe_answers(self):
        """--probe is what the installer tells people to run; it must exist."""
        p = subprocess.run(["node", str(self.WATCHDOG_DIR / "my-error-watchdog.cjs"), "--probe"],
                           input='{"session_id":"probe","cwd":"/tmp"}',
                           capture_output=True, text=True, env=self.isolated_env(), timeout=30)
        self.assertEqual(p.returncode, 0, p.stderr)
        out = json.loads(p.stdout)
        self.assertIn("health", out)
        self.assertIn("line", out)


if __name__ == "__main__":
    unittest.main()
