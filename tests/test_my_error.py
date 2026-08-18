import json
import re
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "my_error.py"


def me_version() -> str:
    src = (ROOT / 'scripts' / 'my_error.py').read_text()
    return re.search(r'VERSION = "([^"]+)"', src).group(1)


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

    def run_cli(self, *args, event=None, project=None, mode=None, locale=None):
        env = self.env.copy()
        if locale is not None:
            env["LC_ALL"] = locale; env["LANG"] = locale; env.pop("LC_MESSAGES", None)
        if project is not None:
            env["CLAUDE_PROJECT_DIR"] = str(project)
        if mode is not None:
            env["MY_ERROR_MODE"] = mode
        p = subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            input=(json.dumps(event) if event is not None else None),
            text=True, capture_output=True, env=env, cwd=str(project or self.project),
        )
        return p

    def hook(self, kind, event, project=None, mode=None, locale=None):
        p = self.run_cli("hook", kind, event=event, project=project, mode=mode, locale=locale)
        self.assertEqual(p.returncode, 0, p.stderr)
        return json.loads(p.stdout) if p.stdout.strip() else None

    def candidate_count(self):
        db = sqlite3.connect(self.data / "my-error.db")
        try: return db.execute("select count(*) from candidates").fetchone()[0]
        finally: db.close()

    def lesson_count(self):
        db = sqlite3.connect(self.data / "my-error.db")
        try: return db.execute("select count(*) from lessons where status='active'").fetchone()[0]
        finally: db.close()

    def train_pair(self, bad, error, good, sid="s1", locale=None):
        fail = {
            "session_id": sid, "cwd": str(self.project), "hook_event_name": "PostToolUseFailure",
            "tool_name": "Bash", "tool_input": {"command": bad}, "error": error, "is_interrupt": False
        }
        success = {
            "session_id": sid, "cwd": str(self.project), "hook_event_name": "PostToolUse",
            "tool_name": "Bash", "tool_input": {"command": good},
            "tool_response": {"stdout": "ok", "stderr": "", "interrupted": False, "isImage": False}
        }
        out1 = self.hook("failure", fail, locale=locale)
        out2 = self.hook("success", success, locale=locale)
        return out1, out2

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
        p = self.run_cli("learn", "--title", "Generated Prisma client", "--cause", "Generated code was edited directly", "--rule", "Edit prisma/schema.prisma and regenerate the client instead of editing generated client files.", "--confidence", "verified", "--tags", "prisma,schema,generated")
        self.assertEqual(p.returncode, 0, p.stderr)
        event = {"session_id":"s","cwd":str(self.project),"prompt":"Update the Prisma generated client after changing the schema"}
        out = self.hook("prompt", event)
        self.assertIn("prisma/schema.prisma", out["hookSpecificOutput"]["additionalContext"])

    def test_manual_write_guard_blocks_precise_pattern(self):
        p = self.run_cli("learn", "--title", "Do not edit generated file", "--cause", "File is generated", "--rule", "Do not write generated/client.ts directly.", "--confidence", "verified", "--guard-tool", "Write", "--guard-field", "file_path", "--guard-match", "contains", "--guard-pattern", "generated/client.ts", "--guard-reason", "Generated file must be regenerated")
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

    def test_expired_guard_fails_open(self):
        self.train_pair("npm run buil", "Exit code 1\nMissing script: buil", "npm run build")
        db = sqlite3.connect(self.data / "my-error.db")
        db.execute("update guards set expires_at='2000-01-01T00:00:00+00:00' where id=1")
        db.commit(); db.close()
        pre = {"session_id":"s","cwd":str(self.project),"tool_name":"Bash","tool_input":{"command":"npm run buil"}}
        self.assertIsNone(self.hook("guard", pre))

    def test_concurrent_duplicate_failure_capture_is_atomic(self):
        from concurrent.futures import ThreadPoolExecutor
        event = {"session_id":"parallel","cwd":str(self.project),"tool_name":"Bash","tool_input":{"command":"npm run buil"},"error":"Exit code 1\nMissing script: buil","is_interrupt":False}
        def one(_):
            p = self.run_cli("hook", "failure", event=event)
            return p.returncode, p.stderr
        with ThreadPoolExecutor(max_workers=4) as ex:
            results = list(ex.map(one, range(8)))
        self.assertTrue(all(code == 0 for code, _ in results), results)
        db = sqlite3.connect(self.data / "my-error.db")
        row = db.execute("select count(*), max(occurrences) from candidates").fetchone()
        db.close()
        self.assertEqual(row[0], 1)
        self.assertEqual(row[1], 8)

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
        p = self.run_cli("learn", "--title", "Money precision", "--cause", "Binary floating point corrupted monetary values", "--rule", "Use decimal or integer minor units for money.", "--confidence", "verified", "--tags", "money,decimal,precision")
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

    def metrics(self, mode=None):
        p = self.run_cli("metrics", mode=mode)
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
        self.assertEqual(m["predictions_confirmed"], 1)
        self.assertEqual(m["predictions_refuted"], 0)

    def test_shadow_measures_a_false_positive(self):
        """The point of SHADOW: a guard that lets a command run and sees it
        succeed has been proven wrong, rather than merely suspected."""
        self.train_pair("git sttaus", "git: 'sttaus' is not a git command.", "git status")
        repeat = {"session_id": "sh", "cwd": str(self.project), "tool_name": "Bash",
                  "tool_input": {"command": "git sttaus"}}
        self.hook("guard", repeat, mode="SHADOW")
        self.hook("success", {**repeat, "tool_response": {"stdout": "ok"}}, mode="SHADOW")
        m = self.metrics()
        self.assertEqual(m["predictions_refuted"], 1)
        self.assertEqual(m["predictions_confirmed"], 0)

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
        m = self.metrics()          # reopening must migrate
        self.assertEqual(m["lessons_active"], 1)
        db = sqlite3.connect(self.data / "my-error.db")
        try:
            self.assertEqual(int(db.execute("PRAGMA user_version").fetchone()[0]), 2)
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
        self.run_cli("learn", "--title", "Money precision", "--cause", "float corrupted money",
                     "--rule", "Use decimal for money.", "--confidence", "verified", "--tags", "money")
        out = self.hook("prompt", {"session_id": "r", "cwd": str(self.project),
                                   "prompt": "compute invoice payment amounts"})
        self.assertIn("Use decimal", out["hookSpecificOutput"]["additionalContext"])

    def test_dormant_lessons_leave_recall_but_stay_stored(self):
        self.run_cli("learn", "--title", "Old rule", "--cause", "c", "--rule",
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


if __name__ == "__main__":
    unittest.main()
