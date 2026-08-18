#!/usr/bin/env python3
"""my-error: persistent, evidence-gated error learning for Claude Code.

No third-party dependencies. Hook events arrive on stdin as JSON.
State is stored in CLAUDE_PLUGIN_DATA (or MY_ERROR_DATA_DIR for tests).
"""
from __future__ import annotations

import argparse
import datetime as dt
import difflib
import hashlib
import json
import os
import random
import re
import shlex
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Iterable

VERSION = "0.3.2"
SCHEMA_VERSION = 3
MAX_TEXT = 4000
AUTO_GUARD_TTL_DAYS = 90
RECOVERY_WINDOW_MINUTES = 15
# Kept under the hook timeout budget: waiting past it just gets the process killed.
BUSY_TIMEOUT_MS = 4000

# Guards start in SHADOW: they record what they *would* have blocked and let the
# command run. That is the only way to measure the base rate this plugin is on
# probation for -- an enforcing guard destroys its own counterfactual, and a
# shadow miss that then succeeds is a *provable* false positive.
MODE_SHADOW = "SHADOW"
MODE_ENFORCE = "ENFORCE"
DEFAULT_MODE = MODE_SHADOW
LAST_SEEN_REFRESH_SECONDS = 300

# Population tag for the 30-day SHADOW experiment. `controlled_test` is data
# produced by deliberately provoking a repeat mistake (development, fuzzing,
# demos); `natural_usage` is everything else. shadow_verdict() reads
# natural_usage exclusively -- see METRICS.md. Nothing but an explicit,
# temporary MY_ERROR_EVENT_ORIGIN=controlled_test marks an event controlled;
# the absence of that marker is itself the natural-usage default, so nobody
# can contaminate the experiment by forgetting to flag a test.
ORIGIN_NATURAL = "natural_usage"
ORIGIN_CONTROLLED = "controlled_test"
VALID_ORIGINS = {ORIGIN_NATURAL, ORIGIN_CONTROLLED}

# Recall policy. A lesson unused for this long stops being injected automatically;
# it stays stored, stays queryable via `review`, and returns to the active set the
# moment it is used again. Age alone never deletes anything.
# FROZEN EXPERIMENT PARAMETERS -- DO NOT EDIT BEFORE 2026-09-17.
#
# Fixed 2026-08-18T14:24:26Z, before a single measurement existed, precisely so
# that day 30 cannot be argued from the numbers. Whatever they turn out to be,
# the verdict was already written. Changing either constant in response to an
# observed result invalidates the experiment rather than improving it.
#
#   confirmed == 0                  -> REMOVE the auto-guard from the code
#   refuted > confirmed             -> REMOVE
#   confirmed >= 3 and refuted == 0 -> PROMOTE to ENFORCE
#   anything else                   -> EXTEND another 30 days
#
# Experiment start: 2026-08-18T14:24:26Z   Decision due: 2026-09-17
SHADOW_EXPERIMENT_DAYS = 30
SHADOW_PROMOTE_THRESHOLD = 3

# The one source string produced without human causal review. Creation and the
# recall filter both reference this constant so the two cannot drift apart; a
# future automatic path must be added here, and the test suite asserts that an
# auto-created lesson actually carries it.
AUTO_LESSON_SOURCES = {"auto-verified-recovery"}

RECALL_DORMANT_DAYS = 90
# Technical ceiling only. It is a guard against a pathological table, never the
# selection policy -- selection is status + source + confidence + recency below.
RECALL_SCAN_CEILING = 2000

STOPWORDS = {
    "the","a","an","and","or","to","of","in","on","for","with","from","this","that","is","are","be","as","at","by",
    "o","a","os","as","e","ou","de","da","do","das","dos","em","no","na","nos","nas","para","com","por","um","uma",
    "use","using","run","make","create","fix","change","please","quero","faça","faca","corrija","crie","rode","execute"
}

# Small, dependency-free concept expansion. This is not an embedding model; it
# gives lexical recall a safer semantic bridge for common software-engineering
# concepts while keeping retrieval local, deterministic, and auditable.
SEMANTIC_GROUPS = {
    "money": {"money","monetary","payment","payments","amount","amounts","price","prices","currency","currencies","decimal","cents","finance","financial","invoice","invoices"},
    "database": {"database","databases","db","sql","migration","migrations","schema","schemas","column","columns","constraint","constraints"},
    "generated": {"generate","generated","generating","regenerate","regenerated","codegen","generated-code"},
    "secret": {"secret","secrets","token","tokens","password","passwords","credential","credentials","apikey","api-key","redact","redaction","sensitive"},
    "transaction": {"atomic","atomically","transaction","transactions","transactional","commit","rollback","consistency","all-or-nothing","allornothing"},
    "dependency": {"dependency","dependencies","package","packages","module","modules","import","imports","library","libraries"},
    "testing": {"test","tests","testing","pytest","jest","assertion","assertions","spec","specs"},
    "path": {"path","paths","file","files","directory","directories","folder","folders"},
    "auth": {"auth","authentication","authorization","permission","permissions","role","roles","scope","scopes"},
    "api": {"api","apis","endpoint","endpoints","route","routes","request","requests","response","responses","http"},
    "concurrency": {"race","races","concurrency","concurrent","lock","locks","mutex","deadlock","deadlocks"},
    "time": {"time","date","dates","timestamp","timestamps","timezone","timezones","utc"},
    "cache": {"cache","caches","cached","caching","stale","invalidate","invalidation"},
}
# Locales whose failure messages FAMILY_PATTERNS covers explicitly. Anywhere
# else, the heuristic fallback is the only thing standing between the user and
# a plugin that silently never learns.
RECOGNIZED_LANGS = {"en", "c", "pt", "es", "fr", "de", "it", ""}

SEMANTIC_LOOKUP = {term: f"@{name}" for name, terms in SEMANTIC_GROUPS.items() for term in terms}

SECRET_PATTERNS = [
    re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[^\s'\"]+"),
    # The value class must exclude quotes: a greedy [^\s]+ swallows the closing
    # quote, leaving an unparseable command that shlex (and therefore all
    # correction analysis) rejects outright.
    re.compile(r"(?i)\b(api[_-]?key|token|password|passwd|secret|client[_-]?secret)\s*=\s*([^\s'\"]+)"),
    re.compile(r"\b(sk-[A-Za-z0-9_-]{12,})\b"),
    re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{20,})\b"),
    re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
]

TRANSIENT_PATTERNS = [
    r"rate limit", r"\b429\b", r"\b5(?:00|02|03|04)\b", r"timed? out", r"timeout", r"econnreset",
    r"temporary failure", r"temporarily unavailable", r"network is unreachable", r"\bdns\b",
    r"name resolution", r"connection reset", r"connection refused", r"service unavailable",
    r"socket hang up", r"tls handshake", r"certificate has expired",
    # Localized equivalents. Error text follows the machine locale, not English.
    r"limite de (?:taxa|requisi)", r"tempo (?:limite|esgotado)", r"esgotou o tempo",
    r"falha tempor[aá]ria", r"tempor[aá]riamente indispon[ií]vel", r"rede inacess[ií]vel",
    r"conex[aã]o (?:recusada|reiniciada|redefinida)", r"servi[cç]o indispon[ií]vel",
    r"n[aã]o foi poss[ií]vel resolver",
    r"tiempo de espera agotado", r"conexi[oó]n rechazada", r"servicio no disponible",
    r"d[eé]lai d[eé]pass[eé]", r"connexion refus[eé]e", r"service indisponible",
    r"zeit[uü]berschreitung", r"verbindung abgelehnt", r"dienst nicht verf[uü]gbar",
]

# Failure families. Each family carries English patterns plus the localized
# equivalents emitted by coreutils/git/npm/python under non-English locales.
# Without these, the whole auto-learning path silently degrades on any machine
# whose LANG is not English (measured: 70% recognition on a pt_BR host).
FAMILY_PATTERNS = [
    ("shell_command_not_found", [
        r"command not found", r"not recognized as an internal or external command",
        r":\s*\d+:\s*[^\s:]+:\s*not found",
        r"comando n[aã]o encontrado", r"ordre non trouv", r"commande introuvable",
        r"orden no encontrada", r"no se encontr[oó] la orden", r"befehl nicht gefunden",
        r"comando non trovato",
    ]),
    ("npm_missing_script", [r"missing script[: ]", r"npm error missing script", r"script ausente"]),
    ("path_not_found", [
        r"no such file or directory", r"can't open file .*no such file", r"cannot find the path",
        r"file or directory not found", r"cannot access .*no such file",
        r"arquivo ou diret[oó]rio (?:inexistente|n[aã]o encontrado)",
        r"n[aã]o [eé] poss[ií]vel acessar", r"n[aã]o foi poss[ií]vel abrir",
        r"no existe el (?:archivo|fichero) o el directorio",
        r"aucun fichier ou dossier de ce (?:type|nom)",
        r"datei oder verzeichnis nicht gefunden", r"file o directory non esistente",
    ]),
    ("unknown_option", [
        r"unknown option", r"unrecognized option", r"unrecognized arguments?", r"invalid option",
        r"unexpected argument", r"unknown argument", r"no such option", r"bad option", r"illegal option",
        r"op[cç][aã]o (?:n[aã]o reconhecida|inv[aá]lida|desconhecida|ilegal)",
        r"argumento (?:n[aã]o reconhecido|inesperado|desconhecido)",
        r"opci[oó]n (?:no reconocida|no v[aá]lida|desconocida)",
        r"option (?:non reconnue|invalide|inconnue)",
        r"unbekannte option", r"ung[uü]ltige option", r"opzione (?:non riconosciuta|non valida)",
    ]),
    ("unknown_subcommand", [
        r"unknown command", r"unknown subcommand", r"invalid command",
        r"is not a .* command", r"is not a .* subcommand",
        r"n[aã]o [eé] um comando", r"comando (?:desconhecido|inv[aá]lido)",
        r"subcomando (?:desconhecido|inv[aá]lido)",
        r"no es un comando", r"comando desconocido",
        r"n'est pas une commande", r"commande inconnue",
        r"ist kein .* befehl", r"unbekannter befehl",
        r"non . un comando", r"comando sconosciuto",
    ]),
    ("git_pathspec", [
        r"pathspec .* did not match", r"unknown revision or path not in the working tree",
        r"ambiguous argument .*unknown revision",
        r"pathspec .* n[aã]o (?:corresponde|coincide|casou)",
        r"revis[aã]o desconhecida ou caminho fora", r"argumento amb[ií]guo",
        r"r[eé]vision inconnue ou chemin", r"unbekannte revision",
    ]),
]

# Families whose root cause is never provable from a nearby success alone.
NEVER_AUTO_FAMILIES = {"transient", "interrupt", "test_failure", "dependency_or_import"}

AUTO_ELIGIBLE = {
    "shell_command_not_found", "npm_missing_script", "path_not_found",
    "unknown_option", "unknown_subcommand", "git_pathspec"
}


def utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def event_origin() -> str:
    """Resolve the origin of the event being captured right now.

    Read fresh at each capture point (candidate creation, guard firing, manual
    `learn`) rather than cached, so a single hook invocation that forgets to
    set the marker defaults safely to natural_usage instead of silently
    inheriting a stale controlled_test from elsewhere in the process.
    """
    val = (os.getenv("MY_ERROR_EVENT_ORIGIN") or "").strip().lower()
    return val if val in VALID_ORIGINS else ORIGIN_NATURAL


def redact(text: Any) -> str:
    s = str(text if text is not None else "")
    for pat in SECRET_PATTERNS:
        if pat.pattern.lower().startswith("(?i)(authorization"):
            s = pat.sub(r"\1[REDACTED]", s)
        elif "api[_-]?key" in pat.pattern:
            s = pat.sub(lambda m: f"{m.group(1)}=[REDACTED]", s)
        else:
            s = pat.sub("[REDACTED]", s)
    return s[:MAX_TEXT]


def canonical_root(event: dict[str, Any] | None = None) -> str:
    root = os.getenv("CLAUDE_PROJECT_DIR")
    if not root and event:
        root = event.get("cwd")
    root = root or os.getcwd()
    try:
        return str(Path(root).resolve())
    except Exception:
        return str(root)


def git_common_dir(root: str) -> str | None:
    """The shared Git directory, which is the identity that survives worktrees.

    `--show-toplevel` is the *worktree* root and differs for every linked
    worktree, so hashing it would split one repository's lessons across every
    branch checked out beside it. `--git-common-dir` resolves to the same shared
    area from the main worktree and every linked one.

    Known limit: moving or renaming the whole repository still changes this path
    and orphans its lessons. Surviving that needs a marker stored inside the
    repository, which is a larger change than identity resolution.
    """
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--git-common-dir"],
            cwd=root, capture_output=True, text=True, timeout=2,
        )
    except Exception:
        return None
    if out.returncode != 0:
        return None
    raw = out.stdout.strip()
    if not raw:
        return None
    try:
        return str((Path(root) / raw).resolve() if not Path(raw).is_absolute() else Path(raw).resolve())
    except Exception:
        return None


def project_identity(root: str) -> str:
    """Prefer the repository over the directory; fall back to the path outside Git."""
    return git_common_dir(root) or root


def project_id(root: str) -> str:
    return hashlib.sha256(project_identity(root).encode("utf-8", "replace")).hexdigest()[:20]


# --- canonical storage -------------------------------------------------------
#
# THE single resolution of where my-error's database lives. Every consumer --
# hooks, skills, the CLI, the external watchdog -- must arrive here, or the
# plugin silently keeps two databases and the one you can read is not the one
# the hooks write to.
#
# Why not ${CLAUDE_PLUGIN_DATA}, the officially injected context:
#
#   1. It is injected into hook processes only. A skill runs as a plain Bash
#      command and never receives it, so every user-facing command resolved
#      somewhere else -- the defect this replaces.
#   2. It is not stable. Claude Code derives it as
#      `plugins/data/<pluginId with non-alphanumerics replaced by ->`, and the
#      pluginId carries the *load method*: `my-error@inline` for --plugin-dir,
#      `my-error@<marketplace>` for an installed plugin. On this machine that
#      produced two directories, `my-error-inline` and `my-error-my-error-local`,
#      with the learning history in one and nothing in the other.
#
# So the injected value is used to *find* legacy data to adopt, never as the
# place to store it. The canonical directory is a fixed name that no load method
# can perturb. It cannot collide with a Claude-derived directory, because those
# always carry a marketplace suffix.
CANONICAL_DIR_NAME = "my-error"

_DATA_DIR_CACHE: Path | None = None


def claude_plugins_root() -> Path:
    override = os.getenv("CLAUDE_CODE_PLUGIN_CACHE_DIR")
    if override:
        return Path(override)
    return Path.home() / ".claude" / "plugins"


def legacy_data_dirs() -> list[Path]:
    """Directories a previous version may have written to, newest first."""
    found: list[Path] = []
    injected = os.getenv("CLAUDE_PLUGIN_DATA")
    if injected:
        found.append(Path(injected))
    base = claude_plugins_root() / "data"
    try:
        for child in sorted(base.iterdir()):
            if child.is_dir() and child.name.startswith("my-error") and child.name != CANONICAL_DIR_NAME:
                found.append(child)
    except Exception:
        pass
    # The original pre-0.3.1 fallback.
    found.append(Path.home() / ".claude" / "my-error")
    seen: set[str] = set()
    out: list[Path] = []
    for d in found:
        try:
            key = str(d.resolve())
        except Exception:
            key = str(d)
        if key in seen:
            continue
        seen.add(key)
        out.append(d)
    return out


def _db_population(path: Path) -> int:
    """Rows that represent real user history. Used only to decide adoption."""
    db_file = path / "my-error.db"
    if not db_file.exists():
        return 0
    try:
        db = sqlite3.connect(f"file:{db_file}?mode=ro", uri=True)
    except sqlite3.Error:
        return 0
    total = 0
    try:
        for table in ("candidates", "lessons", "guard_events"):
            try:
                total += int(db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            except sqlite3.Error:
                pass
    finally:
        db.close()
    return total


def adopt_legacy(canonical: Path) -> str | None:
    """Move a single populated legacy database into the canonical location.

    Deliberately refuses to merge. If two legacy databases both hold history,
    picking one silently would discard the other's lessons, so the situation is
    reported through `doctor` and left for a human instead.
    """
    if (canonical / "my-error.db").exists():
        return None
    populated = [(d, _db_population(d)) for d in legacy_data_dirs()]
    populated = [(d, n) for d, n in populated if n > 0]
    if len(populated) != 1:
        return None
    source = populated[0][0]
    try:
        canonical.mkdir(parents=True, exist_ok=True)
        for name in ("my-error.db", "my-error.db-wal", "my-error.db-shm", "runtime.json"):
            src = source / name
            if src.exists():
                src.replace(canonical / name)
        return str(source)
    except Exception:
        return None


def unmerged_legacy() -> list[str]:
    """Populated legacy directories that were left alone. Reported by doctor."""
    canonical = data_dir()
    out = []
    for d in legacy_data_dirs():
        try:
            if d.resolve() == canonical.resolve():
                continue
        except Exception:
            pass
        if _db_population(d) > 0:
            out.append(str(d))
    return out


def data_dir() -> Path:
    """Canonical, cached, identical for hooks, skills, CLI and watchdog."""
    global _DATA_DIR_CACHE
    if _DATA_DIR_CACHE is not None:
        return _DATA_DIR_CACHE
    override = os.getenv("MY_ERROR_DATA_DIR")
    if override:
        p = Path(override)
        p.mkdir(parents=True, exist_ok=True)
        _DATA_DIR_CACHE = p
        return p
    p = claude_plugins_root() / "data" / CANONICAL_DIR_NAME
    p.mkdir(parents=True, exist_ok=True)
    adopt_legacy(p)
    _DATA_DIR_CACHE = p
    return p


def with_retry(fn, db: sqlite3.Connection | None = None, attempts: int = 8):
    """Retry a write through transient SQLite lock contention.

    Hooks fire concurrently (parallel tool calls, subagents), so a lock is
    expected rather than exceptional. Losing a capture is worse than waiting.

    The rollback is essential and its absence was a real data-loss bug: after a
    BUSY, Python's sqlite3 leaves the failed transaction open, so a retry issued
    on top of it re-enters a connection that is still holding state and fails
    again immediately, defeating the retry entirely. Jitter keeps a set of
    processes that collided once from colliding again in lockstep.
    """
    delay = 0.05
    for attempt in range(attempts):
        try:
            return fn()
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc).lower() and "busy" not in str(exc).lower():
                raise
            if db is not None:
                try:
                    db.rollback()
                except sqlite3.Error:
                    pass
            if attempt == attempts - 1:
                raise
            time.sleep(delay + random.uniform(0, delay))
            delay = min(delay * 2, 0.4)


def connect() -> sqlite3.Connection:
    db_path = data_dir() / "my-error.db"
    is_new = not db_path.exists()
    # Several hooks can fire concurrently (parallel tool calls, subagents). A short
    # busy timeout silently drops captures under I/O contention, so keep it generous:
    # a hook that waits is invisible, a hook that loses a lesson is not.
    db = sqlite3.connect(db_path, timeout=BUSY_TIMEOUT_MS / 1000.0)
    db.row_factory = sqlite3.Row
    # WAL is a persistent property of the file, so set it only when it is not
    # already set. Issuing this PRAGMA unconditionally was a data-loss bug:
    # journal_mode requires a brief exclusive lock and, unlike ordinary
    # statements, does NOT honour busy_timeout -- it returns SQLITE_BUSY at once.
    # With several hooks connecting at the same instant, one would lose its whole
    # event to a lock it was never given the chance to wait for.
    if str(db.execute("PRAGMA journal_mode").fetchone()[0]).lower() != "wal":
        with_retry(lambda: db.execute("PRAGMA journal_mode=WAL"), db)
    db.execute("PRAGMA synchronous=NORMAL")
    db.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
    current = int(db.execute("PRAGMA user_version").fetchone()[0])
    if current < 1:
        # Every statement here is idempotent, so a racing creator is harmless; the
        # retry only absorbs the write lock that concurrent first-run hooks contend for.
        with_retry(lambda: db.executescript("""
        CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS projects (
          id TEXT PRIMARY KEY, root TEXT NOT NULL, created_at TEXT NOT NULL, last_seen TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS candidates (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          project_id TEXT NOT NULL,
          session_id TEXT,
          created_at TEXT NOT NULL,
          last_seen TEXT NOT NULL,
          tool_name TEXT NOT NULL,
          bad_action TEXT NOT NULL,
          error_family TEXT NOT NULL,
          error_fingerprint TEXT NOT NULL,
          error_excerpt TEXT NOT NULL,
          auto_eligible INTEGER NOT NULL DEFAULT 0,
          occurrences INTEGER NOT NULL DEFAULT 1,
          status TEXT NOT NULL DEFAULT 'captured',
          recovery_action TEXT,
          recovery_evidence INTEGER NOT NULL DEFAULT 0,
          lesson_id INTEGER,
          UNIQUE(project_id, tool_name, bad_action, error_fingerprint)
        );
        CREATE TABLE IF NOT EXISTS lessons (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          project_id TEXT,
          scope TEXT NOT NULL DEFAULT 'project',
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          title TEXT NOT NULL,
          cause TEXT NOT NULL,
          rule_text TEXT NOT NULL,
          confidence REAL NOT NULL,
          status TEXT NOT NULL DEFAULT 'active',
          source TEXT NOT NULL,
          source_candidate_id INTEGER,
          tags TEXT NOT NULL DEFAULT '',
          use_count INTEGER NOT NULL DEFAULT 0,
          last_used TEXT
        );
        CREATE TABLE IF NOT EXISTS guards (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          lesson_id INTEGER NOT NULL,
          project_id TEXT,
          tool_name TEXT NOT NULL,
          field_name TEXT NOT NULL,
          match_type TEXT NOT NULL,
          pattern TEXT NOT NULL,
          replacement TEXT,
          reason TEXT NOT NULL,
          active INTEGER NOT NULL DEFAULT 1,
          created_at TEXT NOT NULL,
          expires_at TEXT,
          hit_count INTEGER NOT NULL DEFAULT 0,
          last_hit TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_candidates_project ON candidates(project_id, status, last_seen);
        CREATE INDEX IF NOT EXISTS idx_lessons_project ON lessons(project_id, status);
        CREATE INDEX IF NOT EXISTS idx_guards_project ON guards(project_id, active, tool_name);
        PRAGMA user_version=1;
        """), db)
        with_retry(db.commit, db)
        current = 1
    migrate(db, current)
    # Only write when it actually changes. An unconditional write here dirties the
    # database on every invocation, including read-only ones, which destroys the
    # watchdog's ability to tell a real mutation from a routine open.
    row = db.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
    if row is None or str(row[0]) != str(SCHEMA_VERSION):
        with_retry(lambda: db.execute(
            "INSERT OR REPLACE INTO meta(key,value) VALUES('schema_version',?)", (str(SCHEMA_VERSION),)), db)
        with_retry(db.commit, db)
    return db


SCHEMA_V2 = """
CREATE TABLE IF NOT EXISTS guard_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  guard_id INTEGER NOT NULL,
  lesson_id INTEGER NOT NULL,
  project_id TEXT NOT NULL,
  session_id TEXT,
  tool_name TEXT NOT NULL,
  action TEXT NOT NULL,
  mode TEXT NOT NULL,
  created_at TEXT NOT NULL,
  outcome TEXT NOT NULL DEFAULT 'pending',
  resolved_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_guard_events_project ON guard_events(project_id, outcome, created_at);
CREATE INDEX IF NOT EXISTS idx_guard_events_session ON guard_events(session_id, outcome);
"""


ORIGIN_TABLES = ("candidates", "lessons", "guards", "guard_events")


def _add_origin_columns(db: sqlite3.Connection) -> None:
    """ALTER ADD COLUMN, guarded against a column that already exists.

    Unlike the CREATE TABLE IF NOT EXISTS statements elsewhere, ALTER TABLE ADD
    COLUMN has no idempotent form in SQLite -- re-running it against a table
    that already has the column raises "duplicate column name". That is a real
    path, not just theoretical: `user_version` can be rolled back (as the v1
    migration test deliberately does) without the columns themselves being
    dropped, so this must tolerate being entered more than once.
    """
    for table in ORIGIN_TABLES:
        cols = {row[1] for row in db.execute(f"PRAGMA table_info({table})")}
        if "origin" not in cols:
            db.execute(f"ALTER TABLE {table} ADD COLUMN origin TEXT NOT NULL DEFAULT 'natural_usage'")


def migrate(db: sqlite3.Connection, current: int) -> None:
    """Forward-only migrations. Each step is idempotent and independently retried."""
    if current < 2:
        with_retry(lambda: db.executescript(SCHEMA_V2), db)
        with_retry(lambda: db.execute("PRAGMA user_version=2"), db)
        with_retry(db.commit, db)
    if current < 3:
        with_retry(lambda: _add_origin_columns(db), db)
        # Explicit, auditable backfill -- not a counter reset. Every row that
        # existed before this plugin tracked origin was produced while
        # developing and testing my-error itself, never by unprompted agent
        # use, so it is data for the pipeline's functional proof, not for the
        # natural-usage SHADOW verdict. Stamping it controlled_test here keeps
        # those rows (they are never deleted) while starting the natural
        # population at a true, auditable zero. The timestamp in `meta` is the
        # audit trail: exactly when this reclassification happened and why.
        backfilled_at = utcnow()
        with_retry(lambda: db.execute(
            "UPDATE candidates SET origin=? WHERE origin=?", (ORIGIN_CONTROLLED, ORIGIN_NATURAL)), db)
        with_retry(lambda: db.execute(
            "UPDATE lessons SET origin=? WHERE origin=?", (ORIGIN_CONTROLLED, ORIGIN_NATURAL)), db)
        with_retry(lambda: db.execute(
            "UPDATE guards SET origin=? WHERE origin=?", (ORIGIN_CONTROLLED, ORIGIN_NATURAL)), db)
        with_retry(lambda: db.execute(
            "UPDATE guard_events SET origin=? WHERE origin=?", (ORIGIN_CONTROLLED, ORIGIN_NATURAL)), db)
        with_retry(lambda: db.execute(
            "INSERT OR REPLACE INTO meta(key,value) VALUES('origin_migration_backfilled_at',?)",
            (backfilled_at,)), db)
        with_retry(lambda: db.execute("PRAGMA user_version=3"), db)
        with_retry(db.commit, db)


def experiment_started(db: sqlite3.Connection, create: bool = False) -> str | None:
    """Stamp the first moment SHADOW ran, so 'day 30' is a fact, not a memory.

    Only hooks may create the stamp. A read-only command that wrote it would be a
    write, which is exactly the defect this codebase just removed elsewhere.
    """
    row = db.execute("SELECT value FROM meta WHERE key='shadow_started_at'").fetchone()
    if row:
        return str(row[0])
    if not create:
        return None
    now = utcnow()
    try:
        with_retry(lambda: db.execute(
            "INSERT OR IGNORE INTO meta(key,value) VALUES('shadow_started_at',?)", (now,)), db)
        with_retry(db.commit, db)
    except sqlite3.Error:
        return now
    row = db.execute("SELECT value FROM meta WHERE key='shadow_started_at'").fetchone()
    return str(row[0]) if row else now


def get_mode(db: sqlite3.Connection) -> str:
    """Mode resolution: env override, then stored setting, then the safe default."""
    env = (os.getenv("MY_ERROR_MODE") or "").strip().upper()
    if env in (MODE_SHADOW, MODE_ENFORCE):
        return env
    try:
        row = db.execute("SELECT value FROM meta WHERE key='mode'").fetchone()
    except sqlite3.Error:
        return DEFAULT_MODE
    if row and str(row[0]).upper() in (MODE_SHADOW, MODE_ENFORCE):
        return str(row[0]).upper()
    return DEFAULT_MODE


def set_mode(db: sqlite3.Connection, mode: str) -> str:
    mode = mode.strip().upper()
    if mode not in (MODE_SHADOW, MODE_ENFORCE):
        raise ValueError("mode must be SHADOW or ENFORCE")
    with_retry(lambda: db.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('mode',?)", (mode,)), db)
    with_retry(db.commit, db)
    return mode

def ensure_project(db: sqlite3.Connection, root: str) -> str:
    pid = project_id(root)
    now = utcnow()
    # SELECT-then-INSERT races: two concurrent hooks both observe an absent row
    # and both insert, and one loses its whole event to the UNIQUE violation.
    # Throttled: refreshing last_seen on every open would make every read-only
    # command a write, defeating the watchdog's staleness check and amplifying
    # lock contention for a field nothing reads at minute resolution.
    row = db.execute("SELECT last_seen FROM projects WHERE id=?", (pid,)).fetchone()
    if row is not None:
        try:
            age = (dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(row[0])).total_seconds()
        except Exception:
            age = LAST_SEEN_REFRESH_SECONDS + 1
        if age < LAST_SEEN_REFRESH_SECONDS:
            return pid

    def write():
        db.execute(
            "INSERT INTO projects(id,root,created_at,last_seen) VALUES(?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen",
            (pid, root, now, now),
        )
        db.commit()
    with_retry(write, db)
    return pid

def json_out(obj: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(obj, ensure_ascii=False, separators=(",", ":")))


def hook_context(event_name: str, text: str) -> dict[str, Any]:
    return {"hookSpecificOutput": {"hookEventName": event_name, "additionalContext": text}}


def base_tokens(text: str) -> set[str]:
    parts = re.findall(r"[A-Za-zÀ-ÿ0-9_.:/-]{2,}", text.lower())
    return {p for p in parts if p not in STOPWORDS}

def tokenize(text: str) -> set[str]:
    raw = base_tokens(text)
    expanded = set(raw)
    for token in raw:
        concept = SEMANTIC_LOOKUP.get(token)
        if concept:
            expanded.add(concept)
        # Conservative singular fallback improves migrations->migration, tests->test, etc.
        if token.endswith("s") and len(token) > 4:
            singular = token[:-1]
            expanded.add(singular)
            concept = SEMANTIC_LOOKUP.get(singular)
            if concept:
                expanded.add(concept)
    return expanded


def extract_action(tool_name: str, tool_input: dict[str, Any]) -> str:
    if tool_name == "Bash":
        return redact(tool_input.get("command", "")).strip()
    if tool_name == "Write":
        path = redact(tool_input.get("file_path", ""))
        content = str(tool_input.get("content", ""))
        digest = hashlib.sha256(content.encode("utf-8", "replace")).hexdigest()[:12] if content else ""
        return f"file={path};content_sha256={digest}"
    if tool_name == "Edit":
        path = redact(tool_input.get("file_path", ""))
        new = redact(tool_input.get("new_string", ""))
        return f"file={path};new={new[:500]}"
    return redact(json.dumps(tool_input, ensure_ascii=False, sort_keys=True))


def normalize_error(error: str) -> str:
    text = redact(error).lower()
    text = re.sub(r"/[^\s:]+", "<path>", text)
    text = re.sub(r"\b\d+(?:\.\d+)?\b", "<n>", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:1200]


def fingerprint(error: str) -> str:
    return hashlib.sha256(normalize_error(error).encode()).hexdigest()[:24]


def classify_failure(error: str, interrupted: bool) -> tuple[str, bool, bool]:
    low = error.lower()
    if interrupted:
        return "interrupt", False, True
    if any(re.search(p, low, re.I) for p in TRANSIENT_PATTERNS):
        return "transient", False, True
    for family, patterns in FAMILY_PATTERNS:
        if any(re.search(p, low, re.I) for p in patterns):
            return family, family in AUTO_ELIGIBLE, False
    if re.search(r"module not found|cannot find module|no module named|modulenotfounderror|importerror|"
                 r"m[oó]dulo n[aã]o encontrado|nenhum m[oó]dulo (?:chamado|denominado)|no se encontr[oó] el m[oó]dulo", low, re.I):
        return "dependency_or_import", False, False
    if re.search(r"assertionerror|tests? failed|failed,|\bfailures?\b|testes? (?:falhou|falharam|com falha)|\\bfalhas?\\b|\\bfallo|\\b[eé]chec", low, re.I):
        return "test_failure", False, False
    return "other", False, False


def missing_target_is_action_token(error: str, action: str) -> bool:
    """True only when a missing-module diagnostic names a shell token from the action.

    This distinguishes `node sever.js` (entrypoint typo) from `node app.js`
    failing because app.js imports an absent dependency such as `express`.
    """
    try:
        tokens = shlex.split(action)
    except ValueError:
        tokens = action.split()
    if len(tokens) < 2:
        return False
    lines = error.lower().splitlines()
    diagnostic_lines = [
        line for line in lines
        if re.search(r"cannot find module|module not found|no module named|can't find module|"
                     r"m[oó]dulo n[aã]o encontrado|nenhum m[oó]dulo|no se encontr[oó] el m[oó]dulo", line, re.I)
    ]
    if not diagnostic_lines:
        return False
    diagnostic = " ".join(diagnostic_lines)
    for token in tokens[1:]:
        clean = token.strip("'\"` ").lower()
        if not clean or clean.startswith("-"):
            continue
        variants = {clean, Path(clean).name.lower()}
        if any(v and v in diagnostic for v in variants):
            return True
    return False


def active_locale() -> str:
    return os.getenv("LC_ALL") or os.getenv("LC_MESSAGES") or os.getenv("LANG") or ""


def locale_is_recognized(loc: str | None = None) -> bool:
    raw = active_locale() if loc is None else loc
    lang = raw.split(".")[0].split("_")[0].lower()
    return lang in RECOGNIZED_LANGS


def fallback_active() -> bool:
    """The heuristic fallback is emergency cover, not a general mechanism.

    Where FAMILY_PATTERNS already covers the language it buys nothing measurable
    (both live benchmarks reach 100% without it) while adding false-positive
    surface. Where the language is unknown it is the difference between learning
    and doing nothing at all. So it is gated on exactly that condition.
    """
    return not locale_is_recognized()


def changed_token(bad: str, good: str) -> str | None:
    """Return the single shell token that differs between two commands, if exactly one does."""
    try:
        bad_tokens, good_tokens = shlex.split(bad), shlex.split(good)
    except ValueError:
        return None
    if len(bad_tokens) != len(good_tokens) or not bad_tokens:
        return None
    diffs = [(a, b) for a, b in zip(bad_tokens, good_tokens) if a != b]
    return diffs[0][0] if len(diffs) == 1 else None


def error_blames_changed_token(error: str, bad: str, good: str) -> bool:
    """Locale-independent evidence that the one changed token caused the failure.

    Family regexes are message-text based and therefore language-dependent. This
    check is not: if the failing command differs from the succeeding one by
    exactly one token, and the failure output literally names that token (and
    does not name its corrected form), the diagnostic itself points at the typo.
    That holds in every locale, because the offending token is echoed verbatim.
    """
    token = changed_token(bad, good)
    if not token:
        return False
    clean = token.strip("'\"` ").lower()
    good_token = changed_token(good, bad)
    good_clean = (good_token or "").strip("'\"` ").lower()
    # A token too short or too generic would match by accident.
    if len(clean) < 3 or not clean or clean == good_clean:
        return False
    # Ignore stack-trace frames: a traceback naming the entrypoint file proves
    # only that the file ran, not that its name was the mistake.
    lines = [
        line for line in redact(error).lower().splitlines()
        if not re.match(r"\s*(?:at\s|file\s+\"|\s+in\s)", line)
    ]
    low = "\n".join(lines)
    variants = {clean, Path(clean).name.lower(), clean.lstrip("-")}
    if not any(v and v in low for v in variants if len(v) >= 3):
        return False
    # If the output also names the corrected token, the message is a
    # "did you mean" suggestion listing both; that is still evidence, but only
    # when the bad token appears first (i.e. as the subject of the complaint).
    if good_clean and len(good_clean) >= 3 and good_clean in low:
        return low.index(clean) < low.index(good_clean)
    return True


def auto_eligible_for_failure(family: str, base_eligible: bool, error: str, action: str) -> bool:
    if base_eligible:
        return True
    if family == "dependency_or_import" and missing_target_is_action_token(error, action):
        return True
    return False


def lesson_rows(db: sqlite3.Connection, pid: str) -> list[sqlite3.Row]:
    """Candidates for prompt recall, selected explicitly.

    Two filters that are policy, not optimisation:

    - automatically learned lessons are excluded. One reads "do not run
      `git sttaus`, run `git status`" -- useless as context, and already covered
      by its guard. Auto lessons are fuel for prediction; reviewed lessons are
      fuel for context. Mixing them spends tokens on every prompt to degrade the
      half that matters. The filter keys off AUTO_LESSON_SOURCES rather than an
      allow-list, so a lesson written by any human-reviewed path still recalls.
    - dormant lessons are excluded. Unused for RECALL_DORMANT_DAYS means it stops
      being injected, not that it is gone: `review` still lists it and a single
      use makes it current again.

    The LIMIT is a ceiling against a pathological table, applied *after* ordering,
    never the selection rule itself.
    """
    cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=RECALL_DORMANT_DAYS)).isoformat(timespec="seconds")
    return list(db.execute(
        "SELECT * FROM lessons "
        " WHERE status='active' "
        f"   AND source NOT IN ({','.join('?' * len(AUTO_LESSON_SOURCES))}) "
        "   AND (scope='global' OR project_id=?) "
        "   AND COALESCE(last_used, updated_at) >= ? "
        " ORDER BY confidence DESC, COALESCE(last_used, updated_at) DESC "
        " LIMIT ?",
        (*sorted(AUTO_LESSON_SOURCES), pid, cutoff, RECALL_SCAN_CEILING),
    ))


def recall(db: sqlite3.Connection, pid: str, query: str, limit: int = 5) -> list[sqlite3.Row]:
    q_raw = base_tokens(query)
    q = tokenize(query)
    scored: list[tuple[float, sqlite3.Row]] = []
    for row in lesson_rows(db, pid):
        hay = f"{row['title']} {row['cause']} {row['rule_text']} {row['tags']}"
        t_raw = base_tokens(hay)
        t = tokenize(hay)
        exact_overlap = len(q_raw & t_raw)
        expanded_overlap = len(q & t)
        semantic_only = max(0, expanded_overlap - exact_overlap)
        if not q:
            score = row["confidence"] * 0.2
        else:
            # Exact words remain strongest; concept aliases bridge different wording.
            score = exact_overlap * 2.0 + semantic_only * 1.15 + row["confidence"]
            if expanded_overlap and row["confidence"] >= 0.85:
                score += 0.3
        if expanded_overlap > 0:
            scored.append((score, row))
    scored.sort(key=lambda x: (-x[0], -x[1]["confidence"], x[1]["id"]))
    chosen = [r for _, r in scored[:limit]]
    if chosen:
        now = utcnow()
        db.executemany("UPDATE lessons SET use_count=use_count+1,last_used=? WHERE id=?", [(now, r["id"]) for r in chosen])
        db.commit()
    return chosen


def format_lessons(rows: Iterable[sqlite3.Row], heading: str = "Relevant learned rules") -> str:
    rows = list(rows)
    if not rows:
        return ""
    lines = [f"[my-error] {heading}. Treat these as project memory; verify against current code if circumstances changed:"]
    for r in rows:
        lines.append(f"- ERR-{r['id']:04d} ({r['confidence']:.2f}): {r['rule_text']}")
    return "\n".join(lines)


def upsert_candidate(db: sqlite3.Connection, pid: str, event: dict[str, Any]) -> tuple[int | None, str, bool, bool]:
    tool = str(event.get("tool_name", ""))
    action = extract_action(tool, event.get("tool_input") or {})
    err = redact(event.get("error", ""))
    family, base_eligible, ignored = classify_failure(err, bool(event.get("is_interrupt", False)))
    eligible = auto_eligible_for_failure(family, base_eligible, err, action)
    if ignored or not action:
        return None, family, eligible, ignored
    fp = fingerprint(err)
    now = utcnow()
    session = str(event.get("session_id", ""))
    # Origin is captured only on first sighting and never touched by the
    # ON CONFLICT branch: a candidate's classification is decided the moment
    # it is first observed and does not flip on a later repeat.
    origin = event_origin()
    with_retry(lambda: db.execute("""
      INSERT INTO candidates(project_id,session_id,created_at,last_seen,tool_name,bad_action,error_family,error_fingerprint,error_excerpt,auto_eligible,origin)
      VALUES(?,?,?,?,?,?,?,?,?,?,?)
      ON CONFLICT(project_id,tool_name,bad_action,error_fingerprint)
      DO UPDATE SET occurrences=occurrences+1,last_seen=excluded.last_seen,session_id=excluded.session_id,error_excerpt=excluded.error_excerpt
    """, (pid, session, now, now, tool, action, family, fp, err[:1600], int(eligible), origin)), db)
    row = db.execute(
        "SELECT id FROM candidates WHERE project_id=? AND tool_name=? AND bad_action=? AND error_fingerprint=?",
        (pid, tool, action, fp),
    ).fetchone()
    db.commit()
    return int(row["id"]), family, eligible, ignored


def command_similarity(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    ratio = difflib.SequenceMatcher(None, a, b).ratio()
    try:
        ta, tb = shlex.split(a), shlex.split(b)
    except ValueError:
        ta, tb = a.split(), b.split()
    token_ratio = difflib.SequenceMatcher(None, ta, tb).ratio()
    return max(ratio, token_ratio)


def narrow_command_correction(bad: str, good: str) -> bool:
    """Accept only a conservative one-token correction for auto-learning.

    A nearby success is not enough. Exactly one shell token must change, and
    that token must itself be strongly similar. Broader fixes require manual
    causal review so unrelated successful commands cannot become false rules.
    """
    if not bad or not good:
        return False
    try:
        bad_tokens = shlex.split(bad)
        good_tokens = shlex.split(good)
    except ValueError:
        return False
    if len(bad_tokens) != len(good_tokens) or not bad_tokens:
        return False
    diffs = [(a, b) for a, b in zip(bad_tokens, good_tokens) if a != b]
    if len(diffs) != 1:
        return False
    before, after = diffs[0]
    token_similarity = difflib.SequenceMatcher(None, before, after).ratio()
    return token_similarity >= 0.70 and command_similarity(bad, good) >= 0.75


def make_auto_lesson(db: sqlite3.Connection, pid: str, candidate: sqlite3.Row, good_action: str) -> int:
    now = utcnow()
    # Inherited from the candidate that caused it, not re-read from the current
    # environment: the lesson and its guard are the direct, same-transaction
    # consequence of that one candidate, so they carry its classification
    # rather than risk drifting from it.
    origin = candidate["origin"]
    title = f"Correct {candidate['error_family']} command"
    cause = (
        f"The exact command `{candidate['bad_action']}` produced a deterministic {candidate['error_family']} failure; "
        f"the closely related command `{good_action}` then succeeded in the same session."
    )
    rule = f"For this project, do not retry `{candidate['bad_action']}` for this operation; use `{good_action}` instead."
    cur = db.execute("""
      INSERT INTO lessons(project_id,scope,created_at,updated_at,title,cause,rule_text,confidence,status,source,source_candidate_id,tags,origin)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (pid, "project", now, now, title, cause, rule, 0.95, "active", sorted(AUTO_LESSON_SOURCES)[0], candidate["id"], candidate["error_family"], origin))
    lesson_id = int(cur.lastrowid)
    expires = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=AUTO_GUARD_TTL_DAYS)).isoformat(timespec="seconds")
    db.execute("""
      INSERT INTO guards(lesson_id,project_id,tool_name,field_name,match_type,pattern,replacement,reason,active,created_at,expires_at,origin)
      VALUES(?,?,?,?,?,?,?,?,1,?,?,?)
    """, (lesson_id, pid, "Bash", "command", "exact", candidate["bad_action"], good_action,
          f"my-error learned this exact command already failed; use `{good_action}` instead.", now, expires, origin))
    db.execute("UPDATE candidates SET status='learned',recovery_action=?,recovery_evidence=recovery_evidence+1,lesson_id=? WHERE id=?",
               (good_action, lesson_id, candidate["id"]))
    db.commit()
    return lesson_id


def observe_success(db: sqlite3.Connection, pid: str, event: dict[str, Any]) -> tuple[int | None, int | None]:
    tool = str(event.get("tool_name", ""))
    if tool != "Bash":
        return None, None
    resp = event.get("tool_response")
    if isinstance(resp, dict) and (resp.get("is_error") or resp.get("error")):
        return None, None
    good = extract_action(tool, event.get("tool_input") or {})
    session = str(event.get("session_id", ""))
    cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=RECOVERY_WINDOW_MINUTES)).isoformat(timespec="seconds")
    rows = list(db.execute("""
      SELECT * FROM candidates
      WHERE project_id=? AND session_id=? AND tool_name='Bash' AND status IN ('captured','evidence') AND last_seen>=?
      ORDER BY last_seen DESC LIMIT 8
    """, (pid, session, cutoff)))
    for row in rows:
        # Narrow deterministic failures can be auto-learned when a closely related
        # corrected command succeeds immediately afterward.
        if row["bad_action"] != good and narrow_command_correction(row["bad_action"], good):
            eligible = bool(row["auto_eligible"])
            if not eligible and fallback_active() and row["error_family"] not in NEVER_AUTO_FAMILIES:
                # Unrecognized locale only: the failure text itself blames the
                # single token that the correction changed.
                eligible = error_blames_changed_token(row["error_excerpt"], row["bad_action"], good)
            if eligible:
                lesson_id = make_auto_lesson(db, pid, row, good)
                return int(row["id"]), lesson_id

        # For semantic/test failures, a later success is evidence of recovery, not
        # proof of cause. Preserve it for Claude to review at Stop.
        if row["bad_action"] == good or command_similarity(row["bad_action"], good) >= 0.80:
            db.execute(
                "UPDATE candidates SET status='evidence',recovery_action=?,recovery_evidence=recovery_evidence+1,last_seen=? WHERE id=?",
                (good, utcnow(), row["id"]),
            )
            db.commit()
            return int(row["id"]), None
    return None, None

def get_field(tool_input: dict[str, Any], field_name: str) -> str:
    val = tool_input.get(field_name, "")
    if isinstance(val, (dict, list)):
        return json.dumps(val, ensure_ascii=False, sort_keys=True)
    return str(val)


def guard_matches(match_type: str, pattern: str, value: str) -> bool:
    if match_type == "exact":
        return value.strip() == pattern.strip()
    if match_type == "contains":
        return pattern in value
    if match_type == "regex":
        try:
            return re.search(pattern, value, re.MULTILINE) is not None
        except re.error:
            return False
    return False


def active_guards(db: sqlite3.Connection, pid: str, tool: str) -> list[sqlite3.Row]:
    now = utcnow()
    return list(db.execute(
        "SELECT g.*,l.rule_text FROM guards g JOIN lessons l ON l.id=g.lesson_id WHERE g.active=1 AND l.status='active' AND g.tool_name=? AND (g.project_id IS NULL OR g.project_id=?) AND (g.expires_at IS NULL OR g.expires_at>=?)",
        (tool, pid, now),
    ))

def run_guard(db: sqlite3.Connection, pid: str, event: dict[str, Any]) -> dict[str, Any] | None:
    tool = str(event.get("tool_name", ""))
    inp = event.get("tool_input") or {}
    mode = get_mode(db)
    session = str(event.get("session_id", ""))
    for g in active_guards(db, pid, tool):
        raw = get_field(inp, g["field_name"])
        # Guard patterns are stored redacted, so a command carrying a secret would
        # never match its own stored pattern. Compare both forms.
        candidates = {raw, redact(raw)}
        if not any(guard_matches(g["match_type"], g["pattern"], v) for v in candidates):
            continue
        now = utcnow()
        action = redact(raw)
        # Read fresh here, not inherited from the guard: a guard learned during
        # a controlled test can still fire on genuine natural use later, and
        # that firing must be judged as natural evidence, not attributed
        # forever to how the guard first came to exist.
        origin = event_origin()

        def record() -> None:
            db.execute("UPDATE guards SET hit_count=hit_count+1,last_hit=? WHERE id=?", (now, g["id"]))
            db.execute(
                "INSERT INTO guard_events(guard_id,lesson_id,project_id,session_id,tool_name,action,mode,created_at,origin)"
                " VALUES(?,?,?,?,?,?,?,?,?)",
                (g["id"], g["lesson_id"], pid, session, tool, action, mode, now, origin),
            )
            db.commit()
        with_retry(record, db)

        if mode == MODE_SHADOW:
            # Deliberately permissive: let it run so the outcome can be observed.
            # Emitting no output at all keeps the measurement uncontaminated -- an
            # injected warning would change the very behaviour being measured.
            return None

        reason = g["reason"]
        if g["replacement"]:
            reason += f" Suggested replacement: {g['replacement']}"
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
                "additionalContext": f"[my-error] Prevented recurrence of ERR-{g['lesson_id']:04d}. {g['rule_text']}"
            }
        }
    return None


def resolve_guard_events(db: sqlite3.Connection, pid: str, event: dict[str, Any], failed: bool) -> None:
    """Score a shadow guard against what the command actually did.

    This is the whole point of SHADOW. The guard predicted "this will fail again".
    If the command then succeeds, the guard was demonstrably wrong -- a false
    positive measured, not estimated. If it fails again, the prediction held.
    """
    tool = str(event.get("tool_name", ""))
    session = str(event.get("session_id", ""))
    action = redact(get_field(event.get("tool_input") or {}, "command" if tool == "Bash" else "file_path"))
    if not action:
        return
    outcome = "true_positive" if failed else "false_positive"
    now = utcnow()

    def write() -> None:
        db.execute(
            "UPDATE guard_events SET outcome=?,resolved_at=? "
            "WHERE outcome='pending' AND project_id=? AND session_id=? AND tool_name=? AND action=?",
            (outcome, now, pid, session, tool, action),
        )
        db.commit()
    with_retry(write)



def write_beacon(db: sqlite3.Connection, event: dict[str, Any], kind: str,
                 pid: str | None = None) -> None:
    """Emit a liveness beacon for the external watchdog.

    my-error must not be the judge of whether my-error is running -- if it stops
    loading, its own hooks stop too and it would report nothing rather than
    report failure. So it only emits evidence; the global watchdog decides.

    The beacon carries the metrics too. Not as a cache: the database can only be
    mutated by this process, so a beacon written after the last mutation is not
    stale, it is current. The watchdog still compares the beacon's timestamp
    against the database mtime, so a beacon that falls behind is reported as
    stale rather than trusted.
    """
    try:
        db_path = data_dir() / "my-error.db"
        payload = {
            "version": VERSION,
            "mode": get_mode(db),
            "session_id": str(event.get("session_id", "")),
            "last_hook": kind,
            "last_seen": utcnow(),
            "plugin_root": str(Path(__file__).resolve().parents[1]),
            "db": str(db_path),
            "db_mtime": db_path.stat().st_mtime if db_path.exists() else None,
            "projects": {},
        }
        if pid:
            payload["projects"][pid] = collect_metrics(db, pid)
        path = data_dir() / "runtime.json"
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload), encoding="utf-8")
        tmp.replace(path)  # atomic: the watchdog never reads a half-written beacon
    except Exception:
        pass  # a beacon failure must never affect the session


def cmd_hook(args: argparse.Namespace) -> int:
    """Dispatch, then beacon. The beacon must describe state *after* the hook ran,
    otherwise every metric it carries is one event behind."""
    db, pid, event = None, None, {}
    try:
        rc, db, pid, event = _dispatch_hook(args)
    finally:
        if db is not None:
            write_beacon(db, event, args.kind, pid)
    return rc


def _dispatch_hook(args: argparse.Namespace) -> tuple[int, sqlite3.Connection, str, dict[str, Any]]:
    try:
        event = json.load(sys.stdin)
    except Exception:
        event = {}
    db = connect()
    root = canonical_root(event)
    pid = ensure_project(db, root)
    kind = args.kind
    if get_mode(db) == MODE_SHADOW:
        experiment_started(db, create=True)

    if kind == "session-start":
        rows = [r for r in lesson_rows(db, pid) if r["confidence"] >= 0.90][:3]
        if rows:
            json_out(hook_context("SessionStart", format_lessons(rows, "high-confidence memory loaded at session start")))
        return 0, db, pid, event

    if kind == "prompt":
        prompt = redact(event.get("prompt", ""))
        rows = recall(db, pid, prompt, 5)
        if rows:
            json_out(hook_context("UserPromptSubmit", format_lessons(rows)))
        return 0, db, pid, event

    if kind == "guard":
        out = run_guard(db, pid, event)
        if out:
            json_out(out)
        return 0, db, pid, event

    if kind == "failure":
        resolve_guard_events(db, pid, event, failed=True)
        cid, family, eligible, ignored = upsert_candidate(db, pid, event)
        if ignored:
            return 0, db, pid, event
        query = f"{event.get('tool_name','')} {extract_action(str(event.get('tool_name','')), event.get('tool_input') or {})} {event.get('error','')}"
        rows = recall(db, pid, query, 3)
        bits = []
        if cid:
            bits.append(f"[my-error] Captured candidate CAND-{cid:04d} ({family}). A failure is NOT yet a lesson; identify root cause and verify the correction before promoting it.")
            if eligible:
                bits.append("If a closely related Bash command succeeds next, my-error can automatically learn the exact correction and guard against repeating the failed command.")
        if rows:
            bits.append(format_lessons(rows, "possibly relevant prior lessons"))
        if bits:
            json_out(hook_context("PostToolUseFailure", "\n".join(bits)))
        return 0, db, pid, event

    if kind == "success":
        resolve_guard_events(db, pid, event, failed=False)
        cid, lesson_id = observe_success(db, pid, event)
        if lesson_id:
            json_out(hook_context(
                "PostToolUse",
                f"[my-error] Verified recovery: CAND-{cid:04d} became ERR-{lesson_id:04d}. The exact failed command is now guarded in this project."
            ))
        return 0, db, pid, event

    if kind == "stop":
        session = str(event.get("session_id", ""))
        rows = list(db.execute(
            "SELECT * FROM candidates WHERE project_id=? AND session_id=? AND status='evidence' AND recovery_evidence>0 ORDER BY last_seen DESC LIMIT 3",
            (pid, session),
        ))
        if rows:
            ids = ", ".join(f"CAND-{r['id']:04d}" for r in rows)
            db.executemany("UPDATE candidates SET status='review_requested' WHERE id=?", [(r["id"],) for r in rows])
            db.commit()
            json_out(hook_context(
                "Stop",
                f"[my-error] {ids} now has recovery evidence: a previously failing operation succeeded. Before finishing, invoke the `my-error:learn` skill for these candidates. Promote only if you can state the root cause and why the successful verification proves the correction; otherwise ignore the candidate."
            ))
        return 0, db, pid, event

    if kind == "cleanup":
        cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=180)).isoformat(timespec="seconds")
        db.execute("DELETE FROM candidates WHERE status='captured' AND last_seen<?", (cutoff,))
        db.execute("UPDATE guards SET active=0 WHERE active=1 AND expires_at IS NOT NULL AND expires_at<?", (utcnow(),))
        db.commit()
        return 0, db, pid, event

    return 0, db, pid, event


def confidence_value(raw: str) -> float:
    m = {"low": 0.55, "medium": 0.75, "high": 0.90, "verified": 0.98}
    try:
        return max(0.0, min(1.0, float(raw)))
    except ValueError:
        return m.get(raw.lower(), 0.75)


def cmd_learn(args: argparse.Namespace) -> int:
    db = connect()
    root = canonical_root()
    pid = ensure_project(db, root)
    scope = args.scope
    now = utcnow()
    source_candidate = args.candidate_id
    cand = None
    if source_candidate:
        cand = db.execute("SELECT * FROM candidates WHERE id=? AND project_id=?", (source_candidate, pid)).fetchone()
        if not cand:
            print(f"Candidate {source_candidate} not found in this project", file=sys.stderr)
            return 2
    conf = confidence_value(args.confidence)
    # --origin is the explicit, temporary override for manual testing; absent
    # that, a lesson born from a candidate inherits its origin (same reasoning
    # as make_auto_lesson), and a lesson with no candidate falls back to
    # whatever MY_ERROR_EVENT_ORIGIN says right now (natural_usage by default).
    if args.origin in VALID_ORIGINS:
        origin = args.origin
    elif cand is not None:
        origin = cand["origin"]
    else:
        origin = event_origin()
    cur = db.execute("""
      INSERT INTO lessons(project_id,scope,created_at,updated_at,title,cause,rule_text,confidence,status,source,source_candidate_id,tags,origin)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (None if scope == "global" else pid, scope, now, now, args.title, args.cause, args.rule, conf,
          "active", "manual-verified", source_candidate, args.tags or "", origin))
    lid = int(cur.lastrowid)
    if source_candidate:
        db.execute("UPDATE candidates SET status='learned',lesson_id=? WHERE id=?", (lid, source_candidate))
    if args.guard_tool:
        if not args.guard_field or not args.guard_pattern:
            print("--guard-field and --guard-pattern are required with --guard-tool", file=sys.stderr)
            db.rollback()
            return 2
        expires = None
        if args.guard_ttl_days > 0:
            expires = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=args.guard_ttl_days)).isoformat(timespec="seconds")
        db.execute("""
          INSERT INTO guards(lesson_id,project_id,tool_name,field_name,match_type,pattern,replacement,reason,active,created_at,expires_at,origin)
          VALUES(?,?,?,?,?,?,?,?,1,?,?,?)
        """, (lid, None if scope == "global" else pid, args.guard_tool, args.guard_field, args.guard_match,
              args.guard_pattern, args.replacement, args.guard_reason or args.rule, now, expires, origin))
    db.commit()
    print(f"Learned ERR-{lid:04d} confidence={conf:.2f} scope={scope}" + (" with guard" if args.guard_tool else ""))
    return 0



def collect_metrics(db: sqlite3.Connection, pid: str) -> dict[str, Any]:
    """The single source of truth for both the watchdog line and doctor.

    Every field here is a count of rows that exist. Nothing is estimated, and a
    metric that cannot be computed is absent rather than zero.
    """
    mode = get_mode(db)
    started = experiment_started(db)
    try:
        days = (dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(started)).days
    except Exception:
        days = None
    one = lambda q, a=(): db.execute(q, a).fetchone()[0]  # noqa: E731

    failures = one("SELECT COUNT(*) FROM candidates WHERE project_id=?", (pid,))
    failure_events = one("SELECT COALESCE(SUM(occurrences),0) FROM candidates WHERE project_id=?", (pid,))
    # 'learned' is the only status that survived the plugin's verification gate.
    # 'evidence' means a later success was observed but the cause is unproven, so
    # it deliberately does NOT count as a correction.
    verified = one("SELECT COUNT(*) FROM candidates WHERE project_id=? AND status='learned'", (pid,))
    unverified_recovery = one(
        "SELECT COUNT(*) FROM candidates WHERE project_id=? AND status IN ('evidence','review_requested')", (pid,))
    lessons = one(
        "SELECT COUNT(*) FROM lessons WHERE status='active' AND (scope='global' OR project_id=?)", (pid,))
    guards = one(
        "SELECT COUNT(*) FROM guards g JOIN lessons l ON l.id=g.lesson_id "
        "WHERE g.active=1 AND l.status='active' AND (g.project_id IS NULL OR g.project_id=?)", (pid,))

    ev = lambda where, a=(): one(  # noqa: E731
        f"SELECT COUNT(*) FROM guard_events WHERE project_id=? {where}", (pid,) + a)
    would_block = ev("AND mode='SHADOW'")
    actual_blocks = ev("AND mode='ENFORCE'")
    confirmed_total = ev("AND outcome='true_positive'")
    refuted_total = ev("AND outcome='false_positive'")
    pending_total = ev("AND outcome='pending'")

    # The SHADOW experiment's population split. `shadow_verdict_*` is what the
    # 30-day pre-committed rule reads -- natural_usage only, never
    # controlled_test. `controlled_*` exists purely for the auditable "the
    # pipeline works" record; it must never feed the verdict. See METRICS.md.
    natural_would_block = ev("AND mode='SHADOW' AND origin=?", (ORIGIN_NATURAL,))
    natural_confirmed = ev("AND outcome='true_positive' AND origin=?", (ORIGIN_NATURAL,))
    natural_refuted = ev("AND outcome='false_positive' AND origin=?", (ORIGIN_NATURAL,))
    natural_pending = ev("AND outcome='pending' AND origin=?", (ORIGIN_NATURAL,))

    controlled_would_block = ev("AND mode='SHADOW' AND origin=?", (ORIGIN_CONTROLLED,))
    controlled_confirmed = ev("AND outcome='true_positive' AND origin=?", (ORIGIN_CONTROLLED,))
    controlled_refuted = ev("AND outcome='false_positive' AND origin=?", (ORIGIN_CONTROLLED,))
    controlled_pending = ev("AND outcome='pending' AND origin=?", (ORIGIN_CONTROLLED,))

    return {
        "mode": mode,
        "shadow_started_at": started,   # None until the first hook stamps it
        "shadow_day": days,
        "failures_captured": failures,
        "failure_events": failure_events,
        "verified_corrections": verified,
        "unverified_recoveries": unverified_recovery,
        "lessons_active": lessons,
        "guards_active": guards,
        "guard_matches_total": would_block + actual_blocks,
        "would_block_shadow": would_block,
        "actual_blocks_enforce": actual_blocks,
        # Totals across BOTH populations. May include controlled_test; never
        # use these for the shadow verdict -- use shadow_verdict_* below.
        "predictions_confirmed_total": confirmed_total,
        "predictions_refuted_total": refuted_total,
        "predictions_pending_total": pending_total,
        # natural_usage only. This is what shadow_verdict() consumes.
        "natural_would_block": natural_would_block,
        "shadow_verdict_confirmed": natural_confirmed,
        "shadow_verdict_refuted": natural_refuted,
        "shadow_verdict_pending": natural_pending,
        # controlled_test only. Proof the pipeline works; never a decision input.
        "controlled_would_block": controlled_would_block,
        "controlled_confirmed": controlled_confirmed,
        "controlled_refuted": controlled_refuted,
        "controlled_pending": controlled_pending,
    }



def shadow_verdict(m: dict[str, Any]) -> tuple[str, str]:
    """Apply the pre-committed rule. Returns (verdict, rationale).

    Chosen before the first measurement:
      confirmed == 0                      -> REMOVE the auto-guard from the code
      refuted > confirmed                 -> REMOVE
      confirmed >= 3 and refuted == 0     -> PROMOTE to ENFORCE
      anything else                       -> EXTEND another 30 days

    Reads shadow_verdict_confirmed / shadow_verdict_refuted -- natural_usage
    only. controlled_test data (deliberately provoked repeats used to prove
    the pipeline works) never reaches this function's inputs; see
    docs/METRICS.md for why mixing the two would invalidate the experiment.
    """
    confirmed = m.get("shadow_verdict_confirmed", 0)
    refuted = m.get("shadow_verdict_refuted", 0)
    day = m.get("shadow_day")
    if day is None:
        return "NOT STARTED", "no hook has run yet"
    if day < SHADOW_EXPERIMENT_DAYS:
        return "RUNNING", f"day {day} of {SHADOW_EXPERIMENT_DAYS}; verdict is not due yet"
    if confirmed == 0:
        return "REMOVE", "the guard never once correctly predicted a repeat; the mechanism has no measured base rate"
    if refuted > confirmed:
        return "REMOVE", f"wrong more often than right ({refuted} refuted vs {confirmed} confirmed)"
    if confirmed >= SHADOW_PROMOTE_THRESHOLD and refuted == 0:
        return "PROMOTE", f"{confirmed} correct predictions, no false positives"
    return "EXTEND", f"inconclusive ({confirmed} confirmed, {refuted} refuted); another {SHADOW_EXPERIMENT_DAYS} days"


def cmd_datadir(args: argparse.Namespace) -> int:
    """The resolver, exposed so the watchdog does not reimplement it.

    One implementation, many consumers. A second copy in JavaScript would drift
    from this one and recreate exactly the split it is meant to fix.
    """
    d = data_dir()
    out = {
        "data_dir": str(d.resolve()),
        "database": str((d / "my-error.db").resolve()),
        "beacon": str((d / "runtime.json").resolve()),
        "canonical": True,
        "injected_plugin_data": os.getenv("CLAUDE_PLUGIN_DATA"),
        "unmerged_legacy": unmerged_legacy(),
    }
    print(json.dumps(out, ensure_ascii=False,
                     separators=(",", ":") if args.compact else None,
                     indent=None if args.compact else 2))
    return 0


def cmd_metrics(args: argparse.Namespace) -> int:
    db = connect()
    root = canonical_root()
    pid = ensure_project(db, root)
    out = {"version": VERSION, "project_root": root, "project_identity": project_identity(root),
           "project_id": pid, **collect_metrics(db, pid)}
    print(json.dumps(out, ensure_ascii=False, separators=(",", ":") if args.compact else None,
                     indent=None if args.compact else 2))
    return 0


def cmd_mode(args: argparse.Namespace) -> int:
    db = connect()
    if args.set:
        try:
            print(set_mode(db, args.set))
        except ValueError as exc:
            print(str(exc), file=sys.stderr); return 2
    else:
        print(get_mode(db))
    return 0

def cmd_status(args: argparse.Namespace) -> int:
    db = connect(); pid = ensure_project(db, canonical_root())
    counts = {}
    counts["active_lessons"] = db.execute("SELECT COUNT(*) c FROM lessons WHERE status='active' AND (scope='global' OR project_id=?)", (pid,)).fetchone()[0]
    counts["active_guards"] = db.execute("SELECT COUNT(*) c FROM guards g JOIN lessons l ON l.id=g.lesson_id WHERE g.active=1 AND l.status='active' AND (g.project_id IS NULL OR g.project_id=?)", (pid,)).fetchone()[0]
    counts["pending_candidates"] = db.execute("SELECT COUNT(*) c FROM candidates WHERE project_id=? AND status IN ('captured','evidence','review_requested')", (pid,)).fetchone()[0]
    counts["guard_hits"] = db.execute("SELECT COALESCE(SUM(hit_count),0) FROM guards WHERE project_id IS NULL OR project_id=?", (pid,)).fetchone()[0]
    print(json.dumps({"version": VERSION, "project": canonical_root(), **counts}, indent=2, ensure_ascii=False))
    return 0


def cmd_review(args: argparse.Namespace) -> int:
    db = connect(); pid = ensure_project(db, canonical_root())
    cands = list(db.execute("SELECT id,created_at,tool_name,bad_action,error_family,occurrences,recovery_action,recovery_evidence FROM candidates WHERE project_id=? AND status IN ('captured','evidence','review_requested') ORDER BY last_seen DESC LIMIT ?", (pid,args.limit)))
    lessons = list(db.execute("SELECT id,title,rule_text,confidence,source,use_count FROM lessons WHERE status='active' AND (scope='global' OR project_id=?) ORDER BY updated_at DESC LIMIT ?", (pid,args.limit)))
    print("PENDING CANDIDATES")
    if not cands: print("(none)")
    for c in cands:
        print(f"CAND-{c['id']:04d} {c['error_family']} x{c['occurrences']} | {c['bad_action']}")
    print("\nACTIVE LESSONS")
    if not lessons: print("(none)")
    for l in lessons:
        print(f"ERR-{l['id']:04d} [{l['confidence']:.2f}] {l['title']} | {l['rule_text']} | source={l['source']} uses={l['use_count']}")
    return 0


def parse_id(raw: str) -> int:
    m = re.search(r"(\d+)$", raw)
    if not m: raise ValueError("invalid id")
    return int(m.group(1))


def cmd_forget(args: argparse.Namespace) -> int:
    db = connect(); pid = ensure_project(db, canonical_root())
    try: lid = parse_id(args.lesson_id)
    except ValueError:
        print("Invalid lesson id", file=sys.stderr); return 2
    row = db.execute("SELECT * FROM lessons WHERE id=? AND (scope='global' OR project_id=?)", (lid,pid)).fetchone()
    if not row:
        print("Lesson not found", file=sys.stderr); return 2
    db.execute("UPDATE lessons SET status='superseded',updated_at=? WHERE id=?", (utcnow(), lid))
    db.execute("UPDATE guards SET active=0 WHERE lesson_id=?", (lid,))
    db.commit(); print(f"Superseded ERR-{lid:04d}; associated guards disabled")
    return 0


def cmd_ignore(args: argparse.Namespace) -> int:
    db = connect(); pid = ensure_project(db, canonical_root())
    try:
        cid = parse_id(args.candidate_id)
    except ValueError:
        print("Invalid candidate id", file=sys.stderr); return 2
    cur = db.execute("UPDATE candidates SET status='ignored' WHERE id=? AND project_id=?", (cid,pid))
    db.commit()
    if cur.rowcount == 0:
        print("Candidate not found", file=sys.stderr); return 2
    print(f"Ignored CAND-{cid:04d}"); return 0


def hooks_declared() -> dict[str, bool]:
    """Which hook events the shipped manifest actually registers."""
    manifest = Path(__file__).resolve().parents[1] / "hooks" / "hooks.json"
    try:
        data = json.loads(manifest.read_text(encoding="utf-8")).get("hooks", {})
    except Exception:
        return {}
    return {ev: bool(groups) for ev, groups in data.items()}


def locale_recognized() -> tuple[str, bool]:
    loc = active_locale()
    return (loc or "unset"), locale_is_recognized(loc)


def cmd_doctor(args: argparse.Namespace) -> int:
    db = connect(); root = canonical_root(); pid = ensure_project(db, root)
    schema = int(db.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0])
    db_path = data_dir() / "my-error.db"
    loc, loc_ok = locale_recognized()
    m = collect_metrics(db, pid)
    hooks = hooks_declared()
    beacon_path = data_dir() / "runtime.json"
    beacon: dict[str, Any] | None = None
    try:
        beacon = json.loads(beacon_path.read_text(encoding="utf-8"))
    except Exception:
        beacon = None

    origin_backfilled_row = db.execute(
        "SELECT value FROM meta WHERE key='origin_migration_backfilled_at'").fetchone()
    origin_backfilled_at = str(origin_backfilled_row[0]) if origin_backfilled_row else None

    if args.json:
        print(json.dumps({
            "version": VERSION, "schema_version": schema, "database": str(db_path.resolve()),
            "data_dir": str(data_dir().resolve()),
            "injected_plugin_data": os.getenv("CLAUDE_PLUGIN_DATA"),
            "injected_matches_canonical": (
                Path(os.getenv("CLAUDE_PLUGIN_DATA")).resolve() == data_dir().resolve()
                if os.getenv("CLAUDE_PLUGIN_DATA") else None),
            "unmerged_legacy": unmerged_legacy(),
            "database_readable": os.access(db_path, os.R_OK),
            "database_writable": os.access(data_dir(), os.W_OK), "project_root": root, "project_identity": project_identity(root),
            "project_id": pid, "python": sys.version.split()[0], "locale": loc,
            "locale_recognized": loc_ok, "fallback_active": not loc_ok, "hooks_declared": hooks, "beacon": beacon,
            "families_supported": sorted(AUTO_ELIGIBLE),
            "shadow_verdict": shadow_verdict(m)[0], "shadow_verdict_reason": shadow_verdict(m)[1],
            "verdict_dataset": "NATURAL USAGE ONLY",
            "origin_migration_backfilled_at": origin_backfilled_at, **m,
        }, indent=2, ensure_ascii=False))
        return 0

    L = []
    L.append("MY-ERROR DOCTOR")
    L.append("")
    L.append(f"Version:            {VERSION}")
    L.append(f"Schema version:     {schema}")
    L.append(f"Python:             {sys.version.split()[0]}")
    L.append(f"Mode:               {m['mode']}")
    if m["mode"] == MODE_SHADOW:
        if m["shadow_started_at"]:
            L.append(f"Shadow experiment:  day {m['shadow_day']} of {SHADOW_EXPERIMENT_DAYS} "
                     f"(started {m['shadow_started_at']})")
            v, why = shadow_verdict(m)
            L.append(f"Pre-committed verdict: {v} - {why}")
        else:
            L.append("Shadow experiment:  not started (no hook has run yet)")
        L.append("                    nothing is blocked; the guard only records what it would have blocked")
    L.append("")
    L.append("Hooks declared by this plugin:")
    for ev in sorted(hooks):
        L.append(f"  {ev}: {'OK' if hooks[ev] else 'MISSING'}")
    if not hooks:
        L.append("  (manifest unreadable)")
    L.append("")
    L.append("Liveness beacon (read by the external watchdog):")
    if beacon:
        L.append(f"  last hook:        {beacon.get('last_hook')} at {beacon.get('last_seen')}")
        L.append(f"  session:          {beacon.get('session_id') or '(none)'}")
    else:
        L.append("  ABSENT - no hook of this plugin has run yet")
    L.append("")
    L.append(f"Database:           {db_path.resolve()}")
    L.append(f"Database readable:  {'yes' if os.access(db_path, os.R_OK) else 'NO'}")
    L.append(f"Database writable:  {'yes' if os.access(data_dir(), os.W_OK) else 'NO'}")
    injected = os.getenv("CLAUDE_PLUGIN_DATA")
    if injected:
        same = Path(injected).resolve() == data_dir().resolve()
        L.append(f"Injected data dir:  {Path(injected).resolve()}")
        L.append(f"                    {'matches canonical' if same else 'IGNORED - canonical path wins (see CANONICAL_DIR_NAME)'}")
    else:
        L.append("Injected data dir:  not set (skill/CLI context) - canonical path used")
    stray = unmerged_legacy()
    if stray:
        L.append("Legacy databases still holding data (NOT merged automatically):")
        for d in stray:
            L.append(f"  {d}")
    L.append(f"Project root:       {root}")
    ident = project_identity(root)
    L.append(f"Project identity:   {ident}")
    L.append(f"                    ({'git common dir' if ident != root else 'filesystem path (not a Git repository)'})")
    L.append(f"Project namespace:  {pid}")
    L.append(f"Locale:             {loc}")
    L.append(f"Locale recognized:  {'yes' if loc_ok else 'no'}")
    L.append(f"Fallback active:    {'no (explicit patterns cover this locale)' if loc_ok else 'YES (emergency cover for an unrecognized locale)'}")
    L.append("")
    L.append("Metrics (this project):")
    L.append(f"  failures captured:      {m['failures_captured']} distinct ({m['failure_events']} events)")
    L.append(f"  verified corrections:   {m['verified_corrections']}")
    L.append(f"  unverified recoveries:  {m['unverified_recoveries']} (awaiting causal review)")
    L.append(f"  lessons active:         {m['lessons_active']}")
    L.append(f"  guards active:          {m['guards_active']}")
    L.append(f"  guard matches total:    {m['guard_matches_total']}")
    L.append(f"    would-block (SHADOW): {m['would_block_shadow']}")
    L.append(f"    actual blocks:        {m['actual_blocks_enforce']}")
    L.append("")
    L.append("Shadow experiment")
    L.append("")
    L.append("Natural usage:")
    L.append(f"  would_block: {m['natural_would_block']}")
    L.append(f"  confirmed: {m['shadow_verdict_confirmed']}")
    L.append(f"  refuted: {m['shadow_verdict_refuted']}")
    L.append(f"  pending: {m['shadow_verdict_pending']}")
    L.append("")
    L.append("Controlled tests:")
    L.append(f"  would_block: {m['controlled_would_block']}")
    L.append(f"  confirmed: {m['controlled_confirmed']}")
    L.append(f"  refuted: {m['controlled_refuted']}")
    L.append("")
    L.append("Verdict dataset:")
    L.append("  NATURAL USAGE ONLY")
    if origin_backfilled_at:
        L.append("")
        L.append(f"Origin migration:   pre-existing rows backfilled as controlled_test at {origin_backfilled_at}")
    print("\n".join(L))
    return 0 if os.access(data_dir(), os.W_OK) else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="my_error.py")
    sub = p.add_subparsers(dest="command", required=True)
    h = sub.add_parser("hook"); h.add_argument("kind", choices=["session-start","prompt","guard","failure","success","stop","cleanup"]); h.set_defaults(func=cmd_hook)
    l = sub.add_parser("learn")
    l.add_argument("--candidate-id", type=int)
    l.add_argument("--title", required=True); l.add_argument("--cause", required=True); l.add_argument("--rule", required=True)
    l.add_argument("--confidence", default="high"); l.add_argument("--scope", choices=["project","global"], default="project"); l.add_argument("--tags", default="")
    l.add_argument("--guard-tool", choices=["Bash","Write","Edit"]); l.add_argument("--guard-field")
    l.add_argument("--guard-match", choices=["exact","contains","regex"], default="exact"); l.add_argument("--guard-pattern")
    l.add_argument("--replacement"); l.add_argument("--guard-reason"); l.add_argument("--guard-ttl-days", type=int, default=0)
    l.add_argument("--origin", choices=sorted(VALID_ORIGINS),
                    help="Explicit, temporary override for the SHADOW experiment population. "
                         "Defaults to the source candidate's origin, or MY_ERROR_EVENT_ORIGIN, or natural_usage.")
    l.set_defaults(func=cmd_learn)
    s = sub.add_parser("status"); s.set_defaults(func=cmd_status)
    r = sub.add_parser("review"); r.add_argument("--limit", type=int, default=20); r.set_defaults(func=cmd_review)
    f = sub.add_parser("forget"); f.add_argument("lesson_id"); f.set_defaults(func=cmd_forget)
    i = sub.add_parser("ignore"); i.add_argument("candidate_id"); i.set_defaults(func=cmd_ignore)
    d = sub.add_parser("doctor"); d.add_argument("--json", action="store_true"); d.set_defaults(func=cmd_doctor)
    dd = sub.add_parser("datadir"); dd.add_argument("--compact", action="store_true"); dd.set_defaults(func=cmd_datadir)
    mt = sub.add_parser("metrics"); mt.add_argument("--compact", action="store_true"); mt.set_defaults(func=cmd_metrics)
    md = sub.add_parser("mode"); md.add_argument("--set"); md.set_defaults(func=cmd_mode)
    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "hook":
        # A learning plugin must never be able to break a session. Any internal
        # failure (locked/corrupt DB, read-only data dir, malformed event) is
        # swallowed: no output, exit 0, tool call proceeds untouched.
        try:
            return int(cmd_hook(args))
        except Exception as exc:  # noqa: BLE001 - deliberate catch-all at the boundary
            if os.getenv("MY_ERROR_DEBUG"):
                print(f"my-error hook error: {exc!r}", file=sys.stderr)
            return 0
    return int(args.func(args))

if __name__ == "__main__":
    raise SystemExit(main())
