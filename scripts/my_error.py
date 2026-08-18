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
import re
import shlex
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any, Iterable

VERSION = "0.3.0"
SCHEMA_VERSION = 2
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


def project_id(root: str) -> str:
    return hashlib.sha256(root.encode("utf-8", "replace")).hexdigest()[:20]


def data_dir() -> Path:
    raw = os.getenv("MY_ERROR_DATA_DIR") or os.getenv("CLAUDE_PLUGIN_DATA") or str(Path.home() / ".claude" / "my-error")
    p = Path(raw)
    p.mkdir(parents=True, exist_ok=True)
    return p


def with_retry(fn, attempts: int = 6):
    """Retry a write through transient SQLite lock contention.

    Hooks fire concurrently (parallel tool calls, subagents), so a lock is
    expected rather than exceptional. Losing a capture is worse than waiting.
    """
    delay = 0.05
    for attempt in range(attempts):
        try:
            return fn()
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc).lower() and "busy" not in str(exc).lower():
                raise
            if attempt == attempts - 1:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 0.5)


def connect() -> sqlite3.Connection:
    db_path = data_dir() / "my-error.db"
    is_new = not db_path.exists()
    # Several hooks can fire concurrently (parallel tool calls, subagents). A short
    # busy timeout silently drops captures under I/O contention, so keep it generous:
    # a hook that waits is invisible, a hook that loses a lesson is not.
    db = sqlite3.connect(db_path, timeout=BUSY_TIMEOUT_MS / 1000.0)
    db.row_factory = sqlite3.Row
    # WAL is a persistent property of the file, but set it unconditionally so a
    # database created by a racing process is not left in rollback-journal mode.
    db.execute("PRAGMA journal_mode=WAL")
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
        """))
        with_retry(db.commit)
        current = 1
    migrate(db, current)
    # Only write when it actually changes. An unconditional write here dirties the
    # database on every invocation, including read-only ones, which destroys the
    # watchdog's ability to tell a real mutation from a routine open.
    row = db.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
    if row is None or str(row[0]) != str(SCHEMA_VERSION):
        with_retry(lambda: db.execute(
            "INSERT OR REPLACE INTO meta(key,value) VALUES('schema_version',?)", (str(SCHEMA_VERSION),)))
        with_retry(db.commit)
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


def migrate(db: sqlite3.Connection, current: int) -> None:
    """Forward-only migrations. Each step is idempotent and independently retried."""
    if current < 2:
        with_retry(lambda: db.executescript(SCHEMA_V2))
        with_retry(lambda: db.execute("PRAGMA user_version=2"))
        with_retry(db.commit)


def experiment_started(db: sqlite3.Connection) -> str:
    """Stamp the first moment SHADOW ran, so 'day 30' is a fact, not a memory."""
    row = db.execute("SELECT value FROM meta WHERE key='shadow_started_at'").fetchone()
    if row:
        return str(row[0])
    now = utcnow()
    try:
        with_retry(lambda: db.execute(
            "INSERT OR IGNORE INTO meta(key,value) VALUES('shadow_started_at',?)", (now,)))
        with_retry(db.commit)
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
    with_retry(lambda: db.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('mode',?)", (mode,)))
    with_retry(db.commit)
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
    with_retry(write)
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
    return list(db.execute(
        "SELECT * FROM lessons WHERE status='active' AND (scope='global' OR project_id=?) "
        "ORDER BY confidence DESC, updated_at DESC LIMIT 500",
        (pid,),
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
    with_retry(lambda: db.execute("""
      INSERT INTO candidates(project_id,session_id,created_at,last_seen,tool_name,bad_action,error_family,error_fingerprint,error_excerpt,auto_eligible)
      VALUES(?,?,?,?,?,?,?,?,?,?)
      ON CONFLICT(project_id,tool_name,bad_action,error_fingerprint)
      DO UPDATE SET occurrences=occurrences+1,last_seen=excluded.last_seen,session_id=excluded.session_id,error_excerpt=excluded.error_excerpt
    """, (pid, session, now, now, tool, action, family, fp, err[:1600], int(eligible))))
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
    title = f"Correct {candidate['error_family']} command"
    cause = (
        f"The exact command `{candidate['bad_action']}` produced a deterministic {candidate['error_family']} failure; "
        f"the closely related command `{good_action}` then succeeded in the same session."
    )
    rule = f"For this project, do not retry `{candidate['bad_action']}` for this operation; use `{good_action}` instead."
    cur = db.execute("""
      INSERT INTO lessons(project_id,scope,created_at,updated_at,title,cause,rule_text,confidence,status,source,source_candidate_id,tags)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
    """, (pid, "project", now, now, title, cause, rule, 0.95, "active", "auto-verified-recovery", candidate["id"], candidate["error_family"]))
    lesson_id = int(cur.lastrowid)
    expires = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=AUTO_GUARD_TTL_DAYS)).isoformat(timespec="seconds")
    db.execute("""
      INSERT INTO guards(lesson_id,project_id,tool_name,field_name,match_type,pattern,replacement,reason,active,created_at,expires_at)
      VALUES(?,?,?,?,?,?,?,?,1,?,?)
    """, (lesson_id, pid, "Bash", "command", "exact", candidate["bad_action"], good_action,
          f"my-error learned this exact command already failed; use `{good_action}` instead.", now, expires))
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

        def record() -> None:
            db.execute("UPDATE guards SET hit_count=hit_count+1,last_hit=? WHERE id=?", (now, g["id"]))
            db.execute(
                "INSERT INTO guard_events(guard_id,lesson_id,project_id,session_id,tool_name,action,mode,created_at)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (g["id"], g["lesson_id"], pid, session, tool, action, mode, now),
            )
            db.commit()
        with_retry(record)

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

    if kind == "session-start":
        rows = list(db.execute(
            "SELECT * FROM lessons WHERE status='active' AND (scope='global' OR project_id=?) AND confidence>=0.90 ORDER BY updated_at DESC LIMIT 3",
            (pid,),
        ))
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
    if source_candidate:
        cand = db.execute("SELECT * FROM candidates WHERE id=? AND project_id=?", (source_candidate, pid)).fetchone()
        if not cand:
            print(f"Candidate {source_candidate} not found in this project", file=sys.stderr)
            return 2
    conf = confidence_value(args.confidence)
    cur = db.execute("""
      INSERT INTO lessons(project_id,scope,created_at,updated_at,title,cause,rule_text,confidence,status,source,source_candidate_id,tags)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
    """, (None if scope == "global" else pid, scope, now, now, args.title, args.cause, args.rule, conf,
          "active", "manual-verified", source_candidate, args.tags or ""))
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
          INSERT INTO guards(lesson_id,project_id,tool_name,field_name,match_type,pattern,replacement,reason,active,created_at,expires_at)
          VALUES(?,?,?,?,?,?,?,?,1,?,?)
        """, (lid, None if scope == "global" else pid, args.guard_tool, args.guard_field, args.guard_match,
              args.guard_pattern, args.replacement, args.guard_reason or args.rule, now, expires))
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
        days = 0
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
    confirmed = ev("AND outcome='true_positive'")
    refuted = ev("AND outcome='false_positive'")
    pending = ev("AND outcome='pending'")

    return {
        "mode": mode,
        "shadow_started_at": started,
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
        "predictions_confirmed": confirmed,
        "predictions_refuted": refuted,
        "predictions_pending": pending,
    }


def cmd_metrics(args: argparse.Namespace) -> int:
    db = connect()
    root = canonical_root()
    pid = ensure_project(db, root)
    out = {"version": VERSION, "project_root": root, "project_id": pid, **collect_metrics(db, pid)}
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

    if args.json:
        print(json.dumps({
            "version": VERSION, "schema_version": schema, "database": str(db_path),
            "database_writable": os.access(data_dir(), os.W_OK), "project_root": root,
            "project_id": pid, "python": sys.version.split()[0], "locale": loc,
            "locale_recognized": loc_ok, "fallback_active": not loc_ok, "hooks_declared": hooks, "beacon": beacon,
            "families_supported": sorted(AUTO_ELIGIBLE), **m,
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
        L.append(f"Shadow experiment:  day {m['shadow_day']} of 30 (started {m['shadow_started_at']})")
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
    L.append(f"Database:           {db_path}")
    L.append(f"Database writable:  {'yes' if os.access(data_dir(), os.W_OK) else 'NO'}")
    L.append(f"Project root:       {root}")
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
    L.append("  Shadow scoring (what the guard predicted vs what happened):")
    L.append(f"    predictions confirmed: {m['predictions_confirmed']} (ran anyway, failed again)")
    L.append(f"    predictions refuted:   {m['predictions_refuted']} (ran anyway, SUCCEEDED = false positive)")
    L.append(f"    still pending:         {m['predictions_pending']}")
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
    l.set_defaults(func=cmd_learn)
    s = sub.add_parser("status"); s.set_defaults(func=cmd_status)
    r = sub.add_parser("review"); r.add_argument("--limit", type=int, default=20); r.set_defaults(func=cmd_review)
    f = sub.add_parser("forget"); f.add_argument("lesson_id"); f.set_defaults(func=cmd_forget)
    i = sub.add_parser("ignore"); i.add_argument("candidate_id"); i.set_defaults(func=cmd_ignore)
    d = sub.add_parser("doctor"); d.add_argument("--json", action="store_true"); d.set_defaults(func=cmd_doctor)
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
