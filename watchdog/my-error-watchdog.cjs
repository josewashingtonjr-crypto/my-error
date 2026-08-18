#!/usr/bin/env node
/**
 * my-error watchdog — GLOBAL observability for the my-error plugin.
 *
 * WHY THIS LIVES HERE, OUTSIDE THE PLUGIN
 * A plugin cannot credibly monitor itself: if my-error stops loading, a hook
 * belonging to my-error stops running too, and its silence is indistinguishable
 * from health. So the plugin only *emits evidence* (a liveness beacon and a
 * queryable database) and this global process is the one that *judges*.
 *
 * WHERE TO PUT IT
 * Anywhere stable that another tool does not regenerate. ~/.claude/watchdogs is
 * a good default; avoid directories owned by a framework that rewrites them on
 * setup (a file placed there is silently reverted on the next run).
 *
 * WHY IT WRAPS RATHER THAN ADDS A HOOK
 * A single hook may emit exactly one JSON document. If you already run something
 * on UserPromptSubmit, registering this as a second hook makes the two fight
 * over the output. Set MY_ERROR_WRAP_COMMAND to your existing command instead:
 * it runs as a child with the same stdin and its plain-text stdout is merged
 * into `additionalContext`, which is where it already went. Hook count unchanged.
 *
 * HONESTY RULES
 * - Structural facts are cached; liveness and metrics never are.
 * - An unreadable database reports UNAVAILABLE. It never degrades to zeros.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawnSync } = require('child_process');

const HOME = os.homedir();
const CLAUDE = path.join(HOME, '.claude');
const CACHE = path.join(CLAUDE, 'watchdogs', '.my-error-health.json');
const CACHE_TTL_MS = 5 * 60 * 1000;
const PROBE_TIMEOUT_MS = 2500;

const readJson = (p) => { try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return null; } };
const mtime = (p) => { try { return fs.statSync(p).mtimeMs; } catch { return 0; } };

/** Facts that only change when configuration changes — safe to cache. */
function structuralHealth() {
  const installedPath = path.join(CLAUDE, 'plugins', 'installed_plugins.json');
  const settingsPath = path.join(CLAUDE, 'settings.json');
  const stamp = `${mtime(installedPath)}:${mtime(settingsPath)}`;

  const cached = readJson(CACHE);
  if (cached && cached.stamp === stamp && Date.now() - cached.at < CACHE_TTL_MS) return cached.health;

  const health = {
    installation: false, scope: null, enabled: false,
    install_path: null, hooks_registered: false, hooks: {}, data_dir: null,
  };

  const installed = readJson(installedPath);
  if (installed && installed.plugins) {
    for (const [key, entries] of Object.entries(installed.plugins)) {
      if (!key.startsWith('my-error@')) continue;
      const entry = (entries || []).find((e) => e && e.installPath) || null;
      if (!entry) continue;
      health.installation = fs.existsSync(path.join(entry.installPath, 'scripts', 'my_error.py'));
      health.scope = entry.scope || null;
      health.install_path = entry.installPath;
      health.plugin_key = key;
      health.version = entry.version || null;
      break;
    }
  }

  const settings = readJson(settingsPath) || {};
  const enabledMap = settings.enabledPlugins || {};
  health.enabled = health.plugin_key ? enabledMap[health.plugin_key] !== false : false;

  if (health.install_path) {
    const manifest = readJson(path.join(health.install_path, 'hooks', 'hooks.json'));
    const events = manifest && manifest.hooks ? Object.keys(manifest.hooks) : [];
    // The events that carry the plugin's actual function. Missing any of these
    // means it is installed but structurally incapable of doing its job.
    const required = ['PreToolUse', 'PostToolUseFailure', 'PostToolUse', 'SessionStart'];
    health.hooks = Object.fromEntries(required.map((e) => [e, events.includes(e)]));
    health.hooks_registered = required.every((e) => events.includes(e));
  }

  health.data_dir = resolveDataDir(health.install_path);

  try {
    fs.mkdirSync(path.dirname(CACHE), { recursive: true });
    fs.writeFileSync(CACHE, JSON.stringify({ stamp, at: Date.now(), health }));
  } catch { /* cache is an optimisation, never a requirement */ }
  return health;
}

/** Ask the plugin where its data lives. There is exactly one implementation of
 *  that resolution, in scripts/my_error.py, and this calls it rather than
 *  reproducing it. A second copy here would drift and recreate the split-brain
 *  database this replaces. The answer is cached with the structural health,
 *  which is invalidated whenever the installation changes. */
function resolveDataDir(installPath) {
  if (!installPath) return null;
  const res = spawnSync('python3', [path.join(installPath, 'scripts', 'my_error.py'), 'datadir', '--compact'], {
    encoding: 'utf8', timeout: PROBE_TIMEOUT_MS,
  });
  if (res.status !== 0 || !res.stdout) return null;
  try { return JSON.parse(res.stdout).data_dir || null; } catch { return null; }
}

/** Never cached: liveness and freshness are exactly what must not go stale.
 *
 *  Metrics come from the beacon rather than a fresh query, because only the
 *  plugin's own hooks can mutate the database — a beacon written after the last
 *  mutation is current, not cached. Freshness is proven, never assumed: the
 *  beacon carries the database mtime it observed, and if the real file has moved
 *  on, the metrics are declared stale instead of being believed. The expensive
 *  live query is kept for `--probe` and for doctor. */
function liveState(health, sessionId, cwd) {
  const state = {
    plugin_loaded: false, database_readable: false, status_query: false,
    metrics: null, beacon: null, stale: false, data_dir: health.data_dir,
  };
  if (!state.data_dir) return state;

  const db = path.join(state.data_dir, 'my-error.db');
  let dbMtime = 0;
  try {
    fs.accessSync(db, fs.constants.R_OK);
    dbMtime = fs.statSync(db).mtimeMs;
    state.database_readable = true;
  } catch { return state; }   // unreadable database short-circuits: no metrics, no pretending

  const beacon = readJson(path.join(state.data_dir, 'runtime.json'));
  state.beacon = beacon;
  if (!beacon) return state;
  // Loaded == a hook of this plugin ran in THIS session. A beacon from an older
  // session proves the plugin used to work, not that it works now.
  if (sessionId && beacon.session_id === sessionId) state.plugin_loaded = true;

  const projects = beacon.projects || {};
  const key = Object.keys(projects)[0];
  if (key) {
    state.metrics = projects[key];
    // 1s of slack absorbs WAL checkpoints that touch the file without changing rows.
    state.stale = typeof beacon.db_mtime === 'number' && dbMtime - beacon.db_mtime * 1000 > 1000;
    state.status_query = !state.stale;
  }
  return state;
}

/** The full live query. Deliberately off the per-prompt path. */
function liveStateDeep(health, sessionId, cwd) {
  const state = liveState(health, sessionId, cwd);
  if (!health.install_path || !state.data_dir) return state;
  const res = spawnSync('python3', [path.join(health.install_path, 'scripts', 'my_error.py'), 'metrics', '--compact'], {
    encoding: 'utf8', timeout: PROBE_TIMEOUT_MS,
    env: { ...process.env, CLAUDE_PROJECT_DIR: cwd || process.cwd() },
  });
  state.status_query = false;
  if (res.status === 0 && res.stdout) {
    try { state.metrics = JSON.parse(res.stdout); state.status_query = true; state.stale = false; } catch { /* malformed */ }
  }
  return state;
}

function statusLine(health, live) {
  const P = '🧠 my-error:';
  if (!health.installation) return `${P} ❌ INATIVO | não instalado`;
  if (!health.enabled) return `${P} ❌ INATIVO | instalado mas desabilitado`;
  if (health.scope !== 'user') return `${P} ⚠️ ATIVO LOCAL | não está global (scope: ${health.scope || 'desconhecido'})`;
  if (!health.hooks_registered) {
    const miss = Object.entries(health.hooks).filter(([, v]) => !v).map(([k]) => k).join(',');
    return `${P} ⚠️ INSTALADO / HOOKS INATIVOS | faltando: ${miss || 'manifesto ilegível'}`;
  }
  // Database first: a missing database is a more specific fact than a missing
  // beacon, and checking liveness first would mask it behind "no beacon".
  if (!live.database_readable) return `${P} ⚠️ ATIVO / DB INDISPONÍVEL`;
  if (!live.plugin_loaded) return `${P} ⚠️ INSTALADO / HOOKS INATIVOS | sem beacon desta sessão`;
  if (!live.metrics) return `${P} ⚠️ ATIVO / MÉTRICAS INDISPONÍVEIS`;
  if (live.stale) return `${P} ⚠️ ATIVO / MÉTRICAS DEFASADAS (banco mudou após o último hook)`;

  const m = live.metrics;
  const f = m.failures_captured;
  const v = m.verified_corrections;
  const pct = f > 0 ? ` (${Math.round((v / f) * 100)}%)` : '';
  const rep = m.mode === 'ENFORCE'
    ? `bloqueios: ${m.actual_blocks_enforce}`
    : `repetições detectadas: ${m.would_block_shadow}`;
  return `${P} ✅ ATIVO GLOBAL | falhas: ${f} | corrigidas: ${v}/${f}${pct} | lições: ${m.lessons_active} | ${rep} | modo: ${m.mode}`;
}

/** Optionally wrap a hook command you already run on UserPromptSubmit.
 *
 *  A single hook may emit only one JSON document, so if you already have a
 *  UserPromptSubmit hook, adding this one as a second entry would make the two
 *  fight over the output. Instead, point MY_ERROR_WRAP_COMMAND at your existing
 *  command: it is executed with the same stdin, and its plain-text stdout is
 *  merged into `additionalContext` — exactly where it landed before. That keeps
 *  your hook count unchanged.
 *
 *  Example, in ~/.claude/settings.json:
 *    "command": "sh -c 'MY_ERROR_WRAP_COMMAND=\"node $HOME/.claude/helpers/my-router.js route\" exec node $HOME/.claude/watchdogs/my-error-watchdog.cjs'"
 */
function runWrappedCommand(stdin, cwd) {
  const cmd = process.env.MY_ERROR_WRAP_COMMAND;
  if (!cmd) return '';
  const res = spawnSync(cmd, {
    shell: true, input: stdin, encoding: 'utf8', timeout: 8000, cwd: cwd || process.cwd(),
  });
  return (res.stdout || '').trim();
}

function main() {
  if (process.argv.includes('--probe')) {
    let ev = {};
    try { ev = JSON.parse(fs.readFileSync(0, 'utf8')); } catch { /* optional */ }
    process.stdout.write(JSON.stringify(probe(ev), null, 2));
    return;
  }
  let raw = '';
  try { raw = fs.readFileSync(0, 'utf8'); } catch { /* no stdin */ }
  let event = {};
  try { event = JSON.parse(raw); } catch { /* tolerate */ }

  const health = structuralHealth();
  const live = liveState(health, event.session_id, event.cwd);
  const line = statusLine(health, live);
  const routing = runWrappedCommand(raw, event.cwd);

  const payload = { systemMessage: line };
  if (routing) {
    payload.hookSpecificOutput = {
      hookEventName: 'UserPromptSubmit',
      additionalContext: routing,
    };
  }
  process.stdout.write(JSON.stringify(payload));
}

try { main(); } catch (err) {
  // A watchdog must never break the session it is watching.
  process.stdout.write(JSON.stringify({ systemMessage: `🧠 my-error: ⚠️ WATCHDOG FALHOU | ${String(err && err.message || err).slice(0, 120)}` }));
}
