#!/usr/bin/env node
/**
 * my-error observability state — the single reader used by every observer.
 *
 * WHY THIS FILE EXISTS
 * There are now two things outside the plugin that need to know how my-error is
 * doing: the UserPromptSubmit watchdog, and the status line segment. Left alone
 * they would each grow their own answer to "where is the database", "is the
 * beacon current", "is this installation healthy" — three implementations of
 * one question, drifting apart the first time any of them changes. Everything
 * that decides those questions lives here; the callers only decide how to
 * *phrase* the answer, which is genuinely different between a one-line system
 * message and a four-token status line segment.
 *
 * WHY IT READS THE BEACON RATHER THAN QUERYING
 * Not to avoid the database, but to avoid a second implementation of the
 * metrics. `my_error.py` writes `runtime.json` after every hook, and the numbers
 * in it come from `collect_metrics` — the same function `doctor` uses. Reading
 * the beacon is reading the plugin's own answer. Re-deriving "active lessons"
 * in JavaScript would invent a competing definition.
 *
 * HONESTY RULES (inherited from the watchdog, now shared)
 * - Structural facts are cached; liveness and metrics never are.
 * - An unreadable database reports UNAVAILABLE. It never degrades to zeros.
 * - A beacon older than the database it describes is stale, not trusted: only
 *   the plugin mutates that database, so a beacon written after the last
 *   mutation is current — and one written before it is not.
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

/** The canonical location, without asking the plugin.
 *
 *  Used only by callers that may not spawn a process (the status line runs on
 *  every redraw). It is a deliberate second statement of the default path, and
 *  the only one: it is reached exactly when the authoritative answer is
 *  unavailable, and any caller using it must treat the result as a guess by
 *  reporting degraded health if the files are not where it looked. */
function fallbackDataDir() {
  const override = process.env.MY_ERROR_DATA_DIR;
  if (override && override.trim()) return override.trim();
  return path.join(CLAUDE, 'plugins', 'data', 'my-error');
}

/** MY_ERROR_DATA_DIR wins, always and everywhere.
 *
 *  It is the escape hatch tests and multi-install setups rely on, so a value
 *  read from a cache — written by some other process, possibly without it — must
 *  never outrank it. Applied as the last step of every path so there is one
 *  place to look when the answer is surprising. */
function applyDataDirOverride(health) {
  const override = process.env.MY_ERROR_DATA_DIR;
  if (override && override.trim()) {
    health.data_dir = override.trim();
    health.data_dir_guessed = false;
  }
  return health;
}

/**
 * Facts that only change when configuration changes — safe to cache.
 *
 * @param {object} [opts]
 * @param {boolean} [opts.allowSpawn=true]  May run python3 to resolve the data
 *   directory. Callers on a hot path (the status line) pass false and accept
 *   the cached or fallback answer instead of paying for a process per redraw.
 * @param {boolean} [opts.writeCache=true]  May refresh the shared cache file.
 *   A read-only caller passes false so that two observers running concurrently
 *   cannot race each other over the same file.
 */
function structuralHealth(opts) {
  const allowSpawn = !opts || opts.allowSpawn !== false;
  const writeCache = !opts || opts.writeCache !== false;

  const installedPath = path.join(CLAUDE, 'plugins', 'installed_plugins.json');
  const settingsPath = path.join(CLAUDE, 'settings.json');
  const stamp = `${mtime(installedPath)}:${mtime(settingsPath)}`;

  const cached = readJson(CACHE);
  const cacheFresh = cached && cached.stamp === stamp && Date.now() - cached.at < CACHE_TTL_MS;
  // The override is applied on the way out of every path, cache hit included:
  // a cache written by a process that did not have MY_ERROR_DATA_DIR set would
  // otherwise silently outrank an explicit instruction.
  if (cacheFresh) return applyDataDirOverride(cached.health);

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

  if (allowSpawn) {
    health.data_dir = resolveDataDir(health.install_path);
  } else {
    // No process may be spawned here, so prefer a stale cached answer from a
    // caller that was allowed to ask, and only then guess. `data_dir_guessed`
    // travels with the value so a formatter can report degraded health instead
    // of asserting a path it never verified.
    health.data_dir = (cached && cached.health && cached.health.data_dir) || fallbackDataDir();
    health.data_dir_guessed = !(cached && cached.health && cached.health.data_dir);
  }

  applyDataDirOverride(health);

  // Never cache an overridden answer: the cache is shared by every observer on
  // this machine, and one test run with MY_ERROR_DATA_DIR set would otherwise
  // hand a throwaway directory to the real status line for the next five minutes.
  if (writeCache && allowSpawn && !process.env.MY_ERROR_DATA_DIR) {
    try {
      fs.mkdirSync(path.dirname(CACHE), { recursive: true });
      fs.writeFileSync(CACHE, JSON.stringify({ stamp, at: Date.now(), health }));
    } catch { /* cache is an optimisation, never a requirement */ }
  }
  return health;
}

/** Never cached: liveness and freshness are exactly what must not go stale. */
function liveState(health, sessionId) {
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

module.exports = {
  CACHE, CACHE_TTL_MS, PROBE_TIMEOUT_MS,
  readJson, mtime, resolveDataDir, fallbackDataDir, applyDataDirOverride,
  structuralHealth, liveState,
};
