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
const { spawnSync } = require('child_process');

// Health, freshness and data-directory resolution are shared with the status
// line segment and live in one file, so the two observers cannot drift into
// disagreeing about whether my-error is healthy. This module only *judges and
// phrases*; it does not re-derive.
const state = require('./my-error-state.cjs');
const { structuralHealth, liveState, PROBE_TIMEOUT_MS } = state;

/** The full live query. Deliberately off the per-prompt path. */
function liveStateDeep(health, sessionId, cwd) {
  const deep = liveState(health, sessionId);
  if (!health.install_path || !deep.data_dir) return deep;
  const res = spawnSync('python3', [path.join(health.install_path, 'scripts', 'my_error.py'), 'metrics', '--compact'], {
    encoding: 'utf8', timeout: PROBE_TIMEOUT_MS,
    env: { ...process.env, CLAUDE_PROJECT_DIR: cwd || process.cwd() },
  });
  deep.status_query = false;
  if (res.status === 0 && res.stdout) {
    try { deep.metrics = JSON.parse(res.stdout); deep.status_query = true; deep.stale = false; } catch { /* malformed */ }
  }
  return deep;
}

/** `--probe`: the one-shot manual verification the installer points at.
 *
 *  It exists so that "is this wired up correctly" can be answered without
 *  waiting for a prompt, and it is the only path allowed to pay for the deep
 *  query — which is why it is not what the per-prompt hook runs. */
function probe(event) {
  const health = structuralHealth();
  const live = liveStateDeep(health, event && event.session_id, event && event.cwd);
  return { health, live, line: statusLine(health, live) };
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
  // Older beacons/metrics (pre-0.3.2) won't carry the natural/controlled
  // split yet -- fall back to the pre-existing single-population line rather
  // than printing "undefined".
  const hasOriginSplit = m.shadow_verdict_confirmed !== undefined;
  const rep = m.mode === 'ENFORCE'
    ? `bloqueios: ${m.actual_blocks_enforce}`
    : hasOriginSplit
      ? `natural: ${m.shadow_verdict_confirmed} confirmações / ${m.shadow_verdict_refuted} refutações | teste: ${m.controlled_confirmed} confirmações`
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
  const live = liveState(health, event.session_id);
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
