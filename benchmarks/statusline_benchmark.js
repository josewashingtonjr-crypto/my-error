#!/usr/bin/env node
/**
 * What the my-error segment costs a status line.
 *
 * A status line is redrawn on essentially every interaction, so the only
 * interesting number is what this plugin ADDS — not what the bar costs in
 * total, and not what `node` costs to start. So three things are measured
 * separately and the delta is reported rather than a single total:
 *
 *   segment   in-process cost of deciding what to print (the plugin's own work)
 *   wrapper   the whole wrapper process, wrapping the real bar
 *   base      the wrapped bar on its own, same input
 *
 * `wrapper - base` is the honest end-to-end overhead, and it necessarily
 * includes one extra `node` startup, which is the price of not editing the
 * other tool's file. `segment` is the part that is actually this code.
 *
 * Usage:  node benchmarks/statusline_benchmark.js [iterations]
 *         MY_ERROR_STATUSLINE_WRAP='<command>' node benchmarks/... (optional)
 */
'use strict';

const path = require('path');
const { spawnSync } = require('child_process');

const SCRIPT = path.join(__dirname, '..', 'watchdog', 'my-error-statusline.cjs');
const { segment } = require(SCRIPT);

const N = Number(process.argv[2]) || 200;
const PAYLOAD = JSON.stringify({
  session_id: 'benchmark', cwd: process.cwd(),
  workspace: { current_dir: process.cwd() },
});

const pct = (xs, p) => {
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.floor((p / 100) * s.length))];
};
const report = (name, xs, unit = 'ms') => {
  if (!xs.length) { console.log(`${name.padEnd(10)} (não medido)`); return; }
  const mean = xs.reduce((a, b) => a + b, 0) / xs.length;
  console.log(
    `${name.padEnd(10)} n=${String(xs.length).padStart(4)}  ` +
    `p50=${pct(xs, 50).toFixed(3)}${unit}  p95=${pct(xs, 95).toFixed(3)}${unit}  ` +
    `max=${Math.max(...xs).toFixed(3)}${unit}  média=${mean.toFixed(3)}${unit}`
  );
};

// 1. The segment itself, in process.
const seg = [];
segment();                                   // warm the filesystem cache
for (let i = 0; i < N; i++) {
  const t = process.hrtime.bigint();
  segment();
  seg.push(Number(process.hrtime.bigint() - t) / 1e6);
}

// 2/3. End to end, only if a real bar was given to wrap: without one there is
// no base to subtract and the comparison would be meaningless.
const wrap = process.env.MY_ERROR_STATUSLINE_WRAP;
const PROC_N = Math.min(N, 40);   // process spawns are slow; fewer, still enough for p95
const wrapper = [];
const base = [];
if (wrap) {
  const run = (cmd, args, env) => {
    const t = process.hrtime.bigint();
    spawnSync(cmd, args, { input: PAYLOAD, encoding: 'utf8', env, timeout: 15000 });
    return Number(process.hrtime.bigint() - t) / 1e6;
  };
  for (let i = 0; i < PROC_N; i++) {
    wrapper.push(run(process.execPath, [SCRIPT], process.env));
    base.push(run(wrap, [], { ...process.env, MY_ERROR_STATUSLINE_WRAP: undefined }));
  }
}

console.log(`\nmy-error — custo do segmento de status line (${N} amostras)\n`);
report('segment', seg);
if (wrap) {
  report('wrapper', wrapper);
  report('base', base);
  const d50 = pct(wrapper, 50) - pct(base, 50);
  const d95 = pct(wrapper, 95) - pct(base, 95);
  console.log(`\noverhead ponta a ponta  p50=${d50.toFixed(1)}ms  p95=${d95.toFixed(1)}ms  (inclui 1 startup de node)`);
} else {
  console.log('\n(defina MY_ERROR_STATUSLINE_WRAP para medir o overhead ponta a ponta)');
}
