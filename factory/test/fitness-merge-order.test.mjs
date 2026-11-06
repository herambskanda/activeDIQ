// T-1707: the M5 history check and the bound-test runner, proven on throw-away repositories.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { checkHistory, checkBound, stackingLanded } from '../lib/fitness-merge-order.mjs';

const g = (cwd, ...a) => execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@t', ...a], { cwd, encoding: 'utf8' }).trim();

function repo() {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'fmo-'));
  g(d, 'init', '-q', '-b', 'main');
  g(d, 'commit', '-q', '--allow-empty', '-m', 'root');
  return d;
}
/** A branch factory/<id> with one commit, merged --no-ff as "Merge <id>: x"; returns nothing. */
function land(d, id) {
  g(d, 'checkout', '-q', '-b', `factory/${id}`, 'main');
  fs.writeFileSync(path.join(d, `${id}.txt`), id);
  g(d, 'add', '.'); g(d, 'commit', '-q', '-m', id);
  g(d, 'checkout', '-q', 'main');
  g(d, 'merge', '-q', '--no-ff', '-m', `Merge ${id}: x`, `factory/${id}`);
}
const deps = (o) => new Map(Object.entries(o));
const opts = (d, o) => ({ repo: d, deps: deps(o), grandfatherUntil: '' });

test('M5 passes when a dependency merged first', () => {
  const d = repo(); land(d, 'T-1'); land(d, 'T-2');
  assert.deepEqual(checkHistory(opts(d, { 'T-2': ['T-1'] })).violations, []);
});

test('M5 fails when the dependent merged before its dependency (failing fixture)', () => {
  const d = repo(); land(d, 'T-2'); land(d, 'T-1');
  const { violations } = checkHistory(opts(d, { 'T-2': ['T-1'] }));
  assert.equal(violations.length, 1);
  assert.equal(violations[0].dep, 'T-1');
});

test('M5 fails for a stacked dependent that carries its dependency\'s commits but lands first', () => {
  const d = repo();
  g(d, 'checkout', '-q', '-b', 'factory/T-1', 'main'); fs.writeFileSync(path.join(d, 'a'), 'a'); g(d, 'add', '.'); g(d, 'commit', '-q', '-m', 'a');
  g(d, 'checkout', '-q', '-b', 'factory/T-2'); fs.writeFileSync(path.join(d, 'b'), 'b'); g(d, 'add', '.'); g(d, 'commit', '-q', '-m', 'b');
  g(d, 'checkout', '-q', 'main'); g(d, 'merge', '-q', '--no-ff', '-m', 'Merge T-2: x', 'factory/T-2');
  assert.equal(checkHistory(opts(d, { 'T-2': ['T-1'] })).violations.length, 1);
});

test('M5 accepts a dependency with no branch (spec/docs) and a hand-merged tip', () => {
  const d = repo(); land(d, 'T-2');
  assert.deepEqual(checkHistory(opts(d, { 'T-2': ['T-9'] })).violations, []); // T-9: never had a branch
  const e = repo();
  g(e, 'checkout', '-q', '-b', 'factory/T-1'); fs.writeFileSync(path.join(e, 'a'), 'a'); g(e, 'add', '.'); g(e, 'commit', '-q', '-m', 'a');
  g(e, 'checkout', '-q', 'main'); g(e, 'merge', '-q', '--ff-only', 'factory/T-1'); // fast-forward: no Merge commit
  land(e, 'T-2');
  assert.deepEqual(checkHistory(opts(e, { 'T-2': ['T-1'] })).violations, []);
});

test('M5 grandfathers history up to the boundary only', () => {
  const d = repo(); land(d, 'T-2'); land(d, 'T-1');
  const boundary = g(d, 'rev-parse', 'HEAD');
  land(d, 'T-3');
  const r = checkHistory({ repo: d, deps: deps({ 'T-2': ['T-1'], 'T-3': ['T-4'] }), grandfatherUntil: boundary });
  assert.equal(r.checked, 1);
  assert.deepEqual(r.violations, []);
});

test('bound tests: a missing part is pending before stacking lands and fails after; a failing one fails', () => {
  const d = repo();
  fs.mkdirSync(path.join(d, 'factory/test'), { recursive: true });
  assert.ok(checkBound(d, false).every((r) => r.state === 'pending'));
  assert.ok(checkBound(d, true).every((r) => r.state === 'fail'));
  const body = (n, ok) => `import test from 'node:test';\ntest('${n} x', () => { ${ok ? '' : 'throw new Error("no")'} });\n`;
  fs.writeFileSync(path.join(d, 'factory/test/stacking.test.mjs'), body('M1', true) + body('M2', false).replace("import test from 'node:test';\n", '') + body('M3', true).replace("import test from 'node:test';\n", ''));
  fs.writeFileSync(path.join(d, 'factory/test/premerge.test.mjs'), body('M4', true));
  const by = Object.fromEntries(checkBound(d, true).map((r) => [r.id, r.state]));
  assert.deepEqual(by, { M1: 'pass', M2: 'fail', M3: 'pass', M4: 'pass' });
});

test('stackingLanded reads factory/lib for max_depth', () => {
  const d = repo(); fs.mkdirSync(path.join(d, 'factory/lib'), { recursive: true });
  fs.writeFileSync(path.join(d, 'factory/lib/a.mjs'), 'x');
  assert.equal(stackingLanded(d), false);
  fs.writeFileSync(path.join(d, 'factory/lib/a.mjs'), 'cfg.max_depth');
  assert.equal(stackingLanded(d), true);
});
