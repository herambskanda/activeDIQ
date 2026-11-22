// Merge plan 5.4: the pre-screen runs several tickets at once and looks a set distance down the line; the light filter
// script sends back only what main does not already have, and finds the right Go packages to test.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Dispatcher } from '../lib/dispatcher.mjs';
import { preMergeSettings } from '../lib/premerge.mjs';
import { advanceTicket, claimTicket, createTicket, setTicketLinks } from '../lib/tickets.mjs';
import { ensureWorktree } from '../lib/worktree.mjs';
import { commitAll, initRepo, makeFactory, ticketInput } from './helpers.mjs';

const BIN = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'bin');
let minute = 0;

function setup(pm) {
  const f = makeFactory({ config: (c) => { c.dispatcher.pre_merge = { enabled: true, argv: ['node', 'gate.mjs'], timeout_minutes: 5, train_size: 1, prescreen_ahead: true, prescreen_argv: ['node', 'pre.mjs'], ...pm }; } });
  initRepo(f.root);
  fs.writeFileSync(path.join(f.root, 'gate.mjs'), 'process.exit(0);\n');
  fs.writeFileSync(path.join(f.root, 'pre.mjs'), 'process.exit(0);\n');
  commitAll(f.root, 'ci fixture');
  return f;
}
async function finished(f, title) {
  const t = createTicket(f.ctx, ticketInput({ title, status: 'ready' }), 'x');
  const wt = await ensureWorktree(f.ctx, t.id);
  fs.writeFileSync(path.join(wt.path, `work-${t.id}.txt`), 'work\n');
  commitAll(wt.path, `work ${t.id}`);
  f.ctx.now = () => new Date(Date.UTC(2026, 10, 1, 10, minute++));
  claimTicket(f.ctx, t.id);
  for (let i = 0; i < 3; i++) advanceTicket(f.ctx, t.id, 'w', 'ok');
  setTicketLinks(f.ctx, t.id, { branch: wt.branch, worktree: wt.path });
  return t;
}
const busy = (d, ids = ['T-9999']) => d.gateLanes.push({ ids, abort: new AbortController(), run: Promise.resolve() });
/** A runGate that records how many pre-screens are in flight and holds each until released. */
function heldGate(d) {
  const state = { now: 0, max: 0, started: [], release: [] };
  d.runGate = (ctx, tickets) => new Promise((resolve) => {
    state.now++; state.max = Math.max(state.max, state.now); state.started.push(tickets[0].id);
    state.release.push(() => { state.now--; resolve({ status: 'pass', findings: [], summary: 'ok', members: tickets.map((t) => t.id), conflicts: [] }); });
  });
  return state;
}
const tick = () => new Promise((r) => setTimeout(r, 30));

test('prescreen_parallel 2 runs two pre-screens at once and the third waits for a free place', async () => {
  const f = setup({ prescreen_parallel: 2, prescreen_lookahead: 3 });
  try {
    for (const n of ['a', 'b', 'c']) await finished(f, n);
    const d = new Dispatcher(f.ctx); d.shared = false; busy(d);
    const g = heldGate(d);
    await d.prescreenAhead(preMergeSettings(f.ctx.config)); await tick();
    assert.equal(g.now, 2, 'two in flight');
    assert.equal(g.started.length, 2);
    g.release.shift()(); await tick();
    await d.prescreenAhead(preMergeSettings(f.ctx.config)); await tick();
    assert.equal(g.started.length, 3, 'the third started once one finished');
    assert.equal(g.max, 2, 'never more than 2 at once');
    for (const r of g.release) r();
    await d.prescreenIdle();
  } finally { f.cleanup(); }
});

test('prescreen_lookahead limits how far down the line it looks', async () => {
  const f = setup({ prescreen_parallel: 3, prescreen_lookahead: 1 });
  try {
    for (const n of ['a', 'b', 'c']) await finished(f, n);
    const d = new Dispatcher(f.ctx); d.shared = false; busy(d);
    const g = heldGate(d);
    await d.prescreenAhead(preMergeSettings(f.ctx.config)); await tick();
    assert.equal(g.started.length, 1, 'only the first ticket in line');
    for (const r of g.release) r();
    await d.prescreenIdle();
  } finally { f.cleanup(); }
});

test('the default is one pre-screen at a time, as before', async () => {
  const f = setup({ prescreen_lookahead: 3 });
  try {
    for (const n of ['a', 'b']) await finished(f, n);
    const d = new Dispatcher(f.ctx); d.shared = false; busy(d);
    const g = heldGate(d);
    await d.prescreenAhead(preMergeSettings(f.ctx.config)); await tick();
    assert.equal(g.started.length, 1);
    for (const r of g.release) r();
    await d.prescreenIdle();
  } finally { f.cleanup(); }
});

test('the new settings are validated', () => {
  const cfg = (pm) => ({ dispatcher: { pre_merge: { enabled: true, argv: ['x'], ...pm } } });
  assert.throws(() => preMergeSettings(cfg({ prescreen_parallel: 0 })), /prescreen_parallel must be a whole number of at least 1/);
  assert.throws(() => preMergeSettings(cfg({ prescreen_lookahead: -1 })), /prescreen_lookahead must be a whole number/);
  assert.equal(preMergeSettings(cfg({})).prescreen_parallel, 1);
  assert.equal(preMergeSettings(cfg({})).prescreen_lookahead, 0);
});

// ---- the light filter script ---------------------------------------------------------------

const git = (dir, ...a) => execFileSync('git', ['-C', dir, '-c', 'user.name=t', '-c', 'user.email=t@x', ...a], { encoding: 'utf8' }).trim();
function goRepo() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'light-'));
  const w = (f, t) => { fs.mkdirSync(path.dirname(path.join(dir, f)), { recursive: true }); fs.writeFileSync(path.join(dir, f), t); };
  w('go.mod', 'module example.test/m\n\ngo 1.21\n');
  w('a/a.go', 'package a\n\nfunc A() int { return 1 }\n');
  w('b/b.go', 'package b\n\nimport "example.test/m/a"\n\nfunc B() int { return a.A() }\n');
  w('b/b_test.go', 'package b\n\nimport "testing"\n\nfunc TestB(t *testing.T) { if B() != 1 { t.Fatal("B") } }\n');
  w('c/c.go', 'package c\n\nfunc C() int { return 3 }\n');
  w('c/c_test.go', 'package c\n\nimport "testing"\n\nfunc TestC(t *testing.T) { if C() != 3 { t.Fatal("C") } }\n');
  git(dir, 'init', '-q', '-b', 'main'); git(dir, 'add', '-A'); git(dir, 'commit', '-q', '-m', 'base');
  return { dir, w };
}
/** main + a branch merged with --no-ff, so HEAD has two parents like the gate's merge result. */
function mergeResult(r, edit) {
  git(r.dir, 'checkout', '-q', '-b', 'topic'); edit(r.w); git(r.dir, 'add', '-A'); git(r.dir, 'commit', '-q', '-m', 'topic');
  git(r.dir, 'checkout', '-q', 'main'); git(r.dir, 'merge', '-q', '--no-ff', '-m', 'merge', 'topic');
}

test('affected-packages finds the changed package and the packages that import it, and not the rest', () => {
  const r = goRepo();
  try {
    mergeResult(r, (w) => w('a/a.go', 'package a\n\nfunc A() int { return 1 } // changed\n'));
    const out = execFileSync('python3', [path.join(BIN, 'affected-packages.py'), git(r.dir, 'rev-parse', 'HEAD^1')], { cwd: r.dir, encoding: 'utf8' }).trim().split(' ').sort();
    assert.deepEqual(out, ['example.test/m/a', 'example.test/m/b']);
  } finally { fs.rmSync(r.dir, { recursive: true, force: true }); }
});

test('affected-packages says ALL when go.mod or the CI files change', () => {
  const r = goRepo();
  try {
    mergeResult(r, (w) => w('go.mod', 'module example.test/m\n\ngo 1.22\n'));
    const out = execFileSync('python3', [path.join(BIN, 'affected-packages.py'), git(r.dir, 'rev-parse', 'HEAD^1')], { cwd: r.dir, encoding: 'utf8' }).trim();
    assert.equal(out, 'ALL');
  } finally { fs.rmSync(r.dir, { recursive: true, force: true }); }
});

/** A make that always succeeds, so the script's Go-test part is what is tested. */
function fakeMake() {
  const bin = fs.mkdtempSync(path.join(os.tmpdir(), 'fakemake-'));
  fs.writeFileSync(path.join(bin, 'make'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
  return bin;
}
const runLight = (r, bin) => {
  try { return { code: 0, out: execFileSync('bash', [path.join(BIN, 'light-filter.sh')], { cwd: r.dir, encoding: 'utf8', env: { ...process.env, PATH: `${bin}:${process.env.PATH}` }, stdio: ['ignore', 'pipe', 'pipe'] }) }; } catch (e) { return { code: e.status, out: `${e.stdout}${e.stderr}` }; }
};

test('the light filter fails a ticket whose change breaks a test in an affected package', () => {
  const r = goRepo(); const bin = fakeMake();
  try {
    mergeResult(r, (w) => w('a/a.go', 'package a\n\nfunc A() int { return 2 }\n')); // b's test now fails
    const res = runLight(r, bin);
    assert.equal(res.code, 1, res.out);
    assert.match(res.out, /--- FAIL: TestB/);
  } finally { fs.rmSync(r.dir, { recursive: true, force: true }); fs.rmSync(bin, { recursive: true, force: true }); }
});

test('the light filter does not count a test that already fails on main', () => {
  const r = goRepo(); const bin = fakeMake();
  try {
    // break TestB on main itself, then merge a harmless change to a
    fs.writeFileSync(path.join(r.dir, 'b/b_test.go'), 'package b\n\nimport "testing"\n\nfunc TestB(t *testing.T) { t.Fatal("already red on main") }\n');
    git(r.dir, 'add', '-A'); git(r.dir, 'commit', '-q', '-m', 'main is red');
    mergeResult(r, (w) => w('a/a.go', 'package a\n\nfunc A() int { return 1 } // harmless\n'));
    const res = runLight(r, bin);
    assert.equal(res.code, 0, res.out);
    assert.match(res.out, /all exist on main too/);
  } finally { fs.rmSync(r.dir, { recursive: true, force: true }); fs.rmSync(bin, { recursive: true, force: true }); }
});

test('the light filter passes a ticket that changes only an unrelated package', () => {
  const r = goRepo(); const bin = fakeMake();
  try {
    mergeResult(r, (w) => w('c/c.go', 'package c\n\nfunc C() int { return 3 } // fine\n'));
    const res = runLight(r, bin);
    assert.equal(res.code, 0, res.out);
  } finally { fs.rmSync(r.dir, { recursive: true, force: true }); fs.rmSync(bin, { recursive: true, force: true }); }
});
