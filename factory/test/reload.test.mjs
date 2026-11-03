// T-1336: the dispatcher and the board reload themselves when factory code (lib, bin, board) lands on
// main, keeping running workers; `factory restart` is the same path for humans. The unit tests drive
// Dispatcher#maybeReload with an injected successor; the last test runs real processes end to end.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { Dispatcher } from '../lib/dispatcher.mjs';
import { factoryChange, mainSha, stopStaleGateChildren } from '../lib/reload.mjs';
import { scratchRoot } from '../lib/premerge.mjs';
import { readDispatcherState, readRecentEvents, readJson, pidAlive, putEntity, newRunId, getEntity, setControl } from '../lib/store.mjs';
import { restart } from '../lib/lifecycle.mjs';
import { FACTORY_BIN, commitAll, initRepo, makeFactory, makeLiveFactory, waitFor } from './helpers.mjs';

const sleeper = () => spawn('sleep', ['120'], { stdio: 'ignore', detached: true });
const events = (ctx) => readRecentEvents(ctx, 100).map((e) => e.text);

/** A daemon-mode dispatcher on a fixture repo, with a fake successor that announces itself at once. */
function setup({ ready = true, config } = {}) {
  const f = makeFactory({ config });
  initRepo(f.root);
  const successor = sleeper();
  const spawned = [];
  const boards = [];
  const d = new Dispatcher(f.ctx, {
    reload: {
      readyTimeoutMs: 500,
      spawnSuccessor: (ctx) => {
        spawned.push(successor.pid);
        if (ready) { const s = readDispatcherState(ctx); fs.writeFileSync(path.join(ctx.stateDir, 'dispatcher.json'), JSON.stringify({ ...s, successor_ready: successor.pid })); }
        return successor.pid;
      },
      restartBoard: async () => { boards.push(1); return { old: 1, pid: 2, port: 3 }; },
    },
  });
  d.daemon = true;
  const land = (file, text = 'x\n') => {
    fs.mkdirSync(path.dirname(path.join(f.root, file)), { recursive: true });
    fs.writeFileSync(path.join(f.root, file), text);
    commitAll(f.root, `land ${file}`);
  };
  const ready$ = async () => { d.codeSha = await mainSha(f.ctx); };
  return { ...f, d, spawned, boards, successor, land, ready$, cleanup: () => { try { process.kill(successor.pid, 'SIGKILL'); } catch { /* gone */ } f.cleanup(); } };
}

test('factoryChange sees lib, bin and board under factory/, and nothing else', async () => {
  const s = setup();
  try {
    await s.ready$();
    for (const [file, changed] of [
      ['knowledge/development/x.md', false], ['factory/test/x.test.mjs', false], ['factory/templates/t.md', false], ['internal/x.go', false],
      ['factory/lib/x.mjs', true], ['factory/bin/y', true], ['factory/board/public/app.js', true],
    ]) {
      const from = await mainSha(s.ctx);
      s.land(file);
      const result = await factoryChange(s.ctx, from, await mainSha(s.ctx));
      assert.equal(result.changed, changed, file);
    }
  } finally { s.cleanup(); }
});

test('factory code lands on main: the dispatcher starts a successor, restarts the board, names old and new SHA, and never signals a worker', async () => {
  const s = setup();
  const worker = sleeper();
  try {
    putEntity(s.ctx, 'runs', { id: newRunId(s.ctx), ticket: 'T-9999', stage: 'in_progress', role: 'backend-engineer', pid: worker.pid, status: 'running', started: new Date().toISOString() });
    s.d.adopt();
    await s.ready$();
    const before = s.d.codeSha;
    assert.equal(await s.d.maybeReload(), false, 'nothing landed yet');
    s.land('factory/lib/newcode.mjs');
    const after = await mainSha(s.ctx);

    assert.equal(await s.d.maybeReload(), true);
    assert.deepEqual([s.spawned.length, s.boards.length, s.d.reloaded], [1, 1, true]);
    const text = events(s.ctx).find((t) => t.startsWith('reload:'));
    assert.ok(text.includes(before.slice(0, 12)) && text.includes(after.slice(0, 12)), text);
    assert.match(text, /factory\/lib\/newcode\.mjs/);
    assert.match(text, /adopts 1 running worker/);
    assert.equal(pidAlive(worker.pid), true, 'the worker was not signalled');
    assert.equal(s.d.active.size, 1);
  } finally { process.kill(worker.pid, 'SIGKILL'); s.cleanup(); }
});

test('a merge gate in flight postpones the reload until it ends', async () => {
  const s = setup();
  try {
    await s.ready$();
    s.land('factory/lib/newcode.mjs');
    let end;
    s.d.gateRun = new Promise((resolve) => { end = resolve; });
    s.d.gateAbort = new AbortController();
    assert.equal(await s.d.maybeReload(), false);
    assert.equal(await s.d.maybeReload(), false);
    assert.deepEqual([s.spawned.length, s.d.gateAbort.signal.aborted], [0, false], 'the gate is neither aborted nor replaced');
    end();
    await s.d.gateRun;
    s.d.gateRun = null;
    assert.equal(await s.d.maybeReload(), true, 'one tick after the gate ends');
    assert.equal(s.spawned.length, 1);
  } finally { s.cleanup(); }
});

test('only knowledge/ landing: no reload, and the baseline moves so a later factory change is compared with it', async () => {
  const s = setup();
  try {
    await s.ready$();
    s.land('knowledge/memory/note.md');
    assert.equal(await s.d.maybeReload(), false);
    assert.equal(s.spawned.length, 0);
    assert.equal(s.d.codeSha, await mainSha(s.ctx));
    assert.equal(events(s.ctx).some((t) => t.startsWith('reload')), false);
    s.land('factory/board/server.mjs');
    assert.equal(await s.d.maybeReload(), true);
  } finally { s.cleanup(); }
});

test('a successor that does not come up leaves the old dispatcher running, says so once, and does not retry the same commit', async () => {
  const s = setup({ ready: false });
  try {
    await s.ready$();
    s.land('factory/lib/broken.mjs');
    assert.equal(await s.d.maybeReload(), false);
    assert.equal(s.d.reloaded, false);
    const failure = events(s.ctx).filter((t) => /reload to \w+ failed/.test(t));
    assert.equal(failure.length, 1);
    assert.match(failure[0], /still running the code from/);
    assert.equal(s.boards.length, 0, 'the board is left alone when the successor failed');
    assert.equal(await s.d.maybeReload(), false);
    assert.equal(s.spawned.length, 1, 'no second attempt for the same commit');
    s.land('factory/lib/fixed.mjs');
    s.successor.kill(); // a fresh commit is tried again
    assert.equal(await s.d.maybeReload(), false);
    assert.equal(s.spawned.length, 2);
  } finally { s.cleanup(); }
});

test('factory restart aborts a gate in flight and reloads at once, even with nothing new on main', async () => {
  const s = setup();
  try {
    await s.ready$();
    s.d.gateAbort = new AbortController();
    s.d.gateRun = new Promise((resolve) => { s.d.gateAbort.signal.addEventListener('abort', () => { s.d.gateRun = null; resolve(); }); });
    s.d.requestRestart();
    assert.equal(await s.d.maybeReload(), true);
    assert.equal(s.d.gateAbort.signal.aborted, true);
    assert.equal(s.d.restartRequested, false);
    assert.match(events(s.ctx).find((t) => t.startsWith('reload:')), /factory restart requested/);
  } finally { s.cleanup(); }
});

test('dispatcher.auto_reload=false switches the automatic reload off; a restart still works', async () => {
  const s = setup({ config: (c) => { c.dispatcher.auto_reload = false; } });
  try {
    await s.ready$();
    s.land('factory/lib/x.mjs');
    assert.equal(await s.d.maybeReload(), false);
    s.d.requestRestart();
    assert.equal(await s.d.maybeReload(), true);
  } finally { s.cleanup(); }
});

test('a reload stops a stale gate process under .premerge and leaves everything else alone', { skip: !fs.existsSync('/proc') }, async () => {
  const s = setup();
  const bystander = sleeper();
  try {
    const dir = path.join(scratchRoot(s.ctx), 'cand-T-0001');
    fs.mkdirSync(dir, { recursive: true });
    const stale = spawn('sleep', ['120'], { cwd: dir, stdio: 'ignore', detached: true });
    await waitFor(() => { try { return fs.readlinkSync(`/proc/${stale.pid}/cwd`) === fs.realpathSync(dir); } catch { return false; } });
    await s.ready$();
    s.land('factory/lib/x.mjs');
    assert.equal(await s.d.maybeReload(), true);
    await waitFor(() => !pidAlive(stale.pid) || fs.readFileSync(`/proc/${stale.pid}/stat`, 'utf8').includes(') Z '), { what: 'stale gate process stopped' });
    assert.equal(pidAlive(bystander.pid), true);
    assert.match(events(s.ctx).find((t) => t.startsWith('reload:')), /stopped 1 stale gate process/);
    assert.deepEqual(await stopStaleGateChildren(s.ctx), [], 'nothing left');
  } finally { process.kill(bystander.pid, 'SIGKILL'); s.cleanup(); }
});

// ---- real processes -----------------------------------------------------------------------------

const OLD_BOARD = `import http from 'node:http';
import fs from 'node:fs';
const s = http.createServer((q, r) => { r.setHeader('content-type', 'application/json'); r.end('{"old":true}'); });
s.listen(0, '127.0.0.1', () => fs.writeFileSync(process.env.BOARD_JSON, JSON.stringify({ pid: process.pid, port: s.address().port })));
process.on('SIGTERM', () => { fs.rmSync(process.env.BOARD_JSON, { force: true }); s.close(() => process.exit(0)); s.closeAllConnections(); });
`;

test('end to end: a running dispatcher with two workers and a stale board reloads on a factory/lib commit; both runs survive and are reaped by the new pid', { timeout: 90_000 }, async () => {
  const f = makeLiveFactory({ config: (c) => { c.dispatcher.tick_seconds = 1; c.dispatcher.poll_seconds = 0.2; } });
  initRepo(f.root);
  const workers = [sleeper(), sleeper()];
  const pids = [];
  try {
    setControl(f.ctx, { paused: true, reason: 'test', by: 'test' }); // nothing launches: only the reload is under test
    const runs = workers.map((w) => putEntity(f.ctx, 'runs', {
      id: `${newRunId(f.ctx)}-${w.pid}`, ticket: 'T-9999', stage: 'in_progress', role: 'backend-engineer', pid: w.pid, status: 'running', started: new Date().toISOString(),
    }));
    const boardJson = path.join(f.ctx.stateDir, 'board.json');
    fs.writeFileSync(path.join(f.root, 'old-board.mjs'), OLD_BOARD);
    const board = spawn(process.execPath, [path.join(f.root, 'old-board.mjs')], { env: { ...process.env, BOARD_JSON: boardJson }, stdio: 'ignore', detached: true });
    await waitFor(() => fs.existsSync(boardJson), { what: 'old board' });
    const state = () => readDispatcherState(f.ctx);

    const old = spawn(process.execPath, [FACTORY_BIN, 'run'], { cwd: f.root, env: { ...process.env, FACTORY_HOME: f.home }, stdio: 'ignore', detached: true });
    pids.push(old.pid);
    await waitFor(() => state().pid === old.pid && state().code_sha && state().active.length === 2, { what: 'old dispatcher adopting both workers' });
    const oldSha = state().code_sha;

    fs.mkdirSync(path.join(f.root, 'factory', 'lib'), { recursive: true });
    fs.writeFileSync(path.join(f.root, 'factory', 'lib', 'landed.mjs'), '// landed\n');
    commitAll(f.root, 'factory code lands');
    const newSha = await mainSha(f.ctx);

    const next = await waitFor(() => state().pid && state().pid !== old.pid && pidAlive(state().pid) && state().code_sha === newSha && state(), { timeoutMs: 30_000, what: 'a new dispatcher pid' });
    pids.push(next.pid);
    assert.equal(pidAlive(old.pid), false, 'the old dispatcher exited');
    for (const w of workers) assert.equal(pidAlive(w.pid), true, 'workers were not signalled');
    const text = events(f.ctx).find((t) => t.startsWith('reload:'));
    assert.ok(text.includes(oldSha.slice(0, 12)) && text.includes(newSha.slice(0, 12)), text);

    const boardNow = await waitFor(() => { const b = readJson(boardJson); return b && b.pid !== board.pid && b; }, { what: 'the board restarted' });
    pids.push(boardNow.pid);
    assert.equal(pidAlive(board.pid), false, 'the stale board was stopped');
    const api = await (await fetch(`http://127.0.0.1:${boardNow.port}/api/state`)).json();
    assert.ok('merge_queue' in api, 'the restarted board serves merge_queue');

    // the new dispatcher adopted both runs and reaps them when they end
    await waitFor(() => state().active.length === 2, { what: 'successor adopted both runs' });
    for (const w of workers) process.kill(w.pid, 'SIGKILL');
    await waitFor(() => runs.every((r) => getEntity(f.ctx, 'runs', r.id).status !== 'running'), { what: 'both runs reaped' });
    assert.equal(state().pid, next.pid, 'reaped by the new pid');
  } finally {
    for (const pid of pids) { try { process.kill(pid, 'SIGKILL'); } catch { /* gone */ } }
    for (const w of workers) { try { process.kill(w.pid, 'SIGKILL'); } catch { /* gone */ } }
    f.cleanup();
  }
});

test('factory restart: the dispatcher and the board change pid, a worker survives', { timeout: 90_000 }, async () => {
  const f = makeLiveFactory({ config: (c) => { c.dispatcher.tick_seconds = 1; c.dispatcher.poll_seconds = 0.2; } });
  initRepo(f.root);
  const worker = sleeper();
  const pids = [];
  try {
    setControl(f.ctx, { paused: true, reason: 'test', by: 'test' });
    putEntity(f.ctx, 'runs', { id: newRunId(f.ctx), ticket: 'T-9999', stage: 'in_progress', role: 'backend-engineer', pid: worker.pid, status: 'running', started: new Date().toISOString() });
    const spawnOpts = { cwd: f.root, env: { ...process.env, FACTORY_HOME: f.home }, stdio: 'ignore', detached: true };
    const board = spawn(process.execPath, [FACTORY_BIN, 'board', '--port', '0'], spawnOpts);
    const old = spawn(process.execPath, [FACTORY_BIN, 'run'], spawnOpts);
    pids.push(board.pid, old.pid);
    await waitFor(() => readDispatcherState(f.ctx).pid === old.pid && readDispatcherState(f.ctx).active.length === 1 && readJson(path.join(f.ctx.stateDir, 'board.json'))?.pid === board.pid, { what: 'both up' });
    const result = await restart(f.ctx, FACTORY_BIN);
    pids.push(result.dispatcher.pid);
    assert.notEqual(result.dispatcher.pid, old.pid);
    assert.equal(result.legacy, false);
    assert.equal(pidAlive(worker.pid), true);
    const boardNow = await waitFor(() => { const b = readJson(path.join(f.ctx.stateDir, 'board.json')); return b && b.pid !== board.pid && b; }, { what: 'board restarted' });
    pids.push(boardNow.pid);
    assert.equal(pidAlive(old.pid), false);
  } finally {
    for (const pid of pids) { try { process.kill(pid, 'SIGKILL'); } catch { /* gone */ } }
    try { process.kill(worker.pid, 'SIGKILL'); } catch { /* gone */ }
    f.cleanup();
  }
});
