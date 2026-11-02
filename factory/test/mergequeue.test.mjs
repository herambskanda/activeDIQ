// T-1296: the done queue is taken by waiting dependents, then priority, then the earliest done
// time (not by ticket ID), and the board shows the queue.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { Dispatcher } from '../lib/dispatcher.mjs';
import { buildMergeQueue, orderDoneQueue } from '../lib/mergequeue.mjs';
import { advanceTicket, claimTicket, createTicket, setTicketLinks } from '../lib/tickets.mjs';
import { ensureWorktree } from '../lib/worktree.mjs';
import { listEntities, updateDispatcherState } from '../lib/store.mjs';
import { startBoard } from '../board/server.mjs';
import { commitAll, git, initRepo, makeFactory, ticketInput } from './helpers.mjs';

function setup() {
  const f = makeFactory({ config: (c) => { c.dispatcher.pre_merge = { enabled: true, argv: ['true'], timeout_minutes: 5 }; } });
  initRepo(f.root);
  return f;
}

let minute = 0;
/** Create a ticket (optionally a dependency of `waiter`'s) with a branch ahead of main; not yet done. */
async function withBranch(f, { priority, title, depends_on = [] }) {
  const t = createTicket(f.ctx, ticketInput({ title, priority, status: 'ready', depends_on }), 'x');
  const wt = await ensureWorktree(f.ctx, t.id);
  fs.writeFileSync(path.join(wt.path, `work-${t.id}.txt`), 'work\n');
  commitAll(wt.path, `work ${t.id}`);
  setTicketLinks(f.ctx, t.id, { branch: wt.branch, worktree: wt.path });
  return t;
}
/** Take the ticket to done at the next minute of a fixed clock. */
function finish(f, t) {
  f.ctx.now = () => new Date(Date.UTC(2026, 10, 1, 10, minute++));
  claimTicket(f.ctx, t.id);
  for (let i = 0; i < 3; i++) advanceTicket(f.ctx, t.id, 'w', 'ok');
}

test('mergePass sends waiting dependencies first, then P0 first, then the earliest done', async () => {
  const f = setup();
  try {
    const p3old = await withBranch(f, { priority: 'P3', title: 'low, lowest id' });      // T-0001
    const p2 = await withBranch(f, { priority: 'P2', title: 'normal' });                  // T-0002
    const p0late = await withBranch(f, { priority: 'P0', title: 'urgent, done later' });  // T-0003
    const p0early = await withBranch(f, { priority: 'P0', title: 'urgent, done first' }); // T-0004
    const awaited = await withBranch(f, { priority: 'P3', title: 'low but awaited' });    // T-0005
    createTicket(f.ctx, ticketInput({ title: 'waits', status: 'ready', depends_on: [awaited.id] }), 'x');
    // done order: p0early, p0late, p2, p3old, awaited
    for (const t of [p0early, p0late, p2, p3old, awaited]) finish(f, t);

    const picked = [];
    const d = new Dispatcher(f.ctx);
    d.shared = false;
    d.runGate = async (ctx, tickets) => { picked.push(...tickets.map((t) => t.id)); return { status: 'pass', mode: 'stub', summary: 'stubbed' }; };
    for (let i = 0; i < 5; i++) { await d.mergePass(); await d.gateIdle(); }

    assert.deepEqual(picked, [awaited.id, p0early.id, p0late.id, p2.id, p3old.id]);
    assert.ok(listEntities(f.ctx, 'tickets').filter((t) => t.status === 'done').every((t) => t.links.merged), 'all merged');
    assert.equal(git(f.root, 'status', '--porcelain', '--untracked-files=no'), '');
  } finally { f.cleanup(); }
});

test('orderDoneQueue is pure and only a blocked or ready dependent counts', () => {
  const done = (id, priority, ts) => ({ id, priority, status: 'done', history: [{ to: 'done', ts }] });
  const a = done('T-0001', 'P1', '2026-11-01T10:00:00Z');
  const b = done('T-0002', 'P1', '2026-11-01T09:00:00Z');
  const c = done('T-0003', 'P3', '2026-11-01T11:00:00Z');
  const all = (status) => [a, b, c, { id: 'T-0009', status, depends_on: ['T-0003'] }];
  assert.deepEqual(orderDoneQueue([a, b, c], all('blocked')).map((t) => t.id), ['T-0003', 'T-0002', 'T-0001']);
  assert.deepEqual(orderDoneQueue([a, b, c], all('ready')).map((t) => t.id), ['T-0003', 'T-0002', 'T-0001']);
  assert.deepEqual(orderDoneQueue([a, b, c], all('in_progress')).map((t) => t.id), ['T-0002', 'T-0001', 'T-0003'], 'a running dependent is not waiting');
  assert.deepEqual([a, b, c].map((t) => t.id), ['T-0001', 'T-0002', 'T-0003'], 'input untouched');
});

test('buildMergeQueue lists waiting in gate order, the gate in flight and the last merge', async () => {
  const f = setup();
  try {
    const lo = await withBranch(f, { priority: 'P3', title: 'lo' });
    const hi = await withBranch(f, { priority: 'P0', title: 'hi' });
    const gated = await withBranch(f, { priority: 'P1', title: 'in the gate' });
    const merged = await withBranch(f, { priority: 'P2', title: 'merged' });
    for (const t of [lo, hi, gated, merged]) finish(f, t);
    setTicketLinks(f.ctx, merged.id, { worktree: null, merged: '2026-11-01T12:00:00.000Z' });
    const state = { merge_gate: { ticket: gated.id, started_at: '2026-11-01T12:30:00.000Z' } };
    assert.deepEqual(buildMergeQueue(f.ctx, state, true), {
      waiting: [hi.id, lo.id], in_gate: { id: gated.id, ids: [gated.id], started_at: '2026-11-01T12:30:00.000Z' }, last_merged_at: '2026-11-01T12:00:00.000Z',
    });
    const dead = buildMergeQueue(f.ctx, state, false);
    assert.equal(dead.in_gate, null, 'a gate record from a dead dispatcher is not shown');
    assert.deepEqual(dead.waiting, [hi.id, gated.id, lo.id]);
  } finally { f.cleanup(); }
});

test('the dispatcher records the gate in flight in its state and clears it afterwards', async () => {
  const f = setup();
  try {
    const t = await withBranch(f, { priority: 'P2', title: 'one' });
    finish(f, t);
    const { readDispatcherState } = await import('../lib/store.mjs');
    const d = new Dispatcher(f.ctx);
    d.shared = false;
    let seen = null;
    d.runGate = async () => { seen = readDispatcherState(f.ctx).merge_gate; return { status: 'pass', mode: 'stub', summary: 's' }; };
    await d.mergePass(); await d.gateIdle();
    assert.equal(seen.ticket, t.id);
    assert.match(seen.started_at, /^2026-11-01T/);
    assert.equal(readDispatcherState(f.ctx).merge_gate, null);
  } finally { f.cleanup(); }
});

test('GET /api/state carries merge_queue', async () => {
  const f = makeFactory();
  const { server, port } = await startBoard(f.ctx, { port: 0 });
  try {
    const mk = (title, priority) => {
      const t = createTicket(f.ctx, ticketInput({ title, priority, status: 'ready' }), 'x');
      setTicketLinks(f.ctx, t.id, { worktree: `/nowhere/${t.id}` });
      finish(f, t);
      return t;
    };
    const lo = mk('lo', 'P3'); const hi = mk('hi', 'P0'); const gated = mk('gated', 'P1');
    f.ctx.now = () => new Date();
    updateDispatcherState(f.ctx, { pid: process.pid, heartbeat: new Date().toISOString(), merge_gate: { ticket: gated.id, started_at: '2026-11-01T12:30:00.000Z' } });
    const s = await (await fetch(`http://127.0.0.1:${port}/api/state`)).json();
    assert.deepEqual(s.merge_queue, { waiting: [hi.id, lo.id], in_gate: { id: gated.id, ids: [gated.id], started_at: '2026-11-01T12:30:00.000Z' }, last_merged_at: null });
  } finally {
    server.closeAllConnections();
    await new Promise((r) => server.close(r));
    f.cleanup();
  }
});

test('the board header line is built by the real app.js from merge_queue', async () => {
  const vm = await import('node:vm');
  const src = fs.readFileSync(new URL('../board/public/app.js', import.meta.url), 'utf8');
  const grab = (re) => { const m = re.exec(src); assert.ok(m, `app.js has ${re}`); return m[0]; };
  const code = [
    grab(/^const ts = .*$/m),
    ...['fmtCountdown', 'fmtRel', 'mergeQueueText'].map((n) => grab(new RegExp(`^function ${n}\\(.*?^}$`, 'ms'))),
  ].join('\n');
  const NOW = Date.UTC(2026, 10, 2, 12, 0, 0);
  {
    const ctx = vm.createContext({ Date: Object.assign(function D(...a) { return new Date(...a); }, { parse: Date.parse, now: () => NOW }) });
    vm.runInContext(code, ctx);
    const text = (q) => vm.runInContext(`mergeQueueText(${JSON.stringify(q)})`, ctx);
    assert.equal(text({ waiting: ['T-1', 'T-2', 'T-3'], in_gate: { id: 'T-0696', started_at: '2026-11-02T11:00:00Z' }, last_merged_at: '2026-11-02T09:00:00Z' }),
      'Merge queue: 3 waiting · in gate T-0696 · last merge 3h ago');
    assert.equal(text({ waiting: [], in_gate: null, last_merged_at: null }), 'Merge queue: 0 waiting · no merge yet');
    assert.equal(text(undefined), '');
    const html = fs.readFileSync(new URL('../board/public/index.html', import.meta.url), 'utf8');
    assert.match(html, /id="merge-queue"/);
    assert.match(src, /setText\(mq, mqText\)/);
  }
});
