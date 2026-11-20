// The merge drain (`factory drain`): a switch that holds all merging so a person can merge to main by
// hand without throwing away a gate run in flight. A gate run that finishes after main moved is
// discarded, and `pause` does not stop the gate, so the dispatcher needs its own off-switch.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { runCli } from '../lib/cli.mjs';
import { Dispatcher } from '../lib/dispatcher.mjs';
import { buildMergeQueue } from '../lib/mergequeue.mjs';
import { advanceTicket, claimTicket, createTicket, setTicketLinks } from '../lib/tickets.mjs';
import { ensureWorktree } from '../lib/worktree.mjs';
import { listEntities, readMergeDrain, readRecentEvents, setControl, setMergeDrain } from '../lib/store.mjs';
import { buildStatus } from '../lib/status.mjs';
import { commitAll, initRepo, makeFactory, makeLiveFactory, ticketInput } from './helpers.mjs';

function setup() {
  const f = makeFactory({ config: (c) => { c.dispatcher.pre_merge = { enabled: true, argv: ['true'], timeout_minutes: 5 }; } });
  initRepo(f.root);
  return f;
}

/** A finished ticket with one commit on its branch, ready to go to the gate. */
async function finished(f, title) {
  const t = createTicket(f.ctx, ticketInput({ title, priority: 'P1', status: 'ready' }), 'x');
  const wt = await ensureWorktree(f.ctx, t.id);
  fs.writeFileSync(path.join(wt.path, `work-${t.id}.txt`), 'work\n');
  commitAll(wt.path, `work ${t.id}`);
  setTicketLinks(f.ctx, t.id, { branch: wt.branch, worktree: wt.path });
  claimTicket(f.ctx, t.id);
  for (let i = 0; i < 3; i++) advanceTicket(f.ctx, t.id, 'w', 'ok');
  return t;
}

const stubGate = (picked) => async (ctx, tickets) => { picked.push(...tickets.map((t) => t.id)); return { status: 'pass', mode: 'stub', summary: 'stubbed' }; };
const events = (f) => readRecentEvents(f.ctx, 100).map((e) => e.text);

test('while the drain is on no gate run starts; after undrain it does', async () => {
  const f = setup();
  try {
    const t = await finished(f, 'waits for the drain');
    const picked = [];
    const d = new Dispatcher(f.ctx);
    d.shared = false;
    d.runGate = stubGate(picked);

    setMergeDrain(f.ctx, { on: true, minutes: 30, reason: 'hand merge' });
    for (let i = 0; i < 3; i++) { await d.mergePass(); await d.gateIdle(); }
    assert.deepEqual(picked, [], 'no gate started while drained');
    assert.equal(listEntities(f.ctx, 'tickets').find((x) => x.id === t.id).links.merged ?? null, null);

    setMergeDrain(f.ctx, { on: false });
    await d.mergePass(); await d.gateIdle();
    assert.deepEqual(picked, [t.id], 'the gate starts once the drain is off');
  } finally { f.cleanup(); }
});

test('a drain also holds merges that need no gate (spec and docs branches), since they move main too', async () => {
  const f = setup();
  try {
    f.ctx.config.dispatcher.pre_merge.enabled = false; // ungated: the pass would merge straight away
    const t = await finished(f, 'ungated merge');
    const d = new Dispatcher(f.ctx);
    d.shared = false;
    setMergeDrain(f.ctx, { on: true, minutes: 30 });
    await d.mergePass();
    assert.equal(listEntities(f.ctx, 'tickets').find((x) => x.id === t.id).links.merged ?? null, null, 'not merged while drained');
    setMergeDrain(f.ctx, { on: false });
    await d.mergePass();
    assert.ok(listEntities(f.ctx, 'tickets').find((x) => x.id === t.id).links.merged, 'merged after the drain');
  } finally { f.cleanup(); }
});

test('a gate run already in flight finishes and lands even when the drain starts after it began', async () => {
  const f = setup();
  try {
    const t = await finished(f, 'in flight');
    const d = new Dispatcher(f.ctx);
    d.shared = false;
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    d.runGate = async () => { await gate; return { status: 'pass', mode: 'stub', summary: 'stubbed' }; };
    await d.mergePass();                                   // the gate is now in flight
    assert.equal(d.gateLanes.length, 1);
    setMergeDrain(f.ctx, { on: true, minutes: 30 });
    release();
    await d.gateIdle();
    assert.ok(listEntities(f.ctx, 'tickets').find((x) => x.id === t.id).links.merged, 'the in-flight run still landed');
  } finally { f.cleanup(); }
});

test('the drain ends by itself, and its start and end are each reported once', async () => {
  const f = setup();
  try {
    const t = await finished(f, 'drain expires');
    let now = Date.UTC(2026, 10, 17, 12, 0);
    f.ctx.now = () => new Date(now);
    const picked = [];
    const d = new Dispatcher(f.ctx);
    d.shared = false;
    d.runGate = stubGate(picked);

    setMergeDrain(f.ctx, { on: true, minutes: 30 });
    now += 10 * 60_000;
    await d.mergePass(); await d.mergePass();
    assert.deepEqual(picked, [], 'still drained after 10 minutes');

    now += 25 * 60_000; // 35 minutes in: past `until`
    assert.equal(readMergeDrain(f.ctx).on, false);
    assert.equal(readMergeDrain(f.ctx).expired, true);
    await d.mergePass(); await d.gateIdle();
    assert.deepEqual(picked, [t.id], 'merging resumed without anyone running undrain');

    const said = events(f);
    assert.equal(said.filter((x) => /merge drain in force/.test(x)).length, 1, 'start reported once');
    assert.equal(said.filter((x) => /merge drain expired on its own/.test(x)).length, 1, 'expiry reported once');
  } finally { f.cleanup(); }
});

test('a drain needs a sensible length, and pause does not erase it', () => {
  const f = setup();
  try {
    assert.throws(() => setMergeDrain(f.ctx, { on: true, minutes: 0 }), /between 1 and 120/);
    assert.throws(() => setMergeDrain(f.ctx, { on: true, minutes: 500 }), /between 1 and 120/);
    assert.throws(() => setMergeDrain(f.ctx, { on: true, minutes: Number.NaN }), /between 1 and 120/);
    setMergeDrain(f.ctx, { on: true, minutes: 20, reason: 'demo' });
    setControl(f.ctx, { paused: true, reason: 'x' });       // rewrites control.json whole
    setControl(f.ctx, { paused: false });
    assert.equal(readMergeDrain(f.ctx).on, true, 'the drain survived pause and resume');
  } finally { f.cleanup(); }
});

test('a corrupt drain file reads as "not draining" instead of stalling every merge', () => {
  const f = setup();
  try {
    fs.mkdirSync(f.ctx.stateDir, { recursive: true });
    fs.writeFileSync(path.join(f.ctx.stateDir, 'merge-drain.json'), '{not json');
    assert.equal(readMergeDrain(f.ctx).on, false);
    fs.writeFileSync(path.join(f.ctx.stateDir, 'merge-drain.json'), JSON.stringify({ on: true })); // no end time
    assert.equal(readMergeDrain(f.ctx).on, false, 'a drain with no end time is ignored');
  } finally { f.cleanup(); }
});

test('the board state and factory status show the drain and the gate in flight', async () => {
  const f = setup();
  try {
    assert.equal(buildMergeQueue(f.ctx, {}, true).drain, null);
    assert.equal(buildStatus(f.ctx).merge_drain, null);
    setMergeDrain(f.ctx, { on: true, minutes: 15, reason: 'hand merge', by: 'khushi' });
    const q = buildMergeQueue(f.ctx, {}, true).drain;
    assert.deepEqual([q.reason, q.by], ['hand merge', 'khushi']);
    assert.ok(Date.parse(q.until) > f.ctx.now().getTime());
    assert.equal(buildStatus(f.ctx).merge_drain.reason, 'hand merge');
    assert.deepEqual(buildStatus(f.ctx).merge_queue.in_gates, []);
  } finally { f.cleanup(); }
});

test('factory drain / undrain from the command line', async () => {
  const f = makeLiveFactory();
  const run = async (args) => {
    const out = []; const err = [];
    const code = await runCli(args, { out: (s) => out.push(s), err: (s) => err.push(s), env: { FACTORY_HOME: f.home }, cwd: f.root });
    return { code, out: out.join('\n'), err: err.join('\n') };
  };
  try {
    let r = await run(['drain', '--minutes', '10', '--reason', 'phase 0 merge']);
    assert.equal(r.code, 0, r.err);
    assert.match(r.out, /merge drain on until/);
    assert.match((await run(['status'])).out, /merge drain on until .* phase 0 merge/);
    assert.match((await run(['status'])).out, /merge gate\s+.*no gate run in flight/);

    r = await run(['drain', '--minutes', '999']);
    assert.notEqual(r.code, 0);
    assert.match(r.err, /between 1 and 120/);

    r = await run(['undrain']);
    assert.match(r.out, /merge drain off/);
    assert.doesNotMatch((await run(['status'])).out, /merge drain on/);
    assert.match((await run(['undrain'])).out, /no merge drain was on/);
  } finally { f.cleanup(); }
});
