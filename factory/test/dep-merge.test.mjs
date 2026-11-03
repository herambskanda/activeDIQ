// T-1266: a dependency is met only when its work is on main — `done` with a `factory/<id>` branch
// that has commits ahead of main does not count. Runtime tests against a real temporary git repo.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { Dispatcher, loadStateWithMerges, planDryRun } from '../lib/dispatcher.mjs';
import { selectCandidates } from '../lib/candidates.mjs';
import { blockTicket, claimBlockers, claimTicket, createTicket, indexById, doneDependencies } from '../lib/tickets.mjs';
import { unmergedBranches, mergeTicket } from '../lib/worktree.mjs';
import { getEntity, listEntities, updateEntity } from '../lib/store.mjs';
import { runCli } from '../lib/cli.mjs';
import { startBoard } from '../board/server.mjs';
import { commitAll, git, initRepo, makeFactory, makeLiveFactory, ticketInput, useFakeClaude } from './helpers.mjs';

/** A branch factory/<id> with one commit ahead of main, made without touching the main checkout. */
function branchAhead(root, id) {
  const dir = path.join(root, '.worktrees', id);
  git(root, 'worktree', 'add', '-q', '-b', `factory/${id}`, dir, 'main');
  fs.writeFileSync(path.join(dir, `${id}.txt`), `${id}\n`);
  commitAll(dir, `feat: ${id}`);
  git(root, 'worktree', 'remove', '--force', dir);
}

const markDone = (f, id) => updateEntity(f.ctx, 'tickets', id, (t) => { t.status = 'done'; });
const ready = (f, o = {}) => createTicket(f.ctx, ticketInput({ type: 'docs', owner: 'docs-writer', status: 'ready', ...o }), 'x');
const picked = async (f) => selectCandidates({
  ...await loadStateWithMerges(f.ctx), sharedCheckout: false, skip: new Set(),
}, f.ctx.now(), f.ctx.config).map((c) => c.ticket?.id).filter(Boolean);

// A is the dependent, B its dependency; the ready filler keeps grooming meta tickets out of the way.
function scenario(f) {
  initRepo(f.root);
  const b = createTicket(f.ctx, ticketInput({ type: 'docs', owner: 'docs-writer' }), 'x');
  const a = ready(f, { depends_on: [b.id] });
  for (let i = 0; i < 3; i += 1) ready(f, { title: `filler ${i}`, priority: 'P3' });
  markDone(f, b.id);
  return { a: a.id, b: b.id };
}

test('unmergedBranches: only branches with commits not on main', async () => {
  const f = makeFactory();
  try {
    initRepo(f.root);
    branchAhead(f.root, 'T-0001');
    git(f.root, 'branch', 'factory/T-0002'); // nothing ahead
    assert.deepEqual([...await unmergedBranches(f.ctx, ['T-0001', 'T-0002', 'T-0003'])], ['T-0001']);
    await mergeTicket(f.ctx, { id: 'T-0001', title: 'x' });
    assert.equal((await unmergedBranches(f.ctx, ['T-0001'])).size, 0, 'merged work is on main');
  } finally { f.cleanup(); }
});

test('claimBlockers: a done dependency whose branch is not on main is "unmerged", not unfinished', () => {
  const tickets = indexById([{ id: 'T-1', status: 'done' }, { id: 'T-2', status: 'done' }, { id: 'T-3', status: 'review' }]);
  const t = { depends_on: ['T-1', 'T-2', 'T-3'] };
  assert.deepEqual(claimBlockers(t, tickets, new Map(), new Set(['T-2', 'T-3'])), { deps: ['T-3'], unmerged: ['T-2'], decisions: [] });
  assert.deepEqual(claimBlockers(t, tickets, new Map()).unmerged, [], 'nothing unmerged without git evidence');
  assert.deepEqual([...doneDependencies([t], tickets)], ['T-1', 'T-2']);
});

test('a dependent is not claimed while its done dependency is not on main, and is once it is', async () => {
  const f = makeFactory();
  try {
    const { a, b } = scenario(f);
    branchAhead(f.root, b);
    assert.ok(!(await picked(f)).includes(a), 'A waits for the merge of B');
    assert.throws(() => claimTicket(f.ctx, a, 'dispatcher', new Set([b])), new RegExp(`waits for the merge of ${b}`));
    assert.equal(getEntity(f.ctx, 'tickets', a).status, 'ready');

    await mergeTicket(f.ctx, { id: b, title: 'B' });
    assert.ok((await picked(f)).includes(a), 'B is merged: A is claimable');
  } finally { f.cleanup(); }
});

test('a done dependency with no branch, or a branch with nothing ahead of main, is met', async () => {
  const f = makeFactory();
  try {
    const { a, b } = scenario(f);
    assert.ok((await picked(f)).includes(a), 'no branch at all');
    git(f.root, 'branch', `factory/${b}`);
    assert.ok((await picked(f)).includes(a), 'a branch with nothing ahead of main');
  } finally { f.cleanup(); }
});

test('an unfinished dependency still blocks, merged or not', async () => {
  const f = makeFactory();
  try {
    const { a, b } = scenario(f);
    updateEntity(f.ctx, 'tickets', b, (t) => { t.status = 'review'; });
    assert.ok(!(await picked(f)).includes(a));
  } finally { f.cleanup(); }
});

test('the dispatcher fill leaves A ready while B is unmerged and launches it after the merge', async () => {
  const f = makeLiveFactory({ config: (c) => { c.dispatcher.persist_seconds = 0; } });
  const restore = useFakeClaude({});
  try {
    const { a, b } = scenario(f);
    branchAhead(f.root, b);
    const d = new Dispatcher(f.ctx);
    await d.fill();
    assert.equal(getEntity(f.ctx, 'tickets', a).status, 'ready', 'A was not claimed');
    assert.ok(!listEntities(f.ctx, 'runs').some((r) => r.ticket === a), 'no run for A');

    const plan = await planDryRun(f.ctx);
    assert.ok(!plan.candidates.some((c) => c.ticket === a), 'dry run agrees');

    await mergeTicket(f.ctx, { id: b, title: 'B' });
    await d.fill();
    assert.notEqual(getEntity(f.ctx, 'tickets', a).status, 'ready', 'A was claimed once B is on main');
  } finally {
    restore();
    for (const r of listEntities(f.ctx, 'runs')) if (r.pid) try { process.kill(r.pid, 'SIGKILL'); } catch { /* gone */ }
    f.cleanup();
  }
});

test('the board shows A as waiting on the merge of B', async () => {
  const f = makeFactory();
  const { server, port } = await startBoard(f.ctx, { port: 0 });
  try {
    const { a, b } = scenario(f);
    branchAhead(f.root, b);
    const state = async () => (await (await fetch(`http://127.0.0.1:${port}/api/state`)).json()).tickets.find((t) => t.id === a);
    assert.deepEqual((await state()).waiting_on_merge, [b]);
    await mergeTicket(f.ctx, { id: b, title: 'B' });
    assert.deepEqual((await state()).waiting_on_merge, []);
  } finally {
    server.closeAllConnections();
    await new Promise((r) => server.close(r));
    f.cleanup();
  }
});

// T-1400: a ticket blocked only because its dependency is done-but-unmerged goes to ready, not back
// to the stage that blocked it, so the T-1266 claim check holds it.
async function cli(f, args) {
  const out = []; const err = [];
  const code = await runCli(args, { out: (x) => out.push(x), err: (x) => err.push(x), env: { FACTORY_HOME: f.home }, cwd: f.root });
  return { code, out: out.join('\n'), err: err.join('\n') };
}

test('unblock --to-ready parks a ticket in ready, the claim check holds it, and the merge releases it', async () => {
  const f = makeLiveFactory({ config: (c) => { c.dispatcher.persist_seconds = 0; } });
  const restore = useFakeClaude({});
  try {
    const { a, b } = scenario(f);
    branchAhead(f.root, b);
    claimTicket(f.ctx, a, 'dispatcher', new Set()); // a was running when the owner blocked it
    blockTicket(f.ctx, a, 'docs-writer', `waiting for ${b} to merge`);

    const r = await cli(f, ['ticket', 'unblock', a, '--to-ready', '--by', 'factory-director', '--note', 'dependency done, not merged']);
    assert.equal(r.code, 0, r.err);
    assert.match(r.out, new RegExp(`unblocked to ready, waiting on ${b}`));
    const t = getEntity(f.ctx, 'tickets', a);
    assert.deepEqual([t.status, t.stage_role, t.attempts, t.blocked_from], ['ready', null, 0, null]);
    assert.match(t.history.at(-1).note, new RegExp(`^unblocked to ready: .*\\(waiting on ${b} to merge\\)`));
    assert.ok(!(await picked(f)).includes(a), 'the claim gate holds it while the dependency is off main');

    const d = new Dispatcher(f.ctx);
    await d.fill();
    assert.equal(getEntity(f.ctx, 'tickets', a).status, 'ready', 'still held after a dispatcher tick');

    await mergeTicket(f.ctx, { id: b, title: 'B' });
    await d.fill();
    assert.notEqual(getEntity(f.ctx, 'tickets', a).status, 'ready', 'claimed into its first stage once the dependency is on main');
    assert.equal(getEntity(f.ctx, 'tickets', a).stage_role, 'docs-writer');
  } finally {
    restore();
    for (const r of listEntities(f.ctx, 'runs')) if (r.pid) try { process.kill(r.pid, 'SIGKILL'); } catch { /* gone */ }
    f.cleanup();
  }
});

test('unblock without --to-ready still restores blocked_from, merged dependency or not', async () => {
  const f = makeLiveFactory();
  try {
    const { a, b } = scenario(f);
    branchAhead(f.root, b);
    claimTicket(f.ctx, a, 'dispatcher', new Set());
    blockTicket(f.ctx, a, 'docs-writer', 'x');
    updateEntity(f.ctx, 'tickets', a, (t) => { t.handoff = { ...t.handoff, pending: true }; });
    const r = await cli(f, ['ticket', 'unblock', a, '--by', 'factory-director', '--note', 'go']);
    assert.equal(r.code, 0, r.err);
    const t = getEntity(f.ctx, 'tickets', a);
    assert.deepEqual([t.status, t.stage_role], ['in_progress', 'docs-writer']);
    assert.match(t.history.at(-1).note, /^unblocked: go$/);
    assert.equal(t.handoff.pending, true, 'plain unblock leaves a pending handoff alone, as on main');
    assert.equal((await cli(f, ['ticket', 'unblock', a, '--to-ready', '--by', 'x', '--note', 'n'])).code, 1, 'not blocked any more');
  } finally { f.cleanup(); }
});

test('unblock --to-ready with nothing to wait on is plain ready, and needs a note', async () => {
  const f = makeLiveFactory();
  try {
    initRepo(f.root);
    const t = ready(f);
    claimTicket(f.ctx, t.id, 'dispatcher', new Set());
    blockTicket(f.ctx, t.id, 'docs-writer', 'x');
    assert.equal((await cli(f, ['ticket', 'unblock', t.id, '--to-ready', '--by', 'd'])).code, 2, '--note is required');
    const r = await cli(f, ['ticket', 'unblock', t.id, '--to-ready', '--by', 'd', '--note', 'ok']);
    assert.equal(r.code, 0, r.err);
    assert.doesNotMatch(getEntity(f.ctx, 'tickets', t.id).history.at(-1).note, /waiting on/);
  } finally { f.cleanup(); }
});
