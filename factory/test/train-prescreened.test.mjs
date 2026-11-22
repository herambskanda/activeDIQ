// Merge plan 5.5: with pre_merge.train_prescreened_max set, a train is built only from tickets that passed the
// pre-screen on their current branch commit; the size grows with clean trains and halves after a refused one.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Dispatcher } from '../lib/dispatcher.mjs';
import { preMergeSettings } from '../lib/premerge.mjs';
import { advanceTicket, claimTicket, createTicket, setTicketLinks } from '../lib/tickets.mjs';
import { ensureWorktree } from '../lib/worktree.mjs';
import { listEntities, readRecentEvents } from '../lib/store.mjs';
import { commitAll, git, initRepo, makeFactory, ticketInput } from './helpers.mjs';

const GATE = `import fs from 'node:fs';
import path from 'node:path';
fs.appendFileSync(process.env.TRAIN_LOG, path.basename(process.cwd()) + '\\n');
const bad = fs.readdirSync('.').some((n) => /^violation-/.test(n));
if (bad) console.error('internal/x/x.go:5: P1 (ADR-0002 fitness function): bad');
process.exit(bad ? 1 : 0);
`;
function setup(pm = {}) {
  const log = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'tps-')), 'runs.txt');
  process.env.TRAIN_LOG = log;
  const f = makeFactory({ config: (c) => { c.dispatcher.pre_merge = { enabled: true, argv: ['node', 'gate.mjs'], timeout_minutes: 5, train_size: 1, ...pm }; } });
  initRepo(f.root);
  fs.writeFileSync(path.join(f.root, 'gate.mjs'), GATE);
  commitAll(f.root, 'ci fixture');
  const runs = () => (fs.existsSync(log) ? fs.readFileSync(log, 'utf8').split('\n').filter(Boolean).map((l) => l.replace(/-\d+-[0-9a-f]{8}$/, '')) : []);
  return { ...f, runs, cleanup: () => { f.cleanup(); fs.rmSync(path.dirname(log), { recursive: true, force: true }); } };
}
let minute = 0;
async function finished(f, title, files = {}) {
  const t = createTicket(f.ctx, ticketInput({ title, status: 'ready' }), 'x');
  const wt = await ensureWorktree(f.ctx, t.id);
  fs.writeFileSync(path.join(wt.path, `work-${t.id}.txt`), 'work\n');
  for (const [file, text] of Object.entries(files)) fs.writeFileSync(path.join(wt.path, file), text);
  commitAll(wt.path, `work ${t.id}`);
  f.ctx.now = () => new Date(Date.UTC(2026, 10, 1, 10, minute++));
  claimTicket(f.ctx, t.id);
  for (let i = 0; i < 3; i++) advanceTicket(f.ctx, t.id, 'w', 'ok');
  setTicketLinks(f.ctx, t.id, { branch: wt.branch, worktree: wt.path });
  return t;
}
const dispatcher = (f) => { const d = new Dispatcher(f.ctx); d.shared = false; return d; };
const sha = (f, t) => git(f.root, 'rev-parse', `refs/heads/factory/${t.id}`).trim();
const screen = (f, d, ...ts) => ts.forEach((t) => d.prescreenPass.set(t.id, sha(f, t)));
const pass = async (d) => { await d.mergePass(); await d.gateIdle(); };

test('a train takes only tickets that passed the pre-screen; the others wait and go on their own later', async () => {
  const f = setup({ train_prescreened_max: 6 });
  try {
    const a = await finished(f, 'a'); const b = await finished(f, 'b'); const c = await finished(f, 'c'); const e = await finished(f, 'e');
    const d = dispatcher(f);
    screen(f, d, b, c, e); // a is first in line but was not screened
    await pass(d);
    assert.deepEqual(f.runs(), [`cand-train-${b.id}+${c.id}+${e.id}`], 'one run for the three screened tickets, a is left out');
    await pass(d);
    assert.equal(f.runs().at(-1), `cand-${a.id}`, 'with nothing screened left, a goes alone as before');
  } finally { f.cleanup(); }
});

test('the train is capped at the current screened size, starting at 4', async () => {
  const f = setup({ train_prescreened_max: 6 });
  try {
    const ts = []; for (const n of 'abcdef') ts.push(await finished(f, n));
    const d = dispatcher(f); screen(f, d, ...ts);
    await pass(d);
    assert.equal(f.runs()[0], `cand-train-${ts.slice(0, 4).map((t) => t.id).join('+')}`);
    assert.equal(d.screenedSize, 5, 'a clean train of four grows the next one');
  } finally { f.cleanup(); }
});

test('a pass recorded for an older branch commit no longer counts', async () => {
  const f = setup({ train_prescreened_max: 6 });
  try {
    const a = await finished(f, 'a'); const b = await finished(f, 'b');
    const d = dispatcher(f); screen(f, d, a, b);
    const wt = path.join(f.ctx.root, '..'); // a worker adds a commit to a's branch
    const w = (await ensureWorktree(f.ctx, a.id)).path;
    fs.writeFileSync(path.join(w, 'more.txt'), 'x\n'); commitAll(w, 'more');
    assert.equal(await d.passedPrescreen(a), false);
    assert.equal(await d.passedPrescreen(b), true);
    assert.ok(wt);
  } finally { f.cleanup(); }
});

test('a refused train of screened tickets halves the next size, and the culprit is found as before', async () => {
  const f = setup({ train_prescreened_max: 6 });
  try {
    const a = await finished(f, 'a'); const b = await finished(f, 'b', { 'violation-1.txt': 'x' });
    const c = await finished(f, 'c'); const e = await finished(f, 'e');
    const d = dispatcher(f); screen(f, d, a, b, c, e);
    await pass(d);
    assert.equal(d.screenedSize, 2, 'size 4 refused: next is 2');
    const text = readRecentEvents(f.ctx, 50).map((x) => x.text).join('\n');
    assert.match(text, /train of pre-screened tickets was refused: the next one holds up to 2/);
  } finally { f.cleanup(); }
});

test('with train_prescreened_max 0 (the default) pre-screen passes change nothing', async () => {
  const f = setup();
  try {
    const a = await finished(f, 'a'); const b = await finished(f, 'b');
    const d = dispatcher(f); screen(f, d, b);
    await pass(d);
    assert.equal(f.runs()[0], `cand-${a.id}`, 'the front ticket goes first, alone, as before');
  } finally { f.cleanup(); }
});

test('a pre-screen that passes is remembered, one that fails is not; the setting is validated', async () => {
  const f = setup({ train_prescreened_max: 4, prescreen_ahead: true, prescreen_argv: ['node', 'pre.mjs'] });
  try {
    const a = await finished(f, 'a');
    const d = dispatcher(f);
    d.gateLanes.push({ ids: ['T-9999'], abort: new AbortController(), run: Promise.resolve() });
    d.runGate = async () => ({ status: 'pass', findings: [], summary: 'ok', members: [a.id], conflicts: [] });
    await d.prescreenAhead(preMergeSettings(f.ctx.config)); await d.prescreenIdle();
    assert.equal(d.prescreenPass.get(a.id), sha(f, a));
    for (const bad of [1, -2, 2.5]) assert.throws(() => preMergeSettings({ dispatcher: { pre_merge: { enabled: true, argv: ['x'], train_prescreened_max: bad } } }), /train_prescreened_max/);
  } finally { f.cleanup(); }
});

test('the pre-screen sends a ticket that conflicts with main back at once, with no strike, and screens the clean ones', async () => {
  const f = setup({ train_prescreened_max: 4, prescreen_ahead: true, prescreen_argv: ['node', 'pre.mjs'], prescreen_parallel: 2 });
  try {
    const clash = await finished(f, 'clash', { 'shared.txt': 'branch\n' });
    const clean = await finished(f, 'clean');
    fs.writeFileSync(path.join(f.root, 'shared.txt'), 'main\n'); commitAll(f.root, 'main moves on the same file');
    const d = dispatcher(f);
    d.gateLanes.push({ ids: ['T-9999'], abort: new AbortController(), run: Promise.resolve() });
    const screenedIds = [];
    d.runGate = async (ctx, tickets) => { screenedIds.push(tickets[0].id); return { status: 'pass', findings: [], summary: 'ok', members: [tickets[0].id], conflicts: [] }; };
    await d.prescreenAhead(preMergeSettings(f.ctx.config)); await d.prescreenIdle();
    const byId = Object.fromEntries(listEntities(f.ctx, 'tickets').map((t) => [t.id, t]));
    assert.notEqual(byId[clash.id].status, 'done', 'the clashing ticket is back with its worker');
    assert.equal(byId[clash.id].gate_failures ?? 0, 0, 'no strike');
    assert.equal(byId[clean.id].status, 'done');
    assert.deepEqual(screenedIds, [clean.id], 'only the clean ticket was screened');
    assert.equal(d.prescreenPass.get(clean.id), sha(f, clean));
  } finally { f.cleanup(); }
});
