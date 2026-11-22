// Merge plan 4.4: while the gate is busy, the cheap pre-screen runs on the tickets at the front of the line; a failing ticket
// is reopened with no strike and no gate run.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Dispatcher } from '../lib/dispatcher.mjs';
import { preMergeSettings, splitTrain } from '../lib/premerge.mjs';
import { advanceTicket, claimTicket, createTicket, setTicketLinks, unblockTicket } from '../lib/tickets.mjs';
import { ensureWorktree, landedCommit } from '../lib/worktree.mjs';
import { buildMergeQueue } from '../lib/mergequeue.mjs';
import { appendEvent, listEntities, readRecentEvents } from '../lib/store.mjs';
import { commitAll, git, initRepo, makeFactory, ticketInput } from './helpers.mjs';

// Like mergetrain.test.mjs, but each finding names the file the faulty ticket changed
// (`violation-tN.txt`), which is what the culprit finder maps a finding by.
const GATE = `import fs from 'node:fs';
import path from 'node:path';
fs.appendFileSync(process.env.TRAIN_LOG, path.basename(process.cwd()) + '|' + fs.readdirSync('.').filter((n) => /^work-/.test(n)).sort().join(',') + '\\n');
let bad = 0;
for (const name of fs.readdirSync('.').filter((n) => /^violation-.*\\.txt$/.test(n)).sort()) {
  console.error(\`\${name}:5: P1 (ADR-0002 fitness function): \${fs.readFileSync(name, 'utf8').trim()}\`);
  bad++;
}
process.exit(bad ? 1 : 0);
`;

function setup({ ahead = true } = {}) {
  const log = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'train-log-')), 'runs.txt');
  process.env.TRAIN_LOG = log;
  const f = makeFactory({ config: (c) => {
    c.dispatcher.pre_merge = { enabled: true, argv: ['node', 'gate.mjs'], timeout_minutes: 5, train_size: 1, prescreen_ahead: ahead, prescreen_argv: ['node', 'pre.mjs'] };
  } });
  initRepo(f.root);
  fs.writeFileSync(path.join(f.root, 'gate.mjs'), GATE);
  fs.writeFileSync(path.join(f.root, 'pre.mjs'), GATE);
  commitAll(f.root, 'ci fixture');
  const lines = () => (fs.existsSync(log) ? fs.readFileSync(log, 'utf8').split('\n').filter(Boolean) : []);
  // A scratch tree's name ends in a per-invocation tag (`-<pid>-<hex>`, T-0696); the tests name runs without it.
  const runs = () => lines().map((l) => l.split('|')[0].replace(/-\d+-[0-9a-f]{8}$/, ''));
  /** What each run's tree held: the work-<ticket>.txt files of the tickets merged into it. */
  const trees = () => lines().map((l) => l.split('|')[1].split(',').filter(Boolean).map((n) => /^work-(T-\d+)\.txt$/.exec(n)[1]));
  return { ...f, runs, trees, cleanup: () => { f.cleanup(); fs.rmSync(path.dirname(log), { recursive: true, force: true }); } };
}

let minute = 0;
/** A done ticket whose branch writes `files`; done times run in creation order. */
async function finished(f, title, files = {}, extra = {}) {
  const t = createTicket(f.ctx, ticketInput({ title, status: 'ready', ...extra }), 'x');
  const wt = await ensureWorktree(f.ctx, t.id);
  fs.writeFileSync(path.join(wt.path, `work-${t.id}.txt`), 'work\n');
  for (const [file, text] of Object.entries(files)) { fs.mkdirSync(path.dirname(path.join(wt.path, file)), { recursive: true }); fs.writeFileSync(path.join(wt.path, file), text); }
  commitAll(wt.path, `work ${t.id}`);
  f.ctx.now = () => new Date(Date.UTC(2026, 10, 1, 10, minute++));
  claimTicket(f.ctx, t.id);
  for (let i = 0; i < 3; i++) advanceTicket(f.ctx, t.id, 'w', 'ok');
  setTicketLinks(f.ctx, t.id, { branch: wt.branch, worktree: wt.path });
  return t;
}

const byId = (f) => Object.fromEntries(listEntities(f.ctx, 'tickets').map((t) => [t.id, t]));
const dispatcher = (f) => { const d = new Dispatcher(f.ctx); d.shared = false; return d; };
const busy = (d, ids = ['T-9999']) => d.gateLanes.push({ ids, abort: new AbortController(), run: Promise.resolve() });
const events = (f) => readRecentEvents(f.ctx, 300).map((e) => e.text).join('\n');
const screen = async (d, f) => { await d.prescreenAhead(preMergeSettings(f.ctx.config)); await d.prescreenIdle(); };

test('a ticket at the front that fails the pre-screen is reopened with no strike while the gate is busy', async () => {
  const f = setup();
  try {
    const bad = await finished(f, 'bad', { 'violation-t1.txt': 'tenant check fails\n' });
    const d = dispatcher(f);
    busy(d);
    await screen(d, f);
    const t = byId(f)[bad.id];
    assert.equal(t.status, 'in_progress');
    assert.equal(t.prescreen_failures, 1);
    assert.ok(!t.gate_failures, 'no gate strike');
    assert.match(events(f), /failed the pre-screen .*no gate run spent and no strike/);
    assert.equal(f.runs().filter((r) => r.startsWith('cand-')).length >= 1, true);
  } finally { f.cleanup(); }
});

test('a clean ticket passes the pre-screen, stays done and is not screened again for the same commit', async () => {
  const f = setup();
  try {
    const ok = await finished(f, 'ok');
    const d = dispatcher(f);
    busy(d);
    await screen(d, f);
    const first = f.runs().length;
    assert.equal(byId(f)[ok.id].status, 'done');
    assert.ok(first >= 1);
    await screen(d, f);
    assert.equal(f.runs().length, first, 'screened once');
  } finally { f.cleanup(); }
});

test('nothing is screened when no gate run is in flight, when the setting is off, or after 3 failures', async () => {
  const f = setup();
  try {
    await finished(f, 'bad', { 'violation-t1.txt': 'x\n' });
    const d = dispatcher(f);
    await screen(d, f);
    assert.equal(f.runs().length, 0, 'gate idle: the gate itself will judge it');
  } finally { f.cleanup(); }
  const g = setup({ ahead: false });
  try {
    await finished(g, 'bad', { 'violation-t1.txt': 'x\n' });
    const d = dispatcher(g);
    busy(d);
    await screen(d, g);
    assert.equal(g.runs().length, 0, 'setting off');
  } finally { g.cleanup(); }
  const h = setup();
  try {
    const t = await finished(h, 'bad', { 'violation-t1.txt': 'x\n' });
    const { updateEntity } = await import('../lib/store.mjs');
    updateEntity(h.ctx, 'tickets', t.id, (x) => { x.prescreen_failures = 3; });
    const d = dispatcher(h);
    busy(d);
    await screen(d, h);
    assert.equal(h.runs().length, 0, 'given up after 3 failures');
    assert.equal(byId(h)[t.id].status, 'done');
  } finally { h.cleanup(); }
});

test('only the tickets that fit the next train are screened, and tickets already in the running lane are skipped', async () => {
  const f = setup();
  try {
    const a = await finished(f, 'a');
    const b = await finished(f, 'b', { 'violation-t2.txt': 'bad\n' });
    const d = dispatcher(f);
    busy(d, [a.id]); // a is in the running lane
    await screen(d, f);
    assert.equal(byId(f)[b.id].status, 'in_progress', 'b was screened and failed');
    assert.equal(byId(f)[a.id].status, 'done');
  } finally { f.cleanup(); }
});
