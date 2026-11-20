// Merge plan 4.2: with pre_merge.train_size_max set, the size of a train follows the pass rate of the last
// gate verdicts (read from the events); tickets that change go.mod, the Makefile, *.mk or tools/ci go alone.
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

function setup({ trainSize, main = {}, split, gate = GATE, max } = {}) {
  const log = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'train-log-')), 'runs.txt');
  process.env.TRAIN_LOG = log;
  const f = makeFactory({ config: (c) => {
    c.dispatcher.pre_merge = { enabled: true, argv: ['node', 'gate.mjs'], timeout_minutes: 5, ...(trainSize ? { train_size: trainSize } : {}), ...(split === undefined ? {} : { culprit_split: split }), ...(max === undefined ? {} : { train_size_max: max }) };
  } });
  initRepo(f.root);
  fs.writeFileSync(path.join(f.root, 'gate.mjs'), gate);
  for (const [file, text] of Object.entries(main)) fs.writeFileSync(path.join(f.root, file), text);
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

const buildMergeQueueIds = (f) => buildMergeQueue(f.ctx, {}, false).waiting;
const byId = (f) => Object.fromEntries(listEntities(f.ctx, 'tickets').map((t) => [t.id, t]));
const dispatcher = (f) => { const d = new Dispatcher(f.ctx); d.shared = false; return d; };
const pass = async (d) => { await d.mergePass(); await d.gateIdle(); };
/** The tickets merged into main, oldest first, from the first-parent merge commits. */
const mergedOrder = (f) => git(f.root, 'log', '--first-parent', '--merges', '--reverse', '--format=%s').split('\n').filter(Boolean).map((s) => /^Merge (T-\d+):/.exec(s)[1]);



const events = (f) => readRecentEvents(f.ctx, 200).map((e) => e.text).join('\n');
const trains = (f) => f.runs().filter((r) => r.startsWith('cand-'));
function seed(f, passes, fails) {
  for (let i = 0; i < passes; i++) appendEvent(f.ctx, { actor: 'dispatcher', kind: 'ticket', ticket: `T-9${i}`, text: `T-9${i} pre-merge gate passed (ratchet): seeded` });
  for (let i = 0; i < fails; i++) appendEvent(f.ctx, { actor: 'dispatcher', kind: 'ticket', ticket: `T-8${i}`, text: `T-8${i} merge refused by the pre-merge gate: seeded` });
}
/** One merge pass per lane: with concurrency 1 each pass gates one train, so several trains need several passes. */
const passes = async (d, n = 6) => { for (let i = 0; i < n; i++) await pass(d); };
async function four(f, extra = {}) {
  const ts = [];
  for (let i = 0; i < 4; i++) ts.push(await finished(f, `ticket ${i + 1}`, extra[i] ?? {}));
  return ts;
}

test('train_size_max 4 with a clean record: all four tickets go in one run', async () => {
  const f = setup({ max: 4 });
  try {
    seed(f, 20, 0);
    const ts = await four(f);
    await pass(dispatcher(f));
    assert.deepEqual(trains(f), [`cand-train-${ts.map((t) => t.id).join('+')}`]);
    assert.equal(mergedOrder(f).length, 4);
    assert.match(events(f), /merge train size is now 4/);
  } finally { f.cleanup(); }
});

test('train_size_max 4 with no record yet: starts with 2, so four tickets take two runs', async () => {
  const f = setup({ max: 4 });
  try {
    await four(f);
    await passes(dispatcher(f));
    assert.equal(trains(f).length, 2);
    assert.equal(mergedOrder(f).length, 4);
    assert.match(events(f), /merge train size is now 2/);
  } finally { f.cleanup(); }
});

test('train_size_max 4 with a poor record (1 in 3 passed): tickets go one per run', async () => {
  const f = setup({ max: 4 });
  try {
    seed(f, 7, 13);
    await four(f);
    await passes(dispatcher(f));
    assert.equal(trains(f).length, 4, trains(f).join(', '));
    assert.match(events(f), /merge train size is now 1/);
  } finally { f.cleanup(); }
});

test('a ticket that changes the Makefile is gated alone even in a big train; the others still travel together', async () => {
  const f = setup({ max: 4 });
  try {
    seed(f, 20, 0);
    const ts = await four(f, { 1: { Makefile: 'all:\n\ttrue\n' } });
    await passes(dispatcher(f));
    const gated = trains(f);
    assert.equal(gated[0], `cand-train-${ts[0].id}+${ts[2].id}+${ts[3].id}`, `first train skips the Makefile ticket (${gated.join(', ')})`);
    assert.ok(gated.includes(`cand-${ts[1].id}`), 'the Makefile ticket ran alone');
    assert.equal(mergedOrder(f).length, 4);
  } finally { f.cleanup(); }
});

test('a Makefile ticket at the front goes first and alone', async () => {
  const f = setup({ max: 4 });
  try {
    seed(f, 20, 0);
    const ts = await four(f, { 0: { 'extra.mk': 'x:\n\ttrue\n' } });
    await passes(dispatcher(f));
    const gated = trains(f);
    assert.equal(gated[0], `cand-${ts[0].id}`);
    assert.equal(gated[1], `cand-train-${ts[1].id}+${ts[2].id}+${ts[3].id}`);
  } finally { f.cleanup(); }
});

test('train_size_max 0 (the default): the fixed train_size is used and nothing is read from the events', async () => {
  const f = setup({ trainSize: 2 });
  try {
    seed(f, 0, 20);
    await four(f);
    await passes(dispatcher(f));
    assert.equal(trains(f).length, 2);
    assert.doesNotMatch(events(f), /merge train size is now/);
  } finally { f.cleanup(); }
});

test('train_size_max must be a whole number', () => {
  assert.throws(() => preMergeSettings({ dispatcher: { pre_merge: { enabled: true, argv: ['x'], train_size_max: -1 } } }), /train_size_max must be a whole number/);
  assert.throws(() => preMergeSettings({ dispatcher: { pre_merge: { enabled: true, argv: ['x'], train_size_max: 2.5 } } }), /train_size_max/);
  assert.equal(preMergeSettings({ dispatcher: { pre_merge: { enabled: true, argv: ['x'] } } }).train_size_max, 0);
});
