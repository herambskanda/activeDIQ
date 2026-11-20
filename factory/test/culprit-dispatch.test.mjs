// Merge plan 4.1: with pre_merge.culprit_split on, a refused train is not halved when every new finding
// names a file only one member changed: that member is refused (reopened, one strike) and the others are
// gated again once. Anything it cannot blame falls back to halving. Off by default.
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
import { listEntities, readRecentEvents } from '../lib/store.mjs';
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

function setup({ trainSize, main = {}, split, gate = GATE } = {}) {
  const log = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'train-log-')), 'runs.txt');
  process.env.TRAIN_LOG = log;
  const f = makeFactory({ config: (c) => {
    c.dispatcher.pre_merge = { enabled: true, argv: ['node', 'gate.mjs'], timeout_minutes: 5, ...(trainSize ? { train_size: trainSize } : {}), ...(split === undefined ? {} : { culprit_split: split }) };
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


const events = (f) => readRecentEvents(f.ctx, 120).map((e) => e.text).join('\n');
const whole = (f, ts) => f.runs().filter((r) => r === `cand-train-${ts.map((t) => t.id).join('+')}`).length;

test('culprit_split on: one ticket of four adds a finding in its own file; it alone is refused, the other three are gated once more and merge', async () => {
  const f = setup({ split: true });
  try {
    const ts = [];
    for (let i = 0; i < 4; i++) ts.push(await finished(f, `ticket ${i + 1}`, i === 2 ? { 'violation-t3.txt': 'CloudThing3 names a deployment profile\n' } : {}));
    const d = dispatcher(f);
    await pass(d);

    const out = byId(f);
    const bad = ts[2];
    assert.deepEqual([out[bad.id].status, out[bad.id].gate_failures], ['in_progress', 1], 'the faulty ticket is reopened with one strike');
    assert.match(out[bad.id].notes.at(-1).text, /CloudThing3/);
    const others = ts.filter((t) => t !== bad);
    for (const t of others) assert.ok(out[t.id].links.merged, `${t.id} merged`);
    assert.deepEqual(mergedOrder(f), others.map((t) => t.id));
    const gated = f.runs().filter((r) => r.startsWith('cand-'));
    assert.equal(gated.length, 2, `the whole train once, then the three kept tickets once (${gated.join(', ')})`);
    assert.equal(whole(f, ts), 1);
    assert.equal(gated[1], `cand-train-${others.map((t) => t.id).join('+')}`);
    assert.match(events(f), /every new finding that names a file is in a file only T-\d+ changed, so refusing it; gating /);
    assert.doesNotMatch(events(f), /splitting it in halves/);
    assert.equal(git(f.root, 'status', '--porcelain', '--untracked-files=no'), '');
  } finally { f.cleanup(); }
});

test('culprit_split on: two faulty tickets are both refused and the other two merge, in two gate runs', async () => {
  const f = setup({ split: true });
  try {
    const ts = [];
    for (let i = 0; i < 4; i++) ts.push(await finished(f, `ticket ${i + 1}`, i === 0 || i === 3 ? { [`violation-t${i + 1}.txt`]: `Cloud${i + 1} names a deployment profile\n` } : {}));
    await pass(dispatcher(f));
    const out = byId(f);
    assert.deepEqual([ts[0], ts[3]].map((t) => out[t.id].status), ['in_progress', 'in_progress']);
    assert.deepEqual(mergedOrder(f), [ts[1].id, ts[2].id]);
    assert.equal(f.runs().filter((r) => r.startsWith('cand-')).length, 2);
  } finally { f.cleanup(); }
});

test('culprit_split on: a finding no ticket can be blamed for falls back to halving', async () => {
  const f = setup({ split: true, main: {} });
  try {
    const ts = [];
    // The finding names internal/<name>/x.go, a file nobody changed: nobody can be blamed.
    for (let i = 0; i < 4; i++) ts.push(await finished(f, `ticket ${i + 1}`, i === 1 ? { 'violation-t2.txt': 'CloudThing2 names a deployment profile\n', 'gate.mjs': GATE.replace('`${name}:5:', '`internal/${name.slice(10, -4)}/x.go:5:').replace('\\`\\${name}:5:', '') } : {}));
    await pass(dispatcher(f));
    assert.match(events(f), /splitting it in halves/);
    assert.doesNotMatch(events(f), /every new finding that names a file is in a file only/);
  } finally { f.cleanup(); }
});

test('culprit_split off (the default): the same refused train is halved, as before', async () => {
  const f = setup();
  try {
    const ts = [];
    for (let i = 0; i < 4; i++) ts.push(await finished(f, `ticket ${i + 1}`, i === 2 ? { 'violation-t3.txt': 'CloudThing3 names a deployment profile\n' } : {}));
    await pass(dispatcher(f));
    assert.match(events(f), /splitting it in halves/);
    assert.ok(f.runs().filter((r) => r.startsWith('cand-')).length > 2, 'halving needs more runs than the culprit finder');
    assert.equal(mergedOrder(f).length, 3);
  } finally { f.cleanup(); }
});

test('culprit_split must be a boolean', () => {
  assert.throws(() => preMergeSettings({ dispatcher: { pre_merge: { enabled: true, argv: ['x'], culprit_split: 'yes' } } }), /culprit_split must be true or false/);
  assert.equal(preMergeSettings({ dispatcher: { pre_merge: { enabled: true, argv: ['x'] } } }).culprit_split, false);
});

// A failing PACKAGE is only a likely culprit: the ticket that changed it is gated alone, never refused by the train.
const PKG_GATE = GATE.replace(/console\.error\(.*\);/, "console.error(`./${name.slice(10, -4).replace('t', 'pkg')} TestThing FF-KEY-3 [test-failed]: the test failed`);");

test('culprit_split on: a failing package is a suspect, gated alone afterwards (one strike from its own verdict, none from the train)', async () => {
  const f = setup({ split: true, gate: PKG_GATE });
  try {
    const ts = [];
    for (let i = 0; i < 4; i++) ts.push(await finished(f, `ticket ${i + 1}`, i === 2 ? { 'violation-t3.txt': 'x\n', 'pkg3/a.txt': 'a\n' } : {}));
    await pass(dispatcher(f));
    const out = byId(f);
    const bad = ts[2];
    assert.deepEqual([out[bad.id].status, out[bad.id].gate_failures], ['in_progress', 1], 'one strike, from its own solo verdict');
    assert.deepEqual(mergedOrder(f), ts.filter((t) => t !== bad).map((t) => t.id));
    const gated = f.runs().filter((r) => r.startsWith('cand-'));
    assert.equal(gated.length, 3, `the train, the three others, then the suspect alone (${gated.join(', ')})`);
    assert.equal(gated[2], `cand-${bad.id}`);
    assert.match(events(f), /changed the failing package and is gated alone afterwards/);
  } finally { f.cleanup(); }
});
