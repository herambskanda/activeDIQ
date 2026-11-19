// Merge plan 4.3: a ticket that conflicts with main is reopened before it joins a train, so it does not take a
// slot, and the train is filled with the next clean ticket. It is never merged by this check.
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




const events = (f) => readRecentEvents(f.ctx, 300).map((e) => e.text).join('\n');
const trains = (f) => f.runs().filter((r) => r.startsWith('cand-'));
const conflicting = (f, title) => finished(f, title, { 'shared.txt': 'from the branch\n' });
function mainChangesSharedFile(f) {
  fs.writeFileSync(path.join(f.root, 'shared.txt'), 'from main\n');
  commitAll(f.root, 'main adds shared.txt');
}

test('size 2: a ticket that conflicts with main is reopened at once and the train is filled with the next two clean tickets', async () => {
  const f = setup({ max: 2 });
  try {
    const a = await conflicting(f, 'conflicts');
    const b = await finished(f, 'clean one');
    const c = await finished(f, 'clean two');
    mainChangesSharedFile(f);
    await pass(dispatcher(f));
    const out = byId(f);
    assert.equal(out[a.id].status, 'in_progress', 'the conflicting ticket went back to its owner');
    assert.match(out[a.id].notes.at(-1).text, /conflicted \(CONFLICT/);
    assert.equal(out[a.id].gate_failures ?? 0, 0, 'a conflict is not a gate strike');
    assert.deepEqual(trains(f), [`cand-train-${b.id}+${c.id}`], 'one run, with the two clean tickets');
    assert.deepEqual(mergedOrder(f), [b.id, c.id]);
  } finally { f.cleanup(); }
});

test('size 2: no more than 5 conflicting tickets are reopened in one pass; the rest wait and are not put in the train', async () => {
  const f = setup({ max: 2 });
  try {
    const bad = [];
    for (let i = 0; i < 7; i++) bad.push(await conflicting(f, `conflicts ${i + 1}`));
    const b = await finished(f, 'clean one');
    const c = await finished(f, 'clean two');
    mainChangesSharedFile(f);
    await pass(dispatcher(f));
    const out = byId(f);
    assert.equal(bad.filter((t) => out[t.id].status === 'in_progress').length, 5, 'five reopened');
    assert.equal(bad.filter((t) => out[t.id].status === 'done').length, 2, 'two left for the next pass');
    assert.deepEqual(trains(f), [`cand-train-${b.id}+${c.id}`]);
    assert.deepEqual(mergedOrder(f), [b.id, c.id]);
  } finally { f.cleanup(); }
});

test('the check only reopens: if the conflict is gone when it is looked at again under the lock, nothing is reopened or merged', async () => {
  const f = setup({ max: 2 });
  try {
    const a = await conflicting(f, 'conflicts');
    mainChangesSharedFile(f);
    const d = dispatcher(f);
    let calls = 0;
    d.conflictDetail = async () => (++calls === 1 ? 'CONFLICT (add/add): Merge conflict in shared.txt' : null);
    const reopened = await d.reopenIfConflicting(byId(f)[a.id]);
    assert.equal(reopened, false);
    assert.equal(byId(f)[a.id].status, 'done', 'still done, not reopened');
    assert.deepEqual(mergedOrder(f), [], 'and nothing was merged');
    assert.equal(git(f.root, 'status', '--porcelain', '--untracked-files=no'), '');
  } finally { f.cleanup(); }
});

test('size 1 (batching off): the pre-check is not used and a conflicting ticket is still reopened by the single-ticket path', async () => {
  const f = setup({ trainSize: 1 });
  try {
    const a = await conflicting(f, 'conflicts');
    const b = await finished(f, 'clean');
    mainChangesSharedFile(f);
    const d = dispatcher(f);
    let checks = 0;
    const orig = d.reopenIfConflicting.bind(d);
    d.reopenIfConflicting = async (t) => { checks++; return orig(t); };
    await pass(d); await pass(d);
    assert.equal(checks, 0, 'not consulted at size 1');
    assert.equal(byId(f)[a.id].status, 'in_progress');
    assert.deepEqual(mergedOrder(f), [b.id]);
  } finally { f.cleanup(); }
});

test('a git error (a ticket with no branch) is not a conflict: nothing is reopened', async () => {
  const f = setup({ max: 2 });
  try {
    const d = dispatcher(f);
    assert.equal(await d.conflictDetail({ id: 'T-9999' }), null);
    assert.equal(await d.reopenIfConflicting({ id: 'T-9999', type: 'build', links: {} }), false);
  } finally { f.cleanup(); }
});
