// T-1297: the merge train. The pre-merge gate judges up to dispatcher.pre_merge.train_size done tickets
// in one run on their combined merge result. Green merges each in queue order with its own --no-ff
// commit; a refusal splits the train in halves until the ticket that adds the findings is alone and is
// reopened with them; a text conflict between members leaves the later one done for the next train.
// The "CI" in the fixture repo is gate.mjs: it logs each run (the scratch directory it ran in) to
// $TRAIN_LOG and prints one fitness-style finding per violation-*.txt file in the tree, then fails.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Dispatcher } from '../lib/dispatcher.mjs';
import { preMergeSettings, splitTrain } from '../lib/premerge.mjs';
import { advanceTicket, claimTicket, createTicket, setTicketLinks } from '../lib/tickets.mjs';
import { ensureWorktree } from '../lib/worktree.mjs';
import { listEntities, readRecentEvents } from '../lib/store.mjs';
import { commitAll, git, initRepo, makeFactory, ticketInput } from './helpers.mjs';

const GATE = `import fs from 'node:fs';
import path from 'node:path';
fs.appendFileSync(process.env.TRAIN_LOG, path.basename(process.cwd()) + '|' + fs.readdirSync('.').filter((n) => /^work-/.test(n)).sort().join(',') + '\\n');
let bad = 0;
for (const name of fs.readdirSync('.').filter((n) => /^violation-.*\\.txt$/.test(n)).sort()) {
  console.error(\`internal/\${name.slice(10, -4)}/x.go:5: P1 (ADR-0002 fitness function): \${fs.readFileSync(name, 'utf8').trim()}\`);
  bad++;
}
process.exit(bad ? 1 : 0);
`;

function setup({ trainSize, main = {} } = {}) {
  const log = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'train-log-')), 'runs.txt');
  process.env.TRAIN_LOG = log;
  const f = makeFactory({ config: (c) => {
    c.dispatcher.pre_merge = { enabled: true, argv: ['node', 'gate.mjs'], timeout_minutes: 5, ...(trainSize ? { train_size: trainSize } : {}) };
  } });
  initRepo(f.root);
  fs.writeFileSync(path.join(f.root, 'gate.mjs'), GATE);
  for (const [file, text] of Object.entries(main)) fs.writeFileSync(path.join(f.root, file), text);
  commitAll(f.root, 'ci fixture');
  const lines = () => (fs.existsSync(log) ? fs.readFileSync(log, 'utf8').split('\n').filter(Boolean) : []);
  const runs = () => lines().map((l) => l.split('|')[0]);
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
  for (const [file, text] of Object.entries(files)) fs.writeFileSync(path.join(wt.path, file), text);
  commitAll(wt.path, `work ${t.id}`);
  f.ctx.now = () => new Date(Date.UTC(2026, 10, 1, 10, minute++));
  claimTicket(f.ctx, t.id);
  for (let i = 0; i < 3; i++) advanceTicket(f.ctx, t.id, 'w', 'ok');
  setTicketLinks(f.ctx, t.id, { branch: wt.branch, worktree: wt.path });
  return t;
}

const byId = (f) => Object.fromEntries(listEntities(f.ctx, 'tickets').map((t) => [t.id, t]));
const dispatcher = (f) => { const d = new Dispatcher(f.ctx); d.shared = false; return d; };
const pass = async (d) => { await d.mergePass(); await d.gateIdle(); };
/** The tickets merged into main, oldest first, from the first-parent merge commits. */
const mergedOrder = (f) => git(f.root, 'log', '--first-parent', '--merges', '--reverse', '--format=%s').split('\n').filter(Boolean).map((s) => /^Merge (T-\d+):/.exec(s)[1]);

test('four done tickets whose merged result passes: the gate runs once and each merges in queue order with its own --no-ff commit', async () => {
  const f = setup();
  try {
    const ts = [];
    for (const title of ['one', 'two', 'three', 'four']) ts.push(await finished(f, title));
    const d = dispatcher(f);
    await pass(d);

    assert.deepEqual(f.runs(), [`cand-train-${ts.map((t) => t.id).join('+')}`], 'one gate invocation, on the combined result');
    assert.deepEqual(mergedOrder(f), ts.map((t) => t.id));
    const merges = git(f.root, 'log', '--first-parent', '--merges', '--format=%P').split('\n').filter(Boolean);
    assert.ok(merges.every((p) => p.split(' ').length === 2), 'every merge is a two-parent --no-ff commit');
    const out = byId(f);
    for (const t of ts) {
      assert.ok(out[t.id].links.merged && !out[t.id].links.worktree, `${t.id} merged and cleaned up`);
      assert.equal(out[t.id].links.merge_commit, git(f.root, 'log', '--first-parent', '--merges', '--format=%H', '--grep', `^Merge ${t.id}:`));
    }
    const events = readRecentEvents(f.ctx, 50).map((e) => e.text);
    assert.equal(events.filter((e) => /pre-merge gate passed \(green\) \(train of 4/.test(e)).length, 4);
    assert.equal(events.filter((e) => /merged into main/.test(e)).length, 4);
    assert.equal(git(f.root, 'worktree', 'list').split('\n').length, 1, 'no scratch worktree left');
    assert.equal(git(f.root, 'status', '--porcelain', '--untracked-files=no'), '');
  } finally { f.cleanup(); }
});

for (const [name, main] of [['main green', {}], ['main red for an older finding', { 'violation-old.txt': 'an older finding\n' }]]) {
  for (const at of [0, 2, 3]) {
    test(`a train of four where ticket ${at + 1} adds a finding (${name}): the train is bisected, only that ticket is reopened, the other three merge`, async () => {
      const f = setup({ main });
      try {
        const ts = [];
        for (let i = 0; i < 4; i++) {
          ts.push(await finished(f, `ticket ${i + 1}`, i === at ? { [`violation-t${i + 1}.txt`]: `CloudThing${i + 1} names a deployment profile\n` } : {}));
        }
        const d = dispatcher(f);
        await pass(d);

        const out = byId(f);
        const bad = ts[at];
        assert.deepEqual([out[bad.id].status, out[bad.id].stage_role], ['in_progress', 'backend-engineer'], 'the faulty ticket is reopened for its owner');
        assert.match(out[bad.id].notes.at(-1).text, new RegExp(`pre-merge gate refused the merge[\\s\\S]*CloudThing${at + 1}`));
        assert.equal(out[bad.id].links.merged, undefined);
        const others = ts.filter((t) => t !== bad);
        for (const t of others) assert.ok(out[t.id].links.merged, `${t.id} merged`);
        assert.deepEqual(mergedOrder(f), others.map((t) => t.id), 'the others merged in queue order');
        assert.equal(listEntities(f.ctx, 'tickets').filter((t) => t.status === 'done').length, 3);
        assert.equal(f.runs()[0], `cand-train-${ts.map((t) => t.id).join('+')}`, 'the first run was the whole train');
        const gated = f.runs().filter((r) => r.startsWith('cand-')); // the baseline runs on main are not trains
        assert.ok(gated.length > 1 && gated.length <= 5, `bisection re-gated the halves (${gated.join(', ')})`);
        assert.ok(gated.slice(1).every((r) => !r.includes(ts.map((t) => t.id).join('+'))), 'no later run re-judged the whole train');
        assert.match(readRecentEvents(f.ctx, 80).map((e) => e.text).join('\n'), /refused the train .*; splitting it in halves/);
        assert.equal(git(f.root, 'status', '--porcelain', '--untracked-files=no'), '');
      } finally { f.cleanup(); }
    });
  }
}

test('a text conflict between two train members: the later one stays done and waits for the next train, the others are gated and merge', async () => {
  const f = setup();
  try {
    const a = await finished(f, 'a', { 'shared.txt': 'from a\n' });
    const b = await finished(f, 'b', { 'shared.txt': 'from b\n' });
    const c = await finished(f, 'c');
    const d = dispatcher(f);
    const notesBefore = byId(f)[b.id].notes.length;
    await pass(d);

    assert.deepEqual(f.runs(), [`cand-train-${a.id}+${b.id}+${c.id}`]);
    assert.deepEqual(f.trees(), [[a.id, c.id]], 'the gate saw a and c only: b was left out of the combined result');
    let out = byId(f);
    assert.ok(out[a.id].links.merged && out[c.id].links.merged);
    assert.deepEqual([out[b.id].status, out[b.id].links.merged, Boolean(out[b.id].links.worktree)], ['done', undefined, true], 'b is not reopened');
    assert.equal(out[b.id].notes.length, notesBefore, 'b was not annotated');
    assert.match(readRecentEvents(f.ctx, 50).map((e) => e.text).join('\n'), new RegExp(`${b.id} conflicts with an earlier ticket in its merge train .*waits for the next train`));
    assert.deepEqual(mergedOrder(f), [a.id, c.id]);

    // next train: b alone now conflicts with main itself, so it is reopened for its owner as before
    await pass(d);
    out = byId(f);
    assert.equal(out[b.id].status, 'in_progress');
    assert.match(out[b.id].notes.at(-1).text, /conflicted/);
    assert.deepEqual(mergedOrder(f), [a.id, c.id]);
    assert.equal(git(f.root, 'status', '--porcelain', '--untracked-files=no'), '');
  } finally { f.cleanup(); }
});

test('the train holds at most train_size tickets, takes them in queue order and leaves the rest for the next train', async () => {
  const f = setup({ trainSize: 2 });
  try {
    const low = await finished(f, 'low', {}, { priority: 'P3' });
    const urgent = await finished(f, 'urgent', {}, { priority: 'P0' });
    const mid = await finished(f, 'mid', {}, { priority: 'P2' });
    const d = dispatcher(f);
    await pass(d);
    assert.deepEqual(f.runs(), [`cand-train-${urgent.id}+${mid.id}`]);
    await pass(d);
    assert.deepEqual(f.runs().at(-1), `cand-${low.id}`, 'a train of one is gated as a single ticket');
    assert.deepEqual(mergedOrder(f), [urgent.id, mid.id, low.id]);
  } finally { f.cleanup(); }
});

test('an embargoed ticket is held out of the train and the rest still go', async () => {
  const f = setup();
  try {
    const a = await finished(f, 'a');
    const held = await finished(f, 'held', {}, { tags: ['embargoed'] });
    const c = await finished(f, 'c');
    await pass(dispatcher(f));
    assert.deepEqual(f.runs(), [`cand-train-${a.id}+${c.id}`]);
    const out = byId(f);
    assert.deepEqual([out[held.id].status, Boolean(out[held.id].links.held), out[held.id].links.merged], ['done', true, undefined]);
  } finally { f.cleanup(); }
});

test('a gate that cannot judge merges nothing, and every member waits ten minutes', async () => {
  const f = setup();
  try {
    const ts = [await finished(f, 'a'), await finished(f, 'b')];
    const d = dispatcher(f);
    const start = Date.UTC(2026, 10, 2, 12, 0);
    let clock = start;
    f.ctx.now = () => new Date(clock); // frozen: the fixture clock otherwise ticks a minute per read
    let calls = 0;
    d.runGate = async () => { calls++; throw new Error('gate timed out'); };
    await pass(d);
    assert.equal(calls, 1, 'the train was gated once');
    assert.equal(git(f.root, 'log', '--merges', '--format=%s').trim(), '');
    for (const t of ts) assert.equal(d.gateRetryAt.get(t.id), start + 10 * 60_000, `${t.id} is held for ten minutes on the dispatcher clock`);
    assert.equal(byId(f)[ts[0].id].status, 'done');
    // while they wait, nothing is gated again
    await pass(d);
    assert.equal(calls, 1, 'no second gate run during the ten-minute hold');
    // once the hold has passed the train is gated again
    clock = start + 10 * 60_000 + 1;
    await pass(d);
    assert.equal(calls, 2, 'gated again after ten minutes');
  } finally { f.cleanup(); }
});

test('two members that add the same migration number: the numbering refusal bisects, the first merges, the second is told the free number', async () => {
  const f = setup();
  try {
    fs.writeFileSync(path.join(f.root, 'numbering.mjs'), `import fs from 'node:fs';
const names = fs.readdirSync('migrations').filter((n) => n.endsWith('.sql')).sort();
let next = 1; let bad = 0;
for (const name of names) { const n = Number(name.slice(0, 4)); if (n !== next) { console.error('--- FAIL: TestMigrationNumbers ' + name); bad++; } next = n + 1; }
process.exit(bad ? 1 : 0);
`);
    fs.mkdirSync(path.join(f.root, 'migrations'));
    fs.writeFileSync(path.join(f.root, 'migrations', '0001_init.sql'), '-- init\n');
    commitAll(f.root, 'migrations');
    f.ctx.config.dispatcher.pre_merge.numbering = { dir: 'migrations', argv: ['node', 'numbering.mjs'], timeout_seconds: 30 };
    const first = await finished(f, 'first', { 'migrations/0002_first.sql': '-- first\n' });
    const second = await finished(f, 'second', { 'migrations/0002_second.sql': '-- second\n' });
    await pass(dispatcher(f));
    const out = byId(f);
    assert.ok(out[first.id].links.merged);
    assert.equal(out[second.id].status, 'in_progress');
    assert.match(out[second.id].notes.at(-1).text, /Renumber to 0003: git mv migrations\/0002_second\.sql migrations\/0003_second\.sql/);
    assert.deepEqual(f.runs(), [`cand-${first.id}`], 'the full command ran only for the half that passed the numbering check');
  } finally { f.cleanup(); }
});

test('train_size is validated and splitTrain halves in order', () => {
  const s = (train_size) => preMergeSettings({ dispatcher: { pre_merge: { train_size } } });
  assert.equal(preMergeSettings({ dispatcher: {} }).train_size, 4, 'default 4');
  assert.equal(s(1).train_size, 1);
  for (const bad of [0, -1, 2.5, '4', null]) assert.throws(() => s(bad), /train_size must be a whole number/, String(bad));
  assert.deepEqual(splitTrain([1, 2, 3, 4]), [[1, 2], [3, 4]]);
  assert.deepEqual(splitTrain([1, 2, 3]), [[1, 2], [3]]);
  assert.deepEqual(splitTrain([1, 2]), [[1], [2]]);
});
