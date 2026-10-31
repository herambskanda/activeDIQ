// T-1067: two parallel branches that each add migration 00NN pass the numbering test alone and
// collide only once merged. The gate runs the numbering check on the trial merge first, refuses
// before main moves, names the free number, and is cheap when the numbers follow main.
// The "check" in the fixture repo is numbering.mjs, which mirrors
// migrations.TestMigrationNumbersAreUniqueAndContiguous: file names must run 0001, 0002, … with no
// repeat and no gap.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { Dispatcher } from '../lib/dispatcher.mjs';
import { blockedNote, planRenumber, preMergeSettings, runPreMergeGate } from '../lib/premerge.mjs';
import { advanceTicket, claimTicket, createTicket, setTicketLinks } from '../lib/tickets.mjs';
import { ensureWorktree } from '../lib/worktree.mjs';
import { listEntities, readRecentEvents } from '../lib/store.mjs';
import { commitAll, git, initRepo, makeFactory, ticketInput } from './helpers.mjs';

const NUMBERING = `import fs from 'node:fs';
const names = fs.readdirSync('migrations').filter((n) => n.endsWith('.sql')).sort();
let next = 1; let bad = 0;
for (const name of names) {
  const n = Number(name.slice(0, 4));
  if (n !== next) { console.error(\`--- FAIL: TestMigrationNumbersAreUniqueAndContiguous\\n    \${name}: expected number \${String(next).padStart(4, '0')}\`); bad++; }
  next = n + 1;
}
process.exit(bad ? 1 : 0);
`;
// the full command: records that it ran, so a refused numbering check can be shown to stop it first
const FULL = `import fs from 'node:fs';
fs.appendFileSync(process.env.FULL_RAN ?? 'full-ran.txt', 'ran\\n');
`;

function setup({ numbering = true } = {}) {
  const f = makeFactory({ config: (c) => {
    c.dispatcher.pre_merge = { enabled: true, argv: ['node', 'full.mjs'], timeout_minutes: 5 };
    if (numbering) c.dispatcher.pre_merge.numbering = { dir: 'migrations', argv: ['node', 'numbering.mjs'], timeout_seconds: 30 };
  } });
  initRepo(f.root);
  fs.mkdirSync(path.join(f.root, 'migrations'));
  for (const n of ['0001_init.sql', '0002_users.sql', '0003_audit.sql']) fs.writeFileSync(path.join(f.root, 'migrations', n), `-- ${n}\n`);
  fs.writeFileSync(path.join(f.root, 'numbering.mjs'), NUMBERING);
  fs.writeFileSync(path.join(f.root, 'full.mjs'), FULL);
  commitAll(f.root, 'ci fixture');
  return f;
}

/** A finished ticket whose branch adds the given migration files. */
async function finishedWith(f, title, files) {
  const t = createTicket(f.ctx, ticketInput({ title, status: 'ready' }), 'x');
  const wt = await ensureWorktree(f.ctx, t.id);
  for (const name of files) fs.writeFileSync(path.join(wt.path, 'migrations', name), `-- ${name} (${t.id})\n`);
  fs.writeFileSync(path.join(wt.path, `work-${t.id}.txt`), 'work\n');
  commitAll(wt.path, `work ${t.id}`);
  claimTicket(f.ctx, t.id);
  for (let i = 0; i < 3; i++) advanceTicket(f.ctx, t.id, 'w', 'ok');
  setTicketLinks(f.ctx, t.id, { branch: wt.branch, worktree: wt.path });
  return t;
}

test('planRenumber gives each clashing added file the next free number and leaves the others', () => {
  const main = ['0001_a.sql', '0002_b.sql', '0003_c.sql', '0004_d.sql'];
  assert.deepEqual(planRenumber(main, ['0004_mine.sql']), [{ from: '0004_mine.sql', to: '0005_mine.sql' }]);
  assert.deepEqual(planRenumber(main, ['0005_mine.sql']), [], 'follows main: nothing to move');
  assert.deepEqual(
    planRenumber(main, ['0004_x.sql', '0005_y.sql', '0003_z.sql']),
    [{ from: '0003_z.sql', to: '0005_z.sql' }, { from: '0004_x.sql', to: '0006_x.sql' }, { from: '0005_y.sql', to: '0007_y.sql' }],
    'ascending: each clashing file takes the next free number, and a later one that now clashes with a moved file moves too',
  );
  assert.deepEqual(planRenumber(main, ['notes.sql']), [], 'unnumbered files are ignored');
});

test('numbering setting is validated', () => {
  assert.equal(preMergeSettings({ dispatcher: { pre_merge: {} } }).numbering, null);
  assert.throws(() => preMergeSettings({ dispatcher: { pre_merge: { numbering: { dir: 'migrations' } } } }), /numbering needs/);
});

test('two branches add the same number: the second is refused before main moves, naming the free number; a branch that follows main passes fast', async () => {
  const f = setup();
  try {
    const first = await finishedWith(f, 'first adds 0004', ['0004_first.sql']);
    const second = await finishedWith(f, 'second adds 0004', ['0004_second.sql']);
    const d = new Dispatcher(f.ctx);
    d.shared = false;
    const ids = () => Object.fromEntries(listEntities(f.ctx, 'tickets').map((t) => [t.id, t]));

    // each branch is fine alone: the gate passes the first and merges it
    await d.mergePass(); await d.gateIdle();
    assert.ok(ids()[first.id].links.merged, 'the first merged');
    const mainAfterFirst = git(f.root, 'rev-parse', 'main');

    // the second now collides on the merged tree
    await d.mergePass(); await d.gateIdle();
    const cur = ids()[second.id];
    assert.deepEqual([cur.status, cur.links.merged], ['in_progress', undefined]);
    assert.equal(git(f.root, 'rev-parse', 'main'), mainAfterFirst, 'main did not move');
    assert.match(cur.notes.at(-1).text, /pre-merge gate refused the merge/);
    assert.match(cur.notes.at(-1).text, /Renumber to 0005: git mv migrations\/0004_second\.sql migrations\/0005_second\.sql/);
    assert.match(readRecentEvents(f.ctx, 50).map((e) => e.text).join('\n'), new RegExp(`${second.id} merge refused by the pre-merge gate`));
    assert.ok(!fs.existsSync(path.join(f.root, 'full-ran.txt')) || fs.readFileSync(path.join(f.root, 'full-ran.txt'), 'utf8').split('\n').filter(Boolean).length === 1,
      'the full command ran for the first ticket only, not for the refused one');

    // the owner renumbers (as the note says) and advances again
    const wt = cur.links.worktree;
    git(wt, 'merge', '--no-edit', 'main');
    git(wt, 'mv', 'migrations/0004_second.sql', 'migrations/0005_second.sql');
    commitAll(wt, 'renumber to 0005');
    for (let i = 0; i < 2; i++) { try { advanceTicket(f.ctx, second.id, 'w', 'renumbered'); } catch { /* stage bookkeeping */ } }
    setTicketLinks(f.ctx, second.id, { branch: `factory/${second.id}`, worktree: wt });
    const verdict = await runPreMergeGate(f.ctx, ids()[second.id]);
    assert.equal(verdict.status, 'pass');
    const seconds = /migration numbering checked in ([\d.]+) s/.exec(verdict.summary);
    assert.ok(seconds, `timing is in the verdict: ${verdict.summary}`);
    console.log(`# migration-numbering check on a branch that follows main: ${seconds[1]} s`);
    assert.ok(Number(seconds[1]) < 5, 'adds under 5 s');
  } finally { f.cleanup(); }
});

test('with no numbering configured the gate does not look at migrations', async () => {
  const f = setup({ numbering: false });
  try {
    const a = await finishedWith(f, 'a', ['0004_a.sql']);
    const b = await finishedWith(f, 'b', ['0004_b.sql']);
    const d = new Dispatcher(f.ctx);
    d.shared = false;
    await d.mergePass(); await d.gateIdle();
    assert.ok(listEntities(f.ctx, 'tickets').find((t) => t.id === a.id).links.merged);
    const v = await runPreMergeGate(f.ctx, listEntities(f.ctx, 'tickets').find((t) => t.id === b.id));
    assert.equal(v.status, 'pass', 'the duplicate gets through when the check is off (this is what the setting prevents)');
  } finally { f.cleanup(); }
});

test('a numbering check that cannot run fails closed', async () => {
  const f = setup();
  try {
    f.ctx.config.dispatcher.pre_merge.numbering.argv = ['node', '-e', 'setTimeout(() => {}, 60000)'];
    f.ctx.config.dispatcher.pre_merge.numbering.timeout_seconds = 0.2;
    const t = await finishedWith(f, 'slow', ['0004_a.sql']);
    await assert.rejects(runPreMergeGate(f.ctx, t), /migration-numbering check .* timed out/);
  } finally { f.cleanup(); }
});

test('the reopen note for a numbering refusal carries the commands, not the CI wording', () => {
  const note = blockedNote({ mode: 'migration-numbering', summary: 'clash', renumber: [{ from: '0061_x.sql', to: '0062_x.sql' }], log: '/l' }, 'main');
  assert.match(note, /Renumber to 0062: git mv migrations\/0061_x\.sql migrations\/0062_x\.sql/);
  assert.doesNotMatch(note, /never weaken, skip or edit the check/);
});
