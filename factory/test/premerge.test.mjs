// The pre-merge gate (T-0941): a branch that adds a finding cannot merge while main is red for
// older ones, a branch that adds none can, and nothing merges when the gate cannot judge.
// The "CI" in the fixture repo is check.mjs: it prints one fitness-style finding per line of
// violations.txt (file|line|message) and one failed make target per line of targets.txt, to stderr,
// and exits 1 when it printed anything — the shape of `make -k ci` over fitness-profiles.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { Dispatcher } from '../lib/dispatcher.mjs';
import { blockedNote, extractFindings, findingKey, newFindings, runPreMergeGate } from '../lib/premerge.mjs';
import { advanceTicket, claimTicket, createTicket, setTicketLinks } from '../lib/tickets.mjs';
import { ensureWorktree } from '../lib/worktree.mjs';
import { listEntities, readRecentEvents } from '../lib/store.mjs';
import { commitAll, git, initRepo, makeFactory, ticketInput } from './helpers.mjs';

const CHECK = `import fs from 'node:fs';
const read = (f) => (fs.existsSync(f) ? fs.readFileSync(f, 'utf8').split('\\n').filter(Boolean) : []);
let bad = 0;
for (const l of read('violations.txt')) {
  const [file, line, msg] = l.split('|');
  console.error(\`\${file}:\${line}: P1 (ADR-0002 fitness function): \${msg}\`);
  bad++;
}
for (const t of read('targets.txt')) { console.error(\`make: *** [tools/ci/ci.mk:7: \${t}] Error 1\`); bad++; }
console.log('ok  \\tsome/package\\t0.123s');
process.exit(bad ? 1 : 0);
`;

const V = (file, line, msg) => `${file}|${line}|${msg}`;
const OLD1 = V('internal/a/x.go', 10, 'identifier "OnPremisesSID" names a deployment profile');
const OLD2 = V('internal/b/y.go', 20, 'os.Getenv reads an environment variable whose name is not a constant');
const NEW1 = V('internal/c/z.go', 5, 'identifier "CloudThing" names a deployment profile');

function setup({ gate = {}, main = [] } = {}) {
  const f = makeFactory({ config: (c) => { c.dispatcher.pre_merge = { enabled: true, argv: ['node', 'check.mjs'], timeout_minutes: 5, ...gate }; } });
  initRepo(f.root);
  fs.writeFileSync(path.join(f.root, 'check.mjs'), CHECK);
  fs.writeFileSync(path.join(f.root, 'violations.txt'), main.length ? `${main.join('\n')}\n` : '');
  commitAll(f.root, 'ci fixture');
  return f;
}

/** A ticket branch that rewrites violations.txt; returns the ticket. */
async function branchWith(f, id, violations, extra = {}) {
  const wt = await ensureWorktree(f.ctx, id);
  fs.writeFileSync(path.join(wt.path, 'violations.txt'), violations.length ? `${violations.join('\n')}\n` : '');
  fs.writeFileSync(path.join(wt.path, `work-${id}.txt`), 'work\n');
  for (const [file, text] of Object.entries(extra)) fs.writeFileSync(path.join(wt.path, file), text);
  commitAll(wt.path, `work ${id}`);
  return { id, title: `work ${id}`, wt };
}

// ---- finding keys ------------------------------------------------------------------------

test('finding keys drop positions, durations and the worktree path, and ignore pass lines', () => {
  const root = '/srv/wt/cand-T-1';
  const key = (l) => findingKey(l, [root]);
  assert.equal(key(`${root}/internal/a/x.go:10: P1 (ADR-0002 fitness function): bad`), '<root>/internal/a/x.go: P1 (ADR-0002 fitness function): bad');
  assert.equal(key('internal/a/x.go:10:3: P1 (ADR-0002 fitness function): bad'), key('internal/a/x.go:99:1: P1 (ADR-0002 fitness function): bad'));
  assert.equal(key('activation table P2: ACT (ADR-0002 fitness function): packaging/windows exists'), 'activation table P2: ACT (ADR-0002 fitness function): packaging/windows exists');
  assert.equal(key('make: *** [tools/ci/ci.mk:42: fitness-profiles] Error 1'), 'FAILED fitness-profiles');
  assert.equal(key('make[1]: *** [Makefile:3: sub] Error 2'), 'FAILED sub');
  assert.equal(key('--- FAIL: TestThing (0.12s)'), 'FAIL TestThing');
  assert.equal(key('FAIL\tgithub.com/x/y\t1.234s'), 'FAIL github.com/x/y');
  assert.equal(key('\x1b[31m  foo_test.go:12: got 1 want 2\x1b[0m'), 'foo_test.go: got 1 want 2');
  assert.equal(key('fitness-sso: FAIL: record O-4 missing'), 'fitness-sso: FAIL: record O-4 missing');
  for (const quiet of ['', 'ok  \tgithub.com/x/y\t0.4s', 'fitness-profiles: ok (P1,P4)', 'fitness-profiles: 93 violation(s); rules: adr', 'make: Target ci not remade because of errors.', 'go: downloading x v1', 'P3  ACTIVE, FAILING  EXISTS: internal/connector/ad']) {
    assert.equal(key(quiet), null, JSON.stringify(quiet));
  }
});

test('newFindings is a multiset difference', () => {
  const base = extractFindings('a.go:1: m\na.go:2: m\nb.go:3: n\n');
  assert.deepEqual(newFindings(base, extractFindings('a.go:9: m\na.go:8: m\nb.go:1: n\n')), []);
  assert.deepEqual(newFindings(base, extractFindings('a.go:9: m\na.go:8: m\na.go:7: m\nb.go:1: n\nc.go:1: o\n')), [
    { key: 'a.go: m', extra: 1, known: 2 }, { key: 'c.go: o', extra: 1, known: 0 },
  ]);
});

// ---- the gate ----------------------------------------------------------------------------

test('main red for known findings: a branch that adds one is refused naming it', async () => {
  const f = setup({ main: [OLD1, OLD2] });
  try {
    const t = await branchWith(f, 'T-0001', [OLD1, OLD2, NEW1]);
    const v = await runPreMergeGate(f.ctx, t);
    assert.equal(v.status, 'blocked');
    assert.equal(v.mode, 'new-findings');
    assert.deepEqual(v.findings, ['internal/c/z.go: P1 (ADR-0002 fitness function): identifier "CloudThing" names a deployment profile']);
    assert.match(blockedNote(v, 'main'), /CloudThing/);
    assert.ok(fs.existsSync(v.log) && fs.existsSync(v.baseLog));
    assert.equal(git(f.root, 'worktree', 'list').split('\n').length, 2, 'gate worktrees are removed (main + T-0001)');
  } finally { f.cleanup(); }
});

test('main red: a branch that adds none passes, even when the old findings move lines', async () => {
  const f = setup({ main: [OLD1, OLD2] });
  try {
    const moved = [V('internal/a/x.go', 11, 'identifier "OnPremisesSID" names a deployment profile'), OLD2.replace('|20|', '|44|')];
    const t = await branchWith(f, 'T-0001', moved);
    const v = await runPreMergeGate(f.ctx, t);
    assert.deepEqual([v.status, v.mode, v.findings], ['pass', 'ratchet', []]);
    const fewer = await runPreMergeGate(f.ctx, await branchWith(f, 'T-0002', [OLD1]));
    assert.equal(fewer.status, 'pass', 'fixing an old finding is fine');
  } finally { f.cleanup(); }
});

test('a second copy of a known finding counts as new', async () => {
  const f = setup({ main: [OLD1] });
  try {
    const t = await branchWith(f, 'T-0001', [OLD1, V('internal/a/x.go', 30, 'identifier "OnPremisesSID" names a deployment profile')]);
    const v = await runPreMergeGate(f.ctx, t);
    assert.equal(v.status, 'blocked');
    assert.match(v.findings[0], /\(1 more than the 1 on main\)/);
  } finally { f.cleanup(); }
});

test('main green: a branch that adds a finding is refused; a clean one passes untouched', async () => {
  const f = setup();
  try {
    const bad = await runPreMergeGate(f.ctx, await branchWith(f, 'T-0001', [NEW1]));
    assert.deepEqual([bad.status, bad.mode], ['blocked', 'main-green']);
    assert.match(bad.findings.join('\n'), /CloudThing/);
    const good = await runPreMergeGate(f.ctx, await branchWith(f, 'T-0002', []));
    assert.deepEqual([good.status, good.mode], ['pass', 'green']);
  } finally { f.cleanup(); }
});

test('a job that was green on main and is now red is refused even with no finding line', async () => {
  const f = setup({ main: [OLD1] });
  try {
    const t = await branchWith(f, 'T-0001', [OLD1], { 'targets.txt': 'lint-go\n' });
    const v = await runPreMergeGate(f.ctx, t);
    assert.equal(v.status, 'blocked');
    assert.deepEqual(v.findings, ['FAILED lint-go']);
  } finally { f.cleanup(); }
});

test('a red run with nothing recognisable is refused rather than compared', async () => {
  const f = setup({ main: [OLD1], gate: { argv: ['node', '-e', 'console.error("boom"); process.exit(3)'] } });
  try {
    const v = await runPreMergeGate(f.ctx, await branchWith(f, 'T-0001', [OLD1]));
    assert.deepEqual([v.status, v.mode], ['blocked', 'unrecognised']);
  } finally { f.cleanup(); }
});

test('the baseline run is cached per main commit', async () => {
  const f = setup({ main: [OLD1] });
  try {
    await runPreMergeGate(f.ctx, await branchWith(f, 'T-0001', [OLD1, NEW1]));
    const dir = path.join(f.ctx.stateDir, 'premerge');
    const cached = fs.readdirSync(dir).filter((n) => /^baseline-.*\.json$/.test(n));
    assert.equal(cached.length, 1);
    const logMtime = fs.statSync(path.join(dir, cached[0].replace('.json', '.log'))).mtimeMs;
    await runPreMergeGate(f.ctx, await branchWith(f, 'T-0002', [OLD1, NEW1]));
    assert.equal(fs.statSync(path.join(dir, cached[0].replace('.json', '.log'))).mtimeMs, logMtime, 'not re-run');
  } finally { f.cleanup(); }
});

test('a timeout throws: the gate never passes a branch it could not judge', async () => {
  const f = setup({ gate: { argv: ['node', '-e', 'setTimeout(() => {}, 60000)'], timeout_minutes: 0.005 } });
  try {
    const t = await branchWith(f, 'T-0001', []);
    await assert.rejects(runPreMergeGate(f.ctx, t), /timed out/);
    assert.equal(git(f.root, 'worktree', 'list').split('\n').length, 2, 'scratch worktree removed after the timeout');
  } finally { f.cleanup(); }
});

test('a branch that no longer merges cleanly is reported as a conflict', async () => {
  const f = setup();
  try {
    const t = await branchWith(f, 'T-0001', [], { 'shared.txt': 'from branch\n' });
    fs.writeFileSync(path.join(f.root, 'shared.txt'), 'from main\n');
    commitAll(f.root, 'main moves');
    assert.equal((await runPreMergeGate(f.ctx, t)).status, 'conflict');
  } finally { f.cleanup(); }
});

// ---- in the dispatcher ---------------------------------------------------------------------

async function finished(f, title, violations) {
  const t = createTicket(f.ctx, ticketInput({ title, status: 'ready' }), 'x');
  const wt = await ensureWorktree(f.ctx, t.id);
  fs.writeFileSync(path.join(wt.path, 'violations.txt'), violations.length ? `${violations.join('\n')}\n` : '');
  fs.writeFileSync(path.join(wt.path, `work-${t.id}.txt`), 'work\n');
  commitAll(wt.path, `work ${t.id}`);
  claimTicket(f.ctx, t.id);
  for (let i = 0; i < 3; i++) advanceTicket(f.ctx, t.id, 'w', 'ok');
  setTicketLinks(f.ctx, t.id, { branch: wt.branch, worktree: wt.path });
  return t;
}

test('the dispatcher reopens a ticket the gate refuses, leaves main alone, and merges one it passes', async () => {
  const f = setup({ main: [OLD1] });
  try {
    const bad = await finished(f, 'adds one', [OLD1, NEW1]);
    const ok = await finished(f, 'adds none', [OLD1]);
    const mainBefore = git(f.root, 'rev-parse', 'main');
    const d = new Dispatcher(f.ctx);
    d.shared = false;
    await d.mergePass();
    await d.gateIdle();
    let out = Object.fromEntries(listEntities(f.ctx, 'tickets').map((t) => [t.id, t]));
    assert.deepEqual([out[bad.id].status, out[bad.id].stage_role], ['in_progress', 'backend-engineer']);
    assert.match(out[bad.id].notes.at(-1).text, /pre-merge gate refused the merge[\s\S]*CloudThing/);
    assert.equal(git(f.root, 'rev-parse', 'main'), mainBefore, 'nothing merged');
    assert.equal(git(f.root, 'status', '--porcelain', '--untracked-files=no'), '');
    await d.mergePass();
    await d.gateIdle();
    out = Object.fromEntries(listEntities(f.ctx, 'tickets').map((t) => [t.id, t]));
    assert.ok(out[ok.id].links.merged, 'the clean ticket merged');
    assert.match(readRecentEvents(f.ctx, 50).map((e) => e.text).join('\n'), /pre-merge gate passed \(ratchet\)/);
    assert.notEqual(git(f.root, 'rev-parse', 'main'), mainBefore);
  } finally { f.cleanup(); }
});

test('when the gate cannot judge, the ticket stays done, unmerged, and is retried only later', async () => {
  const f = setup({ gate: { argv: ['node', '-e', 'setTimeout(() => {}, 60000)'], timeout_minutes: 0.005 } });
  try {
    const t = await finished(f, 'slow', []);
    const mainBefore = git(f.root, 'rev-parse', 'main');
    const d = new Dispatcher(f.ctx);
    d.shared = false;
    await d.mergePass();
    await d.gateIdle();
    const cur = listEntities(f.ctx, 'tickets').find((x) => x.id === t.id);
    assert.equal(cur.status, 'done');
    assert.equal(cur.links.merged, undefined);
    assert.equal(git(f.root, 'rev-parse', 'main'), mainBefore);
    await d.mergePass();
    assert.equal(d.gateRun, null, 'backing off: not retried at once');
  } finally { f.cleanup(); }
});
