// The shadow gate: the tiered checks that run beside the real gate and decide nothing. The pure
// parts (what a change touches, which packages it affects, how a shadow verdict compares with the
// real one) are tested directly; the run itself against a fixture repo whose "CI" is check.mjs.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { Dispatcher } from '../lib/dispatcher.mjs';
import { runPreMergeGate } from '../lib/premerge.mjs';
import {
  GO_PACKAGES, affectedGoPackages, classifyChange, compareVerdicts, parseGoList, planSteps, readShadowResults,
  runShadowGate, shadowGateSettings, summarizeShadow,
} from '../lib/shadowgate.mjs';
import { readRecentEvents } from '../lib/store.mjs';
import { ensureWorktree } from '../lib/worktree.mjs';
import { commitAll, git, initRepo, makeFactory } from './helpers.mjs';

const CHECK = `import fs from 'node:fs';
const read = (f) => (fs.existsSync(f) ? fs.readFileSync(f, 'utf8').split('\\n').filter(Boolean) : []);
let bad = 0;
for (const l of read('violations.txt')) {
  const [file, line, msg] = l.split('|');
  console.error(\`\${file}:\${line}: P1 (ADR-0002 fitness function): \${msg}\`);
  bad++;
}
process.exit(bad ? 1 : 0);
`;
const V = (file, line, msg) => `${file}|${line}|${msg}`;
const NEW1 = V('internal/c/z.go', 5, 'identifier "CloudThing" names a deployment profile');

const PASSES = { tier: 2, name: 'always-green', when: 'always', argv: ['node', '-e', 'process.exit(0)'] };

function setup({ shadowSteps } = {}) {
  const f = makeFactory({ config: (c) => {
    c.dispatcher.pre_merge = { enabled: true, argv: ['node', 'check.mjs'], timeout_minutes: 5 };
    c.dispatcher.shadow_gate = { enabled: true, step_timeout_minutes: 2, steps: shadowSteps ?? [
      { tier: 1, name: 'check', when: 'always', argv: ['node', 'check.mjs'] },
      { tier: 2, name: 'go-test', when: 'go', argv: ['node', '-e', 'process.exit(0)', GO_PACKAGES] },
      { tier: 2, name: 'web-test', when: 'web', argv: ['node', '-e', 'process.exit(1)'] },
    ] };
  } });
  initRepo(f.root);
  fs.writeFileSync(path.join(f.root, 'check.mjs'), CHECK);
  fs.writeFileSync(path.join(f.root, 'violations.txt'), '');
  commitAll(f.root, 'ci fixture');
  return f;
}

async function branchWith(f, id, violations) {
  const wt = await ensureWorktree(f.ctx, id);
  fs.writeFileSync(path.join(wt.path, 'violations.txt'), violations.length ? `${violations.join('\n')}\n` : '');
  fs.writeFileSync(path.join(wt.path, `work-${id}.txt`), 'work\n');
  commitAll(wt.path, `work ${id}`);
  return { id, title: `work ${id}` };
}

const head = (f, ref) => git(f.root, 'rev-parse', ref);

// ---- what a change touches ---------------------------------------------------------------------

test('classifyChange: prose and the knowledge base need no tests, web and deps are told apart, build files reach everything', () => {
  assert.deepEqual(classifyChange(['knowledge/x.md', 'README.md', 'factory/lib/a.mjs', '.claude/a.md']), { go: false, web: false, deps: false, workflows: false, wide: false, goFiles: [] });
  const web = classifyChange(['web/src/a.tsx']);
  assert.equal(web.web, true); assert.equal(web.go, false); assert.equal(web.deps, false);
  assert.equal(classifyChange(['web/package-lock.json']).deps, true);
  const go = classifyChange(['internal/a/x.go', 'migrations/0083_x.sql']);
  assert.deepEqual([go.go, go.wide, go.goFiles], [true, false, ['internal/a/x.go', 'migrations/0083_x.sql']]);
  for (const wide of ['go.mod', 'Makefile', 'tools/ci/ci.mk', 'tools/ci/proof.sh']) assert.equal(classifyChange([wide]).wide, true, wide);
  assert.equal(classifyChange(['go.sum']).deps, true);
  assert.equal(classifyChange(['.github/workflows/ci.yml']).workflows, true);
});

const PKGS = [
  { path: 'm/internal/a', dir: 'internal/a', imports: [] },
  { path: 'm/internal/b', dir: 'internal/b', imports: ['m/internal/a'] },
  { path: 'm/internal/c', dir: 'internal/c', imports: ['m/internal/b'] },
  { path: 'm/internal/d', dir: 'internal/d', imports: [] },
  { path: 'm/migrations', dir: 'migrations', imports: [] },
];

test('affectedGoPackages: the owning package plus every importer, direct or through others, and nothing else', () => {
  assert.deepEqual(affectedGoPackages(['internal/a/x.go'], PKGS), ['m/internal/a', 'm/internal/b', 'm/internal/c']);
  assert.deepEqual(affectedGoPackages(['internal/c/x.go'], PKGS), ['m/internal/c']);
  assert.deepEqual(affectedGoPackages(['internal/d/testdata/golden/out.json'], PKGS), ['m/internal/d'], 'a file below a package belongs to it');
  assert.deepEqual(affectedGoPackages(['migrations/0084_a.sql'], PKGS), ['m/migrations']);
});

test('affectedGoPackages: a changed file no package owns cannot be traced, so the answer is everything', () => {
  assert.equal(affectedGoPackages(['api/openapi.yaml'], PKGS), null);
  assert.equal(affectedGoPackages(['internal/a/x.go', 'proto/a.proto'], PKGS), null);
});

test('parseGoList reads import paths, repo-relative dirs and test imports', () => {
  const text = 'm/internal/a|/r/internal/a|fmt  \nm/internal/b|/r/internal/b|m/internal/a os m/internal/a\nm|/r|\n';
  assert.deepEqual(parseGoList(text, '/r'), [
    { path: 'm/internal/a', dir: 'internal/a', imports: ['fmt'] },
    { path: 'm/internal/b', dir: 'internal/b', imports: ['m/internal/a', 'os'] },
    { path: 'm', dir: '', imports: [] },
  ]);
});

test('planSteps runs only what the change needs and expands the affected packages into the Go test', () => {
  const { steps } = shadowGateSettings({ dispatcher: {} });
  const names = (plan) => plan.filter((p) => p.argv).map((p) => p.step.name);
  const docs = planSteps(steps, classifyChange(['knowledge/a.md']), []);
  assert.deepEqual(names(docs), ['lint-go', 'gen-check', 'lint-api', 'fitness', 'secrets-scan'], 'tier 1 only');
  const goPlan = planSteps(steps, classifyChange(['internal/a/x.go']), ['m/internal/a', 'm/internal/b']);
  assert.deepEqual(goPlan.find((p) => p.step.name === 'go-test').argv.slice(-2), ['m/internal/a', 'm/internal/b']);
  assert.ok(!names(goPlan).includes('e2e') && !names(goPlan).includes('vuln-scan'));
  const wide = planSteps(steps, classifyChange(['go.mod']), null);
  assert.equal(wide.find((p) => p.step.name === 'go-test').argv.at(-1), './...');
  assert.ok(names(wide).includes('vuln-scan'));
  const web = planSteps(steps, classifyChange(['web/src/a.tsx']), null);
  assert.deepEqual(names(web).filter((n) => ['lint-web', 'test-web', 'e2e', 'go-test'].includes(n)), ['lint-web', 'test-web', 'e2e']);
});

test('settings are validated', () => {
  assert.throws(() => shadowGateSettings({ dispatcher: { shadow_gate: { steps: [{ tier: 1, name: 'a', when: 'sometimes', argv: ['x'] }] } } }), /when/);
  assert.throws(() => shadowGateSettings({ dispatcher: { shadow_gate: { steps: [{ tier: 1, name: 'a', when: 'always', argv: [] }] } } }), /argv/);
  assert.throws(() => shadowGateSettings({ dispatcher: { shadow_gate: { steps: [PASSES, PASSES] } } }), /two steps/);
  assert.equal(shadowGateSettings({ dispatcher: {} }).enabled, false, 'off unless switched on');
});

// ---- comparing with the real gate -----------------------------------------------------------------

test('compareVerdicts: a refusal the shadow passes is a MISS; a red-main pass the shadow fails says nothing', () => {
  const blocked = { status: 'blocked', mode: 'new-findings', log: 'l', findings: ['<root>/a: bad', '<root>/b: worse  (2 times)'] };
  assert.deepEqual(compareVerdicts(blocked, { ok: true, findings: [] }), { agreement: 'MISS', caught: '0/2' });
  assert.deepEqual(compareVerdicts(blocked, { ok: false, findings: ['<root>/a: bad'] }), { agreement: 'MISS', caught: '1/2' });
  assert.deepEqual(compareVerdicts(blocked, { ok: false, findings: ['<root>/a: bad', '<root>/b: worse', 'extra'] }), { agreement: 'agree', caught: '2/2' });
  assert.equal(compareVerdicts({ status: 'pass', mode: 'green' }, { ok: true, findings: [] }).agreement, 'agree');
  assert.equal(compareVerdicts({ status: 'pass', mode: 'green' }, { ok: false, findings: ['x'] }).agreement, 'false-alarm');
  assert.equal(compareVerdicts({ status: 'pass', mode: 'ratchet' }, { ok: false, findings: ['x'] }).agreement, 'inconclusive');
  assert.equal(compareVerdicts({ status: 'blocked', mode: 'unrecognised', log: 'l', findings: [] }, { ok: true, findings: [] }).agreement, 'n/a');
  assert.equal(compareVerdicts({ status: 'conflict' }, { ok: true, findings: [] }).agreement, 'n/a');
});

// ---- running it -------------------------------------------------------------------------------------

test('a clean ticket: the shadow passes, agrees, times every step and skips the steps the change does not need', async (t) => {
  const f = setup(); t.after(f.cleanup);
  const ticket = await branchWith(f, 'T-0001', []);
  const verdict = await runPreMergeGate(f.ctx, ticket);
  assert.equal(verdict.status, 'pass');
  const rec = await runShadowGate(f.ctx, ticket, { mainSha: head(f, 'main'), branchSha: head(f, 'factory/T-0001'), verdict });
  assert.equal(rec.status, 'pass');
  assert.equal(rec.agreement, 'agree');
  const by = Object.fromEntries(rec.steps.map((s) => [s.name, s]));
  assert.equal(by.check.code, 0);
  assert.equal(typeof by.check.seconds, 'number');
  assert.equal(by['go-test'].code, 0, 'the fixture has no Go toolchain answer, so it tests everything');
  assert.equal(by['web-test'].skipped, true);
  assert.deepEqual(readShadowResults(f.ctx).map((r) => r.ticket), ['T-0001']);
  assert.equal(git(f.root, 'worktree', 'list').split('\n').filter((l) => l.includes('shadow-')).length, 0, 'scratch worktree removed');
});

test('a ticket the real gate refuses: a shadow that finds the same violation agrees, one that runs only green checks is a MISS', async (t) => {
  const f = setup(); t.after(f.cleanup);
  const ticket = await branchWith(f, 'T-0002', [NEW1]);
  const verdict = await runPreMergeGate(f.ctx, ticket);
  assert.equal(verdict.status, 'blocked');
  const opts = { mainSha: head(f, 'main'), branchSha: head(f, 'factory/T-0002'), verdict };
  const same = await runShadowGate(f.ctx, ticket, opts);
  assert.equal(same.status, 'fail');
  assert.equal(same.agreement, 'agree');
  assert.equal(same.caught, '1/1');

  f.ctx.config.dispatcher.shadow_gate = { ...f.ctx.config.dispatcher.shadow_gate, steps: [PASSES] };
  const blind = await runShadowGate(f.ctx, ticket, opts);
  assert.equal(blind.status, 'pass');
  assert.equal(blind.agreement, 'MISS');
  const sum = summarizeShadow(readShadowResults(f.ctx));
  assert.deepEqual([sum.judged, sum.agree, sum.misses.length], [2, 1, 1]);
  assert.equal(sum.misses[0].ticket, 'T-0002');
});

test('a ticket that cannot merge onto main is recorded as an error, not thrown', async (t) => {
  const f = setup(); t.after(f.cleanup);
  const ticket = await branchWith(f, 'T-0003', []);
  fs.writeFileSync(path.join(f.root, 'violations.txt'), `${NEW1}\n`);
  commitAll(f.root, 'main changes the same file');
  const wt = await ensureWorktree(f.ctx, 'T-0003');
  fs.writeFileSync(path.join(wt.path, 'violations.txt'), 'x|1|other\n');
  commitAll(wt.path, 'conflicting change');
  const rec = await runShadowGate(f.ctx, ticket, { mainSha: head(f, 'main'), branchSha: head(f, 'factory/T-0003'), verdict: { status: 'conflict' } });
  assert.equal(rec.status, 'error');
  assert.equal(rec.agreement, 'n/a');
});

// ---- the dispatcher hook: logging only ----------------------------------------------------------------

test('the dispatcher starts the shadow after the real gate and still merges on the real verdict; a busy shadow skips', async (t) => {
  const f = setup(); t.after(f.cleanup);
  const calls = [];
  const d = new Dispatcher(f.ctx);
  d.runShadow = async (_ctx, ticket, opts) => { calls.push({ id: ticket.id, status: opts.verdict.status, main: opts.mainSha }); return { status: 'pass', agreement: 'agree', seconds: 3 }; };
  const ticket = await branchWith(f, 'T-0004', []);
  const base = await d.shadowBase(ticket);
  assert.equal(base.mainSha, head(f, 'main'));
  assert.equal(base.branchSha, head(f, 'factory/T-0004'));
  d.startShadow(ticket, base, { status: 'pass', mode: 'green' });
  d.startShadow(ticket, base, { status: 'pass', mode: 'green' }); // second while the first runs
  await d.shadowRun;
  assert.deepEqual(calls.map((c) => c.id), ['T-0004'], 'only one shadow run at a time');
  assert.equal(readShadowResults(f.ctx).filter((r) => r.status === 'skipped').length, 1);
  assert.ok(readRecentEvents(f.ctx, 20).some((e) => /shadow gate on T-0004: pass/.test(e.text) && /does not affect any merge/.test(e.text)));
  assert.equal(d.shadowRun, null);
});

test('a shadow that throws is logged as skipped and never escapes', async (t) => {
  const f = setup(); t.after(f.cleanup);
  const d = new Dispatcher(f.ctx);
  d.runShadow = async () => { throw new Error('boom'); };
  d.startShadow({ id: 'T-0005', title: 'x' }, { mainSha: 'a', branchSha: 'b' }, { status: 'pass' });
  await d.shadowRun;
  const [rec] = readShadowResults(f.ctx);
  assert.equal(rec.status, 'skipped');
  assert.match(rec.error, /boom/);
});
