// Post-merge verification (T-2xxx step 2): ci-full runs on main itself, after merges land, and only
// reports a finding it did not already have the last time it ran. It never blocks a merge; these
// tests exercise the module directly, not through the dispatcher.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { postMergeVerifySettings, readKnownFindings, runPostMergeVerify } from '../lib/postmerge.mjs';
import { Dispatcher } from '../lib/dispatcher.mjs';
import { listEntities, readRecentEvents } from '../lib/store.mjs';
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

function setup({ gate = {} } = {}) {
  const f = makeFactory({ config: (c) => {
    c.dispatcher.post_merge_verify = { enabled: true, argv: ['node', 'check.mjs'], timeout_minutes: 1, cooldown_minutes: 0, ...gate };
  } });
  initRepo(f.root);
  fs.writeFileSync(path.join(f.root, 'check.mjs'), CHECK);
  commitAll(f.root, 'ci fixture');
  return f;
}

function headSha(f) { return git(f.root, 'rev-parse', 'HEAD'); }

function writeViolations(f, violations) {
  fs.writeFileSync(path.join(f.root, 'violations.txt'), violations.length ? `${violations.join('\n')}\n` : '');
}

test('settings validation', () => {
  assert.equal(postMergeVerifySettings({ dispatcher: {} }).enabled, false, 'off by default');
  assert.deepEqual(postMergeVerifySettings({ dispatcher: {} }).argv, ['make', '-k', 'ci-full']);
  assert.throws(() => postMergeVerifySettings({ dispatcher: { post_merge_verify: { argv: [] } } }), /argv must be a non-empty array/);
  assert.throws(() => postMergeVerifySettings({ dispatcher: { post_merge_verify: { argv: [1] } } }), /argv must be a non-empty array/);
  assert.throws(() => postMergeVerifySettings({ dispatcher: { post_merge_verify: { timeout_minutes: 0 } } }), /timeout_minutes must be a positive number/);
  assert.throws(() => postMergeVerifySettings({ dispatcher: { post_merge_verify: { cooldown_minutes: -1 } } }), /cooldown_minutes must be a whole number/);
  assert.equal(postMergeVerifySettings({ dispatcher: { post_merge_verify: { cooldown_minutes: 0 } } }).cooldown_minutes, 0, '0 is allowed: no wait');
});

test('the first run on a sha has nothing to compare against: it records the baseline and reports nothing new', async () => {
  const f = setup();
  try {
    const settings = postMergeVerifySettings(f.ctx.config);
    const sha = headSha(f);
    const result = await runPostMergeVerify(f.ctx, settings, sha);
    assert.equal(result.code, 0);
    assert.equal(result.previousSha, null);
    assert.deepEqual(result.newFindings, []);
    const known = readKnownFindings(f.ctx);
    assert.equal(known.sha, sha);
    assert.deepEqual([...known.findings.entries()], []);
  } finally { f.cleanup(); }
});

test('a finding that was not there last time is reported once; running again on the same sha reports it again (nothing moved to compare)', async () => {
  const f = setup();
  try {
    const settings = postMergeVerifySettings(f.ctx.config);
    const clean = headSha(f);
    await runPostMergeVerify(f.ctx, settings, clean); // records the empty baseline

    writeViolations(f, [V('a.go', 1, 'bad thing')]);
    commitAll(f.root, 'add a violation');
    const red = headSha(f);
    const first = await runPostMergeVerify(f.ctx, settings, red);
    assert.equal(first.code, 1);
    assert.equal(first.previousSha, clean);
    assert.deepEqual(first.newFindings, ['a.go: P1 (ADR-0002 fitness function): bad thing']);

    // Same sha again (e.g. a retry): now it's the known baseline, so nothing is "new" about it.
    const second = await runPostMergeVerify(f.ctx, settings, red);
    assert.equal(second.previousSha, red);
    assert.deepEqual(second.newFindings, []);
  } finally { f.cleanup(); }
});

test('a finding that moves lines or stays is not new; only a genuinely new one is', async () => {
  const f = setup();
  try {
    const settings = postMergeVerifySettings(f.ctx.config);
    writeViolations(f, [V('a.go', 1, 'old thing')]);
    commitAll(f.root, 'one violation');
    await runPostMergeVerify(f.ctx, settings, headSha(f));

    writeViolations(f, [V('a.go', 9, 'old thing'), V('b.go', 2, 'new thing')]);
    commitAll(f.root, 'move the first, add a second');
    const result = await runPostMergeVerify(f.ctx, settings, headSha(f));
    assert.deepEqual(result.newFindings, ['b.go: P1 (ADR-0002 fitness function): new thing']);
  } finally { f.cleanup(); }
});

test('a timeout throws rather than reporting a false all-clear', async () => {
  const f = setup({ gate: { argv: ['node', '-e', 'setTimeout(() => {}, 60000)'], timeout_minutes: 0.005 } });
  try {
    const settings = postMergeVerifySettings(f.ctx.config);
    await assert.rejects(() => runPostMergeVerify(f.ctx, settings, headSha(f)), /timed out/);
    assert.equal(readKnownFindings(f.ctx), null, 'a run that could not finish records nothing');
  } finally { f.cleanup(); }
});

// ---- through the dispatcher -----------------------------------------------------------------

function dispatcher(f) { const d = new Dispatcher(f.ctx); d.shared = false; return d; }
async function verify(d) { await d.maybeVerifyMain(); await d.verifyIdle(); }
const events = (f) => readRecentEvents(f.ctx, 50).map((e) => e.text);

test('disabled: maybeVerifyMain never runs anything', async () => {
  const f = setup({ gate: { enabled: false } });
  try {
    const d = dispatcher(f);
    await verify(d);
    assert.equal(readKnownFindings(f.ctx), null);
  } finally { f.cleanup(); }
});

test('enabled: the first tick records a baseline and is quiet (nothing to compare against yet)', async () => {
  const f = setup();
  try {
    const d = dispatcher(f);
    await verify(d);
    assert.equal(readKnownFindings(f.ctx).sha, headSha(f));
    assert.deepEqual(events(f).filter((t) => t.includes('post-merge')), []);
  } finally { f.cleanup(); }
});

test('a new finding on main gets one loud event naming it and what landed since the last check', async () => {
  const f = setup({ gate: { cooldown_minutes: 0 } });
  try {
    const d = dispatcher(f);
    f.ctx.now = () => new Date(Date.UTC(2026, 10, 1, 10, 0));
    await verify(d); // baseline on the clean commit

    writeViolations(f, [V('a.go', 1, 'bad thing')]);
    commitAll(f.root, 'add a violation');
    const red = headSha(f);
    f.ctx.now = () => new Date(Date.UTC(2026, 10, 1, 10, 1));
    await verify(d);
    const notice = events(f).find((t) => t.includes('post-merge'));
    assert.match(notice, /found 1 finding\(s\) it did not have/);
    assert.match(notice, /a\.go: P1 \(ADR-0002 fitness function\): bad thing/);
    assert.match(notice, /Landed since the last check: .*add a violation/);
    assert.match(notice, /no auto-revert/);
    assert.equal(readKnownFindings(f.ctx).sha, red);

    // The finding is already known now: checking the same sha again reports nothing further.
    const before = events(f).length;
    f.ctx.now = () => new Date(Date.UTC(2026, 10, 1, 10, 2));
    await verify(d);
    assert.equal(events(f).length, before, 'main did not move since the last check: nothing to verify');
  } finally { f.cleanup(); }
});

test('once the cooldown passes, a verify runs again, but a sha already known to be clean stays quiet', async () => {
  const f = setup({ gate: { cooldown_minutes: 1 } });
  try {
    const d = dispatcher(f);
    f.ctx.now = () => new Date(Date.UTC(2026, 10, 1, 10, 0));
    await verify(d); // baseline

    f.ctx.now = () => new Date(Date.UTC(2026, 10, 1, 10, 0, 30)); // within the 1-minute cooldown
    const before = readKnownFindings(f.ctx).sha;
    await verify(d);
    assert.equal(readKnownFindings(f.ctx).sha, before, 'still within cooldown: no run even though nothing changed to check anyway');

    f.ctx.now = () => new Date(Date.UTC(2026, 10, 1, 10, 2)); // cooldown passed, but main has not moved
    await verify(d);
    assert.equal(events(f).filter((t) => t.includes('post-merge')).length, 0, 'main did not move: nothing to verify, so no run and no event');
  } finally { f.cleanup(); }
});

// ---- a red main gets an owner: one P0 ticket (raise_ticket) ----------------------------------------------

const mainRed = (f) => listEntities(f.ctx, 'tickets').filter((t) => (t.tags ?? []).includes('main-red'));

async function goRed(f, d, violations, minute) {
  writeViolations(f, violations);
  commitAll(f.root, `violations ${minute}`);
  f.ctx.now = () => new Date(Date.UTC(2026, 10, 1, 10, minute));
  await verify(d);
}

test('raise_ticket: a new finding on main opens one ready P0 bug naming it; a second red run while it is open adds none', async () => {
  const f = setup({ gate: { cooldown_minutes: 0, raise_ticket: true } });
  try {
    const d = dispatcher(f);
    f.ctx.now = () => new Date(Date.UTC(2026, 10, 1, 10, 0));
    await verify(d); // baseline
    await goRed(f, d, [V('a.go', 1, 'bad thing')], 1);
    const [t] = mainRed(f);
    assert.equal(mainRed(f).length, 1);
    assert.deepEqual([t.type, t.priority, t.status], ['bug', 'P0', 'ready']);
    assert.match(t.body, /a\.go: P1 \(ADR-0002 fitness function\): bad thing/);
    assert.match(t.body, /violations 1/, 'names what landed since the last check');
    assert.ok(events(f).some((x) => x.includes(`${t.id} raised (P0)`)));

    await goRed(f, d, [V('a.go', 1, 'bad thing'), V('b.go', 2, 'worse thing')], 2);
    assert.equal(mainRed(f).length, 1, 'one open ticket covers it');
    assert.ok(events(f).some((x) => /already open for it, so no second ticket/.test(x)));
  } finally { f.cleanup(); }
});

test('raise_ticket: once the ticket is done a later regression opens a new one; off (the default) raises nothing', async () => {
  const f = setup({ gate: { cooldown_minutes: 0, raise_ticket: true } });
  try {
    const d = dispatcher(f);
    f.ctx.now = () => new Date(Date.UTC(2026, 10, 1, 10, 0));
    await verify(d);
    await goRed(f, d, [V('a.go', 1, 'bad thing')], 1);
    const first = mainRed(f)[0];
    const file = path.join(f.ctx.dir('tickets'), `${first.id}.json`);
    fs.writeFileSync(file, JSON.stringify({ ...first, status: 'done' }));
    await goRed(f, d, [V('a.go', 1, 'bad thing'), V('c.go', 3, 'new regression')], 2);
    assert.equal(mainRed(f).length, 2);
  } finally { f.cleanup(); }
  const g = setup({ gate: { cooldown_minutes: 0 } });
  try {
    const d = dispatcher(g);
    g.ctx.now = () => new Date(Date.UTC(2026, 10, 1, 10, 0));
    await verify(d);
    await goRed(g, d, [V('a.go', 1, 'bad thing')], 1);
    assert.equal(mainRed(g).length, 0);
    assert.ok(events(g).some((x) => x.includes('post-merge')), 'the board event is still posted');
  } finally { g.cleanup(); }
});

test('raise_ticket must be a boolean', () => {
  assert.throws(() => postMergeVerifySettings({ dispatcher: { post_merge_verify: { raise_ticket: 'yes' } } }), /raise_ticket/);
  assert.equal(postMergeVerifySettings({ dispatcher: {} }).raise_ticket, false);
});
