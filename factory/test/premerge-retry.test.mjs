// Merge plan 5.1 and 5.2: the gate re-runs the failed jobs once before refusing (a finding counts only if it reproduces),
// and a saved baseline of main is only reused on the UTC day it was made.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { runPreMergeGate, preMergeSettings } from '../lib/premerge.mjs';
import { ensureWorktree } from '../lib/worktree.mjs';
import { commitAll, initRepo, makeFactory } from './helpers.mjs';

// check.mjs prints the lines of violations.txt, and the lines of flaky.txt only the FIRST time it runs in a tree
// (a marker file records that it ran), the way a timing- or cache-sensitive test fails once and passes again.
const CHECK = `import fs from 'node:fs';
const read = (f) => (fs.existsSync(f) ? fs.readFileSync(f, 'utf8').split('\\n').filter(Boolean) : []);
let bad = 0;
for (const l of read('violations.txt')) { const [file, line, msg] = l.split('|'); console.error(\`\${file}:\${line}: P1 (ADR-0002 fitness function): \${msg}\`); bad++; }
if (fs.existsSync('flaky.txt') && !fs.existsSync('flaky-ran.marker')) {
  fs.writeFileSync('flaky-ran.marker', '1');
  for (const l of read('flaky.txt')) { const [file, line, msg] = l.split('|'); console.error(\`\${file}:\${line}: P1 (ADR-0002 fitness function): \${msg}\`); bad++; }
}
process.exit(bad ? 1 : 0);
`;
const OLD = 'internal/a/x.go|10|identifier "OnPremisesSID" names a deployment profile';
const NEW = 'internal/c/z.go|5|identifier "CloudThing" names a deployment profile';

function setup({ retry, daily = false, argv = ['node', 'check.mjs'], main = [], makefile = null } = {}) {
  const f = makeFactory({ config: (c) => { c.dispatcher.pre_merge = { enabled: true, argv, timeout_minutes: 5, retry_failed_jobs: retry, baseline_daily_refresh: daily }; } });
  initRepo(f.root);
  fs.writeFileSync(path.join(f.root, 'check.mjs'), CHECK);
  fs.writeFileSync(path.join(f.root, 'violations.txt'), main.length ? `${main.join('\n')}\n` : '');
  if (makefile) fs.writeFileSync(path.join(f.root, 'Makefile'), makefile);
  commitAll(f.root, 'ci fixture');
  return f;
}
async function branchWith(f, id, files) {
  const wt = await ensureWorktree(f.ctx, id);
  for (const [file, text] of Object.entries(files)) fs.writeFileSync(path.join(wt.path, file), text);
  fs.writeFileSync(path.join(wt.path, `work-${id}.txt`), 'work\n');
  commitAll(wt.path, `work ${id}`);
  return { id, title: `work ${id}` };
}

test('a finding that fails once and passes on the re-run does not refuse the ticket (main green)', async () => {
  const f = setup({ retry: true });
  try {
    const t = await branchWith(f, 'T-9001', { 'flaky.txt': `${NEW}\n` });
    const v = await runPreMergeGate(f.ctx, t);
    assert.equal(v.status, 'pass', v.summary);
    assert.match(v.summary, /re-ran .* once: 1 finding\(s\) did not reproduce/);
    assert.equal(v.retry.dropped.length, 1);
  } finally { f.cleanup(); }
});

test('the same flaky finding refuses the ticket when the retry is off', async () => {
  const f = setup({ retry: false });
  try {
    const t = await branchWith(f, 'T-9001', { 'flaky.txt': `${NEW}\n` });
    const v = await runPreMergeGate(f.ctx, t);
    assert.equal(v.status, 'blocked');
    assert.equal(v.retry, undefined);
  } finally { f.cleanup(); }
});

test('a finding that reproduces on the re-run still refuses the ticket, and says it was confirmed', async () => {
  const f = setup({ retry: true });
  try {
    const t = await branchWith(f, 'T-9001', { 'violations.txt': `${NEW}\n` });
    const v = await runPreMergeGate(f.ctx, t);
    assert.equal(v.status, 'blocked');
    assert.match(v.summary, /the findings reproduced/);
    assert.equal(v.findings.length, 1);
  } finally { f.cleanup(); }
});

test('with main red for an old finding, a flaky new finding is dropped and the old one still counts as known', async () => {
  const f = setup({ retry: true, main: [OLD] });
  try {
    const t = await branchWith(f, 'T-9001', { 'flaky.txt': `${NEW}\n` });
    const v = await runPreMergeGate(f.ctx, t);
    assert.equal(v.status, 'pass', v.summary);
    assert.match(v.summary, /is red \(1 known findings\); after re-running the failed jobs once/);
  } finally { f.cleanup(); }
});

test('with make, only the failed target is re-run', async () => {
  // the target fails once, and only in a candidate tree (main's own baseline run is clean)
  const makefile = 'ci: stable flaky\nstable:\n\t@true\nflaky:\n\t@case "$$PWD" in *cand-*) if [ ! -e flaky-ran.marker ]; then touch flaky-ran.marker; exit 1; fi;; esac\n';
  const f = setup({ retry: true, argv: ['make', '-k', 'ci'], makefile });
  try {
    const t = await branchWith(f, 'T-9001', { 'noop.txt': 'x\n' });
    const v = await runPreMergeGate(f.ctx, t);
    assert.equal(v.status, 'pass', v.summary);
    assert.deepEqual(v.retry.argv, ['make', '-k', 'flaky']);
  } finally { f.cleanup(); }
});

test('a saved baseline is reused on the day it was made and run again the next UTC day (daily refresh)', async () => {
  for (const daily of [false, true]) {
    const f = setup({ retry: false, daily, main: [OLD] });
    try {
      const t1 = await branchWith(f, 'T-9001', { 'violations.txt': `${OLD}\n` });
      await runPreMergeGate(f.ctx, t1); // red main with no new finding: ratchet pass, baseline cached
      const dir = path.join(f.ctx.stateDir, 'premerge');
      const files = fs.readdirSync(dir).filter((n) => /^baseline-.*\.json$/.test(n));
      assert.ok(files.length >= 1, 'a baseline was saved');
      const yesterday = new Date(Date.now() - 36 * 3600 * 1000);
      for (const n of files) fs.utimesSync(path.join(dir, n), yesterday, yesterday);
      const t2 = await branchWith(f, 'T-9002', { 'violations.txt': `${OLD}\n${NEW}\n` });
      const v = await runPreMergeGate(f.ctx, t2);
      assert.equal(v.status, 'blocked');
      assert.match(v.summary, daily ? /ran a fresh baseline/ : /reused the cached run/);
    } finally { f.cleanup(); }
  }
});

test('the new settings are validated', () => {
  const cfg = (pm) => ({ dispatcher: { pre_merge: { enabled: true, argv: ['x'], ...pm } } });
  assert.throws(() => preMergeSettings(cfg({ retry_failed_jobs: 'yes' })), /retry_failed_jobs must be true or false/);
  assert.throws(() => preMergeSettings(cfg({ baseline_daily_refresh: 1 })), /baseline_daily_refresh must be true or false/);
  assert.equal(preMergeSettings(cfg({})).retry_failed_jobs, false);
  assert.equal(preMergeSettings(cfg({})).baseline_daily_refresh, false);
});
