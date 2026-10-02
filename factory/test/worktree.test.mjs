import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {
  branchName, cleanupWorktree, ensureWorktree, mergeTicket, repoState, usesSharedCheckout, worktreePath,
} from '../lib/worktree.mjs';
import { git as gitAsync } from '../lib/git.mjs';
import { commitAll, git, initRepo, makeFactory } from './helpers.mjs';

function commitIn(dir, file, content, message) {
  fs.mkdirSync(path.dirname(path.join(dir, file)), { recursive: true });
  fs.writeFileSync(path.join(dir, file), content);
  commitAll(dir, message);
}

test('git wrappers return results instead of throwing', async () => {
  const f = makeFactory();
  try {
    initRepo(f.root);
    assert.equal((await gitAsync(f.root, ['rev-parse', '--is-inside-work-tree'])).stdout.trim(), 'true');
    const bad = await gitAsync(f.root, ['rev-parse', '--verify', 'no-such-ref']);
    assert.notEqual(bad.code, 0);
  } finally { f.cleanup(); }
});

test('repoState and shared-checkout mode: no repo, no commits, isolation none, or a normal repo', async () => {
  const f = makeFactory();
  try {
    assert.deepEqual(await repoState(f.ctx), { isRepo: false, hasCommits: false, branch: null });
    git(f.root, 'init', '-q', '-b', 'main');
    assert.deepEqual(await repoState(f.ctx), { isRepo: true, hasCommits: false, branch: 'main' });
    assert.equal(usesSharedCheckout(f.ctx, { hasCommits: false }), true);
    initRepo(f.root);
    const state = await repoState(f.ctx);
    assert.deepEqual([state.hasCommits, state.branch], [true, 'main']);
    assert.equal(usesSharedCheckout(f.ctx, state), false);
    f.ctx.config.dispatcher.isolation = 'none';
    assert.equal(usesSharedCheckout(f.ctx, state), true);
  } finally { f.cleanup(); }
});

test('ensureWorktree creates factory/<id> under worktree_root and reuses it', async () => {
  const f = makeFactory();
  try {
    initRepo(f.root);
    const first = await ensureWorktree(f.ctx, 'T-0001');
    assert.deepEqual([first.created, first.branch, first.path], [true, 'factory/T-0001', path.join(f.root, '.worktrees', 'T-0001')]);
    assert.equal(first.path, worktreePath(f.ctx, 'T-0001'));
    assert.equal(git(first.path, 'rev-parse', '--abbrev-ref', 'HEAD'), 'factory/T-0001');
    const again = await ensureWorktree(f.ctx, 'T-0001');
    assert.equal(again.created, false);
    fs.mkdirSync(path.join(f.root, '.worktrees', 'T-0002'));
    await assert.rejects(ensureWorktree(f.ctx, 'T-0002'), /not a git worktree/);
  } finally { f.cleanup(); }
});

test('ensureWorktree re-attaches an existing branch whose worktree directory was lost', async () => {
  const f = makeFactory();
  try {
    initRepo(f.root);
    const wt = await ensureWorktree(f.ctx, 'T-0001');
    commitIn(wt.path, 'a.txt', 'work\n', 'feat: a');
    fs.rmSync(wt.path, { recursive: true, force: true });
    const back = await ensureWorktree(f.ctx, 'T-0001');
    assert.equal(back.created, true);
    assert.equal(fs.readFileSync(path.join(back.path, 'a.txt'), 'utf8'), 'work\n');
  } finally { f.cleanup(); }
});

test('mergeTicket merges with --no-ff and cleanupWorktree removes worktree and branch', async () => {
  const f = makeFactory();
  try {
    initRepo(f.root);
    const wt = await ensureWorktree(f.ctx, 'T-0001');
    commitIn(wt.path, 'src/feature.txt', 'feature\n', 'feat: feature');
    const merged = await mergeTicket(f.ctx, { id: 'T-0001', title: 'Feature' });
    assert.equal(merged.status, 'merged');
    assert.equal(merged.commit, git(f.root, 'rev-parse', 'HEAD'));
    assert.match(git(f.root, 'log', '-1', '--format=%s'), /^Merge T-0001: Feature$/);
    assert.equal(git(f.root, 'log', '-1', '--format=%P').split(' ').length, 2, 'a merge commit, not a fast-forward');
    assert.equal(fs.readFileSync(path.join(f.root, 'src', 'feature.txt'), 'utf8'), 'feature\n');

    assert.deepEqual(await cleanupWorktree(f.ctx, 'T-0001'), []);
    assert.equal(fs.existsSync(wt.path), false);
    assert.equal(git(f.root, 'branch', '--list', branchName('T-0001')), '');
  } finally { f.cleanup(); }
});

test('a conflicting merge is aborted cleanly and reported', async () => {
  const f = makeFactory();
  try {
    initRepo(f.root);
    commitIn(f.root, 'shared.txt', 'base\n', 'chore: base');
    const a = await ensureWorktree(f.ctx, 'T-0001');
    const b = await ensureWorktree(f.ctx, 'T-0002');
    commitIn(a.path, 'shared.txt', 'from A\n', 'feat: a');
    commitIn(b.path, 'shared.txt', 'from B\n', 'feat: b');
    assert.equal((await mergeTicket(f.ctx, { id: 'T-0001', title: 'A' })).status, 'merged');
    const second = await mergeTicket(f.ctx, { id: 'T-0002', title: 'B' });
    assert.equal(second.status, 'conflict');
    assert.match(second.detail, /CONFLICT/);
    assert.equal(git(f.root, 'status', '--porcelain', '--untracked-files=no'), '', 'the merge was aborted');
    assert.equal(fs.readFileSync(path.join(f.root, 'shared.txt'), 'utf8'), 'from A\n');
  } finally { f.cleanup(); }
});

test('mergeTicket refuses when the main checkout is not on the main branch', async () => {
  const f = makeFactory();
  try {
    initRepo(f.root);
    await ensureWorktree(f.ctx, 'T-0001');
    git(f.root, 'checkout', '-q', '-b', 'elsewhere');
    const out = await mergeTicket(f.ctx, { id: 'T-0001', title: 'X' });
    assert.equal(out.status, 'error');
    assert.match(out.detail, /on "elsewhere", not "main"/);
  } finally { f.cleanup(); }
});

test('git arguments are never interpreted by a shell', async () => {
  const f = makeFactory();
  try {
    initRepo(f.root);
    const marker = path.join(f.root, 'pwned');
    const wt = await ensureWorktree(f.ctx, 'T-0001');
    commitIn(wt.path, 'x.txt', 'x\n', 'feat: x');
    const merged = await mergeTicket(f.ctx, { id: 'T-0001', title: `$(touch ${marker}); \`touch ${marker}\`` });
    assert.equal(merged.status, 'merged');
    assert.equal(fs.existsSync(marker), false);
    assert.ok(git(f.root, 'log', '-1', '--format=%s').includes('$(touch'));
  } finally { f.cleanup(); }
});
