// A gate verdict judged on one `main` must not be merged blind after `main` moved. But when the move
// touched only files no gate job reads (the daily digest, agent memory), the verdict still holds, and
// throwing away a 75-minute run for it is waste (T-2232 lost 150 minutes to a digest commit).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { Dispatcher } from '../lib/dispatcher.mjs';
import { preMergeSettings, unreadMove } from '../lib/premerge.mjs';
import { advanceTicket, claimTicket, createTicket, setTicketLinks } from '../lib/tickets.mjs';
import { ensureWorktree } from '../lib/worktree.mjs';
import { listEntities, readRecentEvents } from '../lib/store.mjs';
import { commitAll, git, initRepo, makeFactory, ticketInput } from './helpers.mjs';

function setup({ keep } = {}) {
  const f = makeFactory({ config: (c) => { c.dispatcher.pre_merge = { enabled: true, argv: ['true'], timeout_minutes: 5, ...(keep === undefined ? {} : { keep_unread_moves: keep }) }; } });
  initRepo(f.root);
  return f;
}
async function finished(f, title) {
  const t = createTicket(f.ctx, ticketInput({ title, priority: 'P1', status: 'ready' }), 'x');
  const wt = await ensureWorktree(f.ctx, t.id);
  fs.writeFileSync(path.join(wt.path, `work-${t.id}.txt`), 'work\n');
  commitAll(wt.path, `work ${t.id}`);
  setTicketLinks(f.ctx, t.id, { branch: wt.branch, worktree: wt.path });
  claimTicket(f.ctx, t.id);
  for (let i = 0; i < 3; i++) advanceTicket(f.ctx, t.id, 'w', 'ok');
  return t;
}
const merged = (f, t) => Boolean(listEntities(f.ctx, 'tickets').find((x) => x.id === t.id).links.merged);
const events = (f) => readRecentEvents(f.ctx, 40).map((e) => e.text).join('\n');

/** Judge `t` against the main of now, let `move` change main, then settle the verdict as if it were just returned. */
async function settleAfterMove(f, t, move) {
  const stale = git(f.root, 'rev-parse', 'main');
  move();
  const d = new Dispatcher(f.ctx);
  d.runGate = async () => ({ status: 'pass', mode: 'green', findings: [], summary: 'stubbed', mainSha: stale });
  await d.gateGroup([t], undefined);
}
const write = (f, rel, body = 'x\n') => { fs.mkdirSync(path.dirname(path.join(f.root, rel)), { recursive: true }); fs.writeFileSync(path.join(f.root, rel), body); commitAll(f.root, `touch ${rel}`); };

test('a move that touches only a report is kept when the setting is on: the ticket merges', async () => {
  const f = setup({ keep: true });
  try {
    const t = await finished(f, 'digest lands mid-run');
    await settleAfterMove(f, t, () => write(f, 'factory/reports/digest-2026-11-17.md'));
    assert.ok(merged(f, t), 'merged on the verdict judged before the digest');
    assert.match(events(f), /no gate job reads; the verdict still holds, merging/);
  } finally { f.cleanup(); }
});

test('the same move is still discarded while the setting is off (the default), and the event says what would help', async () => {
  const f = setup();
  try {
    assert.equal(preMergeSettings(f.ctx.config).keep_unread_moves, false);
    const t = await finished(f, 'default behaviour');
    await settleAfterMove(f, t, () => write(f, 'factory/reports/digest-2026-11-17.md'));
    assert.equal(merged(f, t), false);
    assert.equal(listEntities(f.ctx, 'tickets').find((x) => x.id === t.id).status, 'done', 'left done for a fresh run, not reopened');
    assert.match(events(f), new RegExp(`${t.id}.*not merged.*moved under this gate run`));
    assert.match(events(f), /keep_unread_moves/);
  } finally { f.cleanup(); }
});

test('a move that touches code, or factory code the gate tests run, is discarded even with the setting on', async () => {
  for (const rel of ['internal/x/code.go', 'factory/lib/dispatcher.mjs', 'factory/test/premerge.test.mjs', 'factory/config.json', 'tools/ci/ci.mk', 'go.mod']) {
    const f = setup({ keep: true });
    try {
      const t = await finished(f, `code move ${rel}`);
      await settleAfterMove(f, t, () => write(f, rel));
      assert.equal(merged(f, t), false, `${rel}: a verdict judged before this change must not merge`);
      assert.match(events(f), /not merged.*moved under this gate run/, rel);
      assert.doesNotMatch(events(f), /verdict still holds/, rel);
    } finally { f.cleanup(); }
  }
});

test('one read file among unread ones is enough to discard', async () => {
  const f = setup({ keep: true });
  try {
    const t = await finished(f, 'mixed move');
    await settleAfterMove(f, t, () => { write(f, 'knowledge/memory/note.md'); write(f, 'internal/y/code.go'); });
    assert.equal(merged(f, t), false);
  } finally { f.cleanup(); }
});

test('unreadMove: agent memory and knowledge notes are unread, an unreadable diff never counts as unread', async () => {
  const f = setup({ keep: true });
  try {
    const before = git(f.root, 'rev-parse', 'main');
    write(f, '.claude/agent-memory/x/MEMORY.md');
    write(f, 'knowledge/memory/lessons.md');
    const after = git(f.root, 'rev-parse', 'main');
    const s = preMergeSettings(f.ctx.config);
    const ok = await unreadMove(f.ctx, s, before, after);
    assert.equal(ok.unread, true);
    assert.deepEqual(ok.files.sort(), ['.claude/agent-memory/x/MEMORY.md', 'knowledge/memory/lessons.md']);
    const bad = await unreadMove(f.ctx, s, 'deadbeef'.repeat(5), after);
    assert.equal(bad.unread, false, 'a commit that cannot be diffed is never treated as unread');
    assert.equal((await unreadMove(f.ctx, s, after, after)).unread, false, 'no change at all is not a "move"');
  } finally { f.cleanup(); }
});

test('keep_unread_moves must be a boolean', () => {
  const f = setup();
  try {
    f.ctx.config.dispatcher.pre_merge.keep_unread_moves = 'yes';
    assert.throws(() => preMergeSettings(f.ctx.config), /keep_unread_moves must be true or false/);
  } finally { f.cleanup(); }
});
