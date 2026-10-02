import test from 'node:test';
import assert from 'node:assert/strict';
import { getEntity, listEntities, readRecentEvents } from '../lib/store.mjs';
import {
  addNote, advanceTicket, blockTicket, cancelTicket, claimBlockers, claimTicket, createTicket, indexById, markReady,
  readinessProblems, reopenTicket, rejectTicket, setTicketFields, summarizeTicket, unblockTicket,
} from '../lib/tickets.mjs';
import { createDecision, answerDecision } from '../lib/decisions.mjs';
import { createEpic, createMilestone } from '../lib/items.mjs';
import { makeFactory, ticketInput } from './helpers.mjs';

function setup() {
  const f = makeFactory();
  return { ...f, make: (o) => createTicket(f.ctx, ticketInput(o), 'tester') };
}

test('createTicket stores a backlog ticket with history and an event', () => {
  const f = setup();
  try {
    const t = f.make({ title: '  LDAP builder  ' });
    assert.equal(t.id, 'T-0001');
    assert.equal(t.title, 'LDAP builder');
    assert.equal(t.status, 'backlog');
    assert.deepEqual(t.history.map((h) => [h.by, h.to, h.note]), [['tester', 'backlog', 'created']]);
    assert.deepEqual(getEntity(f.ctx, 'tickets', 'T-0001'), t);
    assert.match(readRecentEvents(f.ctx, 1)[0].text, /created T-0001/);
  } finally { f.cleanup(); }
});

test('createTicket validates type, priority, owner, status and references', () => {
  const f = setup();
  try {
    assert.throws(() => f.make({ type: 'nope' }), /type must be/);
    assert.throws(() => f.make({ priority: 'P9' }), /priority must be/);
    assert.throws(() => f.make({ owner: '' }), /owner is required/);
    assert.throws(() => f.make({ title: ' ' }), /title is required/);
    assert.throws(() => f.make({ status: 'done' }), /starts as backlog or ready/);
    assert.throws(() => f.make({ depends_on: ['T-0042'] }), /dependency/);
    assert.throws(() => f.make({ decisions: ['D-0042'] }), /decision/);
    assert.throws(() => f.make({ epic: 'E-009' }), /epic/);
    assert.throws(() => f.make({ milestone: 'M9' }), /milestone/);
    assert.equal(listEntities(f.ctx, 'tickets').length, 0, 'nothing is half-created');
  } finally { f.cleanup(); }
});

test('Definition of Ready: title, owner, acceptance criterion, summary', () => {
  assert.deepEqual(readinessProblems({ title: 'x', owner: 'o', acceptance: ['a'], summary: 's' }), []);
  assert.deepEqual(readinessProblems({ title: '', owner: '', acceptance: [], summary: '' }),
    ['title', 'owner', 'at least one acceptance criterion', 'summary']);
  assert.deepEqual(readinessProblems({ title: 'x', owner: 'o', acceptance: ['  '], summary: 's' }), ['at least one acceptance criterion']);
});

test('a ticket cannot be created ready, or marked ready, without the Definition of Ready', () => {
  const f = setup();
  try {
    assert.throws(() => f.make({ status: 'ready', acceptance: [] }), /not ready: missing at least one acceptance/);
    const t = f.make({ summary: '', acceptance: [] });
    assert.throws(() => markReady(f.ctx, t.id, 'pm'), /missing at least one acceptance criterion, summary/);
    assert.equal(getEntity(f.ctx, 'tickets', t.id).status, 'backlog');
    f.make({ status: 'ready' });
    const ok = f.make({});
    assert.equal(markReady(f.ctx, ok.id, 'pm').status, 'ready');
    assert.throws(() => markReady(f.ctx, ok.id, 'pm'), /only backlog/);
  } finally { f.cleanup(); }
});

test('claimBlockers: unfinished dependencies and unresolved decisions', () => {
  const tickets = indexById([{ id: 'T-1', status: 'done' }, { id: 'T-2', status: 'review' }]);
  const decisions = indexById([{ id: 'D-1', status: 'answered' }, { id: 'D-2', status: 'pending' }, { id: 'D-3', status: 'defaulted' }]);
  assert.deepEqual(claimBlockers({ depends_on: ['T-1', 'T-2', 'T-3'], decisions: ['D-1', 'D-2', 'D-3', 'D-9'] }, tickets, decisions),
    { deps: ['T-2', 'T-3'], decisions: ['D-2', 'D-9'] });
  assert.deepEqual(claimBlockers({}, tickets, decisions), { deps: [], decisions: [] });
});

test('claim moves ready → in_progress with the owner, and refuses while blocked', () => {
  const f = setup();
  try {
    const dep = f.make({ status: 'ready' });
    const t = f.make({ status: 'ready', depends_on: [dep.id] });
    assert.throws(() => claimTicket(f.ctx, t.id), /waits for T-0001/);
    const claimed = claimTicket(f.ctx, dep.id);
    assert.equal(claimed.status, 'in_progress');
    assert.equal(claimed.stage_role, 'backend-engineer');
    assert.throws(() => claimTicket(f.ctx, dep.id), /not ready/);

    const d = createDecision(f.ctx, { kind: 'directional', title: 'q', question: 'q?', options: [{ id: 'a', label: 'A' }, { id: 'b', label: 'B' }], blocks: [t.id] });
    for (let i = 0; i < 3; i++) advanceTicket(f.ctx, dep.id, 'x', 'done');
    assert.equal(getEntity(f.ctx, 'tickets', dep.id).status, 'done');
    assert.throws(() => claimTicket(f.ctx, t.id), /waits for decision D-0001/);
    answerDecision(f.ctx, d.id, { options: ['a'] });
    assert.equal(claimTicket(f.ctx, t.id).status, 'in_progress');
  } finally { f.cleanup(); }
});

test('advance runs a build ticket to done, resets counters, and records history and notes', () => {
  const f = setup();
  try {
    const t = f.make({ status: 'ready' });
    claimTicket(f.ctx, t.id);
    const stages = [];
    for (const note of ['built it', 'reviewed ok', 'qa ok']) {
      const out = advanceTicket(f.ctx, t.id, 'worker', note);
      stages.push([out.status, out.stage_role]);
    }
    assert.deepEqual(stages, [['review', 'code-reviewer'], ['qa', 'qa-verifier'], ['done', null]]);
    const done = getEntity(f.ctx, 'tickets', t.id);
    assert.equal(done.result, 'qa ok');
    assert.equal(done.attempts, 0);
    assert.deepEqual(done.history.map((h) => h.to), ['ready', 'in_progress', 'review', 'qa', 'done']);
    assert.ok(done.notes.some((n) => n.text === 'advanced: built it'));
    assert.throws(() => advanceTicket(f.ctx, t.id, 'x', 'again'), /cannot advance/);
  } finally { f.cleanup(); }
});

test('advance requires --by and a note', () => {
  const f = setup();
  try {
    const t = f.make({ status: 'ready' });
    claimTicket(f.ctx, t.id);
    assert.throws(() => advanceTicket(f.ctx, t.id, '', 'n'), /--by is required/);
    assert.throws(() => advanceTicket(f.ctx, t.id, 'w', ' '), /--note is required/);
    assert.equal(getEntity(f.ctx, 'tickets', t.id).status, 'in_progress');
  } finally { f.cleanup(); }
});

test('reject sends review/qa back to the owner and clears escalation state', () => {
  const f = setup();
  try {
    const t = f.make({ status: 'ready' });
    claimTicket(f.ctx, t.id);
    assert.throws(() => rejectTicket(f.ctx, t.id, 'r', 'no'), /cannot reject/);
    advanceTicket(f.ctx, t.id, 'w', 'done');
    const out = rejectTicket(f.ctx, t.id, 'code-reviewer', 'missing tests');
    assert.deepEqual([out.status, out.stage_role, out.escalations, out.effort_override], ['in_progress', 'backend-engineer', 0, null]);
    assert.ok(out.notes.at(-1).text.startsWith('rejected: missing tests'));
  } finally { f.cleanup(); }
});

test('block remembers where the ticket was and unblock restores it with a fresh retry budget', () => {
  const f = setup();
  try {
    const t = f.make({ status: 'ready' });
    claimTicket(f.ctx, t.id);
    advanceTicket(f.ctx, t.id, 'w', 'done');
    const blocked = blockTicket(f.ctx, t.id, 'code-reviewer', 'waiting for the lab');
    assert.deepEqual([blocked.status, blocked.stage_role], ['blocked', null]);
    assert.throws(() => blockTicket(f.ctx, t.id, 'x', 'again'), /cannot be blocked/);
    const back = unblockTicket(f.ctx, t.id, 'director', 'lab is up');
    assert.deepEqual([back.status, back.stage_role, back.attempts], ['review', 'code-reviewer', 0]);
    assert.throws(() => unblockTicket(f.ctx, t.id, 'd', 'x'), /not blocked/);
  } finally { f.cleanup(); }
});

test('cancel works from live states only; reopen only from done', () => {
  const f = setup();
  try {
    const t = f.make({});
    assert.equal(cancelTicket(f.ctx, t.id, 'd', 'obsolete').status, 'cancelled');
    assert.throws(() => cancelTicket(f.ctx, t.id, 'd', 'again'), /already cancelled/);
    assert.throws(() => reopenTicket(f.ctx, t.id, 'd', 'x'), /not done/);
    const done = f.make({ type: 'meta', status: 'ready' });
    claimTicket(f.ctx, done.id);
    advanceTicket(f.ctx, done.id, 'w', 'finished');
    const reopened = reopenTicket(f.ctx, done.id, 'dispatcher', 'merge conflict');
    assert.deepEqual([reopened.status, reopened.stage_role, reopened.result], ['in_progress', 'backend-engineer', null]);
  } finally { f.cleanup(); }
});

test('setTicketFields edits allowed fields and refuses the rest', () => {
  const f = setup();
  try {
    const dep = f.make({});
    const t = f.make({});
    const epic = createEpic(f.ctx, { title: 'Epic' });
    const ms = createMilestone(f.ctx, { name: 'M one' });
    const out = setTicketFields(f.ctx, t.id, {
      priority: 'P0', owner: 'directory-engineer', epic: epic.id, milestone: ms.id, effort_override: 'xhigh', tags: 'a, b', depends_on: dep.id,
    }, 'pm');
    assert.deepEqual([out.priority, out.owner, out.epic, out.milestone, out.effort_override, out.tags, out.depends_on],
      ['P0', 'directory-engineer', epic.id, ms.id, 'xhigh', ['a', 'b'], [dep.id]]);
    const cleared = setTicketFields(f.ctx, t.id, { epic: 'null', effort_override: 'null', tags: 'null', depends_on: '' }, 'pm');
    assert.deepEqual([cleared.epic, cleared.effort_override, cleared.tags, cleared.depends_on], [null, null, [], []]);
    assert.throws(() => setTicketFields(f.ctx, t.id, { priority: 'P7' }, 'pm'), /priority/);
    assert.throws(() => setTicketFields(f.ctx, t.id, { effort_override: 'ultra' }, 'pm'), /effort_override/);
    assert.throws(() => setTicketFields(f.ctx, t.id, { depends_on: t.id }, 'pm'), /itself/);
    assert.throws(() => setTicketFields(f.ctx, t.id, { status: 'done' }, 'pm'), /cannot set "status"/);
    assert.throws(() => setTicketFields(f.ctx, t.id, { epic: 'E-404' }, 'pm'), /epic/);
  } finally { f.cleanup(); }
});

test('changing the owner of an in-progress ticket moves the working role too', () => {
  const f = setup();
  try {
    const t = f.make({ status: 'ready' });
    claimTicket(f.ctx, t.id);
    const out = setTicketFields(f.ctx, t.id, { owner: 'directory-engineer' }, 'pm');
    assert.equal(out.stage_role, 'directory-engineer');
  } finally { f.cleanup(); }
});

test('addNote appends and summarizeTicket truncates the last note', () => {
  const f = setup();
  try {
    const t = f.make({});
    addNote(f.ctx, t.id, 'w', 'x'.repeat(400));
    const summary = summarizeTicket(getEntity(f.ctx, 'tickets', t.id));
    assert.equal(summary.last_note.length, 280);
    assert.equal(summary.id, t.id);
    assert.equal(summary.notes, undefined);
    assert.throws(() => addNote(f.ctx, t.id, 'w', ''), /note text/);
  } finally { f.cleanup(); }
});
