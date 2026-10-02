import test from 'node:test';
import assert from 'node:assert/strict';
import { launchGate, metaProposals, selectCandidates } from '../lib/candidates.mjs';
import { localDate } from '../lib/store.mjs';
import { REAL_FACTORY } from './helpers.mjs';
import fs from 'node:fs';
import path from 'node:path';

// The real config, with the dispatcher tuning these tests are written against pinned, so raising
// slots or the grooming floor in production does not break the selection-mechanism tests.
const config = JSON.parse(fs.readFileSync(path.join(REAL_FACTORY, 'config.json'), 'utf8'));
Object.assign(config.dispatcher, { max_parallel: 2, grooming_min_ready: 3 });
const NOW = new Date(2026, 9, 2, 10, 0, 0); // local 10:00: before the digest hour
const EVENING = new Date(2026, 9, 2, 19, 0, 0);

let seq = 0;
function ticket(o = {}) {
  seq += 1;
  const id = o.id ?? `T-${String(seq).padStart(4, '0')}`;
  return {
    id, title: `ticket ${id}`, type: 'build', status: 'ready', priority: 'P2', owner: 'backend-engineer', stage_role: null,
    depends_on: [], decisions: [], tags: [], handoff: { pending: false, latest: null },
    created: new Date(2026, 9, 1, 9, 0, seq).toISOString(), ...o,
  };
}
const state = (o = {}) => ({
  tickets: [], decisions: [], feedback: [], runs: [], control: { paused: false },
  dispatcher: { backoff_until: null, runs_today: { date: null, count: 0 } }, sharedCheckout: false, skip: new Set(), ...o,
});
const run = (t, status = 'running') => ({ id: `R-${t}`, ticket: t, status });
const ids = (picks) => picks.map((c) => c.ticket?.id ?? `meta:${c.create.kind}`);
// Three ready tickets keep the grooming meta quiet; tests that want it pass fewer.
const filler = () => ['T-9001', 'T-9002', 'T-9003'].map((id) => ticket({ id, priority: 'P3', type: 'docs', owner: 'docs-writer' }));
const pick = (s, now = NOW, c = config) => selectCandidates(s, now, c);

test('ready tickets sort by priority, then age, then id', () => {
  const t = [
    ticket({ id: 'T-0010', priority: 'P2', created: '2026-10-01T09:00:00Z' }),
    ticket({ id: 'T-0011', priority: 'P0', created: '2026-10-01T10:00:00Z' }),
    ticket({ id: 'T-0012', priority: 'P2', created: '2026-10-01T08:00:00Z' }),
    ticket({ id: 'T-0013', priority: 'P1', created: '2026-10-01T07:00:00Z' }),
  ];
  const big = { ...config, dispatcher: { ...config.dispatcher, max_parallel: 4 } };
  assert.deepEqual(ids(pick(state({ tickets: [...t, ...filler()] }), NOW, big)), ['T-0011', 'T-0013', 'T-0012', 'T-0010']);
});

test('free slots = max_parallel − running; nothing launches with no free slot', () => {
  const t = [ticket({ id: 'T-0001' }), ticket({ id: 'T-0002' }), ticket({ id: 'T-0003' }), ...filler()];
  assert.equal(pick(state({ tickets: t })).length, 2);
  assert.equal(pick(state({ tickets: t, runs: [run('T-0099')] })).length, 1);
  assert.deepEqual(pick(state({ tickets: t, runs: [run('T-0098'), run('T-0099')] })), []);
  assert.equal(pick(state({ tickets: t, runs: [run('T-0098', 'done'), run('T-0099', 'failed')] })).length, 2, 'finished runs do not occupy slots');
});

test('review and qa come before ready work, review before qa', () => {
  const t = [
    ticket({ id: 'T-0001', status: 'ready', priority: 'P0' }),
    ticket({ id: 'T-0002', status: 'qa', priority: 'P3', stage_role: 'qa-verifier' }),
    ticket({ id: 'T-0003', status: 'review', priority: 'P3', stage_role: 'code-reviewer' }),
    ...filler(),
  ];
  const picks = pick(state({ tickets: t }));
  assert.deepEqual(ids(picks), ['T-0003', 'T-0002']);
  assert.deepEqual(picks.map((c) => [c.kind, c.role, c.stage]), [['review', 'code-reviewer', 'review'], ['qa', 'qa-verifier', 'qa']]);
});

test('a second reviewer is launched as the ticket\'s stage role', () => {
  const t = ticket({ status: 'review', stage_role: 'security-architect', tags: ['security-sensitive'] });
  assert.equal(pick(state({ tickets: [t, ...filler()] }))[0].role, 'security-architect');
});

test('tickets with a running session are never launched twice', () => {
  const t = [ticket({ id: 'T-0001', status: 'review', stage_role: 'code-reviewer' }), ticket({ id: 'T-0002', status: 'in_progress', stage_role: 'backend-engineer' }), ...filler()];
  assert.deepEqual(ids(pick(state({ tickets: t, runs: [run('T-0001')] }))), ['T-0002']);
});

test('in_progress tickets without a session are resumed, handoff continuations first', () => {
  const t = [
    ticket({ id: 'T-0001', status: 'in_progress', priority: 'P0', stage_role: 'backend-engineer' }),
    ticket({ id: 'T-0002', status: 'in_progress', priority: 'P3', stage_role: 'backend-engineer', handoff: { pending: true, latest: '/h.md' } }),
    ...filler(),
  ];
  const picks = pick(state({ tickets: t }));
  assert.deepEqual(ids(picks), ['T-0002', 'T-0001']);
  assert.deepEqual(picks.map((c) => [c.kind, c.continuation]), [['continuation', true], ['resume', false]]);
});

test('ready tickets wait for dependencies to be done', () => {
  const t = [
    ticket({ id: 'T-0001', status: 'in_progress', stage_role: 'backend-engineer' }),
    ticket({ id: 'T-0002', depends_on: ['T-0001'] }),
    ticket({ id: 'T-0003', status: 'done' }),
    ticket({ id: 'T-0004', depends_on: ['T-0003'] }),
    ticket({ id: 'T-0005', depends_on: ['T-9999'] }),
    ...filler(),
  ];
  const big = { ...config, dispatcher: { ...config.dispatcher, max_parallel: 10 } };
  const launched = ids(pick(state({ tickets: t, runs: [run('T-0001')] }), NOW, big));
  assert.ok(launched.includes('T-0004'));
  assert.ok(!launched.includes('T-0002'), 'dependency still in progress');
  assert.ok(!launched.includes('T-0005'), 'dangling dependency never satisfies');
});

test('ready tickets wait for their decisions to be answered', () => {
  const t = [ticket({ id: 'T-0001', decisions: ['D-0001'] }), ticket({ id: 'T-0002', decisions: ['D-0002'] }), ticket({ id: 'T-0003', decisions: ['D-0003'] }), ...filler()];
  const decisions = [{ id: 'D-0001', status: 'pending' }, { id: 'D-0002', status: 'answered' }, { id: 'D-0003', status: 'defaulted' }];
  const big = { ...config, dispatcher: { ...config.dispatcher, max_parallel: 10 } };
  const launched = ids(pick(state({ tickets: t, decisions }), NOW, big));
  assert.ok(!launched.includes('T-0001'));
  assert.ok(launched.includes('T-0002') && launched.includes('T-0003'));
});

test('the launch gate: paused, backing off, daily cap', () => {
  const t = [ticket(), ...filler()];
  assert.equal(launchGate(state({ tickets: t }), NOW, config), null);
  assert.equal(launchGate(state({ control: { paused: true } }), NOW, config), 'paused');
  const later = new Date(NOW.getTime() + 600_000).toISOString();
  assert.match(launchGate(state({ dispatcher: { backoff_until: later } }), NOW, config), /backing off until/);
  assert.equal(launchGate(state({ dispatcher: { backoff_until: new Date(NOW.getTime() - 1000).toISOString() } }), NOW, config), null);
  const cap = config.dispatcher.daily_run_cap;
  assert.match(launchGate(state({ dispatcher: { runs_today: { date: localDate(NOW), count: cap } } }), NOW, config), /daily run cap reached/);
  assert.equal(launchGate(state({ dispatcher: { runs_today: { date: '2020-01-01', count: cap + 5 } } }), NOW, config), null, 'the cap resets with the local date');
  for (const s of [{ control: { paused: true } }, { dispatcher: { backoff_until: later } }]) assert.deepEqual(pick(state({ tickets: t, ...s })), []);
});

test('the skip set removes candidates for this round', () => {
  const t = [ticket({ id: 'T-0001', priority: 'P0' }), ticket({ id: 'T-0002', priority: 'P1' }), ...filler()];
  assert.deepEqual(ids(pick(state({ tickets: t, skip: new Set(['T-0001']) }))), ['T-0002', 'T-9001']);
});

test('shared-checkout mode launches one code ticket at a time but still allows other work', () => {
  const t = [
    ticket({ id: 'T-0001', type: 'build' }), ticket({ id: 'T-0002', type: 'bug' }),
    ticket({ id: 'T-0003', type: 'docs', owner: 'docs-writer' }), ...filler(),
  ];
  const big = { ...config, dispatcher: { ...config.dispatcher, max_parallel: 3 } };
  assert.deepEqual(ids(pick(state({ tickets: t, sharedCheckout: true }), NOW, big)), ['T-0001', 'T-0003', 'T-9001']);
  assert.deepEqual(ids(pick(state({ tickets: t, sharedCheckout: false }), NOW, big)), ['T-0001', 'T-0002', 'T-0003']);
});

test('shared-checkout mode counts a running code ticket against the one-code-ticket rule', () => {
  const t = [
    ticket({ id: 'T-0001', type: 'build', status: 'in_progress', stage_role: 'backend-engineer' }),
    ticket({ id: 'T-0002', type: 'build' }), ticket({ id: 'T-0003', type: 'docs', owner: 'docs-writer' }), ...filler(),
  ];
  const big = { ...config, dispatcher: { ...config.dispatcher, max_parallel: 3 } };
  assert.deepEqual(ids(pick(state({ tickets: t, runs: [run('T-0001')], sharedCheckout: true }), NOW, big)), ['T-0003', 'T-9001']);
});

// ---- meta tickets --------------------------------------------------------------------------

const metaTicket = (kind, o = {}) => ticket({ type: 'meta', status: 'ready', owner: 'project-manager', tags: [kind], created: NOW.toISOString(), ...o });

test('triage is proposed when there are answers, new feedback, or un-triaged blocked tickets', () => {
  const none = metaProposals(state({ tickets: filler() }), NOW, config);
  assert.deepEqual(none.map((p) => p.kind), []);

  const withAnswer = metaProposals(state({ tickets: filler(), decisions: [{ id: 'D-0001', status: 'answered', applied: false }] }), NOW, config);
  assert.deepEqual(withAnswer.map((p) => [p.kind, p.owner, p.priority]), [['triage', 'factory-director', 'P0']]);
  assert.equal(withAnswer[0].title, 'Triage: 1 answers · 0 feedback · 0 blocked');
  assert.deepEqual(withAnswer[0].meta, { kind: 'triage', decisions: ['D-0001'], feedback: [], blocked: [] });

  const defaulted = metaProposals(state({ tickets: filler(), decisions: [{ id: 'D-0002', status: 'defaulted', applied: false }] }), NOW, config);
  assert.deepEqual(defaulted[0].meta.decisions, ['D-0002']);

  const applied = metaProposals(state({ tickets: filler(), decisions: [{ id: 'D-0003', status: 'answered', applied: true }, { id: 'D-0004', status: 'pending' }] }), NOW, config);
  assert.deepEqual(applied, []);

  const fb = metaProposals(state({ tickets: filler(), feedback: [{ id: 'F-0001', status: 'new' }, { id: 'F-0002', status: 'triaged' }] }), NOW, config);
  assert.deepEqual(fb[0].meta.feedback, ['F-0001']);

  const blocked = metaProposals(state({ tickets: [...filler(), ticket({ id: 'T-0050', status: 'blocked' })] }), NOW, config);
  assert.deepEqual(blocked[0].meta.blocked, ['T-0050']);
});

test('a blocked ticket is re-triaged only after blocked_retriage_hours', () => {
  const recent = ticket({ id: 'T-0050', status: 'blocked', triaged_at: new Date(NOW.getTime() - 3 * 3_600_000).toISOString() });
  const stale = ticket({ id: 'T-0051', status: 'blocked', triaged_at: new Date(NOW.getTime() - 7 * 3_600_000).toISOString() });
  assert.deepEqual(metaProposals(state({ tickets: [...filler(), recent] }), NOW, config), []);
  assert.deepEqual(metaProposals(state({ tickets: [...filler(), recent, stale] }), NOW, config)[0].meta.blocked, ['T-0051']);
});

test('never more than one open triage; cooldown after the last one', () => {
  const s = { decisions: [{ id: 'D-0001', status: 'answered', applied: false }] };
  const open = metaTicket('triage', { owner: 'factory-director', status: 'in_progress', created: '2026-09-01T00:00:00Z' });
  assert.deepEqual(metaProposals(state({ tickets: [...filler(), open], ...s }), NOW, config), []);
  const justDone = metaTicket('triage', { status: 'done', created: new Date(NOW.getTime() - 5 * 60_000).toISOString() });
  assert.deepEqual(metaProposals(state({ tickets: [...filler(), justDone], ...s }), NOW, config), [], 'within triage_cooldown_minutes');
  const oldDone = metaTicket('triage', { status: 'done', created: new Date(NOW.getTime() - 15 * 60_000).toISOString() });
  assert.deepEqual(metaProposals(state({ tickets: [...filler(), oldDone], ...s }), NOW, config).map((p) => p.kind), ['triage']);
});

test('a blocked triage ticket is not itself triaged', () => {
  const stuck = metaTicket('triage', { status: 'blocked', created: '2026-09-01T00:00:00Z' });
  assert.deepEqual(metaProposals(state({ tickets: [...filler(), stuck] }), NOW, config), []);
});

test('grooming is proposed when fewer than grooming_min_ready are ready and the backlog is not empty', () => {
  const backlog = ticket({ id: 'T-0070', status: 'backlog' });
  const few = metaProposals(state({ tickets: [ticket({ id: 'T-0001' }), backlog] }), NOW, config);
  assert.deepEqual(few.map((p) => [p.kind, p.owner, p.priority]), [['grooming', 'project-manager', 'P1']]);
  assert.deepEqual(few[0].meta, { kind: 'grooming', ready: 1, min_ready: 3, backlog: ['T-0070'] });
  assert.deepEqual(metaProposals(state({ tickets: [...filler(), backlog] }), NOW, config), [], 'enough ready');
  assert.deepEqual(metaProposals(state({ tickets: [ticket({ id: 'T-0001' })] }), NOW, config), [], 'nothing to groom');
  const open = metaTicket('grooming', { created: '2020-01-01T00:00:00Z' });
  assert.deepEqual(metaProposals(state({ tickets: [backlog, open] }), NOW, config), [], 'one open grooming at a time');
  const recent = metaTicket('grooming', { status: 'done', created: new Date(NOW.getTime() - 30 * 60_000).toISOString() });
  assert.deepEqual(metaProposals(state({ tickets: [backlog, recent] }), NOW, config), [], 'cooldown 60 min');
  const older = metaTicket('grooming', { status: 'done', created: new Date(NOW.getTime() - 90 * 60_000).toISOString() });
  assert.equal(metaProposals(state({ tickets: [backlog, older] }), NOW, config).length, 1);
});

test('the digest is proposed once per local day, after digest_hour_local', () => {
  const quiet = filler();
  assert.deepEqual(metaProposals(state({ tickets: quiet }), NOW, config), [], 'before 18:00');
  const evening = metaProposals(state({ tickets: quiet }), EVENING, config);
  assert.deepEqual(evening.map((p) => [p.kind, p.owner, p.priority]), [['digest', 'project-manager', 'P1']]);
  assert.equal(evening[0].title, `Digest: ${localDate(EVENING)}`);
  assert.equal(evening[0].meta.date, localDate(EVENING));
  const today = metaTicket('digest', { status: 'done', created: new Date(2026, 9, 2, 18, 5).toISOString() });
  assert.deepEqual(metaProposals(state({ tickets: [...quiet, today] }), EVENING, config), [], 'already written today');
  const yesterday = metaTicket('digest', { status: 'done', created: new Date(2026, 9, 1, 18, 5).toISOString() });
  assert.equal(metaProposals(state({ tickets: [...quiet, yesterday] }), EVENING, config).length, 1);
  const open = metaTicket('digest', { created: new Date(2026, 9, 1, 18, 5).toISOString() });
  assert.deepEqual(metaProposals(state({ tickets: [...quiet, open] }), EVENING, config), [], 'one open digest at a time');
});

test('meta work competes in the ready pool by priority: triage (P0) ties with P0 work and beats P1', () => {
  const s = state({
    tickets: [ticket({ id: 'T-0001', priority: 'P1' }), ticket({ id: 'T-0002', priority: 'P0' }), ...filler()],
    decisions: [{ id: 'D-0001', status: 'answered', applied: false }],
  });
  assert.deepEqual(ids(pick(s)), ['T-0002', 'meta:triage'], 'equal priority: the older real ticket first');
  const p1Only = state({ ...s, tickets: [ticket({ id: 'T-0001', priority: 'P1' }), ...filler()] });
  assert.deepEqual(ids(pick(p1Only)), ['meta:triage', 'T-0001']);
});

test('a meta candidate carries what the dispatcher needs to create it', () => {
  const s = state({ tickets: filler(), decisions: [{ id: 'D-0001', status: 'answered', applied: false }] });
  const [c] = pick(s);
  assert.equal(c.kind, 'meta');
  assert.equal(c.ticket, null);
  assert.deepEqual([c.role, c.stage, c.create.kind], ['factory-director', 'in_progress', 'triage']);
  assert.deepEqual(pick({ ...s, skip: new Set(['meta:triage']) }).map((x) => x.kind), ['ready', 'ready']);
});

test('real work is not starved by auto-created grooming and digest', () => {
  const t = [ticket({ id: 'T-0001', priority: 'P0' }), ticket({ id: 'T-0070', status: 'backlog' })];
  const wide = { ...config, dispatcher: { ...config.dispatcher, max_parallel: 3 } };
  assert.deepEqual(ids(pick(state({ tickets: t }), EVENING, wide)), ['T-0001', 'meta:digest', 'meta:grooming']);
});
