import test from 'node:test';
import assert from 'node:assert/strict';
import { getEntity, listEntities } from '../lib/store.mjs';
import { createTicket } from '../lib/tickets.mjs';
import {
  acknowledgeNotice, answerDecision, applyAdvisoryDefaults, createDecision, markApplied, openCeoDecisions,
  parseDuration, parseOptionSpec, vetoNotice, withdrawDecision,
} from '../lib/decisions.mjs';
import { makeFactory, ticketInput } from './helpers.mjs';

const OPTS = [{ id: 'a', label: 'A', summary: '' }, { id: 'b', label: 'B', summary: '' }];
const dir = (o = {}) => ({ kind: 'directional', title: 'Which stack?', question: 'Pick one', options: OPTS, ...o });

test('option specs and durations parse', () => {
  assert.deepEqual(parseOptionSpec('a|Alpha|first one'), { id: 'a', label: 'Alpha', summary: 'first one', pros: [], cons: [], preview: null });
  assert.equal(parseOptionSpec('a|Alpha|s|<b>x</b>').preview, '<b>x</b>');
  assert.throws(() => parseOptionSpec('only-id'), /bad option/);
  assert.deepEqual(['72h', '3d', '90m', '1.5h'].map(parseDuration), [72, 72, 1.5, 1.5]);
  assert.throws(() => parseDuration('soon'), /bad duration/);
});

test('a directional decision needs 2–4 options with valid unique ids', () => {
  const f = makeFactory();
  try {
    assert.throws(() => createDecision(f.ctx, dir({ options: [OPTS[0]] })), /2–4 options/);
    const five = Array.from({ length: 5 }, (_, i) => ({ id: `o${i}`, label: 'x' }));
    assert.throws(() => createDecision(f.ctx, dir({ options: five })), /2–4 options/);
    assert.throws(() => createDecision(f.ctx, dir({ options: [OPTS[0], { ...OPTS[0] }] })), /unique/);
    assert.throws(() => createDecision(f.ctx, dir({ options: [{ id: 'a b', label: 'x' }, OPTS[1]] })), /option ids/);
    assert.throws(() => createDecision(f.ctx, dir({ recommendation: 'zzz' })), /recommendation/);
    assert.throws(() => createDecision(f.ctx, dir({ default_option: 'a' })), /only advisory/);
    assert.throws(() => createDecision(f.ctx, dir({ kind: 'weird' })), /kind must be/);
    assert.equal(createDecision(f.ctx, dir({ recommendation: 'a' })).id, 'D-0001');
  } finally { f.cleanup(); }
});

test('at most ceo.max_open_decisions are open; --force overrides; notices do not count', () => {
  const f = makeFactory();
  try {
    for (let i = 0; i < 3; i++) createDecision(f.ctx, dir({ title: `q${i}` }));
    assert.throws(() => createDecision(f.ctx, dir({ title: 'q4' })), /3 CEO decisions are already open.*D-0001/);
    assert.throws(() => createDecision(f.ctx, { ...dir({ kind: 'advisory', default_option: 'a' }), title: 'adv' }), /already open/);
    createDecision(f.ctx, { kind: 'notice', title: 'FYI', question: 'We chose X', options: [] });
    assert.equal(createDecision(f.ctx, dir({ title: 'urgent' }), { force: true }).id, 'D-0005');
    assert.equal(openCeoDecisions(listEntities(f.ctx, 'decisions')).length, 4);
    answerDecision(f.ctx, 'D-0001', { options: ['a'] });
    assert.equal(openCeoDecisions(listEntities(f.ctx, 'decisions')).length, 3);
  } finally { f.cleanup(); }
});

test('the limit follows config', () => {
  const f = makeFactory({ config: (c) => { c.ceo.max_open_decisions = 1; } });
  try {
    createDecision(f.ctx, dir());
    assert.throws(() => createDecision(f.ctx, dir()), /limit 1/);
  } finally { f.cleanup(); }
});

test('an advisory decision gets a default from --default or the recommendation, at +72 h unless told otherwise', () => {
  const f = makeFactory();
  try {
    const a = createDecision(f.ctx, dir({ kind: 'advisory', recommendation: 'b' }));
    assert.equal(a.default_option, 'b');
    assert.equal(a.default_at, new Date(f.clock.ms + 72 * 3_600_000).toISOString());
    const b = createDecision(f.ctx, dir({ kind: 'advisory', default_option: 'a', default_in_hours: 24 }));
    assert.equal(b.default_at, new Date(f.clock.ms + 24 * 3_600_000).toISOString());
    assert.throws(() => createDecision(f.ctx, dir({ kind: 'advisory' })), /needs --default/);
    assert.throws(() => createDecision(f.ctx, dir({ kind: 'advisory', default_option: 'zzz' })), /default "zzz"/);
  } finally { f.cleanup(); }
});

test('the advisory window comes from config.ceo.advisory_default_hours', () => {
  const f = makeFactory({ config: (c) => { c.ceo.advisory_default_hours = 5; } });
  try {
    const d = createDecision(f.ctx, dir({ kind: 'advisory', recommendation: 'a' }));
    assert.equal(d.default_at, new Date(f.clock.ms + 5 * 3_600_000).toISOString());
  } finally { f.cleanup(); }
});

test('applyAdvisoryDefaults defaults only due, pending advisory decisions', () => {
  const f = makeFactory();
  try {
    createDecision(f.ctx, dir({ kind: 'advisory', default_option: 'a', default_in_hours: 10 }));
    createDecision(f.ctx, dir({ kind: 'advisory', default_option: 'b', default_in_hours: 48 }));
    createDecision(f.ctx, dir({}));
    assert.deepEqual(applyAdvisoryDefaults(f.ctx), []);
    f.clock.advance(11 * 3_600_000);
    assert.deepEqual(applyAdvisoryDefaults(f.ctx), ['D-0001']);
    const d = getEntity(f.ctx, 'decisions', 'D-0001');
    assert.deepEqual([d.status, d.answer.options, d.answer.via, d.applied], ['defaulted', ['a'], 'default', false]);
    assert.deepEqual(applyAdvisoryDefaults(f.ctx), [], 'idempotent');
    f.clock.advance(48 * 3_600_000);
    assert.deepEqual(applyAdvisoryDefaults(f.ctx), ['D-0002']);
    assert.equal(getEntity(f.ctx, 'decisions', 'D-0003').status, 'pending', 'directional decisions never default');
  } finally { f.cleanup(); }
});

test('an answer is validated against the options and the multi flag', () => {
  const f = makeFactory();
  try {
    const single = createDecision(f.ctx, dir());
    const multi = createDecision(f.ctx, dir({ multi: true }));
    assert.throws(() => answerDecision(f.ctx, single.id, { options: [] }), /at least one/);
    assert.throws(() => answerDecision(f.ctx, single.id, { options: ['zzz'] }), /unknown option zzz/);
    assert.throws(() => answerDecision(f.ctx, single.id, { options: ['a', 'b'] }), /single option/);
    const ok = answerDecision(f.ctx, multi.id, { options: ['a', 'b', 'a'], note: 'both', via: 'board' });
    assert.deepEqual([ok.status, ok.answer.options, ok.answer.note, ok.answer.via, ok.applied], ['answered', ['a', 'b'], 'both', 'board', false]);
    assert.throws(() => answerDecision(f.ctx, multi.id, { options: ['a'] }), /already answered/);
    assert.equal(getEntity(f.ctx, 'decisions', single.id).status, 'pending', 'rejected answers change nothing');
  } finally { f.cleanup(); }
});

test('blocks attaches the decision to the ticket; unknown tickets are refused', () => {
  const f = makeFactory();
  try {
    const t = createTicket(f.ctx, ticketInput({ status: 'ready' }), 'x');
    const d = createDecision(f.ctx, dir({ blocks: [t.id] }));
    assert.deepEqual(getEntity(f.ctx, 'tickets', t.id).decisions, [d.id]);
    assert.throws(() => createDecision(f.ctx, dir({ blocks: ['T-9999'] })), /ticket/);
    assert.equal(listEntities(f.ctx, 'decisions').length, 1);
  } finally { f.cleanup(); }
});

test('markApplied and withdraw respect the decision state', () => {
  const f = makeFactory();
  try {
    const d = createDecision(f.ctx, dir());
    assert.throws(() => markApplied(f.ctx, d.id, 'fd'), /only answered or defaulted/);
    answerDecision(f.ctx, d.id, { options: ['a'] });
    assert.equal(markApplied(f.ctx, d.id, 'fd').applied, true);
    assert.throws(() => withdrawDecision(f.ctx, d.id, 'fd', 'no'), /already answered/);
    const e = createDecision(f.ctx, dir());
    assert.throws(() => withdrawDecision(f.ctx, e.id, 'fd', ''), /--note/);
    assert.equal(withdrawDecision(f.ctx, e.id, 'fd', 'moot').status, 'withdrawn');
  } finally { f.cleanup(); }
});

test('notices are acknowledged or vetoed; a veto files feedback; they cannot be answered', () => {
  const f = makeFactory();
  try {
    const n1 = createDecision(f.ctx, { kind: 'notice', title: 'Chose Postgres', question: 'We chose Postgres', options: [] });
    const n2 = createDecision(f.ctx, { kind: 'notice', title: 'Chose Redis', question: 'We chose Redis', options: [] });
    assert.throws(() => answerDecision(f.ctx, n1.id, { options: ['a'] }), /notice/);
    assert.equal(acknowledgeNotice(f.ctx, n1.id).status, 'acknowledged');
    assert.throws(() => acknowledgeNotice(f.ctx, n1.id), /already/);
    const vetoed = vetoNotice(f.ctx, n2.id, { note: 'no Redis' });
    assert.deepEqual([vetoed.status, vetoed.applied], ['vetoed', true]);
    const feedback = listEntities(f.ctx, 'feedback');
    assert.equal(feedback.length, 1);
    assert.deepEqual([feedback[0].target, feedback[0].text, feedback[0].status], [`decision:${n2.id}`, 'no Redis', 'new']);
    const real = createDecision(f.ctx, dir());
    assert.throws(() => acknowledgeNotice(f.ctx, real.id), /answer it instead/);
  } finally { f.cleanup(); }
});
