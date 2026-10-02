import test from 'node:test';
import assert from 'node:assert/strict';
import { applyNoProgress, planNoProgress } from '../lib/escalation.mjs';
import { advanceTicket, claimTicket, createTicket } from '../lib/tickets.mjs';
import { getEntity, readRecentEvents } from '../lib/store.mjs';
import { makeFactory, ticketInput } from './helpers.mjs';

const sonnet = { name: 'backend-engineer', model: 'sonnet', effort: 'high' };
const opus = { name: 'factory-director', model: 'opus', effort: 'high' };
const principal = { name: 'principal-engineer', model: 'opus', effort: 'high' };
const base = { stage_role: 'backend-engineer', attempts: 0, escalations: 0, effort_override: null };
let config;
const setup = () => {
  const f = makeFactory();
  config = f.ctx.config; // max_retries 2, escalation role principal-engineer
  return f;
};

test('the ladder: retry, raise effort, reassign to the escalation role, block', () => {
  const f = setup();
  try {
    assert.deepEqual(planNoProgress({ ...base, attempts: 0 }, sonnet, config), { action: 'retry', attempts: 1 });
    assert.deepEqual(planNoProgress({ ...base, attempts: 1 }, sonnet, config), { action: 'raise_effort', effort: 'xhigh' });
    assert.deepEqual(planNoProgress({ ...base, attempts: 1, escalations: 1, effort_override: 'xhigh' }, sonnet, config), { action: 'reassign', role: 'principal-engineer' });
    assert.deepEqual(planNoProgress({ ...base, stage_role: 'principal-engineer', attempts: 1, escalations: 2 }, principal, config), { action: 'block' });
  } finally { f.cleanup(); }
});

test('opus climbs medium → high → xhigh, then reassigns', () => {
  const f = setup();
  try {
    const t = { ...base, stage_role: 'factory-director', attempts: 1 };
    assert.deepEqual(planNoProgress(t, { ...opus, effort: 'medium' }, config), { action: 'raise_effort', effort: 'high' });
    assert.deepEqual(planNoProgress(t, opus, config), { action: 'raise_effort', effort: 'xhigh' });
    assert.deepEqual(planNoProgress({ ...t, effort_override: 'xhigh' }, opus, config), { action: 'reassign', role: 'principal-engineer' });
  } finally { f.cleanup(); }
});

test('with no effort rung left the ladder goes straight to reassignment', () => {
  const f = setup();
  try {
    const top = { ...sonnet, effort: 'xhigh' };
    assert.deepEqual(planNoProgress({ ...base, attempts: 1 }, top, config), { action: 'reassign', role: 'principal-engineer' });
  } finally { f.cleanup(); }
});

test('without an escalation role the ladder ends in block', () => {
  const f = setup();
  try {
    const none = { ...config, models: { ...config.models, escalation_roles: [] } };
    assert.deepEqual(planNoProgress({ ...base, attempts: 1, escalations: 1 }, sonnet, none), { action: 'block' });
  } finally { f.cleanup(); }
});

test('max_retries comes from config', () => {
  const f = setup();
  try {
    const four = { ...config, dispatcher: { ...config.dispatcher, max_retries: 4 } };
    assert.equal(planNoProgress({ ...base, attempts: 2 }, sonnet, four).action, 'retry');
    assert.equal(planNoProgress({ ...base, attempts: 3 }, sonnet, four).action, 'raise_effort');
  } finally { f.cleanup(); }
});

test('applyNoProgress walks a real ticket up the ladder, logging every escalation', () => {
  const f = makeFactory();
  try {
    const t = createTicket(f.ctx, ticketInput({ status: 'ready' }), 'x');
    claimTicket(f.ctx, t.id);
    const agentFor = (ticket) => (ticket.stage_role === 'principal-engineer' ? principal : sonnet);
    const step = () => applyNoProgress(f.ctx, t.id, agentFor(getEntity(f.ctx, 'tickets', t.id)), 'R-1');
    assert.equal(step().action, 'retry');
    let ticket = getEntity(f.ctx, 'tickets', t.id);
    assert.equal(ticket.attempts, 1);

    assert.equal(step().action, 'raise_effort');
    ticket = getEntity(f.ctx, 'tickets', t.id);
    assert.deepEqual([ticket.effort_override, ticket.attempts, ticket.escalations], ['xhigh', 0, 1]);

    assert.equal(step().action, 'retry');
    assert.equal(step().action, 'reassign');
    ticket = getEntity(f.ctx, 'tickets', t.id);
    assert.deepEqual([ticket.stage_role, ticket.reassigned_from, ticket.effort_override, ticket.escalations], ['principal-engineer', 'backend-engineer', null, 2]);

    assert.equal(step().action, 'retry');
    assert.equal(step().action, 'block');
    ticket = getEntity(f.ctx, 'tickets', t.id);
    assert.equal(ticket.status, 'blocked');
    assert.deepEqual(ticket.blocked_from, { status: 'in_progress', stage_role: 'backend-engineer' });

    const texts = readRecentEvents(f.ctx, 50).map((e) => e.text).join('\n');
    assert.match(texts, /escalated, effort raised to xhigh/);
    assert.match(texts, /escalated, stage reassigned to principal-engineer/);
    assert.match(texts, /blocked after exhausting the escalation ladder/);
  } finally { f.cleanup(); }
});

test('an advance resets the escalation state', () => {
  const f = makeFactory();
  try {
    const t = createTicket(f.ctx, ticketInput({ status: 'ready' }), 'x');
    claimTicket(f.ctx, t.id);
    applyNoProgress(f.ctx, t.id, sonnet, 'R-1');
    applyNoProgress(f.ctx, t.id, sonnet, 'R-2');
    assert.equal(getEntity(f.ctx, 'tickets', t.id).effort_override, 'xhigh');
    const out = advanceTicket(f.ctx, t.id, 'w', 'done');
    assert.deepEqual([out.effort_override, out.attempts, out.escalations], [null, 0, 0]);
  } finally { f.cleanup(); }
});
