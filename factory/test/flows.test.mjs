import test from 'node:test';
import assert from 'node:assert/strict';
import {
  TICKET_TYPES, currentRole, isCodeType, nextPosition, rejectPosition, resolveFlow, rolesForStage, validateFlows,
} from '../lib/flows.mjs';
import { REAL_FACTORY } from './helpers.mjs';
import fs from 'node:fs';
import path from 'node:path';

const config = JSON.parse(fs.readFileSync(path.join(REAL_FACTORY, 'config.json'), 'utf8'));
const ticket = (o) => ({ id: 'T-0001', type: 'build', owner: 'backend-engineer', tags: [], status: 'in_progress', stage_role: 'backend-engineer', ...o });

/** Walk a ticket through advance until done; returns the [status, role] visited. */
function walk(t) {
  const seen = [[t.status, t.stage_role]];
  for (let i = 0; i < 10 && t.status !== 'done'; i++) {
    t = { ...t, ...nextPosition(config, t) };
    seen.push([t.status, t.stage_role]);
  }
  return seen;
}

test('the shipped flows validate and every type resolves', () => {
  assert.deepEqual(validateFlows(config), []);
  for (const type of TICKET_TYPES) assert.ok(resolveFlow(config, type).length >= 2, type);
});

test('aliases resolve to their target flow', () => {
  assert.deepEqual(resolveFlow(config, 'bug'), resolveFlow(config, 'build'));
  assert.deepEqual(resolveFlow(config, 'chore'), resolveFlow(config, 'test'));
  assert.deepEqual(resolveFlow(config, 'proposal'), resolveFlow(config, 'research'));
});

test('an alias loop and a bad extra-reviewer spec are reported', () => {
  assert.throws(() => resolveFlow({ flows: { a: 'b', b: 'a' } }, 'a'), /loop/);
  assert.throws(() => resolveFlow({ flows: { a: [['in_progress', '$owner', 'security-architect']] } }, 'a'), /bad extra-reviewer/);
  assert.throws(() => resolveFlow({ flows: {} }, 'a'), /no flow/);
  assert.ok(validateFlows({ flows: { build: [['review', 'x']] } }).length > 0);
});

const EXPECTED = {
  build: [['in_progress', 'backend-engineer'], ['review', 'code-reviewer'], ['qa', 'qa-verifier'], ['done', null]],
  bug: [['in_progress', 'backend-engineer'], ['review', 'code-reviewer'], ['qa', 'qa-verifier'], ['done', null]],
  test: [['in_progress', 'backend-engineer'], ['review', 'code-reviewer'], ['done', null]],
  chore: [['in_progress', 'backend-engineer'], ['review', 'code-reviewer'], ['done', null]],
  ops: [['in_progress', 'backend-engineer'], ['review', 'code-reviewer'], ['done', null]],
  spec: [['in_progress', 'backend-engineer'], ['review', 'solution-architect'], ['done', null]],
  design: [['in_progress', 'backend-engineer'], ['review', 'product-manager'], ['done', null]],
  docs: [['in_progress', 'backend-engineer'], ['review', 'product-manager'], ['done', null]],
  video: [['in_progress', 'backend-engineer'], ['review', 'product-manager'], ['done', null]],
  research: [['in_progress', 'backend-engineer'], ['review', 'factory-director'], ['done', null]],
  proposal: [['in_progress', 'backend-engineer'], ['review', 'factory-director'], ['done', null]],
  'decision-prep': [['in_progress', 'backend-engineer'], ['review', 'factory-director'], ['done', null]],
  spike: [['in_progress', 'backend-engineer'], ['review', 'factory-director'], ['done', null]],
  meta: [['in_progress', 'backend-engineer'], ['done', null]],
};

for (const [type, expected] of Object.entries(EXPECTED)) {
  test(`advance walks the ${type} flow to done`, () => {
    assert.deepEqual(walk(ticket({ type })), expected);
  });
}

test('every ticket type is covered by the table above', () => {
  assert.deepEqual(Object.keys(EXPECTED).sort(), [...TICKET_TYPES].sort());
});

test('a security-sensitive build gets the security architect as a second reviewer', () => {
  assert.deepEqual(walk(ticket({ tags: ['security-sensitive'] })), [
    ['in_progress', 'backend-engineer'], ['review', 'code-reviewer'], ['review', 'security-architect'], ['qa', 'qa-verifier'], ['done', null],
  ]);
  const plain = walk(ticket({ tags: ['frontend'] }));
  assert.equal(plain.filter(([s]) => s === 'review').length, 1);
});

test('when the owner is the reviewer, factory-director reviews instead — and is not doubled', () => {
  const owner = ticket({ owner: 'code-reviewer', stage_role: 'code-reviewer' });
  assert.deepEqual(walk(owner)[1], ['review', 'factory-director']);
  const research = ticket({ type: 'research', owner: 'factory-director', stage_role: 'factory-director' });
  assert.deepEqual(walk(research), [['in_progress', 'factory-director'], ['review', 'factory-director'], ['done', null]]);
  const sec = ticket({ owner: 'security-architect', stage_role: 'security-architect', tags: ['security-sensitive'] });
  assert.deepEqual(walk(sec).filter(([s]) => s === 'review'), [['review', 'code-reviewer'], ['review', 'factory-director']]);
});

test('rolesForStage expands $owner only where the owner works the stage', () => {
  const stage = resolveFlow(config, 'build');
  const t = ticket({ tags: ['security-sensitive'] });
  assert.deepEqual(rolesForStage(t, stage[0]), ['backend-engineer']);
  assert.deepEqual(rolesForStage(t, stage[1]), ['code-reviewer', 'security-architect']);
  assert.deepEqual(rolesForStage(t, stage[3]), []);
});

test('currentRole: stage_role first, owner for ready, stage role otherwise', () => {
  assert.equal(currentRole(config, ticket({ status: 'ready', stage_role: null })), 'backend-engineer');
  assert.equal(currentRole(config, ticket({ status: 'review', stage_role: null })), 'code-reviewer');
  assert.equal(currentRole(config, ticket({ status: 'review', stage_role: 'security-architect' })), 'security-architect');
  assert.equal(currentRole(config, ticket({ status: 'done', stage_role: null })), null);
});

test('an escalated stage (reassigned_from) advances as if the original role had finished', () => {
  const t = ticket({ status: 'review', stage_role: 'principal-engineer', reassigned_from: 'code-reviewer', tags: ['security-sensitive'] });
  assert.deepEqual(nextPosition(config, t), { status: 'review', stage_role: 'security-architect' });
  const last = ticket({ status: 'review', stage_role: 'principal-engineer', reassigned_from: 'security-architect', tags: ['security-sensitive'] });
  assert.deepEqual(nextPosition(config, last), { status: 'qa', stage_role: 'qa-verifier' });
});

test('advance is refused outside the work stages', () => {
  for (const status of ['backlog', 'ready', 'blocked', 'done', 'cancelled']) {
    assert.throws(() => nextPosition(config, ticket({ status })), /cannot advance/, status);
  }
});

test('reject returns review and qa to the owner, and nothing else', () => {
  assert.deepEqual(rejectPosition(ticket({ status: 'review' })), { status: 'in_progress', stage_role: 'backend-engineer' });
  assert.deepEqual(rejectPosition(ticket({ status: 'qa' })), { status: 'in_progress', stage_role: 'backend-engineer' });
  for (const status of ['in_progress', 'ready', 'done']) assert.throws(() => rejectPosition(ticket({ status })), /cannot reject/);
});

test('code types come from config', () => {
  assert.equal(isCodeType(config, 'build'), true);
  assert.equal(isCodeType(config, 'docs'), false);
  assert.equal(isCodeType({ dispatcher: { code_types: ['docs'] } }, 'docs'), true);
});
