import test from 'node:test';
import assert from 'node:assert/strict';
import { pollAdvisories } from '../lib/advisories.mjs';
import { listEntities } from '../lib/store.mjs';
import { makeFactory } from './helpers.mjs';

const GHSA_A = 'GHSA-cfgh-2345-wxvq';
const GHSA_B = 'GHSA-cccc-hhhh-jjjj';
const adv = (id, extra = {}) => ({ ghsa_id: id, html_url: `https://github.com/herambskanda/activeDIQ/security/advisories/${id}`, summary: 'SECRET DETAIL', description: 'SECRET DETAIL', ...extra });

/** A fake `gh api`: role of the caller and the advisories GitHub returns. */
function fakeApi({ role = 'security_manager', advisories = [], fail = null } = {}) {
  return async (endpoint) => {
    if (fail) throw new Error(fail);
    if (endpoint === 'user') return { login: 'factory-bot' };
    if (endpoint.includes('/collaborators/')) return { role_name: role };
    if (endpoint.includes('state=triage')) return advisories;
    throw new Error(`unexpected ${endpoint}`);
  };
}

test('a new private report yields exactly one embargoed ticket with no details, and a re-poll adds none', async () => {
  const { ctx } = makeFactory();
  const api = fakeApi({ advisories: [adv(GHSA_A), adv(GHSA_B)] });
  const first = await pollAdvisories(ctx, { api });
  assert.equal(first.created.length, 2);
  const again = await pollAdvisories(ctx, { api });
  assert.deepEqual(again.created, []);
  const tickets = listEntities(ctx, 'tickets');
  assert.equal(tickets.length, 2);
  const t = tickets.find((x) => x.meta.ghsa_id === GHSA_A);
  assert.equal(t.owner, 'security-architect');
  assert.equal(t.priority, 'P1');
  assert.deepEqual(t.tags, ['security-sensitive', 'embargoed']);
  assert.equal(t.body.trim(), adv(GHSA_A).html_url);
  assert.ok(!JSON.stringify(t).includes('SECRET DETAIL'));
});

test('a cancelled or finished ticket still counts as known: no duplicate', async () => {
  const { ctx } = makeFactory();
  const api = fakeApi({ advisories: [adv(GHSA_A)] });
  const [id] = (await pollAdvisories(ctx, { api })).created;
  const t = listEntities(ctx, 'tickets').find((x) => x.id === id);
  t.status = 'done';
  (await import('../lib/store.mjs')).putEntity(ctx, 'tickets', t);
  assert.deepEqual((await pollAdvisories(ctx, { api })).created, []);
});

test('without the security-manager role the poll fails loudly instead of reporting zero', async () => {
  const { ctx } = makeFactory();
  for (const role of ['write', 'maintain', 'read', null]) {
    await assert.rejects(pollAdvisories(ctx, { api: fakeApi({ role, advisories: [] }) }), /security-manager role/);
  }
  assert.equal(listEntities(ctx, 'tickets').length, 0);
});

test('API errors, unexpected shapes and malformed advisories all throw', async () => {
  const { ctx } = makeFactory();
  await assert.rejects(pollAdvisories(ctx, { api: fakeApi({ fail: 'HTTP 403' }) }), /403/);
  await assert.rejects(pollAdvisories(ctx, { api: fakeApi({ advisories: { message: 'Not Found' } }) }), /refusing to report zero/);
  await assert.rejects(pollAdvisories(ctx, { api: fakeApi({ advisories: [adv('GHSA-bad')] }) }), /unexpected id or link/);
  await assert.rejects(pollAdvisories(ctx, { api: fakeApi({ advisories: [adv(GHSA_A, { html_url: 'https://evil.example/x' })] }) }), /unexpected id or link/);
  await assert.rejects(pollAdvisories(ctx, { repo: 'a b', api: fakeApi() }), /invalid repository/);
  assert.equal(listEntities(ctx, 'tickets').length, 0);
});
