import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { render } from '../lib/render.mjs';
import { buildPrompt, stageInstructions } from '../lib/prompt.mjs';
import { makeFactory, ticketInput, REAL_FACTORY } from './helpers.mjs';
import { createTicket } from '../lib/tickets.mjs';

test('variables are substituted; missing and null become empty', () => {
  assert.equal(render('Hi {{name}}, {{missing}}{{nothing}}!', { name: 'Ada', nothing: null }), 'Hi Ada, !');
  assert.equal(render('{{n}} {{b}}', { n: 0, b: false }), '0 false');
});

test('a value containing {{x}} is not expanded again', () => {
  assert.equal(render('{{a}} {{b}}', { a: '{{b}}', b: 'B' }), '{{b}} B');
});

test('block sections render on a truthy flag and vanish otherwise, leaving no blank line', () => {
  const t = 'before\n{{#flag}}\ninside {{x}}\n{{/flag}}\nafter\n';
  assert.equal(render(t, { flag: true, x: 1 }), 'before\ninside 1\nafter\n');
  assert.equal(render(t, { flag: false, x: 1 }), 'before\nafter\n');
  assert.equal(render(t, {}), 'before\nafter\n');
});

test('inline block sections work too', () => {
  assert.equal(render('a{{#f}}-b{{/f}}c', { f: 1 }), 'a-bc');
  assert.equal(render('a{{#f}}-b{{/f}}c', { f: 0 }), 'ac');
});

test('the shipped worker prompt renders with every variable and no leftover tags', () => {
  const f = makeFactory();
  try {
    const ticket = createTicket(f.ctx, ticketInput({ status: 'ready', title: 'LDAP filter builder', priority: 'P1' }), 'x');
    const prompt = buildPrompt(f.ctx, { ticket, role: 'backend-engineer', stage: 'in_progress', continuation: false, isolated: true });
    assert.match(prompt, /as \*\*backend-engineer\*\*, on stage \*\*in_progress\*\* of ticket \*\*T-0001 — LDAP filter builder\*\* \(build, P1\)/);
    assert.match(prompt, /factory\/bin\/factory ticket advance T-0001 --by backend-engineer/);
    assert.match(prompt, /Implement on branch `factory\/T-0001`/);
    assert.match(prompt, /RESULT: advanced\|rejected\|blocked\|handoff\|failed/);
    assert.doesNotMatch(prompt, /\{\{|\}\}/);
    assert.doesNotMatch(prompt, /This is a continuation/);
  } finally { f.cleanup(); }
});

test('a continuation prompt names the handoff file', () => {
  const f = makeFactory();
  try {
    const ticket = createTicket(f.ctx, ticketInput({ status: 'ready' }), 'x');
    const t = { ...ticket, handoff: { pending: true, latest: '/abs/handoffs/T-0001/h1.md' } };
    const prompt = buildPrompt(f.ctx, { ticket: t, role: 'backend-engineer', stage: 'in_progress', continuation: true, isolated: false });
    assert.match(prompt, /This is a continuation/);
    assert.match(prompt, /\/abs\/handoffs\/T-0001\/h1\.md/);
    assert.match(prompt, /without branch isolation/);
  } finally { f.cleanup(); }
});

test('stage instructions differ per (stage, type)', () => {
  const f = makeFactory();
  try {
    const { config } = f.ctx;
    const t = (type, tags = []) => ({ id: 'T-0007', type, owner: 'backend-engineer', tags, meta: null });
    const get = (type, stage, role = 'x', tags) => stageInstructions({ config, ticket: t(type, tags), stage, role, isolated: true });
    assert.match(get('build', 'in_progress'), /Stage: implement/);
    assert.match(get('docs', 'in_progress'), /produce the deliverable/);
    assert.match(get('build', 'review', 'code-reviewer'), /git diff main\.\.\.factory\/T-0007/);
    assert.match(get('docs', 'review', 'product-manager'), /Review the deliverable/);
    assert.match(get('build', 'review', 'security-architect', ['security-sensitive']), /second reviewer/);
    assert.doesNotMatch(get('build', 'review', 'code-reviewer', ['security-sensitive']), /second reviewer/);
    assert.match(get('build', 'qa', 'qa-verifier'), /Stage: QA/);
    const meta = (kind, extra) => stageInstructions({ config, ticket: { ...t('meta'), meta: { kind, ...extra } }, stage: 'in_progress', role: 'x', isolated: false });
    assert.match(meta('triage', { decisions: ['D-0001'], feedback: [], blocked: ['T-0003'] }), /D-0001.*\n.*none.*\n.*T-0003/);
    assert.match(meta('grooming', { ready: 1, min_ready: 3, backlog: ['T-0009'] }), /1 ready, minimum 3\)\. Backlog tickets to groom: T-0009/);
    assert.match(meta('digest', { date: '2026-10-02' }), /digest-2026-10-02\.md/);
  } finally { f.cleanup(); }
});

test('the template file exists where the README says', () => {
  assert.ok(fs.existsSync(path.join(REAL_FACTORY, 'templates', 'worker-prompt.md')));
  assert.ok(fs.existsSync(path.join(REAL_FACTORY, 'templates', 'handoff.md')));
});
