import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { parseFrontmatter } from '../lib/frontmatter.mjs';
import { loadAgents, parseAgentFile } from '../lib/agents.mjs';
import { checkAgentPolicy, checkLaunchPolicy, modelFamily, nextEffort } from '../lib/policy.mjs';
import { makeFactory, writeAgent, REAL_FACTORY } from './helpers.mjs';

const config = JSON.parse(fs.readFileSync(path.join(REAL_FACTORY, 'config.json'), 'utf8'));

test('frontmatter: plain, quoted and block scalars; body is returned', () => {
  const { data, body } = parseFrontmatter('---\nname: x\ntitle: "Quoted: yes"\ndescription: >\n  one\n  two\nnotes: |\n  a\n  b\nempty:\n---\n\n# Heading\n');
  assert.deepEqual(data, { name: 'x', title: 'Quoted: yes', description: 'one two', notes: 'a\nb', empty: '' });
  assert.equal(body, '\n# Heading\n');
});

test('frontmatter: absent or unterminated yields empty data', () => {
  assert.deepEqual(parseFrontmatter('# just markdown\n').data, {});
  assert.deepEqual(parseFrontmatter('---\nname: x\nno end').data, {});
  assert.deepEqual(parseFrontmatter('---\r\nname: x\r\n---\r\nbody').data, { name: 'x' });
});

test('loadAgents reads name, model and effort, falls back to the file name, and skips non-markdown', () => {
  const f = makeFactory({ agents: { 'a-one': ['opus', 'high'] } });
  try {
    fs.writeFileSync(path.join(f.ctx.agentsDir, 'nameless.md'), '---\nmodel: sonnet\neffort: high\n---\nbody');
    fs.writeFileSync(path.join(f.ctx.agentsDir, 'README.txt'), 'x');
    const agents = loadAgents(f.ctx);
    assert.deepEqual([...agents.keys()].sort(), ['a-one', 'nameless']);
    assert.deepEqual([agents.get('a-one').model, agents.get('a-one').effort], ['opus', 'high']);
    assert.equal(agents.get('nameless').effort, 'high');
    assert.equal(parseAgentFile(path.join(f.ctx.agentsDir, 'a-one.md')).description, 'Fixture agent a-one. Second line.');
  } finally { f.cleanup(); }
});

test('loadAgents returns an empty map when the directory does not exist', () => {
  const f = makeFactory({ agents: {} });
  try {
    fs.rmSync(path.join(f.root, '.claude'), { recursive: true, force: true });
    assert.equal(loadAgents(f.ctx).size, 0);
  } finally { f.cleanup(); }
});

test('modelFamily normalises full model ids and refuses others', () => {
  assert.equal(modelFamily('opus'), 'opus');
  assert.equal(modelFamily('claude-opus-5-5'), 'opus');
  assert.equal(modelFamily('Sonnet'), 'sonnet');
  assert.equal(modelFamily('claude-sonnet-5-5'), 'sonnet');
  assert.equal(modelFamily('claude-haiku-4-5-20251001'), null);
  assert.equal(modelFamily(undefined), null);
});

test('agent policy: opus medium/high ok, opus xhigh only for escalation roles, sonnet high/xhigh, never haiku', () => {
  const ok = (name, model, effort) => checkAgentPolicy(config, { name, model, effort });
  assert.deepEqual(ok('factory-director', 'opus', 'high'), []);
  assert.deepEqual(ok('project-manager', 'opus', 'medium'), []);
  assert.deepEqual(ok('principal-engineer', 'opus', 'xhigh'), []);
  assert.match(ok('factory-director', 'opus', 'xhigh')[0], /escalation-only/);
  assert.match(ok('factory-director', 'opus', 'max')[0], /escalation-only/);
  assert.deepEqual(ok('backend-engineer', 'sonnet', 'high'), []);
  assert.deepEqual(ok('backend-engineer', 'sonnet', 'xhigh'), []);
  assert.match(ok('backend-engineer', 'sonnet', 'medium')[0], /not allowed for sonnet/);
  assert.match(ok('backend-engineer', 'sonnet', 'low')[0], /not allowed/);
  assert.match(ok('x', 'claude-haiku-4-5', 'high')[0], /neither opus nor sonnet/);
  assert.match(ok('x', 'opus', null)[0], /no effort/);
  assert.match(ok('x', null, 'high')[0], /neither opus nor sonnet/);
});

test('launch policy: an effort override is an escalation, so it may be escalation-only but must be allowed', () => {
  const agent = { name: 'backend-engineer', model: 'sonnet', effort: 'high' };
  assert.deepEqual(checkLaunchPolicy(config, agent), []);
  assert.deepEqual(checkLaunchPolicy(config, agent, 'xhigh'), []);
  assert.match(checkLaunchPolicy(config, agent, 'max')[0], /not allowed for sonnet/);
  const director = { name: 'factory-director', model: 'opus', effort: 'high' };
  assert.deepEqual(checkLaunchPolicy(config, director, 'xhigh'), []);
  assert.deepEqual(checkLaunchPolicy(config, director, 'max'), []);
  assert.match(checkLaunchPolicy(config, director, 'low')[0], /not allowed for opus/);
});

test('nextEffort climbs the ladder and stops at the top', () => {
  assert.equal(nextEffort(config, 'sonnet', 'high'), 'xhigh');
  assert.equal(nextEffort(config, 'sonnet', 'xhigh'), null);
  assert.equal(nextEffort(config, 'opus', 'medium'), 'high');
  assert.equal(nextEffort(config, 'opus', 'high'), 'xhigh');
  assert.equal(nextEffort(config, 'opus', 'xhigh'), null);
  assert.equal(nextEffort(config, 'opus', 'bogus'), null);
  assert.equal(nextEffort(config, null, 'high'), null);
});

test('writeAgent fixture is parseable by the runtime', () => {
  const f = makeFactory({ agents: {} });
  try {
    writeAgent(f.ctx.agentsDir, 'solo', 'opus', 'high');
    assert.equal(loadAgents(f.ctx).get('solo').model, 'opus');
  } finally { f.cleanup(); }
});
