// Pins the LIVE model/effort policy (CEO, 2026-10-02: nothing runs above `high`). The mechanism
// tests (ladder, escalation-only, overrides) run against TEST_MODELS in helpers.mjs; this file is
// the one place that reads the real factory/config.json and the real .claude/agents roster, so a
// policy change fails here, deliberately and legibly, and nowhere else.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { parseAgentFile } from '../lib/agents.mjs';
import { checkAgentPolicy, modelFamily } from '../lib/policy.mjs';
import { REAL_FACTORY } from './helpers.mjs';

const CEILING = 'high';
const RUNGS = ['low', 'medium', 'high', 'xhigh', 'max'];
const config = JSON.parse(fs.readFileSync(path.join(REAL_FACTORY, 'config.json'), 'utf8'));
const agentsDir = path.join(REAL_FACTORY, '..', '.claude', 'agents');
const aboveCeiling = (effort) => RUNGS.indexOf(effort) > RUNGS.indexOf(CEILING) || !RUNGS.includes(effort);

test('live policy: no model family allows an effort above high, and nothing is escalation-only', () => {
  const { allowed, escalation_only: only, effort_ladder: ladder } = config.models;
  assert.deepEqual(Object.keys(allowed).sort(), ['opus', 'sonnet']);
  for (const [family, efforts] of Object.entries(allowed)) {
    assert.ok(efforts.length > 0, `${family} allows at least one effort`);
    assert.deepEqual(efforts.filter(aboveCeiling), [], `${family} allowed efforts must not exceed ${CEILING}`);
  }
  assert.deepEqual(only, {}, 'no effort rung is reserved for escalation roles');
  for (const [family, rungs] of Object.entries(ladder)) {
    assert.deepEqual(rungs.filter(aboveCeiling), [], `${family} effort_ladder must not exceed ${CEILING}`);
    assert.ok(rungs.every((r) => allowed[family].includes(r)), `${family} ladder rungs are all allowed`);
  }
  assert.equal(JSON.stringify(config.models).match(/xhigh|max/g), null, 'models block names neither xhigh nor max');
});

test('live roster: every real agent is opus or sonnet with an effort at or below high, and passes checkAgentPolicy', () => {
  const files = fs.readdirSync(agentsDir).filter((f) => f.endsWith('.md'));
  assert.ok(files.length > 0, 'the real roster is not empty');
  for (const file of files) {
    const agent = parseAgentFile(path.join(agentsDir, file));
    assert.ok(modelFamily(agent.model), `${agent.name}: model ${agent.model} is opus or sonnet`);
    assert.ok(!aboveCeiling(agent.effort), `${agent.name}: effort "${agent.effort}" exceeds ${CEILING}`);
    assert.deepEqual(checkAgentPolicy(config, agent), [], `${agent.name} violates the live policy`);
  }
});
