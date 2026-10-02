import test from 'node:test';
import assert from 'node:assert/strict';
import { getEntity, readRecentEvents } from '../lib/store.mjs';
import { createEpic, createMilestone, setEpic } from '../lib/items.mjs';
import { makeFactory } from './helpers.mjs';

const REFS = ['ADM-039', 'ADM-044', 'ADSS-091'];

function setup() {
  const f = makeFactory();
  createMilestone(f.ctx, { name: 'Foundation' });
  createMilestone(f.ctx, { name: 'Parity' });
  const epic = createEpic(f.ctx, { title: 'Automation and JML', goal: 'E2.9', milestone: 'M2', parity_refs: REFS });
  return { ...f, epic };
}

test('createEpic validates parity refs and drops duplicates', () => {
  const f = setup();
  try {
    assert.throws(() => createEpic(f.ctx, { title: 'x', parity_refs: ['adm-1'] }), /parity refs must look like ADM-045 \(got adm-1\)/);
    assert.throws(() => createEpic(f.ctx, { title: 'x', parity_refs: ['ADM 045'] }), /parity refs/);
    const e = createEpic(f.ctx, { title: 'x', parity_refs: ['I360-004', 'M365-018', 'I360-004'] });
    assert.deepEqual(e.parity_refs, ['I360-004', 'M365-018']);
  } finally { f.cleanup(); }
});

test('setEpic parity_refs+= appends one ref, leaves the others untouched and logs who added what', () => {
  const f = setup();
  try {
    const out = setEpic(f.ctx, f.epic.id, { 'parity_refs+': 'ADM-045' }, 'factory-director');
    assert.deepEqual(out.parity_refs, [...REFS, 'ADM-045']);
    assert.deepEqual(getEntity(f.ctx, 'epics', f.epic.id).parity_refs, [...REFS, 'ADM-045']);
    assert.deepEqual([out.title, out.goal, out.milestone, out.status], ['Automation and JML', 'E2.9', 'M2', 'planned']);
    const [event] = readRecentEvents(f.ctx, 1);
    assert.deepEqual([event.actor, event.kind, event.text], ['factory-director', 'ticket', 'epic E-001 updated: parity_refs +ADM-045 (3 → 4)']);

    const again = setEpic(f.ctx, f.epic.id, { 'parity_refs+': 'ADM-045, ADM-039' }, 'factory-director');
    assert.deepEqual(again.parity_refs, [...REFS, 'ADM-045'], 'adding refs already present is a no-op');
    assert.equal(readRecentEvents(f.ctx, 1)[0].text, 'epic E-001 updated: no change');
  } finally { f.cleanup(); }
});

test('setEpic parity_refs-= removes refs and parity_refs= replaces the list', () => {
  const f = setup();
  try {
    assert.deepEqual(setEpic(f.ctx, f.epic.id, { 'parity_refs-': 'ADM-044' }, 'pm').parity_refs, ['ADM-039', 'ADSS-091']);
    assert.match(readRecentEvents(f.ctx, 1)[0].text, /parity_refs -ADM-044 \(3 → 2\)/);
    assert.throws(() => setEpic(f.ctx, f.epic.id, { 'parity_refs-': 'ADM-999' }, 'pm'), /E-001 has no parity ref ADM-999/);

    const replaced = setEpic(f.ctx, f.epic.id, { parity_refs: 'ADM-001,ADSS-091' }, 'pm');
    assert.deepEqual(replaced.parity_refs, ['ADM-001', 'ADSS-091']);
    assert.match(readRecentEvents(f.ctx, 1)[0].text, /parity_refs \+ADM-001 -ADM-039 \(2 → 2\)/);
    assert.deepEqual(setEpic(f.ctx, f.epic.id, { parity_refs: 'null' }, 'pm').parity_refs, []);
  } finally { f.cleanup(); }
});

test('setEpic edits title, goal and milestone and records old → new', () => {
  const f = setup();
  try {
    const out = setEpic(f.ctx, f.epic.id, { title: '  JML  ', goal: 'E2.9 rev 2', milestone: 'M1' }, 'pm');
    assert.deepEqual([out.title, out.goal, out.milestone], ['JML', 'E2.9 rev 2', 'M1']);
    assert.equal(readRecentEvents(f.ctx, 1)[0].text,
      'epic E-001 updated: title "Automation and JML" → "JML"; goal "E2.9" → "E2.9 rev 2"; milestone M2 → M1');
    assert.equal(setEpic(f.ctx, f.epic.id, { milestone: 'null' }, 'pm').milestone, null);
  } finally { f.cleanup(); }
});

test('setEpic validates like ticket set and writes nothing when any assignment fails', () => {
  const f = setup();
  try {
    const before = getEntity(f.ctx, 'epics', f.epic.id);
    const cases = [
      [{ 'parity_refs+': 'ADM-045', milestone: 'M9' }, /milestone M9 not found/],
      [{ 'parity_refs+': 'adm-045' }, /parity refs must look like ADM-045/],
      [{ 'parity_refs+': '' }, /needs at least one ref/],
      [{ title: '  ' }, /title is required/],
      [{ status: 'done' }, /cannot set "status" on an epic/],
      [{ parity: 'ADM-045' }, /cannot set "parity"/],
    ];
    for (const [assignments, error] of cases) assert.throws(() => setEpic(f.ctx, f.epic.id, assignments, 'pm'), error);
    assert.deepEqual(getEntity(f.ctx, 'epics', f.epic.id), before, 'a failed set leaves the epic unchanged');
    assert.throws(() => setEpic(f.ctx, 'E-404', { goal: 'x' }, 'pm'), /E-404/);
  } finally { f.cleanup(); }
});
