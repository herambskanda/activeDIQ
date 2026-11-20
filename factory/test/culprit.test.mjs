import { test } from 'node:test';
import assert from 'node:assert/strict';
import { bareFinding, blameFindings, classifyFinding, planDrop } from '../lib/culprit.mjs';

const A = { id: 'T-1', files: ['internal/compose/server/directory.go', 'internal/directory/inventory/a_test.go'] };
const B = { id: 'T-2', files: ['internal/platform/rbac/catalog.go', 'tools/ci/ci.mk'] };
const C = { id: 'T-3', files: ['docs/x.md', 'internal/compose/server/other.go'] };

test('classifyFinding names what a finding points at', () => {
  assert.deepEqual(classifyFinding('FAILED fitness'), { kind: 'aggregate' });
  assert.deepEqual(classifyFinding('FAIL github.com/skenzeriq/activediq/internal/platform/rbac'), { kind: 'package', path: 'internal/platform/rbac' });
  assert.deepEqual(classifyFinding('FAIL TestHybridGateEveryBuiltInPermissionClassified'), { kind: 'test' });
  assert.deepEqual(classifyFinding('FAIL lock stuck after the holder died'), { kind: 'test' });
  assert.deepEqual(classifyFinding('internal/compose/server/directory.go: [blueprint §2.5] imports x'), { kind: 'path', path: 'internal/compose/server/directory.go' });
  assert.deepEqual(classifyFinding('internal/directory/accountkind: [ADR-0003 M7] package has no row'), { kind: 'path', path: 'internal/directory/accountkind' });
  assert.deepEqual(classifyFinding('tools/x.go:12: [FF-SP2] bad string'), { kind: 'path', path: 'tools/x.go' });
  assert.equal(classifyFinding('make: *** [tools/ci/ci.mk:80: fitness-merge-order] Error 1').kind, 'other');
  assert.equal(classifyFinding('something odd').kind, 'other');
});

test('bareFinding drops the count suffix the gate appends', () => {
  assert.equal(bareFinding('a/b.go: [x] y  (3 times)'), 'a/b.go: [x] y');
  assert.equal(bareFinding('a/b.go: [x] y  (2 more than the 1 on main)'), 'a/b.go: [x] y');
  assert.equal(bareFinding('a/b.go: [x] y'), 'a/b.go: [x] y');
});

test('a finding in a file only one member changed is that member\'s', () => {
  const plan = planDrop(['internal/compose/server/directory.go: [blueprint §2.5] imports modules/directory', 'FAILED fitness'], [A, B, C]);
  assert.deepEqual([...plan.drop.keys()], ['T-1']);
  assert.equal(plan.suspect.size, 0);
  assert.deepEqual(plan.keep, ['T-2', 'T-3']);
  assert.equal(plan.ignored, 1);
});

test('a failing package belongs to the one member that changed files in it; test names under it are explained', () => {
  const plan = planDrop([
    'FAIL TestHybridGateEveryBuiltInPermissionClassified',
    'FAIL github.com/skenzeriq/activediq/internal/platform/rbac',
    'FAILED test-go',
  ], [A, B, C]);
  assert.deepEqual([...plan.suspect.keys()], ['T-2'], 'a package failure is only likely: that ticket is gated alone, not refused');
  assert.equal(plan.drop.size, 0);
  assert.deepEqual(plan.keep, ['T-1', 'T-3']);
});

test('a test failure with no package roll-up cannot be blamed', () => {
  assert.equal(planDrop(['FAIL TestSomething'], [A, B]), null);
});

test('a file two members changed is ambiguous, so the train is halved instead', () => {
  const two = [A, { id: 'T-9', files: ['internal/compose/server/directory.go'] }];
  assert.equal(planDrop(['internal/compose/server/directory.go: [blueprint §2.5] x'], two), null);
});

test('one finding nobody can be blamed for makes the whole plan null, even if others map', () => {
  assert.equal(planDrop(['internal/compose/server/directory.go: [blueprint §2.5] x', 'cmd/connector: [blueprint §2.7] links store'], [A, B, C]), null);
  assert.equal(planDrop(['some odd finding'], [A, B]), null);
});

test('a failing package no member touched is unmapped: the cause may be a dependency', () => {
  const r = blameFindings(['FAIL github.com/skenzeriq/activediq/internal/platform/store'], [A, B, C]);
  assert.equal(r.certain.size + r.likely.size, 0);
  assert.equal(r.unmapped.length, 1);
});

test('a directory finding is blamed on the member that added files under it', () => {
  const m = [{ id: 'T-5', files: ['internal/directory/accountkind/kind.go'] }, B];
  const plan = planDrop(['internal/directory/accountkind: [ADR-0003 M7] package internal/directory/accountkind has no row'], m);
  assert.deepEqual([...plan.drop.keys()], ['T-5']);
  assert.deepEqual(plan.keep, ['T-2']);
});

test('two culprits are both dropped and the rest is kept', () => {
  const plan = planDrop(['internal/compose/server/directory.go: [x] y', 'internal/platform/rbac/catalog.go: [x] y'], [A, B, C]);
  assert.deepEqual([...plan.drop.keys()].sort(), ['T-1', 'T-2']);
  assert.deepEqual(plan.keep, ['T-3']);
});

test('every member blamed leaves nothing to gate again', () => {
  const plan = planDrop(['internal/compose/server/directory.go: [x] y', 'internal/platform/rbac/catalog.go: [x] y'], [A, B]);
  assert.deepEqual(plan.keep, []);
});

test('a train of one, or no findings, is never split', () => {
  assert.equal(planDrop(['internal/compose/server/directory.go: [x] y'], [A]), null);
  assert.equal(planDrop([], [A, B]), null);
});

test('the count suffix does not stop a finding being blamed', () => {
  const plan = planDrop(['internal/compose/server/directory.go: [x] y  (3 times)'], [A, B]);
  assert.deepEqual([...plan.drop.keys()], ['T-1']);
});

test('the finding shapes real gate logs print are understood', () => {
  assert.deepEqual(classifyFinding('lab/e2e/boot-lab-server.sh FF-KEY-3 [provider-default]: the KEK provider setting is given'), { kind: 'path', path: 'lab/e2e/boot-lab-server.sh' });
  assert.deepEqual(classifyFinding('./internal/compose/server TestKEKSettingsAreReadOnlyInComposeServer FF-KEY-3 [test-failed]'), { kind: 'package', path: 'internal/compose/server' });
});

test('a ticket with a certain finding is refused even when it also has a likely one', () => {
  const plan = planDrop([
    'internal/compose/server/directory.go: [blueprint §2.5] x',
    'FAIL github.com/skenzeriq/activediq/internal/directory/inventory',
  ], [A, B, C]);
  assert.deepEqual([...plan.drop.keys()], ['T-1']);
  assert.equal(plan.suspect.size, 0, 'already refused, so not also a suspect');
  assert.deepEqual(plan.keep, ['T-2', 'T-3']);
});

test('a package two members changed files in is ambiguous, so the plan is null', () => {
  assert.equal(planDrop(['FAIL github.com/skenzeriq/activediq/internal/compose/server'], [A, B, C]), null);
});

test('a test failure with no package line next to a blamed finding still vetoes the plan: it may belong to someone else', () => {
  assert.equal(planDrop(['internal/compose/server/directory.go: [blueprint §2.5] x', 'FAIL TestSomethingElse'], [A, B, C]), null);
});
