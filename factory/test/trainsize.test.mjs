import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chooseTrainSize, mustGoAlone, verdictHistory } from '../lib/trainsize.mjs';

const pass = (id = 'T-1') => ({ kind: 'ticket', text: `${id} pre-merge gate passed (ratchet): main is red` });
const refuse = (why = 'main is red and the merge result adds 3') => ({ kind: 'ticket', text: `T-2 merge refused by the pre-merge gate: ${why}` });

test('verdictHistory reads passes and refusals, oldest first, newest 20 only', () => {
  const newestFirst = [refuse(), pass(), pass(), refuse()];
  assert.deepEqual(verdictHistory(newestFirst), [false, true, true, false]);
  const many = Array.from({ length: 30 }, (_, i) => (i < 20 ? pass() : refuse())); // newest first
  const h = verdictHistory(many);
  assert.equal(h.length, 20);
  assert.ok(h.every(Boolean), 'the 20 newest were all passes');
});

test('verdictHistory ignores other events and main\'s own numbering refusals', () => {
  const ev = [
    { kind: 'dispatcher', text: 'pre-merge gate passed' },
    refuse('the migration-numbering check fails on the merge of factory/T-2 into main'),
    { kind: 'ticket', text: 'T-3 merged into main (abc)' },
    pass(),
  ];
  assert.deepEqual(verdictHistory(ev), [true]);
});

test('chooseTrainSize: off below 2, cautious start, then follows the pass rate', () => {
  const run = (pass, fail) => [...Array(pass).fill(true), ...Array(fail).fill(false)];
  assert.equal(chooseTrainSize(0, run(20, 0)), 1);
  assert.equal(chooseTrainSize(1, run(20, 0)), 1);
  assert.equal(chooseTrainSize(4, []), 2, 'no record yet: start with 2');
  assert.equal(chooseTrainSize(4, run(5, 4)), 2, 'fewer than 10 verdicts: still the cautious start');
  assert.equal(chooseTrainSize(4, run(17, 3)), 4, '0.85 is enough for the maximum');
  assert.equal(chooseTrainSize(4, run(16, 4)), 2, '0.80 gives 2');
  assert.equal(chooseTrainSize(4, run(12, 8)), 2, '0.60 gives 2');
  assert.equal(chooseTrainSize(4, run(11, 9)), 1, 'below 0.60 gives 1');
  assert.equal(chooseTrainSize(3, run(20, 0)), 3);
  assert.equal(chooseTrainSize(2, run(20, 0)), 2);
});

test('chooseTrainSize looks only at the last 20 verdicts', () => {
  const old = Array(30).fill(false);
  const recent = Array(20).fill(true);
  assert.equal(chooseTrainSize(4, [...old, ...recent]), 4);
  assert.equal(chooseTrainSize(4, [...recent, ...old.slice(0, 20)]), 1);
});

test('mustGoAlone: go.mod, Makefile, *.mk and tools/ci change the whole build', () => {
  assert.equal(mustGoAlone(['internal/x/a.go', 'go.mod']), true);
  assert.equal(mustGoAlone(['go.sum']), true);
  assert.equal(mustGoAlone(['Makefile']), true);
  assert.equal(mustGoAlone(['tools/ci/ci.mk']), true);
  assert.equal(mustGoAlone(['lab/windows/lab.mk']), true);
  assert.equal(mustGoAlone(['tools/ci/proof.sh']), true);
  assert.equal(mustGoAlone(['internal/x/a.go', 'docs/y.md', 'web/package.json']), false);
  assert.equal(mustGoAlone([]), false);
});
