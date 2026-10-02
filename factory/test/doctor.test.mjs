import test from 'node:test';
import assert from 'node:assert/strict';
import { duplicateTopLevelKeys } from '../lib/doctor.mjs';

test('duplicate top-level keys are found, whatever their value type', () => {
  assert.deepEqual(duplicateTopLevelKeys('{"ceo": "heramb", "a": 1, "ceo": {"x": 1}}'), ['ceo']);
  assert.deepEqual(duplicateTopLevelKeys('{\n  "a": 1,\n  "b": [1, 2],\n  "a": 2,\n  "b": 3\n}'), ['a', 'b']);
  assert.deepEqual(duplicateTopLevelKeys('{"a":1,"a":2,"a":3}'), ['a'], 'reported once');
});

test('the same key at different depths, or inside strings, is not a duplicate', () => {
  assert.deepEqual(duplicateTopLevelKeys('{"a": {"a": 1}, "b": [{"a": 2}]}'), []);
  assert.deepEqual(duplicateTopLevelKeys('{"a": "\\"a\\": 1, \\"a\\": 2", "b": "{ \\"b\\": }"}'), []);
  assert.deepEqual(duplicateTopLevelKeys('{"a": "text with } and { braces", "a": 2}'), ['a'], 'braces in strings do not confuse the depth');
  assert.deepEqual(duplicateTopLevelKeys('{"a": 1, "b": {"c": 1}, "d": 2}'), []);
  assert.deepEqual(duplicateTopLevelKeys('{}'), []);
});
