import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeChoices } from '../src/ballot_config.js';

test('normalizeChoices keeps the active field count before zero padding', () => {
  const { choices, numFields } = normalizeChoices('1, 2, 3, 4, 5');
  assert.equal(numFields, 5);
  assert.deepEqual(choices, [1, 2, 3, 4, 5, 0, 0, 0]);
});

test('normalizeChoices clamps to eight active fields', () => {
  const { choices, numFields } = normalizeChoices('1,2,3,4,5,6,7,8,9');
  assert.equal(numFields, 8);
  assert.deepEqual(choices, [1, 2, 3, 4, 5, 6, 7, 8]);
});
