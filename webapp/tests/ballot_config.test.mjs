import test from 'node:test';
import assert from 'node:assert/strict';
import {
  encodeGoldilocks4Le,
  encodeU64LeChecked,
  normalizeChoices,
  packBallotMode,
} from '../src/ballot_config.js';

test('normalizeChoices keeps the active field count before zero padding', () => {
  const { choices, numFields } = normalizeChoices('1, 2, 3, 4, 5');
  assert.equal(numFields, 5);
  assert.deepEqual(choices, [1n, 2n, 3n, 4n, 5n, 0n, 0n, 0n]);
});

test('normalizeChoices clamps to eight active fields', () => {
  const { choices, numFields } = normalizeChoices('1,2,3,4,5,6,7,8,9');
  assert.equal(numFields, 8);
  assert.deepEqual(choices, [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n]);
});

test('normalizeChoices preserves empty positions as zeroes', () => {
  const { choices, numFields } = normalizeChoices('1,,2');
  assert.equal(numFields, 3);
  assert.deepEqual(choices, [1n, 0n, 2n, 0n, 0n, 0n, 0n, 0n]);
});

test('encodeGoldilocks4Le writes all four limbs', () => {
  const value = (0x44n << 192n) | (0x33n << 128n) | (0x22n << 64n) | 0x11n;
  const encoded = encodeGoldilocks4Le(value);
  assert.equal(encoded.length, 32);
  assert.deepEqual(
    Array.from(encoded),
    [
      0x11, 0, 0, 0, 0, 0, 0, 0,
      0x22, 0, 0, 0, 0, 0, 0, 0,
      0x33, 0, 0, 0, 0, 0, 0, 0,
      0x44, 0, 0, 0, 0, 0, 0, 0,
    ],
  );
});

test('encodeU64LeChecked rejects oversized values', () => {
  assert.throws(() => encodeU64LeChecked(1n << 64n), /does not fit in u64/);
});

test('encodeGoldilocks4Le rejects negative values', () => {
  assert.throws(() => encodeGoldilocks4Le(-1n), /non-negative/);
});

test('packBallotMode rejects values that do not fit the packed bit layout', () => {
  assert.throws(
    () =>
      packBallotMode({
        numFields: 1n,
        groupSize: 1n,
        uniqueValues: 0n,
        costFromWeight: 0n,
        costExponent: 2n,
        maxValue: 1n << 48n,
        minValue: 0n,
        maxValueSum: 0n,
        minValueSum: 0n,
      }),
    /does not fit in 48 bits/,
  );
});
