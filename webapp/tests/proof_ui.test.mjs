import test from 'node:test';
import assert from 'node:assert/strict';

import {
  buildWorkerResultMessage,
  formatBuildCommit,
  formatProofPreview,
  summarizeTimings,
} from '../src/proof_ui.js';

test('formatProofPreview keeps only a short proof prefix', () => {
  const proof = Uint8Array.from({ length: 64 }, (_, i) => i);
  const preview = formatProofPreview(proof);
  assert.match(preview, /^[0-9a-f]+\.\.\.$/);
  assert.ok(preview.length < proof.length * 2);
});

test('summarizeTimings rounds timing fields for display', () => {
  const summary = summarizeTimings({
    wasmProveMs: 12.3456,
    wasmTraceMs: 0.789,
  });
  assert.equal(summary.wasmProveMs, '12.35');
  assert.equal(summary.wasmTraceMs, '0.79');
});

test('buildWorkerResultMessage transfers the proof buffer', () => {
  const proofData = new Uint8Array([1, 2, 3]);
  const message = buildWorkerResultMessage(7, proofData, { workerWallMs: 1.23 });
  assert.equal(message.message.id, 7);
  assert.equal(message.transfer.length, 1);
  assert.equal(message.transfer[0], proofData.buffer);
  assert.deepEqual(Array.from(message.message.result.proofData), [1, 2, 3]);
});

test('formatBuildCommit shortens long commit hashes', () => {
  assert.equal(formatBuildCommit('0735e69abcdef1234567890'), '0735e69abcde');
});

test('formatBuildCommit keeps unknown markers readable', () => {
  assert.equal(formatBuildCommit('unknown'), 'unknown');
});
