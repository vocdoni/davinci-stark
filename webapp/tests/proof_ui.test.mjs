import test from 'node:test';
import assert from 'node:assert/strict';
import { buildWorkerResultMessage, formatProofPreview, summarizeTimings } from '../src/proof_ui.js';

test('formatProofPreview keeps only a short proof prefix', () => {
  const bytes = new Uint8Array(Array.from({ length: 32 }, (_, i) => i));
  const preview = formatProofPreview(bytes, 8);
  assert.equal(preview, '0001020304050607...');
});

test('summarizeTimings rounds timing fields for display', () => {
  const summary = summarizeTimings({
    inputPackMs: 1.234,
    workerWallMs: 20.987,
    wasmDecodeMs: 0.456,
    wasmTraceMs: 5.432,
    wasmProveMs: 99.999,
    wasmSerializeMs: 3.333,
    mainRenderMs: 2.111,
  });

  assert.deepEqual(summary, {
    inputPackMs: '1.23',
    workerWallMs: '20.99',
    wasmDecodeMs: '0.46',
    wasmTraceMs: '5.43',
    wasmProveMs: '100.00',
    wasmSerializeMs: '3.33',
    mainRenderMs: '2.11',
  });
});

test('buildWorkerResultMessage transfers the proof buffer', () => {
  const proofData = new Uint8Array([1, 2, 3, 4]);
  const timings = { wasmProveMs: 12.5 };
  const { message, transfer } = buildWorkerResultMessage(7, proofData, timings);

  assert.equal(message.type, 'result');
  assert.equal(message.id, 7);
  assert.equal(message.result.proofData, proofData);
  assert.deepEqual(message.result.timings, timings);
  assert.deepEqual(transfer, [proofData.buffer]);
});
