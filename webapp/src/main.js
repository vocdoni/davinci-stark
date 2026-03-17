// main.js -- UI controller for the DAVINCI STARK ballot proof webapp.
//
// Talks to the WASM module through a Web Worker (worker.js) so that
// proof generation does not freeze the browser. All WASM calls go through
// the call() helper which returns a promise resolved when the worker replies.

import {
  encodeGoldilocks4Le,
  encodeU64LeChecked,
  normalizeChoices,
  packBallotMode,
  parseBigIntValue,
} from './ballot_config.js';
import { bytesToHex, formatBuildCommit, formatProofPreview, summarizeTimings } from './proof_ui.js';
import { buildInfoText } from './build_info.js';

const logEl = document.getElementById('log');
const metricKeygenEl = document.getElementById('metric-keygen');
const metricProveEl = document.getElementById('metric-prove');
const metricVerifyEl = document.getElementById('metric-verify');
const metricNoteEl = document.getElementById('metric-note');
const buildInfoEl = document.getElementById('build-info');
let pkBytes = null;
let proofData = null;
let msgId = 0;
const pending = new Map(); // id -> {resolve, reject} for pending worker calls

// Spawn the Web Worker that loads and runs the WASM module.
const worker = new Worker(new URL('./worker.js', import.meta.url), { type: 'module' });

// Handle messages coming back from the worker.
worker.onmessage = (e) => {
  const { type, id, result, error } = e.data;
  if (type === 'ready') {
    log('✅ WASM module loaded in Web Worker', 'success');
    if (buildInfoEl) {
      buildInfoEl.textContent = buildInfoText(formatBuildCommit(e.data.buildCommit));
    }
    log('Ready! Fill in your vote and click "Compute Inputs & Generate Proof".', 'info');
    return;
  }
  if (type === 'init_error') {
    log('❌ WASM init failed: ' + error, 'error');
    return;
  }
  const cb = pending.get(id);
  if (!cb) return;
  pending.delete(id);
  if (type === 'error') cb.reject(new Error(error));
  else cb.resolve(result);
};

// Send a typed message to the worker and return a promise for the result.
function call(type, payload) {
  return new Promise((resolve, reject) => {
    const id = ++msgId;
    pending.set(id, { resolve, reject });
    worker.postMessage({ type, id, payload });
  });
}

// Append a line to the on-screen log panel.
function log(msg, cls = '') {
  const span = document.createElement('span');
  span.className = cls;
  span.textContent = msg + '\n';
  logEl.appendChild(span);
  logEl.scrollTop = logEl.scrollHeight;
}

function setMetric(el, value) {
  el.textContent = value;
}

// Convert hex string (with optional 0x prefix) to Uint8Array.
function hexToBytes(hex) {
  hex = hex.replace(/^0x/, '');
  if (hex.length % 2 !== 0) hex = '0' + hex;
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

// Auto-generate random K (32 random bytes as hex)
window.genRandomK = function() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  document.getElementById('k').value = bytesToHex(bytes);
};

// Initialize worker
worker.postMessage({ type: 'init' });

window.doProve = async function() {
  try {
    // Parse vote choices
    const choicesStr = document.getElementById('vote_choices').value;
    const { choices, numFields } = normalizeChoices(choicesStr);

    const weight = parseBigIntValue(document.getElementById('weight').value || '1');
    const processIdStr = document.getElementById('process_id').value;
    const addressStr = document.getElementById('address').value;
    const skHex = document.getElementById('sk').value;
    let kHex = document.getElementById('k').value.trim();

    // Auto-generate k if empty
    if (!kHex) {
      window.genRandomK();
      kHex = document.getElementById('k').value;
    }

    // Read ballot config
    const config = {
      numFields,
      groupSize: parseBigIntValue(document.getElementById('group_size').value || '1'),
      uniqueValues: parseBigIntValue(document.getElementById('unique_values').value || '0'),
      costFromWeight: parseBigIntValue(document.getElementById('cost_from_weight').value || '0'),
      costExponent: parseBigIntValue(document.getElementById('cost_exponent').value || '2'),
      maxValue: parseBigIntValue(document.getElementById('max_value').value || '16'),
      minValue: parseBigIntValue(document.getElementById('min_value').value || '0'),
      maxValueSum: parseBigIntValue(document.getElementById('max_value_sum').value || '1125'),
      minValueSum: parseBigIntValue(document.getElementById('min_value_sum').value || '5'),
    };

    log('\n--- Generating Keys ---', 'info');
    const skBytes = hexToBytes(skHex);
    const kgStart = performance.now();
    const kgResult = await call('keygen', { skBytes });
    pkBytes = kgResult.pk;
    log(`PK: ${bytesToHex(pkBytes).substring(0, 40)}...`);
    const keygenMs = performance.now() - kgStart;
    log(`⏱ Keygen: ${keygenMs.toFixed(1)}ms`, 'timing');
    setMetric(metricKeygenEl, `${keygenMs.toFixed(1)} ms`);

    // Build binary inputs
    const packStart = performance.now();
    const kBytes = hexToBytes(kHex);
    const fields = new Uint8Array(8 * 8);
    for (let i = 0; i < 8; i++) {
      fields.set(encodeU64LeChecked(choices[i] ?? 0n), i * 8);
    }

    const processId = encodeGoldilocks4Le(parseBigIntValue(processIdStr));
    const address = encodeGoldilocks4Le(parseBigIntValue(addressStr));

    const weightBytes = encodeU64LeChecked(weight);
    const ballotMode = packBallotMode(config);
    const inputPackMs = performance.now() - packStart;

    log('\n--- Full Ballot Proof ---', 'info');
    log(`Choices: [${choices.slice(0, numFields).map(String).join(', ')}]`);
    log(`Weight: ${weight.toString()} | Process: ${processIdStr} | Address: ${addressStr}`);
    log(`Config: unique=${config.uniqueValues.toString()} max=${config.maxValue.toString()} min=${config.minValue.toString()} exp=${config.costExponent.toString()}`);
    log('Proving in Web Worker... (UI stays responsive)', 'info');

    document.getElementById('btn-prove').disabled = true;
    const start = performance.now();
    const result = await call('prove', {
      kBytes, fields, pkBytes, processId, address, weight: weightBytes, ballotMode
    });
    proofData = result.proofData;
    const elapsed = performance.now() - start;
    const renderStart = performance.now();
    const timings = summarizeTimings({
      inputPackMs,
      workerWallMs: result.timings?.workerWallMs ?? elapsed,
      wasmDecodeMs: result.timings?.wasmDecodeMs ?? 0,
      wasmTraceMs: result.timings?.wasmTraceMs ?? 0,
      wasmProveMs: result.timings?.wasmProveMs ?? 0,
      wasmSerializeMs: result.timings?.wasmSerializeMs ?? 0,
      mainRenderMs: 0,
    });

    log(`✅ Proof generated!`, 'success');
    log(`Proof size: ${proofData.length} bytes (${(proofData.length / 1024).toFixed(1)} KB)`);
    log(`⏱ ${(elapsed / 1000).toFixed(1)}s`, 'timing');
    log(
      `Timing breakdown: pack=${timings.inputPackMs}ms worker=${timings.workerWallMs}ms ` +
      `decode=${timings.wasmDecodeMs}ms trace=${timings.wasmTraceMs}ms ` +
      `prove=${timings.wasmProveMs}ms serialize=${timings.wasmSerializeMs}ms`,
      'timing',
    );
    setMetric(metricProveEl, `${(elapsed / 1000).toFixed(2)} s`);
    metricNoteEl.textContent =
      `FRI config: blowup 8, 34 queries, 0 PoW bits. Last proof size: ${(proofData.length / 1024).toFixed(1)} KB.`;

    // Show proof data
    document.getElementById('proof-card').style.display = 'block';
    document.getElementById('proof-data').textContent = formatProofPreview(proofData);
    timings.mainRenderMs = (performance.now() - renderStart).toFixed(2);
    log(`Render=${timings.mainRenderMs}ms`, 'timing');

    document.getElementById('btn-prove').disabled = false;
    document.getElementById('btn-verify').disabled = false;
  } catch (e) {
    log('❌ Proving failed: ' + e, 'error');
    document.getElementById('btn-prove').disabled = false;
  }
};

window.doVerify = async function() {
  if (!proofData) { log('Generate a proof first!', 'error'); return; }

  try {
    log('\n--- Verification ---', 'info');
    const start = performance.now();
    const result = await call('verify', { proofData });
    const elapsed = performance.now() - start;

    if (result.valid) {
      log('✅ Proof is VALID!', 'success');
    } else {
      log('❌ Proof is INVALID', 'error');
    }
    log(`⏱ ${elapsed.toFixed(1)}ms`, 'timing');
    setMetric(metricVerifyEl, `${elapsed.toFixed(1)} ms`);
  } catch (e) {
    log('❌ Verification failed: ' + e, 'error');
  }
};
