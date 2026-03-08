// main.js -- UI controller for the DAVINCI STARK ballot proof webapp.
//
// Talks to the WASM module through a Web Worker (worker.js) so that
// proof generation does not freeze the browser. All WASM calls go through
// the call() helper which returns a promise resolved when the worker replies.

const logEl = document.getElementById('log');
const metricKeygenEl = document.getElementById('metric-keygen');
const metricProveEl = document.getElementById('metric-prove');
const metricVerifyEl = document.getElementById('metric-verify');
const metricNoteEl = document.getElementById('metric-note');
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

// Convert Uint8Array to lowercase hex string.
function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Encode a JS number as 8 bytes in little-endian u64 format.
function u64ToLeBytes(val) {
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  view.setBigUint64(0, BigInt(val), true);
  return new Uint8Array(buf);
}

// Parse a user-entered numeric string (supports 0x prefix for hex).
function parseInputValue(str) {
  str = str.trim();
  if (str.startsWith('0x') || str.startsWith('0X')) return BigInt(str);
  return BigInt(str);
}

/** Pack ballot configuration into 4 x u64 LE (248 bits packed into 4 Goldilocks elements).
 *  Bit layout (matching circom's UnpackBallotMode):
 *   [0:8]   num_fields
 *   [8:16]  group_size
 *   [16]    unique_values
 *   [17]    cost_from_weight
 *   [18:26] cost_exponent
 *   [26:74] max_value (48 bits)
 *   [74:122] min_value (48 bits)
 *   [122:185] max_value_sum (63 bits)
 *   [185:248] min_value_sum (63 bits)
 */
function packBallotMode(config) {
  let bits = 0n;
  bits |= BigInt(config.numFields) & 0xFFn;
  bits |= (BigInt(config.groupSize) & 0xFFn) << 8n;
  bits |= (BigInt(config.uniqueValues) & 1n) << 16n;
  bits |= (BigInt(config.costFromWeight) & 1n) << 17n;
  bits |= (BigInt(config.costExponent) & 0xFFn) << 18n;
  bits |= (BigInt(config.maxValue) & 0xFFFFFFFFFFFFn) << 26n;
  bits |= (BigInt(config.minValue) & 0xFFFFFFFFFFFFn) << 74n;
  bits |= (BigInt(config.maxValueSum) & 0x7FFFFFFFFFFFFFFFn) << 122n;
  bits |= (BigInt(config.minValueSum) & 0x7FFFFFFFFFFFFFFFn) << 185n;

  // Split into 4 x 62-bit chunks (fit in Goldilocks field < 2^64 - 2^32 + 1)
  const mask62 = (1n << 62n) - 1n;
  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) {
    const chunk = (bits >> (BigInt(i) * 62n)) & mask62;
    const bytes = u64ToLeBytes(chunk);
    out.set(bytes, i * 8);
  }
  return out;
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
    const choices = choicesStr.split(',').map(s => parseInt(s.trim()) || 0);
    while (choices.length < 8) choices.push(0);

    const weight = parseInt(document.getElementById('weight').value) || 1;
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
      numFields: Math.min(choices.length, 8),
      groupSize: parseInt(document.getElementById('group_size').value) || 1,
      uniqueValues: parseInt(document.getElementById('unique_values').value) || 0,
      costFromWeight: parseInt(document.getElementById('cost_from_weight').value) || 0,
      costExponent: parseInt(document.getElementById('cost_exponent').value) || 2,
      maxValue: parseInt(document.getElementById('max_value').value) || 16,
      minValue: parseInt(document.getElementById('min_value').value) || 0,
      maxValueSum: parseInt(document.getElementById('max_value_sum').value) || 1125,
      minValueSum: parseInt(document.getElementById('min_value_sum').value) || 5,
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
    const kBytes = hexToBytes(kHex);
    const fields = new Uint8Array(8 * 8);
    for (let i = 0; i < 8; i++) {
      fields.set(u64ToLeBytes(choices[i] || 0), i * 8);
    }

    const processId = new Uint8Array(32);
    const pidVal = parseInputValue(processIdStr);
    processId.set(u64ToLeBytes(pidVal), 0);

    const address = new Uint8Array(32);
    const addrVal = parseInputValue(addressStr);
    address.set(u64ToLeBytes(addrVal), 0);

    const weightBytes = u64ToLeBytes(weight);
    const ballotMode = packBallotMode(config);

    log('\n--- Full Ballot Proof ---', 'info');
    log(`Choices: [${choices.slice(0, config.numFields).join(', ')}]`);
    log(`Weight: ${weight} | Process: ${processIdStr} | Address: ${addressStr}`);
    log(`Config: unique=${config.uniqueValues} max=${config.maxValue} min=${config.minValue} exp=${config.costExponent}`);
    log('Proving in Web Worker... (UI stays responsive)', 'info');

    document.getElementById('btn-prove').disabled = true;
    const start = performance.now();
    const result = await call('prove', {
      kBytes, fields, pkBytes, processId, address, weight: weightBytes, ballotMode
    });
    proofData = result.proofData;
    const elapsed = performance.now() - start;

    log(`✅ Proof generated!`, 'success');
    log(`Proof size: ${proofData.length} bytes (${(proofData.length / 1024).toFixed(1)} KB)`);
    log(`⏱ ${(elapsed / 1000).toFixed(1)}s`, 'timing');
    setMetric(metricProveEl, `${(elapsed / 1000).toFixed(2)} s`);
    metricNoteEl.textContent =
      `FRI config: blowup 8, 34 queries, 0 PoW bits. Last proof size: ${(proofData.length / 1024).toFixed(1)} KB.`;

    // Show proof data
    document.getElementById('proof-card').style.display = 'block';
    document.getElementById('proof-data').textContent = bytesToHex(proofData);

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
