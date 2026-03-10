// worker.js -- Web Worker that hosts the WASM ballot proof module.
//
// Runs in a separate thread so proof generation (which can take 15-30s)
// does not block the UI. The main thread sends typed messages (keygen,
// prove, verify) and this worker dispatches them to the WASM exports.
//
// The WASM module auto-initializes when the worker loads. If main.js
// sends an 'init' message before that finishes, we just re-send the
// ready/error status once we know it.

import init, {
  generate_keypair,
  prove_full_detailed,
  verify,
  wasm_build_commit,
} from '../../pkg/davinci_stark.js';
import wasmUrl from '../../pkg/davinci_stark_bg.wasm?url';
import { buildWorkerResultMessage } from './proof_ui.js';

let ready = false;
let initError = null;

// Kick off WASM initialization as soon as the worker starts.
(async () => {
  try {
    console.log('[worker] initializing WASM from:', wasmUrl);
    await init({ module_or_path: wasmUrl });
    ready = true;
    console.log('[worker] WASM ready');
    self.postMessage({ type: 'ready', buildCommit: wasm_build_commit() });
  } catch (err) {
    initError = err;
    console.error('[worker] WASM init failed:', err);
    self.postMessage({ type: 'init_error', error: err.toString() });
  }
})();

self.onmessage = async (e) => {
  const { type, id, payload } = e.data;

  if (type === 'init') {
    // Already auto-initializing; if done, re-send ready
    if (ready) self.postMessage({ type: 'ready', buildCommit: wasm_build_commit() });
    else if (initError) self.postMessage({ type: 'init_error', error: initError.toString() });
    return;
  }

  if (!ready) {
    self.postMessage({ type: 'error', id, error: 'WASM not initialized' + (initError ? ': ' + initError : '') });
    return;
  }

  try {
    switch (type) {

      case 'keygen': {
        const pk = generate_keypair(payload.skBytes);
        self.postMessage({ type: 'result', id, result: { pk } });
        break;
      }

      case 'prove': {
        const { kBytes, fields, pkBytes, processId, address, weight, ballotMode } = payload;
        const workerStart = performance.now();
        const result = prove_full_detailed(
          kBytes,
          fields,
          pkBytes,
          processId,
          address,
          weight,
          ballotMode,
        );
        const proofData = result.proofData;
        const timings = {
          wasmDecodeMs: result.decodeMs,
          wasmTraceMs: result.traceMs,
          wasmProveMs: result.proveMs,
          wasmSerializeMs: result.serializeMs,
          workerWallMs: performance.now() - workerStart,
        };
        const message = buildWorkerResultMessage(id, proofData, timings);
        self.postMessage(message.message, message.transfer);
        break;
      }

      case 'verify': {
        const valid = verify(payload.proofData);
        self.postMessage({ type: 'result', id, result: { valid } });
        break;
      }

      default:
        self.postMessage({ type: 'error', id, error: `Unknown message type: ${type}` });
    }
  } catch (err) {
    self.postMessage({ type: 'error', id, error: err.toString() });
  }
};
