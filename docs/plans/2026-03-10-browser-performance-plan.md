# Browser Performance Optimization Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Reduce browser proving time substantially without weakening the proved ballot statement or the deployed FRI security profile.

**Architecture:** Keep one browser-facing ballot proof statement, but stop paying monolithic-trace costs where the statement can be streamed or localized. Separate browser overhead from prover overhead first, then remove the last replicated ciphertext blocks, and only then decide whether a multi-proof architecture is justified.

**Tech Stack:** Rust, upstream Plonky3, wasm-bindgen, Vite Web Worker, browser WebAssembly.

### Task 1: Add stage-level browser instrumentation

**Files:**
- Modify: `webapp/src/main.js`
- Modify: `webapp/src/worker.js`
- Modify: `src/wasm.rs`
- Test: manual browser timing + existing webapp build

**Step 1: Write the failing instrumentation expectation**
Add a small timing schema for:
- input packing on main thread
- worker prove start/end
- Rust trace generation
- Rust STARK prove
- proof serialization
- worker-to-main transfer
- optional proof rendering

Expected outcome: browser UI shows these stages separately.

**Step 2: Run build to ensure current code still builds before changes**
Run: `cd webapp && npm run build`
Expected: PASS

**Step 3: Add minimal instrumentation plumbing**
- In `src/wasm.rs`, split `prove_full` internal timing into:
  - decode inputs
  - trace generation
  - `p3_uni_stark::prove`
  - proof/public-value serialization
- Return timings alongside proof bytes in a JS-friendly structure or a compact byte header.
- In `worker.js`, capture wall-clock worker time around the WASM call.
- In `main.js`, capture:
  - pre-worker packing time
  - time awaiting worker response
  - time spent rendering proof info

**Step 4: Verify the instrumentation works**
Run: `cd webapp && npm run build`
Expected: PASS

**Step 5: Manual browser measurement**
Open the browser page and record stage times on the target browser.
Expected: one clear breakdown instead of one opaque number.

### Task 2: Remove browser-only waste that does not strengthen the proof

**Files:**
- Modify: `webapp/src/main.js`
- Modify: `webapp/src/worker.js`
- Test: `webapp/tests/ballot_config.test.mjs`

**Step 1: Stop rendering the full proof hex by default**
- Keep proof size and a short prefix only.
- Add an explicit “show proof bytes” action if needed.

**Step 2: Transfer proof bytes instead of structured-cloning them**
- Send `proofData.buffer` from the worker using a transfer list.
- Reconstruct `Uint8Array` on the main thread.

**Step 3: Verify the webapp still works**
Run:
- `cd webapp && node --test tests/ballot_config.test.mjs`
- `cd webapp && npm run build`
Expected: PASS

### Task 3: Remove the remaining replicated ciphertext encodings from the trace

**Files:**
- Modify: `src/columns.rs`
- Modify: `src/trace.rs`
- Modify: `src/air.rs`
- Modify: `tests/trace_layout_test.rs`
- Modify: `tests/ballot_e2e.rs`

**Step 1: Write failing layout and binding tests**
Add tests that require:
- no `GLOBAL_C1_ENC` / `GLOBAL_C2_ENC` replication across all rows
- ciphertext/hash binding still rejects mixed-trace tampering

**Step 2: Replace global ciphertext arrays with a streaming hash path**
Recommended design:
- keep the exact Circom-compatible `inputs_hash` preimage order
- do not store all `C1_i` / `C2_i` encodings on every row
- instead, create a streaming inputs-hash machine that absorbs:
  - prefix `{process_id, packed_ballot_mode, PK, address, vote_id}`
  - then each field’s `C1_i || C2_i` immediately after the corresponding C2 binding row
  - then `weight`
- carry the Poseidon sponge state between dedicated rows instead of storing the entire ciphertext statement globally

**Step 3: Implement the minimal AIR changes**
- Add dedicated rows/selectors for streaming absorb steps
- Bind each absorbed chunk directly to local EC outputs / C2 binding rows
- Remove `GLOBAL_C1_ENC` and `GLOBAL_C2_ENC`

**Step 4: Verify correctness and measure**
Run:
- `cargo test --test trace_layout_test -- --nocapture`
- `cargo test --test ballot_e2e -- --nocapture`
- `cargo test --release --test ballot_e2e test_webapp_defaults -- --nocapture`
- `cargo check --target wasm32-unknown-unknown`
- `~/.cargo/bin/wasm-pack build --target web --release`
- `node /tmp/bench_wasm.mjs /home/p4u/davinci-miden/davinci-stark`
Expected: same statement, smaller trace, lower wasm prove time.

### Task 4: Re-evaluate packed ballot mode work with evidence

**Files:**
- Modify only if measurements justify it: `src/air.rs`, `src/trace.rs`, `README.md`

**Step 1: Check actual timing share from Task 1 instrumentation**
Expected: packed-mode rows should be a very small fraction of total prove cost.

**Step 2: Only optimize if the measurement contradicts expectations**
Likely outcome: leave packed-mode logic alone because it is already down to 4 dedicated rows and is not the dominant cost.

### Task 5: Evaluate threaded browser proving as an operational optimization

**Files:**
- Modify later if selected: wasm build config, webapp hosting docs, deployment setup
- Document: `README.md`, `OPTIMIZATIONS.md`

**Step 1: Confirm hosting constraint**
- GitHub Pages does not provide the `COOP/COEP` header setup needed for `SharedArrayBuffer`-based threaded wasm.

**Step 2: If browser time is still too high after Task 3, prototype threaded hosting on a host with header control**
Expected: better wall-clock time from parallel proving work without weakening the proof.

### Task 6: Decide whether multiple smaller STARKs are justified

**Files:**
- Document only in this phase: `OPTIMIZATIONS.md`, `README.md` if adopted later

**Step 1: Evaluate three architectures**
- A. Keep one monolithic STARK after streaming refactor
- B. Produce multiple independent proofs and verify all of them
- C. Produce multiple smaller proofs plus a final recursive/aggregating proof

**Step 2: Apply the decision rule**
- A is preferred if Task 3 gets browser time into the acceptable range.
- B is only useful if the verifier can accept multiple proofs; it does not reduce total browser work enough by itself.
- C only makes sense if recursion/aggregation becomes a product requirement, because generating several proofs plus an aggregator proof in the browser is likely more work than the current monolith unless the recursive verifier is exceptionally cheap and already engineered.

**Step 3: Do not implement split proofs before Task 3 and Task 5 evidence exists**
Expected: avoid a large redesign unless the simpler structural and runtime optimizations are exhausted.
