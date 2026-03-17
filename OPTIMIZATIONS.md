# Browser Prover Optimizations

## Objective

Reduce browser proving time without weakening the proved ballot statement or reducing the deployed security profile.

## Baseline

- Starting point:
  - `TRACE_WIDTH = 1581`
  - native release `test_webapp_defaults`: about `21.17s`
  - wasm runtime benchmark (`node /tmp/bench_wasm.mjs ...`): about `51.8s`
  - wasm proof size: `1,025,680` bytes
- Root cause:
  - browser slowdown correlated with the trace-width jump from `271` to `1581`
  - the largest replicated statement blocks were `GLOBAL_HASH_INPUT`, `GLOBAL_C2_ADD_INTER`, `GLOBAL_C2_POINTS`, `GLOBAL_PACKED_MODE_BITS`, and `GLOBAL_S_POINTS`

## Attempts

### Attempt 1: Remove duplicated `GLOBAL_HASH_INPUT`

Status: implemented

Result:
- `TRACE_WIDTH` dropped from `1581` to `1465`.
- Rebound each inputs-hash absorb chunk directly to the canonical statement sources.
- Fixed an interleaved `C1_i` / `C2_i` ordering mismatch exposed by the first pass.

### Attempt 2: Move `C2` binding from replicated globals to dedicated rows

Status: implemented

Result:
- `TRACE_WIDTH` dropped from `1465` to `905`.
- Replaced replicated `GLOBAL_C2_POINTS` and `GLOBAL_C2_ADD_INTER` with 8 dedicated C2 binding rows.

### Attempt 3: Move packed-ballot bit decomposition onto dedicated rows

Status: implemented

Result:
- `TRACE_WIDTH` dropped from `905` to `657`.
- Reused `P2_VOTE_ID_BITS` on 4 dedicated top-of-trace rows and removed `GLOBAL_PACKED_MODE_BITS`.

### Attempt 4: Replace replicated `GLOBAL_S_POINTS` with a per-field carry

Status: implemented

Result:
- `TRACE_WIDTH` dropped from `657` to `517`.
- Replaced the 8-field replicated `S_i` array with a 20-column `CURRENT_S` carry:
  - created at the end of each `k_i * PK` phase
  - carried across the matching `field_i * G` phase
  - consumed by the dedicated C2 binding row

### Attempt 5: Tighten release profile

Status: implemented

Change:
- `lto = "fat"`
- `codegen-units = 1`
- `panic = "abort"`

Result:
- modest additional speedup in both native release and wasm runtime benchmarks

### Attempt 6: Probe `wasm-opt`

Status: rejected

Change tried:
- `wasm-opt -O4` on a copy of `pkg/davinci_stark_bg.wasm`

Result:
- rejected because initialization failed in Node with:
  - `RangeError: WebAssembly.Table.grow(): failed to grow table by 4`
- The normal wasm build path was left unchanged.

## Intermediate Measurements After Attempts 1-6

- Final layout:
  - `TRACE_WIDTH = 517`
  - trace for the full ballot test: `4096 x 517`
- Native release:
  - `cargo test --release --test ballot_e2e test_webapp_defaults -- --nocapture`
  - completed in about `8.14s`
- Native release full ballot:
  - `cargo test --release --test ballot_e2e test_full_8field_ballot_proof -- --nocapture`
  - trace generation: `20.84ms`
  - prove: `8.09s`
  - verify: `13.81ms`
- Wasm runtime benchmark:
  - `~/.cargo/bin/wasm-pack build --target web --release`
  - `node /tmp/bench_wasm.mjs /home/p4u/davinci-miden/davinci-stark`
  - `prove_ms = 20106.85`
  - `verify_ms = 36.39`
  - proof size: `641,755` bytes

## Intermediate Summary After Attempts 1-6

Measured improvement from the implemented optimizations:
- trace width: `1581 -> 517`
- native release webapp-default prove: `21.17s -> 8.14s`
- wasm runtime prove: `51.8s -> 20.11s`
- proof size: `1,025,680 -> 641,755` bytes

## Intermediate Verification

Commands run on the final state:
- `cargo test --test trace_layout_test -- --nocapture`
- `cargo test --test ballot_e2e test_inputs_hash_public_values_must_bind_to_poseidon_section -- --nocapture`
- `cargo test --test ballot_e2e test_ciphertexts_must_bind_to_ec_phase_outputs -- --nocapture`
- `cargo test --release --test ballot_e2e test_webapp_defaults -- --nocapture`
- `cargo test --release --test ballot_e2e test_full_8field_ballot_proof -- --nocapture`
- `cargo check --target wasm32-unknown-unknown`
- `~/.cargo/bin/wasm-pack build --target web --release`
- `node /tmp/bench_wasm.mjs /home/p4u/davinci-miden/davinci-stark`
- `cd webapp && npm run build -- --base=./`

## Remaining Options Identified Before Attempt 10

The largest remaining browser-cost blocks are the replicated ciphertext encodings (`GLOBAL_C1_ENC`, `GLOBAL_C2_ENC`) and some of the shared statement prefix. Those are still possible to remove, but the next step is materially more invasive because the inputs-hash section consumes those values far away from the EC section.

## Analysis: Why A Modern Browser Can Still Take ~96s

Current evidence points to three separate effects:

1. The prover is still structurally large.
   - The current trace is `4096 x 517`.
   - The remaining major replicated statement blocks are `GLOBAL_C1_ENC` and `GLOBAL_C2_ENC`.
   - The full ballot statement still includes 24 EC scalar-multiplication phases and 41 Poseidon2 permutations.

2. Browser runtime is materially slower than native and slower than Node's wasm runtime.
   - Native release prove is about `8.1s`.
   - Node wasm prove is about `20.1s`.
   - A real browser at about `96s` indicates an additional browser/runtime penalty on top of wasm cost.

3. GitHub Pages blocks the most promising runtime acceleration path.
   - Threaded wasm in browsers depends on `SharedArrayBuffer`, which in practice requires `COOP/COEP` headers.
   - GitHub Pages does not provide the right header control for that model.

### What Is Probably Not The Main Problem

- Trace generation is not the bottleneck. In native release it is about `20ms`.
- Packed ballot mode serialization is no longer a dominant cost. It already uses 4 dedicated rows rather than a replicated bit block.
- Rendering the proof as hex is wasteful, but it happens after the measured proof wall time currently displayed in the UI. It is still worth removing, but it does not explain the full 96s.

### Highest-Value Next Optimization

The next structural step was to remove the remaining `inputs_hash` machinery overhead while preserving the verifier-visible statement. The chosen approach was to expose the full `inputs_hash` preimage as public values and recompute the hash in `verify_ballot(...)`.

### Multiple Smaller STARKs

This is not the first optimization to take.

- Multiple proofs without aggregation do not reduce total browser work enough by themselves.
- Multiple proofs with a final recursive proof only make sense if recursion is already cheap and engineered in the target stack.
- With the current codebase, the most pragmatic order is:
  1. instrument the browser path,
  2. remove browser-only waste,
  3. remove remaining ciphertext replication,
  4. only then decide whether a multi-proof architecture is justified.

### Attempt 7: Add browser-stage instrumentation and remove obvious browser-only waste

Status: implemented

Changes:
- Added a timed WASM prove result so the worker can report:
  - Rust decode time
  - trace generation time
  - STARK prove time
  - serialization time
- Added worker wall-clock timing.
- Stopped rendering the full proof hex by default; the UI now shows only a short preview.
- Switched worker proof delivery to use a transfer list instead of structured cloning the proof buffer.

Files:
- `src/wasm.rs`
- `webapp/src/worker.js`
- `webapp/src/main.js`
- `webapp/src/proof_ui.js`
- `webapp/tests/proof_ui.test.mjs`

Result:
- Node wasm benchmark remained effectively flat:
  - before: `prove_ms = 20106.85`
  - after: `prove_ms = 20139.76`
- This indicates the instrumentation path itself did not meaningfully change prover cost.
- The browser path now exposes enough timing detail to distinguish:
  - main-thread input packing
  - worker wall time
  - Rust decode
  - Rust trace generation
  - Rust prove
  - Rust serialization
  - main-thread render time

Interpretation:
- If the browser still reports roughly `96s` while Rust `wasmProveMs` is much lower, the remaining gap is browser/runtime overhead.
- If `wasmProveMs` itself is close to the full wall time, the next step is the structural trace refactor rather than more UI work.

### Attempt 8: Probe wasm SIMD (`+simd128`)

Status: rejected

Change tried:
- Temporary `RUSTFLAGS='-C target-feature=+simd128'` build for `wasm-pack`

Result:
- Node wasm benchmark regressed from about `20.1s` to about `32.9s`.
- The SIMD build was not kept.

Interpretation:
- This prover path does not currently benefit from enabling wasm SIMD at the crate level.

### Attempt 9: Probe `wasm-opt -O2`

Status: rejected

Change tried:
- Temporary `wasm-opt -O2` pass on the generated browser wasm

Result:
- Initialization failed with `WebAssembly.Table.grow(): failed to grow table by 4`.
- The optimized artifact was not kept.

Interpretation:
- Safe post-link wasm optimization is not currently available through this path without breaking initialization.

### Attempt 10: Remove the in-trace `inputs_hash` machine

Status: implemented

Change:
- Removed the dedicated `inputs_hash` Poseidon section from the trace.
- Exposed the full 114-element `inputs_hash` preimage as public values.
- Bound that preimage directly in the AIR to:
  - `packed_ballot_mode`
  - the public key
  - `vote_id`
  - `C1[0..7]`
  - `C2[0..7]`
  - `weight`
- Recompute `inputs_hash` in `verify_ballot(...)` with the same Poseidon2 permutation instead of proving a second in-trace sponge.

Result:
- `TRACE_WIDTH` dropped from `517` to `379`.
- Trace height dropped from `4096` to `2048`.
- The proof statement stayed the same at the verifier boundary: the verifier still checks the same `inputs_hash`, but now against an AIR-bound public preimage instead of an in-trace hash machine.
- During implementation I found and fixed a real bug: the `CURRENT_S` carry written by the EC section was being zeroed later in trace generation.

### Final Measurements (current)

- Final layout:
  - `TRACE_WIDTH = 379`
  - full ballot trace: `2048 x 379`
- Native release:
  - `cargo test --release --test ballot_e2e test_webapp_defaults -- --nocapture`
  - completed in about `3.25s`
- Native release full ballot:
  - `cargo test --release --test ballot_e2e test_full_8field_ballot_proof -- --nocapture`
  - trace generation: `4.18ms`
  - prove: `3.20s`
  - verify: `11.93ms`
- Wasm runtime benchmark:
  - `~/.cargo/bin/wasm-pack build --target web --release`
  - `node /tmp/bench_wasm.mjs /home/p4u/davinci-miden/davinci-stark`
  - `prove_ms = 8015.51`
  - `verify_ms = 31.66`
  - proof size: `545,678` bytes

### Summary (current)

Measured improvement from the optimization series:
- trace width: `1581 -> 379`
- trace height: `4096 -> 2048`
- native release webapp-default prove: `21.17s -> 3.25s`
- wasm runtime prove: `51.8s -> 8.02s`
- proof size: `1,025,680 -> 545,678` bytes
