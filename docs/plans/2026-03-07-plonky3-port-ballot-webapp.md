# Plonky3 Port And Webapp Completion Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the current `p3-miden-*` dependency stack with upstream `Plonky3`, finish the ballot-validation constraints, preserve ZisK-compatible Poseidon2 behavior, and ship the result through the existing browser webapp.

**Architecture:** The Rust crate will move from Miden wrapper traits to upstream `p3-air` / `p3-uni-stark` / `p3-fri`, while keeping the same trace layout, proof IO shape, and browser-facing wasm interface. Poseidon2 will be split into upstream reusable primitives plus a local tracing/compatibility layer, and ballot validation will be completed under tests before the webapp integration is refreshed.

**Tech Stack:** Rust, upstream Plonky3 (`p3-air`, `p3-uni-stark`, `p3-fri`, `p3-goldilocks`, `p3-challenger`), `wasm-bindgen`, `postcard`, Vite webapp, Web Worker.

### Task 1: Freeze Existing Behavior With Regression Tests

**Files:**
- Modify: `tests/ballot_e2e.rs`
- Modify: `tests/poseidon2_test.rs`
- Create: `tests/plonky3_port_regression.rs`

**Step 1: Write failing regression tests for completed ballot validation**

Add tests for:
- duplicate active values when `unique_values = 1`
- out-of-range field value
- cost sum above limit
- cost sum below `min_value_sum`
- `cost_from_weight = 1` using `weight` as the upper bound
- invalid `group_size > num_fields`

Add assertions that proving may still succeed on malformed traces, but verification must fail.

**Step 2: Run targeted tests to verify they fail for the expected reason**

Run:
```bash
cargo test --test ballot_e2e -- --nocapture
```

Expected:
- new tests fail because current BV AIR is incomplete

**Step 3: Write failing Poseidon2 compatibility tests**

Add tests that compare:
- local width-8 permutation outputs against the current hardcoded vectors
- local implementation against upstream `Poseidon2GoldilocksHL<8>` where parameters match
- local width-16 infrastructure permutation behavior stays deterministic for proof config reuse

**Step 4: Run Poseidon2 tests and verify failures if behavior diverges**

Run:
```bash
cargo test --test poseidon2_test -- --nocapture
```

Expected:
- any mismatch between local and upstream-compatible behavior fails explicitly

### Task 2: Port From `p3-miden-*` To Upstream `Plonky3`

**Files:**
- Modify: `Cargo.toml`
- Modify: `src/lib.rs`
- Modify: `src/config.rs`
- Modify: `src/air.rs`
- Modify: `tests/ballot_e2e.rs`
- Modify: `tests/poseidon2_test.rs`
- Modify: `tests/ec_test.rs`
- Modify: `tests/fibonacci_smoke.rs`
- Modify: `tests/gfp5_test.rs`

**Step 1: Write a compile-targeted failing test or type check change**

First switch one small test import from `p3_miden_prover::{prove, verify}` to upstream `p3_uni_stark::{prove, verify}` and one AIR trait use from `MidenAir` to upstream `Air`.

**Step 2: Run the smallest affected test to verify compile failure**

Run:
```bash
cargo test --test fibonacci_smoke --no-run
```

Expected:
- compile errors showing all required trait/config API changes

**Step 3: Implement the minimal config port**

Port config types to:
- `p3_fri::HidingFriPcs`
- `p3_uni_stark::StarkConfig`
- upstream `p3-air` builder interfaces

Keep:
- Goldilocks field
- width-16 Poseidon2 challenger
- extension MMCS
- wasm-safe challenger patch via `[patch.crates-io]`

**Step 4: Port `BallotAir` to upstream `Air`**

Replace Miden-specific APIs with upstream equivalents:
- `Air<AB>`
- `builder.main()`
- upstream row windows
- public values access

Prefer implementing `num_public_values`, `main_next_row_columns`, and constraint-degree hints where straightforward.

**Step 5: Update proof types and all tests**

Make [src/lib.rs](/home/p4u/davinci-miden/davinci-stark/src/lib.rs) expose upstream proof/config types while preserving the current public crate API (`prove_full_ballot`, `verify_ballot`, wasm exports).

**Step 6: Run native and wasm compile checks**

Run:
```bash
cargo test --no-run
cargo check --target wasm32-unknown-unknown
```

Expected:
- compile succeeds on native and wasm

### Task 3: Reuse Upstream Poseidon2 While Preserving ZisK Compatibility

**Files:**
- Modify: `src/poseidon2.rs`
- Modify: `src/config.rs`
- Modify: `tests/poseidon2_test.rs`
- Modify: `README.md`

**Step 1: Write a failing test around upstream HL compatibility**

Add tests proving that:
- local width-8 traced permutation equals the ZisK-compatible expected outputs
- upstream `Poseidon2GoldilocksHL<8>` produces the same output when initialized with the same saved constants path or equivalent constants

If exact constant injection is not possible through the public API, assert equality against known vectors and document that the local tracer remains authoritative.

**Step 2: Run the Poseidon2 tests to verify the current mismatch surface**

Run:
```bash
cargo test --test poseidon2_test -- --nocapture
```

**Step 3: Refactor the local module into a thin compatibility/tracing layer**

Reuse upstream primitives where possible:
- width-16 config permutation from `p3-goldilocks`
- width-8 HL-compatible arithmetic helpers when exact compatibility can be proven

Keep local code only for:
- trace recording
- sponge transcript layout
- constant loading if upstream cannot expose the exact ZisK constants cleanly

**Step 4: Re-run the Poseidon2 tests**

Run:
```bash
cargo test --test poseidon2_test -- --nocapture
```

Expected:
- all compatibility tests pass

### Task 4: Finish Ballot Validation Constraints

**Files:**
- Modify: `src/air.rs`
- Modify: `src/trace.rs`
- Modify: `tests/ballot_e2e.rs`

**Step 1: Use the already-written but unreachable BV constraints**

Remove the early `return` and reconcile the duplicated BV sections into one coherent implementation.

Required checks:
- range checks
- exponent decomposition
- power accumulation
- uniqueness
- cost sum transition
- BV entry-point anchor
- bounds row (`min_sum`, upper limit, `group_size`)
- config consistency across BV rows

**Step 2: Run only the BV-focused failing tests**

Run:
```bash
cargo test --test ballot_e2e test_ballot_wrong_vote_fails -- --nocapture
cargo test --test ballot_e2e -- --nocapture
```

Expected:
- previously failing validation tests now pass
- no regression in valid ballot proofs

**Step 3: Clean up trace generation to match the AIR exactly**

Ensure [src/trace.rs](/home/p4u/davinci-miden/davinci-stark/src/trace.rs) populates every column required by the restored constraints and does not rely on unreachable AIR logic.

**Step 4: Run the full Rust suite**

Run:
```bash
cargo test -- --nocapture
```

Expected:
- all Rust tests pass

### Task 5: Keep Browser Proving Working And Integrate With The Example Webapp

**Files:**
- Modify: `src/wasm.rs`
- Modify: `webapp/src/main.js`
- Modify: `webapp/src/worker.js`
- Modify: `webapp/index.html`
- Modify: `webapp/package.json` (only if needed)
- Modify: `README.md`

**Step 1: Write failing integration checks for wasm build and proof flow**

Use existing browser API shape and add a smoke path that:
- builds wasm
- verifies worker import paths still work
- proves and verifies from the browser-facing API

If there is no automated browser test harness yet, add a Rust-side serialization test and a JS-side smoke helper script.

**Step 2: Run wasm build and webapp build to verify failure points**

Run:
```bash
wasm-pack build --target web --release
cd webapp && npm run build
```

Expected:
- failures identify API/packaging mismatches

**Step 3: Update wasm wrapper and JS worker minimally**

Preserve the current worker protocol:
- `init`
- `keygen`
- `prove`
- `verify`

Add only what is necessary:
- any updated proof serialization
- clearer error surfaces
- optional helper formatting for inputs/output display

Avoid touching `webapp/vite.config.js` unless the port makes it strictly necessary.

**Step 4: Verify end-to-end browser build**

Run:
```bash
wasm-pack build --target web --release
cd webapp && npm run build
```

Expected:
- wasm package builds
- Vite production build succeeds

### Task 6: Verification And Documentation

**Files:**
- Modify: `README.md`
- Modify: `docs/plans/2026-03-07-plonky3-port-ballot-webapp.md`

**Step 1: Update docs to match reality**

Document:
- upstream `Plonky3` usage instead of `p3-miden-*`
- actual BV guarantees now enforced
- Poseidon2 compatibility story with ZisK
- wasm/browser build instructions

**Step 2: Run final verification**

Run:
```bash
cargo test -- --nocapture
cargo check --target wasm32-unknown-unknown
wasm-pack build --target web --release
cd webapp && npm run build
```

Expected:
- all commands succeed

**Step 3: Summarize residual risks**

Capture any remaining caveats:
- local challenger patch still required on wasm
- local width-8 Poseidon2 tracer retained if upstream API cannot express the exact ZisK constant set
- proof size/performance tradeoffs after the upstream port
