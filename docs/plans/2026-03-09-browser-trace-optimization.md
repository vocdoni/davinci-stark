# Browser Trace Optimization Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Reduce browser proving time without weakening the proved ballot statement or the deployed security profile.

**Architecture:** Keep the current single-proof statement intact, but reduce trace width by removing statement data that is replicated on every row even though only a small subset of rows consumes it. Start with the duplicated `inputs_hash` preimage block, then move the `C2` binding checks from replicated global columns into dedicated local binding rows that reuse the existing low-width EC area.

**Tech Stack:** Rust, upstream Plonky3, custom AIR, wasm-pack, Vite webapp.

### Task 1: Baseline and regression target

**Files:**
- Create: `OPTIMIZATIONS.md`
- Test: `tests/trace_layout_test.rs`

**Step 1: Write the failing test**

Add a structural regression test asserting the optimized trace width target:

```rust
#[test]
fn trace_width_stays_below_browser_budget() {
    assert!(TRACE_WIDTH <= 1000, "TRACE_WIDTH={} is too wide for the browser budget", TRACE_WIDTH);
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --test trace_layout_test -- --nocapture`
Expected: FAIL because the current width is 1581.

**Step 3: Record the baseline**

Document the current width and prove timings in `OPTIMIZATIONS.md` before implementation.

### Task 2: Remove duplicated inputs-hash globals

**Files:**
- Modify: `src/columns.rs`
- Modify: `src/air.rs`
- Modify: `src/trace.rs`
- Test: `tests/ballot_e2e.rs`

**Step 1: Write the failing test**

Keep the existing `inputs_hash` binding regression tests and run them against the partially changed code after removing the duplicate columns; they should fail until the absorb binding is redirected.

**Step 2: Implement the minimal change**

Remove `GLOBAL_HASH_INPUT[_COUNT]` and compute each absorb chunk directly from the canonical source values already present in the statement: `{process_id, packed_ballot_mode, pk, address, vote_id, C1, C2, weight}`.

**Step 3: Run the targeted tests**

Run: `cargo test --test ballot_e2e test_inputs_hash_public_values_must_bind_to_poseidon_section -- --nocapture`
Run: `cargo test --test ballot_e2e test_circom_style_full_ballot_proof -- --nocapture`
Expected: PASS.

### Task 3: Replace replicated C2 globals with dedicated binding rows

**Files:**
- Modify: `src/columns.rs`
- Modify: `src/air.rs`
- Modify: `src/trace.rs`
- Test: `tests/ballot_e2e.rs`

**Step 1: Write the failing test**

Use the width-budget regression test from Task 1 and the existing ciphertext-binding tests as the guardrail.

**Step 2: Implement the minimal change**

Insert one dedicated binding row after each `M` phase. Reuse the existing low EC columns on those rows to store:
- the expected `C2` point
- the `C2 = M + S` intermediates
- the `C2` encoding

Bind the row to:
- the previous `M` phase output via local/next transition
- the existing `GLOBAL_S_POINTS` and `GLOBAL_C2_ENC` columns

Then remove `GLOBAL_C2_POINTS` and `GLOBAL_C2_ADD_INTER` from the replicated global area.

**Step 3: Run the targeted tests**

Run: `cargo test --test ballot_e2e test_ciphertexts_must_bind_to_ec_phase_outputs -- --nocapture`
Run: `cargo test --test ballot_e2e test_full_8field_ballot_proof -- --nocapture`
Expected: PASS.

### Task 4: Full verification and measurement

**Files:**
- Modify: `OPTIMIZATIONS.md`
- Modify: `README.md` if the final trace width or performance guidance changes materially

**Step 1: Run verification**

Run:
- `cargo test --tests --no-run`
- `cargo test --release --test ballot_e2e test_webapp_defaults -- --nocapture`
- `cargo check --target wasm32-unknown-unknown`
- `wasm-pack build --target web --release`
- `node /tmp/bench_wasm.mjs /home/p4u/davinci-miden/davinci-stark`

**Step 2: Update `OPTIMIZATIONS.md`**

Record each attempt, the measured width, and the measured timings.
