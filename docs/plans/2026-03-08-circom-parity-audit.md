# Circom Parity Audit Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Match the semantic constraints of `resources/davinci-circom`'s `ballot_checker` and `ballot_proof` circuits in the STARK implementation, and reproduce the Circom test intent where it applies.

**Architecture:** First encode the Circom `ballot_checker` test matrix directly in Rust against the current STARK prover/verifier surface. Then close any checker-level parity gaps uncovered by those tests. After checker parity is green, audit and tighten the `ballot_proof` statement-level bindings: packed ballot mode unpacking, vote-id derivation, ciphertext/hash composition, and any remaining missing relations between private ballot inputs and public `{inputs_hash, address, vote_id}`.

**Tech Stack:** Rust, Plonky3 STARK AIR, existing `tests/ballot_e2e.rs`, local Circom sources in `resources/davinci-circom`.

### Task 1: Capture Circom checker parity cases in Rust

**Files:**
- Modify: `tests/ballot_e2e.rs`
- Reference: `resources/davinci-circom/test/ballot_checker_test.go`

**Step 1: Write the failing tests**
- Add Rust tests mirroring the Circom checker scenarios that are not already covered:
  - simple valid ballot with uniqueness on
  - `max_value_sum = 0` disables upper-bound enforcement
  - duplicates allowed when uniqueness is off
  - approval-style exact-sum valid / overflow invalid
  - ranked-choice valid / duplicate-rank invalid
  - all-zero ballot with positive `min_value_sum` invalid

**Step 2: Run the targeted tests to verify failure or gap**
Run: `cargo test --test ballot_e2e circom_ballot_checker -- --nocapture`
Expected: at least one failure if parity is incomplete, otherwise immediate green showing existing coverage is sufficient.

**Step 3: Implement the minimum code or test helper changes needed**
- Only add helpers or AIR changes required by the failing cases.

**Step 4: Re-run the targeted tests**
Run: `cargo test --test ballot_e2e circom_ballot_checker -- --nocapture`
Expected: PASS

### Task 2: Verify checker-level structural parity

**Files:**
- Modify: `src/air.rs`
- Modify: `src/trace.rs`
- Modify: `tests/ballot_e2e.rs`
- Reference: `resources/davinci-circom/circuits/ballot_checker.circom`

**Step 1: Write failing structural tests**
- Add tests for any Circom checker relations not currently asserted by behavior-only cases, especially:
  - `num_fields <= 8` / mask generation semantics
  - `mask[i] == (i < num_fields)`
  - inactive fields do not contribute to uniqueness or cost

**Step 2: Run each test to verify it fails for the expected reason**
Run targeted `cargo test` commands for the added tests.

**Step 3: Implement minimal AIR/trace changes**
- Add the missing constraints only.

**Step 4: Re-run the structural tests**
Expected: PASS

### Task 3: Audit `ballot_proof` semantic parity

**Files:**
- Modify: `src/air.rs`
- Modify: `src/trace.rs`
- Modify: `src/columns.rs`
- Modify: `tests/ballot_e2e.rs`
- Reference: `resources/davinci-circom/circuits/ballot_proof.circom`
- Reference: `resources/davinci-circom/circuits/ballot_cipher.circom`
- Reference: `resources/davinci-circom/circuits/lib/vote_id.circom`

**Step 1: Write failing parity tests around statement binding**
- Add tests that tamper with the STARK trace to check whether the proof still verifies when these relations are broken:
  - packed ballot mode unpacking path
  - vote-id derivation path
  - ciphertext/hash composition path
  - any relation between derived ciphertext material and `inputs_hash`

**Step 2: Run the new tests to determine the exact missing bindings**
- Use the failing tests as the authoritative gap list.

**Step 3: Implement minimal binding changes**
- Add only the columns and AIR constraints required to bind the missing `ballot_proof` relations.

**Step 4: Re-run the statement-binding tests**
Expected: PASS

### Task 4: Reproduce the Circom full-proof intent in STARK tests

**Files:**
- Modify: `tests/ballot_e2e.rs`
- Reference: `resources/davinci-circom/test/ballot_proof_test.go`
- Reference: `resources/davinci-circom/test/testutils/ballot_vectors.go`

**Step 1: Write a valid full-ballot proof test using the same semantic pattern**
- Use a fixed valid ballot vector in the STARK representation.
- Assert proof generation and verification succeed.
- Assert returned outputs are internally consistent with the ballot mode and public values.

**Step 2: Run the test**
Run: `cargo test --test ballot_e2e test_circom_style_full_ballot_proof -- --nocapture`
Expected: PASS

### Task 5: Final verification

**Files:**
- Modify: `README.md` only if the implemented parity changes alter documented guarantees.

**Step 1: Run full targeted verification**
Run:
- `cargo test --test ballot_e2e -- --nocapture`
- `cargo test --test poseidon2_test -- --nocapture`
- `cargo test --test ec_test -- --nocapture`
- `cargo check --target wasm32-unknown-unknown`

**Step 2: Summarize parity status**
- Explicitly list which Circom `ballot_checker` and `ballot_proof` constraints are now matched.
- Call out any intentionally adapted semantics caused by the Goldilocks/ecgfp5 representation.
