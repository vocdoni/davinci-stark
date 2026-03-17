# Circuit Security Remediation Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make the ballot STARK actually prove the intended ballot statement by eliminating the current underconstraints and adding adversarial regression tests.

**Architecture:** The current AIR verifies local EC, Poseidon2, and ballot-validation consistency, but it does not bind those subcircuits into one statement. The fix is to add explicit public-value constraints, constrain Poseidon2 round constants and permutation structure, constrain EC phase boundaries and outputs, constrain ballot-validation row structure, and then add cross-section links so the trace, hashes, ciphertexts, and public values all describe the same ballot.

**Tech Stack:** Rust, Plonky3 (`p3-air`, `p3-uni-stark`, `p3-fri`), custom AIR/trace generation, `cargo test`.

### Task 1: Public-value binding

**Files:**
- Modify: `src/air.rs`
- Modify: `src/lib.rs`
- Test: `tests/ballot_e2e.rs`

**Step 1: Write the failing test**

Add a test that proves a trace with intentionally mismatched public values and expects verification to fail because the AIR binds trace outputs to public values.

```rust
#[test]
fn test_public_values_must_match_trace_outputs() {
    let inputs = valid_inputs();
    let (trace, mut pv, outputs) = generate_full_ballot_trace(&inputs);
    pv[PV_VOTE_ID] = outputs.vote_id + Goldilocks::ONE;

    let config = make_config();
    let proof = prove(&config, &BallotAir::new(), trace, &pv);
    assert!(verify(&config, &BallotAir::new(), &proof, &pv).is_err());
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --test ballot_e2e test_public_values_must_match_trace_outputs -- --nocapture`
Expected: FAIL because the current AIR accepts the proof.

**Step 3: Write minimal implementation**

- Implement the upstream Plonky3 public-values interface for `BallotAir`.
- Add constraints that the trace-exported `inputs_hash`, `address`, and `vote_id` equal the public values.
- Introduce explicit trace cells or boundary rows for those exported values if needed.

**Step 4: Run test to verify it passes**

Run: `cargo test --test ballot_e2e test_public_values_must_match_trace_outputs -- --nocapture`
Expected: PASS.

**Step 5: Commit**

```bash
git add src/air.rs src/lib.rs tests/ballot_e2e.rs
git commit -m "fix: bind public values to ballot trace"
```

### Task 2: Poseidon2 round-function constraints

**Files:**
- Modify: `src/air.rs`
- Modify: `src/trace.rs`
- Test: `tests/poseidon2_test.rs`
- Test: `tests/ballot_e2e.rs`

**Step 1: Write the failing test**

Add a test that generates a valid Poseidon trace, tampers `P2_SBOX_X2` or `P2_ROUND_TYPE`, and expects verification to fail.

```rust
#[test]
fn test_poseidon_x2_must_match_state_plus_round_constant() {
    let (mut trace, pv) = generate_poseidon2_trace(&[input], &constants);
    trace.values[row * TRACE_WIDTH + P2_SBOX_X2] += Goldilocks::ONE;
    let config = make_config();
    let proof = prove(&config, &BallotAir::new(), trace, &pv);
    assert!(verify(&config, &BallotAir::new(), &proof, &pv).is_err());
}
```

Add a second failing test that tampers a round-type/full-partial schedule bit.

**Step 2: Run tests to verify they fail**

Run:
- `cargo test --test poseidon2_test test_poseidon_x2_must_match_state_plus_round_constant -- --nocapture`
- `cargo test --test poseidon2_test test_poseidon_round_schedule_is_fixed -- --nocapture`
Expected: FAIL because the current AIR does not constrain these relations.

**Step 3: Write minimal implementation**

- Constrain `x2` to equal `state + rc` in full rounds and `state[0] + rc` / zero elsewhere in partial rounds.
- Constrain `P2_ROUND` to increment from `0..29` within a permutation.
- Constrain `P2_ROUND_TYPE` to match the fixed schedule `FFFF PPP...P FFFF`.
- Constrain `P2_PERM_ID` to be constant inside a permutation and increment at permutation boundaries if the column remains.
- Constrain the output row after each permutation if it is used as a link point; otherwise replace it with an explicit binding scheme.

**Step 4: Run tests to verify they pass**

Run the two targeted tests again.
Expected: PASS.

**Step 5: Commit**

```bash
git add src/air.rs src/trace.rs tests/poseidon2_test.rs tests/ballot_e2e.rs
git commit -m "fix: fully constrain poseidon2 rounds"
```

### Task 3: EC phase boundaries and outputs

**Files:**
- Modify: `src/air.rs`
- Modify: `src/trace.rs`
- Test: `tests/ec_test.rs`
- Test: `tests/ballot_e2e.rs`

**Step 1: Write the failing test**

Add a test that tampers the base point or starting accumulator on the first row of a later EC phase and expects verification to fail.

```rust
#[test]
fn test_ec_phase_start_is_constrained() {
    let (mut trace, pv, _) = generate_full_ballot_trace(&inputs);
    let row = second_phase_first_row();
    trace.values[row * TRACE_WIDTH + ACC_Z] += Goldilocks::ONE;
    let config = make_config();
    let proof = prove(&config, &BallotAir::new(), trace, &pv);
    assert!(verify(&config, &BallotAir::new(), &proof, &pv).is_err());
}
```

Add a second failing test that tampers a base-point limb mid-phase.

**Step 2: Run tests to verify they fail**

Run the targeted EC tests.
Expected: FAIL because the current AIR does not constrain phase starts or base-point constancy.

**Step 3: Write minimal implementation**

- Constrain `PHASE` to be fixed inside a phase and advance only at phase boundaries.
- Constrain each phase’s first row accumulator to the neutral point.
- Constrain base point constancy within each phase.
- Add explicit per-phase output export cells or boundary rows so each phase result is available for later cross-linking.

**Step 4: Run tests to verify they pass**

Run the targeted EC tests again.
Expected: PASS.

**Step 5: Commit**

```bash
git add src/air.rs src/trace.rs tests/ec_test.rs tests/ballot_e2e.rs
git commit -m "fix: constrain ec phases and outputs"
```

### Task 4: Ballot-validation row structure

**Files:**
- Modify: `src/air.rs`
- Modify: `src/trace.rs`
- Test: `tests/ballot_e2e.rs`

**Step 1: Write the failing test**

Add tests that tamper:
- `BV_ROW_INDEX`
- `BV_MASK`
- `BV_IS_BOUNDS`
- `BV_SQ` so it no longer equals `BV_FIELDS[row_idx]`

Each test should expect verification to fail.

**Step 2: Run tests to verify they fail**

Run the targeted ballot-validation tests.
Expected: FAIL because the current AIR does not constrain row structure tightly enough.

**Step 3: Write minimal implementation**

- Constrain `BV_ROW_INDEX` to run `0..7` on field rows and `8` on the bounds row.
- Constrain `BV_IS_BOUNDS` to be zero on field rows and one exactly on the bounds row.
- Constrain `BV_MASK` to equal `[row_idx < num_fields]`.
- Constrain `BV_SQ[0]` to equal the selected `BV_FIELDS[row_idx]` via per-row selectors.
- Constrain there to be exactly one bounds row at the end of the BV segment.

**Step 4: Run tests to verify they pass**

Run the targeted ballot-validation tests again.
Expected: PASS.

**Step 5: Commit**

```bash
git add src/air.rs src/trace.rs tests/ballot_e2e.rs
git commit -m "fix: constrain ballot validation row structure"
```

### Task 5: Cross-section statement binding

**Files:**
- Modify: `src/air.rs`
- Modify: `src/trace.rs`
- Possibly modify: `src/columns.rs`
- Test: `tests/ballot_e2e.rs`

**Step 1: Write the failing test**

Add adversarial tests that tamper one section while leaving the others honest:
- alter a derived `k_i` relation while keeping EC rows internally valid
- alter exported EC outputs used for `inputs_hash`
- alter `vote_id` truncation/output wiring
- alter BV fields independently from encrypted fields

Each test should expect verification to fail.

**Step 2: Run tests to verify they fail**

Run the new targeted tests.
Expected: FAIL because the current AIR does not link the sections.

**Step 3: Write minimal implementation**

Introduce explicit statement-binding rows/columns that export and link:
- Poseidon k-chain outputs to EC phase scalars
- EC phase outputs to ciphertext limbs
- vote-id hash output to the published `vote_id`
- ballot mode / address / weight / process id inputs to the hashed statement
- BV field values to the encrypted field values if those are intended to match directly

Prefer a single dedicated binding section or dedicated boundary rows instead of implicit reuse of unconstrained padding rows.

**Step 4: Run tests to verify they pass**

Run the new targeted tests.
Expected: PASS.

**Step 5: Commit**

```bash
git add src/air.rs src/trace.rs src/columns.rs tests/ballot_e2e.rs
git commit -m "fix: bind ec poseidon and ballot sections"
```

### Task 6: Verification and documentation

**Files:**
- Modify: `README.md`
- Test: `tests/ballot_e2e.rs`
- Test: `tests/poseidon2_test.rs`
- Test: `tests/ec_test.rs`

**Step 1: Write the failing test**

If any remaining security invariants are undocumented in tests, add them now. Examples:
- proof rejects mismatched public values
- proof rejects poseidon round tampering
- proof rejects phase-boundary tampering
- proof rejects BV row tampering

**Step 2: Run tests to verify they fail**

Run only the new tests.
Expected: FAIL before the final code/doc updates if any invariant is still missing.

**Step 3: Write minimal implementation**

- Update README security section to describe the exact statement now proved.
- Document the new binding rows/sections and the adversarial tests.

**Step 4: Run tests to verify they pass**

Run:
- `cargo test --test poseidon2_test -- --nocapture`
- `cargo test --test ec_test -- --nocapture`
- `cargo test --test ballot_e2e -- --nocapture`
- `cargo test --tests --no-run`

Expected: PASS.

**Step 5: Commit**

```bash
git add README.md tests/poseidon2_test.rs tests/ec_test.rs tests/ballot_e2e.rs
git commit -m "docs: describe constrained ballot statement"
```
