# Ballot Proof Parity Final Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Complete the remaining Circom `ballot_proof` statement bindings in the STARK circuit by proving `vote_id` consistency and binding the statement public key / ciphertexts to the EC phases and public hash path.

**Architecture:** Extend the hidden shared statement carried across the trace with the exact values that Circom treats as statement-level objects: the derived `vote_id`, the encryption public key, and the per-field ciphertext points. Add adversarial mixed-trace tests first, then add the minimal trace columns and AIR constraints that force the vote-id Poseidon section and EC phases to agree with those shared values. Keep the current sectioned STARK architecture; match Circom semantics, not its component layout.

**Tech Stack:** Rust, Plonky3 STARK AIR, existing `tests/ballot_e2e.rs`, `src/air.rs`, `src/trace.rs`, `src/columns.rs`, README documentation.

### Task 1: Add failing tests for the remaining statement bindings

**Files:**
- Modify: `tests/ballot_e2e.rs`
- Reference: `resources/davinci-circom/circuits/ballot_proof.circom`
- Reference: `resources/davinci-circom/circuits/ballot_cipher.circom`
- Reference: `resources/davinci-circom/circuits/lib/vote_id.circom`

**Step 1: Write the failing tests**
- Add a mixed-trace test proving `vote_id` public value must bind to the vote-id Poseidon section.
- Add a mixed-trace test proving the statement public key must bind to the EC phases that compute `k_i * PK`.
- Add a mixed-trace test proving the statement ciphertext outputs must bind to the EC phase outputs for `C1` and `C2`.

**Step 2: Run the targeted tests to verify they fail**
Run:
- `cargo test --test ballot_e2e test_vote_id_public_value_must_bind_to_poseidon_section -- --nocapture`
- `cargo test --test ballot_e2e test_public_key_must_bind_to_ec_cipher_phases -- --nocapture`
- `cargo test --test ballot_e2e test_ciphertexts_must_bind_to_ec_phase_outputs -- --nocapture`
Expected: FAIL because the current circuit does not bind these statement values tightly enough.

**Step 3: Do not change production code until the failures are confirmed**

### Task 2: Bind vote_id to the vote-id Poseidon section

**Files:**
- Modify: `src/columns.rs`
- Modify: `src/trace.rs`
- Modify: `src/air.rs`
- Test: `tests/ballot_e2e.rs`

**Step 1: Add trace support for the vote-id output row**
- Add a selector column for the final vote-id Poseidon output row, analogous to the existing `inputs_hash` output selector.
- Mark the unique vote-id output gap row during trace generation.

**Step 2: Add the AIR binding**
- Constrain the vote-id output selector to be binary and section-disjoint.
- Constrain the selected Poseidon output row to equal the claimed public `vote_id` after the Circom truncation rule.
- Add any helper columns needed for truncation consistency if the direct equality to the already truncated shared value is insufficient.

**Step 3: Run the targeted vote-id test**
Run: `cargo test --test ballot_e2e test_vote_id_public_value_must_bind_to_poseidon_section -- --nocapture`
Expected: PASS

### Task 3: Bind BallotCipher statement values to the EC phases

**Files:**
- Modify: `src/columns.rs`
- Modify: `src/trace.rs`
- Modify: `src/air.rs`
- Test: `tests/ballot_e2e.rs`

**Step 1: Extend the hidden shared statement**
- Add shared hidden columns for:
  - encryption public key coordinates
  - per-field `C1` point encodings
  - per-field `C2` point encodings
- Replicate them across all rows in trace generation.

**Step 2: Bind the EC phases to the shared statement**
- Constrain phase `3i` output to equal statement `C1_i`.
- Constrain phase `3i+1` base point to equal the statement public key and its output to equal the shared `S_i` / ciphertext-derived statement path.
- Constrain phase `3i+2` output to equal `M_i` and use it in the `C2_i = M_i + S_i` relation.
- Add the minimal additional hidden state needed to check `C2_i = M_i + S_i` inside the AIR.

**Step 3: Run the targeted cipher tests**
Run:
- `cargo test --test ballot_e2e test_public_key_must_bind_to_ec_cipher_phases -- --nocapture`
- `cargo test --test ballot_e2e test_ciphertexts_must_bind_to_ec_phase_outputs -- --nocapture`
Expected: PASS

### Task 4: Re-run parity tests and document the proved statement

**Files:**
- Modify: `README.md`
- Test: `tests/ballot_e2e.rs`

**Step 1: Run focused verification**
Run:
- `cargo test --test ballot_e2e circom_ballot_checker -- --nocapture`
- `cargo test --test ballot_e2e test_circom_style_full_ballot_proof -- --nocapture`
- `cargo test --test ballot_e2e test_vote_id_public_value_must_bind_to_poseidon_section -- --nocapture`
- `cargo test --test ballot_e2e test_public_key_must_bind_to_ec_cipher_phases -- --nocapture`
- `cargo test --test ballot_e2e test_ciphertexts_must_bind_to_ec_phase_outputs -- --nocapture`
- `cargo test --test ballot_e2e test_inputs_hash_public_values_must_bind_to_poseidon_section -- --nocapture`

**Step 2: Update README precisely**
- Describe the exact statement now proved by the STARK.
- Separate clearly:
  - private witness values
  - hidden shared statement values inside the trace
  - public outputs `{inputs_hash, address, vote_id}`
- Document the Circom-equivalent logic for ballot validity, vote ID derivation, ciphertext correctness, and inputs-hash consistency.

**Step 3: Final compile checks**
Run:
- `cargo test --tests --no-run`
- `cargo check --target wasm32-unknown-unknown`
Expected: PASS
