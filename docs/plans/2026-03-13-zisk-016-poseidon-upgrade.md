# ZisK 0.16.0 Poseidon Upgrade Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Upgrade `davinci-zkvm` to ZisK `v0.16.0`, verify that the current STARK/ecgfp5 flow still works, and route the zkVM-side `davinci-stark` verifier through the new ZisK Poseidon2 precompile where it matches the width-16 Goldilocks verifier path.

**Architecture:** First upgrade every ZisK pin consistently (`ziskos`, Docker build images, local build docs) and verify the current code still compiles. Then add explicit compatibility tests showing that the width-16 Poseidon2 path used by the STARK verifier matches ZisK semantics. After that, introduce a target-specific width-16 Poseidon2 wrapper for the guest-side verifier path so the zkVM uses the syscall instead of pure software hashing. Do not remove `circuit/src/poseidon.rs` unless the BN254/idEn3 census path is also migrated or dropped; it is still active today via `census.rs`.

**Tech Stack:** Rust (`davinci-zkvm/circuit`, `davinci-stark`), ZisK `ziskos`, Docker, Goldilocks Poseidon2, Plonky3, ecgfp5.

### Task 1: Upgrade all ZisK pins to 0.16.0

**Files:**
- Modify: `davinci-zkvm/circuit/Cargo.toml`
- Modify: `davinci-zkvm/Dockerfile`
- Modify: `davinci-zkvm/Dockerfile.cuda`
- Modify: `davinci-zkvm/README.md`

**Step 1: Write the failing check**
- Confirm the repo is still pinned to `v0.15.0` and that the build/runtime docs mention the old version.

**Step 2: Run the check to verify current state**
- Run: `rg -n "v0\.15\.0|zisk.git" davinci-zkvm`
- Expected: hits in Cargo and Docker files.

**Step 3: Write minimal implementation**
- Bump the `ziskos` git tag to `v0.16.0`.
- Bump both Dockerfiles’ `ZISK_VERSION` args to `v0.16.0`.
- Update docs that mention the old version.

**Step 4: Run compile checks**
- `cargo check --manifest-path davinci-zkvm/circuit/Cargo.toml`
- `cargo check --manifest-path davinci-zkvm/service/Cargo.toml`

### Task 2: Prove width-16 Poseidon2 compatibility explicitly

**Files:**
- Create or modify: `davinci-zkvm/circuit/tests/poseidon2_zisk.rs`
- Modify if needed: `davinci-zkvm/circuit/src/hash.rs`
- Optional test helper: `src/poseidon2.rs` or a new shared wrapper

**Step 1: Write the failing test**
- Add a test that compares the width-16 Poseidon2 result used by the verifier path against ZisK `syscall_poseidon2` host semantics on deterministic vectors.

**Step 2: Run test to verify it fails or is absent**
- Run the focused test target.

**Step 3: Write minimal implementation**
- Add a small width-16 wrapper around the ZisK syscall.
- Keep the test runnable on non-zkVM targets by relying on ZisK’s host fallback implementation.

**Step 4: Run test to verify it passes**
- Run the focused poseidon compatibility tests.

### Task 3: Route the guest-side STARK verifier through the Poseidon2 syscall path

**Files:**
- Modify: `src/config.rs`
- Modify: `src/lib.rs`
- Modify: `davinci-zkvm/circuit/src/davinci_stark.rs`
- Add if needed: target-specific wrapper module under `src/` for width-16 Poseidon2

**Step 1: Write the failing test**
- Add or update a guest-side verifier test to exercise the Poseidon-heavy verification path while the target-specific syscall-backed wrapper is enabled.

**Step 2: Run test to verify it fails**
- Run focused `davinci-zkvm/circuit` tests.

**Step 3: Write minimal implementation**
- Introduce a target-specific width-16 Poseidon2 permutation/provider for the STARK verifier path.
- Keep native/browser builds using the current Plonky3 software path.
- Use the ZisK syscall only in the guest build where it is beneficial and compatible.

**Step 4: Run tests to verify it passes**
- Focused circuit tests plus root `davinci-stark` tests touching verification.

### Task 4: Reassess `circuit/src/poseidon.rs`

**Files:**
- Inspect: `davinci-zkvm/circuit/src/census.rs`
- Inspect: `davinci-zkvm/circuit/src/poseidon.rs`
- Inspect: `davinci-zkvm/circuit/CIRCUIT.md`

**Step 1: Write the failing/guarding test**
- If removal is attempted, add a census-path test proving whether the BN254/idEn3 Poseidon implementation is still required.

**Step 2: Decide based on evidence**
- If census mode remains supported and still uses iden3 Poseidon, keep `poseidon.rs` and document why.
- If census mode is migrated or dropped, remove `poseidon.rs` and its BN254 field helper dependencies.

**Step 3: Verify the decision**
- Run the affected circuit tests.

### Task 5: Full verification and docs

**Files:**
- Modify: `davinci-zkvm/circuit/CIRCUIT.md`
- Modify: `davinci-zkvm/README.md`
- Modify: `README.md`

**Step 1: Run verification**
- `cargo test --tests`
- `cargo test --manifest-path davinci-zkvm/circuit/Cargo.toml`
- `cargo test --manifest-path davinci-zkvm/service/Cargo.toml`
- `cargo test --manifest-path davinci-zkvm/input-gen/Cargo.toml`
- `cd davinci-zkvm/go-sdk && go test ./... -count=1`
- Rebuild Docker service if runtime verification depends on it.

**Step 2: Update documentation**
- State explicitly:
  - ZisK version `v0.16.0`
  - where the Poseidon2 syscall is used
  - which Poseidon implementations remain and why
  - whether BN254/idEn3 Poseidon is still required for census mode
