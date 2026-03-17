# ZKVM Batch Scaling Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Remove legacy-service compatibility behavior, make STARK batch generation scale correctly to the configured batch size, and add bounded parallel proof generation while keeping the active STARK/ecgfp5 path consistent end to end.

**Architecture:** Fix the current service contract mismatch first (`overwritten_ballots` must be an empty array, never `null`), then make the integration tests fail fast instead of silently treating contract errors as "legacy API". After that, introduce a single shared max-batch-size configuration that is enforced in Go, input generation, and the zkVM circuit, and finally parallelize ballot proof generation with a deterministic output order and a bounded worker pool.

**Tech Stack:** Go SDK/tests, Rust input-gen/service/circuit, davinci-stark WASM helper, environment-configurable batch sizing.

### Task 1: Remove false legacy compatibility behavior

**Files:**
- Modify: `davinci-zkvm/go-sdk/tests/integration/helpers.go`
- Modify: `davinci-zkvm/go-sdk/tests/integration/e2e_test.go`
- Modify: `davinci-zkvm/go-sdk/tests/integration/integration_test.go`
- Modify: `davinci-zkvm/go-sdk/tests/integration/csp_test.go`
- Modify: `davinci-zkvm/go-sdk/tests/integration/stark_e2e_test.go`
- Test: `davinci-zkvm/go-sdk/tests/integration/service_test.go`

**Step 1: Write the failing test**
- Add/adjust a test that proves service contract errors are treated as failures, not as a legacy skip path.

**Step 2: Run test to verify it fails**
- Run: `cd davinci-zkvm/go-sdk && go test ./tests/integration -run TestServiceContractErrorsAreNotLegacy -count=1`
- Expected: FAIL because `invalid type: null` is still classified as legacy.

**Step 3: Write minimal implementation**
- Remove the `invalid type: null` match from `isLegacyServiceError`.
- Replace `Skipf(...)` paths for the active STARK tests with hard failures when the service is online but returns a schema error.

**Step 4: Run test to verify it passes**
- Run the same test and confirm PASS.

### Task 2: Guarantee empty ballot overwrite arrays serialize as `[]`, never `null`

**Files:**
- Modify: `davinci-zkvm/go-sdk/tests/integration/election_stark.go`
- Test: `davinci-zkvm/go-sdk/tests/integration/stark_state_test.go`

**Step 1: Write the failing test**
- Add a test that builds a STARK state block with no overwritten ballots and asserts the request JSON contains `"overwritten_ballots":[]`.

**Step 2: Run test to verify it fails**
- Run: `cd davinci-zkvm/go-sdk && go test ./tests/integration -run TestBuildStarkStateBlockUsesEmptyOverwriteSlice -count=1`
- Expected: FAIL because the field serializes as `null`.

**Step 3: Write minimal implementation**
- Initialize overwrite slices with `make(..., 0)` instead of `nil`.
- Check any similar state payload slices that must be encoded as arrays.

**Step 4: Run test to verify it passes**
- Run the same test and confirm PASS.

### Task 3: Make batch-size configuration explicit and shared

**Files:**
- Modify: `davinci-zkvm/go-sdk/types.go`
- Modify: `davinci-zkvm/go-sdk/tests/integration/helpers.go`
- Modify: `davinci-zkvm/input-gen/src/lib.rs`
- Modify: `davinci-zkvm/circuit/src/types.rs`
- Modify: `davinci-zkvm/circuit/src/io.rs`
- Test: `davinci-zkvm/go-sdk/tests/integration/helpers_test.go`
- Test: `davinci-zkvm/input-gen/src/lib.rs` tests or dedicated unit test
- Test: `davinci-zkvm/circuit/tests/stark_input.rs`

**Step 1: Write the failing tests**
- Add tests that:
  - read the configured max batch size from env/build config
  - allow `128` when configured
  - reject larger values than the configured limit

**Step 2: Run tests to verify they fail**
- Run focused Go and Rust tests.

**Step 3: Write minimal implementation**
- Introduce one named configuration variable for max batch size:
  - Go runtime env for integration helpers
  - Rust build-time env/constant for `input-gen` and `circuit`
- Keep the validation rules: power-of-two, at least 2, at most configured limit.

**Step 4: Run tests to verify they pass**
- Run focused Go and Rust tests.

### Task 4: Parallelize STARK ballot proof generation with bounded concurrency

**Files:**
- Modify: `davinci-zkvm/go-sdk/tests/integration/stark_ballot.go`
- Modify: `davinci-zkvm/go-sdk/tests/integration/helpers.go`
- Test: `davinci-zkvm/go-sdk/tests/integration/stark_ballot_test.go`

**Step 1: Write the failing tests**
- Add tests that:
  - derive concurrency from env with default `8`
  - preserve deterministic output order
  - can generate a full `VOTES_PER_BATCH=128` batch without short-circuiting to a smaller size

**Step 2: Run tests to verify they fail**
- Run focused Go tests.

**Step 3: Write minimal implementation**
- Add `DAVINCI_STARK_MAX_CONCURRENCY` with default `8`.
- Use a bounded worker pool/semaphore to run `node` ballot proofs concurrently.
- Preserve stable output ordering in returned arrays.

**Step 4: Run tests to verify they pass**
- Run focused Go tests.

### Task 5: Full verification and documentation

**Files:**
- Modify: `davinci-zkvm/circuit/CIRCUIT.md`
- Modify: `davinci-zkvm/go-sdk/README.md`
- Modify: code comments near batch/concurrency config

**Step 1: Run focused verification**
- `cargo test --manifest-path davinci-zkvm/input-gen/Cargo.toml`
- `cargo test --manifest-path davinci-zkvm/circuit/Cargo.toml`
- `cargo test --manifest-path davinci-zkvm/service/Cargo.toml`
- `cd davinci-zkvm/go-sdk && go test ./tests/integration -count=1`

**Step 2: Run full verification**
- `cd davinci-zkvm/go-sdk && go test ./... -count=1`
- `cargo test --tests`

**Step 3: Document the final behavior**
- Update docs to state:
  - no legacy API compatibility path remains for active tests
  - batch sizes are configurable but must be powers of two
  - proof generation uses bounded parallelism controlled by env
