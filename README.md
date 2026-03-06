# DAVINCI zkSTARK Ballot Proof

A zero-knowledge STARK ballot proof for the [DAVINCI](https://github.com/vocdoni) e-voting
protocol. Replaces the Circom/Groth16 zkSNARK circuit (`davinci-circom`) with a STARK proof
built on [Plonky3](https://github.com/Plonky3/Plonky3), compiled to WebAssembly so voters
can generate proofs directly in the browser.

## Status

**Proof of Concept** -- exploratory implementation, not audited, not production-ready.
Security parameters are intentionally low for fast iteration.

### What works

- Full 8-field ElGamal encryption verification inside the STARK
- Poseidon2 hashing: k-derivation chain, vote ID, inputs hash
- Zero-knowledge proofs via HidingFriPcs (private inputs are hidden)
- WASM build (~800 KB) runs in browsers with a Web Worker for non-blocking proving
- Public values match Circom circuit: {inputs_hash, address, vote_id}
- 20 passing tests (3 E2E ballot, 2 EC, 2 Fibonacci, 3 GF(p^5), 7 Poseidon2, 3 lib)

### What is missing

- Ballot validation constraints (range checks, uniqueness, cost/sum bounds) -- the
  BallotChecker from Circom is not yet ported
- Security parameters are minimal (2 FRI queries, 1 PoW bit) -- roughly 31 bits of security
- No audit or formal verification
- The deterministic RNG used for blinding must be replaced with a real CSPRNG in production
- Proof aggregation and recursive verification not yet implemented

---

## Architecture

### Cryptographic stack

| Component | Implementation | Field |
|---|---|---|
| STARK prover | [Plonky3](https://github.com/Plonky3/Plonky3) p3-miden-prover v0.4.2 | Goldilocks (p = 2^64 - 2^32 + 1) |
| Polynomial commitment | HidingFriPcs (FRI with blinding) | ZK = true |
| Hash function | Poseidon2 (width 8, degree 7, 30 rounds) | Goldilocks |
| Elliptic curve | [ecgfp5](https://github.com/pornin/ecgfp5) Jacobi quartic over GF(p^5) | GF(p^5) extension |
| Encryption | ElGamal over ecgfp5 | -- |
| Extension field | BinomialExtensionField(Goldilocks, 2) | Degree-2 extension |

### Why ecgfp5?

ecgfp5 is specifically designed to be STARK-friendly. It lives over GF(p^5) where p is the
Goldilocks prime, so all curve arithmetic -- point addition, doubling, scalar multiplication --
can be written as polynomial constraints directly in the native STARK field. No range checks,
no non-native field emulation. This is far cheaper than trying to do BabyJubJub inside
Goldilocks (which would need BN254 scalar field emulation).

---

## The STARK Circuit

### Trace layout

The execution trace is a 4096 x 180 matrix over the Goldilocks field. Rows are split
into sections using two binary flags, IS_EC and IS_P2:

```
+---------------------------------------------+
|  EC Section (IS_EC=1, IS_P2=0)              |
|  24 scalar multiplications x 64 bits each   |
|  = 1,536 rows                               |
+---------------------------------------------+
|  Poseidon2 Section (IS_EC=0, IS_P2=1)       |
|  ~40 permutations x 31 rows each            |
|  = ~1,240 rows                              |
+---------------------------------------------+
|  Padding (IS_EC=0, IS_P2=0)                 |
|  Fills up to the next power of 2 (4,096)    |
+---------------------------------------------+
```

### EC Section: ElGamal encryption (24 scalar multiplications)

For each of the 8 vote fields the circuit does 3 scalar multiplications:

1. C1_i = k_i * G -- encryption randomness times the generator
2. S_i  = k_i * PK -- encryption randomness times the public key
3. M_i  = field_i * G -- vote value times the generator

Then C2_i = M_i + S_i (point addition, verified through the public values).

Each scalar mul processes one bit per row with double-and-add. Derived keys (k_i) are
64-bit Goldilocks elements, so we use 64-bit scalar muls instead of full 319-bit ones.
This brings the EC section from 7,656 rows down to 1,536.

**Column layout per EC row (180 columns):**
- Accumulator point (X:Z:U:T) -- 20 columns (4 x GF(p^5) limbs)
- Base point (X:Z:U:T) -- 20 columns
- Scalar bit -- 1 column
- Doubled point + 9 doubling intermediates -- 65 columns
- Added point + 10 addition intermediates -- 70 columns
- Phase ID, IS_LAST_IN_PHASE, IS_EC, IS_P2 -- 4 columns

**Constraints enforced per row:**
- Point doubling: DBL = double(ACC) -- 9 GF(p^5) product constraints
- Point addition: ADD = add(DBL, BASE) -- 10 GF(p^5) product constraints
- Accumulator transition: next.ACC = bit ? ADD : DBL (multiplexer)
- Bit is binary: BIT * (1 - BIT) = 0
- Phase stays constant within a scalar mul
- Base point stays constant within a phase

### Poseidon2 Section: hashing

Poseidon2 operates on width-8 states over Goldilocks with degree-7 S-boxes and
30 rounds (4 full + 22 partial + 4 full).

**Columns (overlapping with EC through section gating):**
- P2_STATE[0..7] -- 8 Goldilocks state elements
- P2_ROUND -- round index (0..29)
- P2_ROUND_TYPE -- 0 = full round, 1 = partial round
- P2_PERM_ID -- which permutation call this row belongs to
- P2_SBOX_X2[0..7], P2_SBOX_X3[0..7], P2_SBOX_X6[0..7] -- S-box intermediates

**S-box degree decomposition:**
The S-box computes x^7. We decompose it to keep constraint degree at most 7
(compatible with FRI blowup factor 8):
```
x2 = x + round_constant    (degree 1)
x3 = x2^2                  (degree 2, constrained)
x6 = x2 * x3               (degree 3, constrained)
x7 = x3^2 * x6             (degree 3, computed inline, not stored)
```
Maximum constraint degree: 3 (inline x7) x 2 (binary flag gating) + 1 = 7.

**Hash computations inside the trace:**
1. K-derivation chain (8 permutations): k_1 = P2([k_limbs, 0,0,0])[0], k_i = P2([k_{i-1}, 0,...,0])[0]
2. Vote ID (2-4 permutations): sponge hash of (process_id, address, k_limbs)
3. Inputs hash (~28 permutations): sponge hash of all ballot data

### Public values (9 Goldilocks elements)

These match the Circom circuit public signals:

| Index | Name | Description |
|---|---|---|
| 0-3 | inputs_hash[4] | Poseidon2 hash committing to all private data |
| 4-7 | address[4] | Voter address (256-bit as 4 x Goldilocks) |
| 8 | vote_id | Deterministic vote identifier |

The inputs_hash covers: process_id, packed_ballot_mode, pk, address, vote_id,
all ciphertext points (C1, C2), and weight. This lets the verifier check that the
proof matches specific election parameters without seeing private data.

### Private inputs

| Input | Type | Description |
|---|---|---|
| k | 320-bit scalar | ElGamal encryption randomness |
| fields[8] | u64 x 8 | Vote field values (the actual choices) |
| pk | ecgfp5 point | Encryption public key |
| process_id | 4 x Goldilocks | Election identifier |
| weight | Goldilocks | Voter weight |
| packed_ballot_mode | 4 x Goldilocks | 248-bit packed ballot config |

---

## Zero-Knowledge: hiding private inputs

We use HidingFriPcs from Plonky3, which gives us real zero-knowledge properties:

- The PCS adds random blinding codewords to the committed trace polynomial evaluations
- Trace values at FRI query positions are masked, so the verifier cannot extract private
  witness data from the opened positions
- The ZK: bool = true flag in HidingFriPcs activates randomization in both commit()
  and commit_quotient()

Without HidingFriPcs, a standard STARK reveals actual trace values (scalar bits, Poseidon2
intermediate states) at opened query positions. For a voting protocol this would be
unacceptable -- it could leak vote choices, encryption randomness, or key material.

**Important caveat:** The PoC uses a deterministic RNG (splitmix64 seeded with a fixed
constant) for the blinding randomness. This is fine for testing but completely inadequate
for production. A real deployment must use a proper CSPRNG (e.g. OsRng) to generate
fresh randomness for every proof.

---

## Verification

Verification needs only the public values and the serialized proof bytes. The verifier:

1. Deserializes the proof (FRI commitments + query responses)
2. Rebuilds the STARK config (deterministic, same setup as the prover)
3. Symbolically evaluates AIR constraints at queried trace positions
4. Runs the FRI low-degree test
5. Checks public value boundary constraints

```rust
use davinci_stark::{verify_ballot, BallotProof};

let ballot_proof: BallotProof = /* deserialized from proof bytes */;

match verify_ballot(&ballot_proof) {
    Ok(()) => println!("Proof is valid!"),
    Err(e) => println!("Invalid proof: {:?}", e),
}
```

The verifier learns only the 9 public values (inputs_hash, address, vote_id).
Everything else -- vote choices, encryption keys, randomness -- stays hidden.

---

## Project structure

```
davinci-stark/
  src/
    air.rs          - AIR constraint definitions (~550 lines)
    columns.rs      - Trace column layout and index constants
    config.rs       - STARK configuration (HidingFriPcs, FRI params)
    ecgfp5_ops.rs   - ecgfp5 point doubling/addition for trace generation
    elgamal.rs      - ElGamal keygen/encrypt helpers
    gfp5.rs         - GF(p^5) arithmetic constraint helpers
    lib.rs          - Public API: prove_ballot, verify_ballot
    poseidon2.rs    - Poseidon2 permutation and sponge (with trace recording)
    trace.rs        - Trace generation (BallotInputs -> trace matrix)
    wasm.rs         - WASM bindings via wasm-bindgen
  tests/
    ballot_e2e.rs   - End-to-end ballot proof tests
    ec_test.rs      - EC scalar multiplication tests
    fibonacci_smoke.rs - Plonky3 integration smoke test
    gfp5_test.rs    - GF(p^5) multiplication constraint tests
    poseidon2_test.rs  - Poseidon2 STARK proof tests
  webapp/
    index.html      - Web UI (dark theme, ballot input form)
    src/
      main.js       - UI logic, input packing, worker communication
      worker.js     - Web Worker for non-blocking WASM proving
    vite.config.js  - Vite dev server configuration
    package.json    - JS dependencies
  pkg/              - WASM output (generated by wasm-pack build)
  Cargo.toml        - Rust dependencies
  Makefile          - Build commands
  README.md         - This file
```

---

## Dependencies

### Rust (Cargo)

| Crate | Version | Purpose |
|---|---|---|
| p3-miden-prover | 0.4.2 | STARK prover and verifier |
| p3-miden-air | 0.4.2 | AIR trait definitions |
| p3-miden-fri | 0.4.2 | FRI PCS (includes HidingFriPcs) |
| p3-goldilocks | 0.4.2 | Goldilocks field + Poseidon2 permutation |
| p3-field | 0.4.2 | Field traits |
| p3-matrix | 0.4.2 | Row-major matrix for traces |
| ecgfp5 | 0.1.0 (local) | ecgfp5 curve operations |
| serde | 1.x | Serialization |
| postcard | 1.0 | Compact binary serialization |
| wasm-bindgen | 0.2 | WASM bindings (wasm32 only) |
| console_error_panic_hook | 0.1 | Readable WASM panic messages |

### JavaScript (npm)

| Package | Purpose |
|---|---|
| vite | Dev server and bundler |

### Build tools

| Tool | Version | Purpose |
|---|---|---|
| Rust | >= 1.85 | Compiler (2024 edition) |
| wasm-pack | >= 0.14 | WASM build tool |
| Node.js | >= 18 | Webapp dev server |

---

## Building and running

### Prerequisites

```bash
# Rust (if not installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# wasm-pack
cargo install wasm-pack

# Webapp dependencies
cd webapp && npm install && cd ..
```

### Quick start

```bash
make build    # Build WASM package
make serve    # Install deps + start dev server on 0.0.0.0:5174
make test     # Run all Rust tests (native)
make clean    # Remove all build artifacts
```

### Manual commands

```bash
# Run native tests
cargo test --release

# Build WASM
wasm-pack build --target web --release

# Start webapp
cd webapp && npx vite --host 0.0.0.0
```

---

## Performance

| Metric | Value | Notes |
|---|---|---|
| Trace size | 4,096 x 180 | -- |
| Native prove time | ~15s | Release mode, single-threaded |
| Native verify time | ~1ms | Release mode |
| WASM prove time | ~60-90s (estimated) | Browser Web Worker |
| WASM binary size | ~800 KB | wasm-opt disabled (see Restrictions) |
| Proof size | ~100-150 KB | Depends on trace |

HidingFriPcs (ZK mode) roughly doubles proving time compared to non-hiding mode because
the trace gets doubled internally for blinding.

---

## Security considerations

### Current parameters (PoC only)

| Parameter | Value | Notes |
|---|---|---|
| FRI blowup | 8 (log2 = 3) | Minimum for degree-7 constraints |
| FRI queries | 2 | Very low -- roughly 31 bits of security |
| Proof-of-work bits | 1 | Negligible grinding |
| Blinding codewords | 1 | Enough for ZK |
| Extension degree | 2 | Quadratic extension |

### Production recommendations

For real deployments, bump the security parameters:

```rust
let fri_params = FriParameters {
    log_blowup: 3,
    num_queries: 28,        // ~100 bits of security
    proof_of_work_bits: 16, // 16 bits of grinding
    // ...
};
```

This will make proofs bigger and slower to verify, but that is the price for actual security.

### Assumptions

1. **Goldilocks field security**: The Goldilocks prime (2^64 - 2^32 + 1) gives ~64 bits of
   field security. The degree-2 extension raises this to ~128 bits.
2. **ecgfp5 curve**: Group order is roughly 2^319, so ~160-bit discrete log security.
3. **Poseidon2**: Width 8, degree 7, 30 rounds (8 full + 22 partial). Round constants come
   from a fixed seed (42). Production should use published/standardized constants.
4. **Deterministic RNG**: Both Poseidon2 constants and HidingFriPcs blinding use splitmix64
   with fixed seeds. The blinding RNG **must** be replaced with a real CSPRNG in production.

### Restrictions

- The `unsafe impl Sync` on SyncBallotConfig is only safe for single-threaded usage. Do not
  enable the `parallel` Cargo feature without replacing this with proper synchronization.
- wasm-opt is disabled in Cargo.toml because wasm-opt v108 corrupts WebAssembly.Table
  entries. Re-enable once a fixed version is available.
- Vote field values must fit in 64 bits (u64). The 64-bit scalar mul optimization assumes
  derived keys and field values are below 2^64.

---

## Comparison with davinci-circom

| Aspect | davinci-circom (zkSNARK) | davinci-stark (this project) |
|---|---|---|
| Proof system | Groth16 (snarkjs) | STARK (Plonky3) |
| Curve | BabyJubJub / BN254 | ecgfp5 / Goldilocks |
| Hash | Poseidon (BN254 scalar field) | Poseidon2 (Goldilocks) |
| Trusted setup | Required (powers of tau) | None (transparent) |
| Proof size | ~200 bytes | ~100-150 KB |
| Prover time (browser) | ~10-30s | ~60-90s |
| Verifier time | ~5ms | ~1ms (native) |
| Post-quantum | No | Plausibly yes |
| Aggregation | Not native | FRI-based recursion possible |

The main advantages of STARK over SNARK for voting are the transparent setup (no trusted
ceremony needed) and potential for post-quantum security.

---

## References

- [DAVINCI Protocol Specification](https://vocdoni.github.io/davinci-paper/)
- [Plonky3](https://github.com/Plonky3/Plonky3) -- STARK framework
- [ecgfp5](https://github.com/pornin/ecgfp5) -- STARK-friendly elliptic curve
- [On the Applicability of STARKs to e-Voting](https://fc24.ifca.ai/voting/papers/Voting24_HH_On_the_Applicability_of_STARKs_to_Counted-as-Collected_Verification_in_Exisitng_Homomorphically_E-Voting_Systems.pdf) -- academic reference for STARK-based ballot verification
- [Poseidon2 paper](https://eprint.iacr.org/2023/323) -- hash function specification


