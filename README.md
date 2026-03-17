# DAVINCI zkSTARK Ballot Proof

A zero-knowledge STARK proof system for the [DAVINCI](https://github.com/vocdoni) e-voting
protocol. This project replaces the Circom/Groth16 zkSNARK circuit (`davinci-circom`) with a
transparent STARK proof built on [Plonky3](https://github.com/Plonky3/Plonky3), compiled to
WebAssembly so voters can generate proofs directly in the browser.

## Background: What is a STARK?

A **STARK** (Scalable Transparent ARgument of Knowledge) is a type of zero-knowledge proof
system. It allows a prover to convince a verifier that a computation was performed correctly
without revealing the inputs to that computation.

Concretely: a voter fills in their ballot (private), the prover generates a cryptographic
proof (~533 KB) that the ballot satisfies all election rules, and a verifier can check the
proof in milliseconds without ever seeing the vote choices.

### How STARKs work (simplified)

1. **Execution trace**: The computation is laid out as a 2D matrix. Each row represents a
   step of the computation, each column represents a register. For our ballot proof, this is
   a 2,048 × 379 matrix over the Goldilocks field.

2. **AIR constraints**: An Algebraic Intermediate Representation (AIR) defines polynomial
   equations that every pair of consecutive rows must satisfy. For example, "the next row's
   accumulator equals the current row's accumulator doubled, plus the base point if the
   scalar bit is 1." If the trace is valid (the computation was correct), these polynomials
   evaluate to zero everywhere.

3. **Low-degree testing (FRI)**: The prover commits to the trace via Merkle trees, then the
   verifier challenges the prover to prove that the constraint polynomials are indeed
   low-degree (which they would be if and only if the constraints hold everywhere). This is
   done through the **Fast Reed-Solomon Interactive Oracle Proof of Proximity (FRI)** protocol,
   where the polynomial is repeatedly folded in half until only a constant remains.

4. **Fiat-Shamir**: The interactive protocol is made non-interactive by deriving the
   verifier's random challenges from a hash of the prover's messages (using Poseidon2 as
   the hash function inside a duplex sponge challenger).

### Key properties

| Property | Explanation |
|---|---|
| **Zero-knowledge** | The proof reveals nothing about private inputs (vote choices, keys) |
| **Soundness** | A cheating prover cannot forge a valid proof for an invalid ballot |
| **Transparency** | No trusted setup ceremony required (unlike Groth16/SNARKs) |
| **Succinctness** | Verification is much faster than re-running the computation |
| **Post-quantum** | Based on hash functions and information-theoretic arguments, not elliptic curve pairings |

## Why STARKs for voting?

1. **No trusted setup**: A voting system must be trustworthy. Eliminating the need for a
   ceremony where secret "toxic waste" must be securely destroyed removes a significant
   trust assumption.

2. **Transparent verification**: Anyone can verify proofs using only public parameters.
   There are no secret keys involved in the verification process.

3. **Post-quantum security**: STARKs are based on hash functions (collision resistance),
   not on the hardness of discrete logarithms or pairings. They are believed to be
   resistant to quantum computer attacks.

4. **Aggregation potential**: STARK proofs can be recursively composed -- multiple ballot
   proofs can be aggregated into a single proof, enabling efficient batch verification
   via a zkVM such as [Zisk](https://github.com/0xPolygonHermez/zisk).

---

## What this project does

The current STARK proves the following:

1. **Ballot validity**: Each active vote field is within `[min_value, max_value]`, optional
   uniqueness is enforced, and the ballot cost bounds follow the ballot mode.
2. **Shared-witness consistency**: The same hidden ballot fields and derived `k_i` values are
   reused across the ballot-validation, Poseidon2, and EC sections.
3. **BallotCipher consistency**: For each field, the EC section proves
   `C1_i = k_i * G`, `S_i = k_i * PK`, `M_i = field_i * G`, and `C2_i = M_i + S_i`.
   The `k_i * PK` phases are bound to the shared election public key `PK`, and each
   `field_i * G` phase is followed by a dedicated C2 binding row that proves `C2_i = M_i + S_i`
   and binds the encoded `C1_i` / `C2_i` values reused by the hash section.
4. **Deterministic vote ID**: `vote_id` is derived from a constrained Poseidon2 sponge over
   `{process_id, address, k_limbs}` and then truncated as `trunc63(hash) + 2^63`.
5. **Inputs-hash consistency**: The full Circom-compatible `inputs_hash` preimage
   `{process_id, packed_ballot_mode, PK, address, vote_id, C1[0..7], C2[0..7], weight}`
   is public, AIR-bound to the trace, and recomputed by the verifier with the same
   Poseidon2 permutation.
6. **Public outputs**: The final row binds the entire public statement to the trace:
   `{inputs_hash, address, vote_id, inputs_hash_preimage}`.

These properties are enforced as AIR constraints in a Plonky3 STARK.

---

## Architecture

### What kind of STARK are we using?

We use **upstream Plonky3** (`p3-air`, `p3-uni-stark`, `p3-fri` at v0.4.2), which implements a
**uni-variate STARK over the Goldilocks field** with FRI-based polynomial commitment.

Key architectural choices:

- **Field**: Goldilocks (`p = 2^64 - 2^32 + 1`). This 64-bit prime is optimized for
  modern CPUs -- field multiplication reduces to a few native multiplies and shifts.
  All trace values, constraints, and hash computations use this field.

- **Extension field**: Degree-2 binomial extension of Goldilocks for the FRI challenge
  space. This gives ~128-bit security against algebraic attacks.

- **Polynomial commitment**: **HidingFriPcs** -- FRI with random blinding codewords.
  Standard FRI reveals trace values at queried positions; HidingFriPcs adds random
  noise so the verifier learns nothing about the witness. This is essential for ZK.

- **AIR model**: We write constraints as an Algebraic Intermediate Representation.
  The trace is a single matrix. Constraints are polynomial equations over pairs of
  consecutive rows (`local` and `next`). Different "sections" of the trace (EC, Poseidon2,
  ballot validation) are gated by binary flags so they don't interfere.

- **Challenger**: Duplex sponge based on width-16 Poseidon2 over Goldilocks. This
  generates all Fiat-Shamir challenges (used internally by the STARK prover/verifier,
  separate from the width-8 Poseidon2 used in the ballot circuit).
  This repository uses the ZisK-compatible width-16 `Poseidon16` constant set for
  transcript and Merkle hashing, not the upstream Plonky3 `new_from_rng_128` width-16
  generator.

### Cryptographic components

| Component | Implementation | Details |
|---|---|---|
| STARK prover/verifier | Plonky3 `p3-uni-stark` v0.4.2 | Uni-variate FRI-based STARK |
| Polynomial commitment | HidingFriPcs (FRI + blinding) | ZK = true, entropy-seeded RNG |
| Hash (ballot circuit) | Poseidon2 width-8 | Zisk-compatible (Horizen Labs constants) |
| Hash (STARK infra) | Poseidon2 width-16 | ZisK-compatible `Poseidon16` permutation for Merkle tree hashing and Fiat-Shamir |
| Elliptic curve | [ecgfp5](https://github.com/pornin/ecgfp5) | Jacobi quartic over GF(p^5) |
| Encryption | ElGamal over ecgfp5 | 3 scalar muls per vote field |
| Serialization | postcard (compact binary) | Proof wire format |

### Why ecgfp5?

The DAVINCI protocol uses ElGamal encryption, which requires elliptic curve operations inside
the proof circuit. The challenge is that STARK arithmetic happens in the Goldilocks field, but
most standard curves (BabyJubJub, secp256k1) live over different fields. Emulating a foreign
field inside a STARK is extremely expensive (hundreds of range checks per multiplication).

**ecgfp5** solves this by defining an elliptic curve over `GF(p^5)` where `p` is the
Goldilocks prime itself. Since `GF(p^5)` is a degree-5 algebraic extension of the STARK's
base field, all curve arithmetic -- point addition, doubling, scalar multiplication -- can
be expressed as polynomial constraints directly over Goldilocks. No range checks, no
non-native field emulation.

The curve is a Jacobi quartic with ~319-bit group order, providing ~160-bit discrete log
security. Each GF(p^5) element is stored as 5 Goldilocks limbs, so a curve point in
extended coordinates (X:Z:U:T) uses 20 columns.

## The STARK Circuit

### How the circuit is built

Rather than using a high-level circuit DSL, we write the AIR constraints directly in Rust
using Plonky3's `AirBuilder` API. This gives us full control over the trace layout,
constraint degree, and column reuse.

The process:

1. **Trace generation** (`trace.rs`): Given the ballot inputs, we execute the entire
   computation (scalar multiplications, Poseidon2 hashes, range checks) in Rust and record
   every intermediate value into a 2D matrix. This is the "execution trace."

2. **Constraint definition** (`air.rs`): We define polynomial equations that relate
   consecutive rows of the trace. The Plonky3 prover evaluates these constraints
   symbolically and proves (via FRI) that they hold everywhere.

3. **Public values**: 123 Goldilocks elements are exposed to the verifier:
   `inputs_hash[4]`, `address[4]`, `vote_id`, and the 114-element `inputs_hash` preimage.
   These are bound on a dedicated final output row in the trace.

4. **Hidden cross-section bindings**: Additional private columns replicate the shared ballot
   statement across the trace: derived `k_i` values, ballot field values, ballot-mode data,
   and the original `k` limbs. The AIR binds Poseidon outputs, EC scalar bits,
   ballot-validation rows, dedicated C2 binding rows, and the public preimage to those shared values.

### Trace layout

The execution trace is a **2,048 × 379 matrix** over Goldilocks. Rows are divided into
dedicated sections using binary flag columns (`IS_EC`, `IS_P2`, `IS_BV`) plus a small
unflagged prefix for packed-ballot decoding:

```
Row 0                                                Row 2047
┌─────────────────────────────────────────────────────────────┐
│  Packed-mode rows (all flags = 0)                           │
│  4 rows                                                      │
│  → Exact in-circuit unpacking of `packed_ballot_mode`       │
├─────────────────────────────────────────────────────────────┤
│  EC Section (IS_EC=1)                                       │
│  24 scalar multiplications × 64 rows + 8 C2 binding rows   │
│  → ElGamal encryption verification for 8 vote fields       │
├─────────────────────────────────────────────────────────────┤
│  Poseidon2 Section (IS_P2=1)                                │
│  12 permutations × 31 rows = 372 rows                      │
│  → K-derivation and vote ID                                │
├─────────────────────────────────────────────────────────────┤
│  Ballot Validation Section (IS_BV=1)                        │
│  8 per-field rows + 1 bounds row = 9 rows                  │
│  → Range checks, uniqueness, cost bounds                   │
├─────────────────────────────────────────────────────────────┤
│  Final output row (all flags = 0)                           │
│  1 row                                                      │
│  → Public statement {inputs_hash, address, vote_id, preimage} │
├─────────────────────────────────────────────────────────────┤
│  Padding (all flags = 0)                                    │
│  Remaining rows to reach the next power of 2 (2,048)       │
│  → No constraints fire; filled with neutral EC points       │
└─────────────────────────────────────────────────────────────┘
```

**Column reuse**: EC, Poseidon2, and BV still reuse the first part of the row layout under
section gating. The extra width comes from selector bits, shared statement columns, and a
small set of exact bit-decomposition columns:
- Poseidon round selectors
- BV row selectors
- EC phase/scalar binding columns
- hidden global `k_i` values
- hidden global field values
- hidden ballot-mode and `k`-limb values
- Poseidon preimage chunk selectors and vote-id bit decomposition
- dedicated packed-mode rows for exact in-circuit unpacking

### EC Section: ElGamal encryption (24 scalar multiplications)

For each of the 8 vote fields, the circuit performs 3 scalar multiplications:

1. **C1_i = k_i × G** -- encryption randomness times the generator point
2. **S_i = k_i × PK** -- encryption randomness times the election public key
3. **M_i = field_i × G** -- vote value times the generator

The underlying `k_i` / `field_i` scalars are tied to the EC rows through hidden linkage
columns and scalar-accumulation constraints, and the `k_i * PK` phases are tied to the
shared public key carried in the statement columns.

Each scalar mul uses the **double-and-add** algorithm, processing one bit per row.
The derived keys `k_i` are 64-bit Goldilocks elements (derived from the master key `k`
via Poseidon2), so we use 64-bit scalar muls instead of full 319-bit ones. This reduces
the EC section to **1,544 rows** (24 muls × 64 bits plus 8 dedicated C2 binding rows).

**Column layout per EC row (178 columns):**

| Columns | Count | Description |
|---|---|---|
| Accumulator (X:Z:U:T) | 20 | Running result of double-and-add |
| Base point (X:Z:U:T) | 20 | The point being multiplied |
| Scalar bit | 1 | Current bit of the scalar |
| Doubled point + intermediates | 65 | Point doubling result + 9 GF(p^5) products |
| Added point + intermediates | 70 | Point addition result + 10 GF(p^5) products |
| Phase / bind metadata | 28 | Phase ID, bind flag, scalar accumulator/target, phase selectors |
| Section flags | 3 | `IS_LAST`, `IS_EC`, `IS_P2` |

**Constraints per row (degree ≤ 4):**
- Point doubling: 9 GF(p^5) product verifications
- Point addition: 10 GF(p^5) product verifications
- Accumulator transition: `next.ACC = bit ? ADD : DBL` (multiplexer, degree 3 × gate 1 = 4)
- Bit is binary: `BIT × (1 - BIT) = 0`
- Base point continuity within a scalar mul phase
- Phase progression and neutral reset at phase boundaries
- Scalar-bit accumulation matches the hidden target scalar for that phase

### Poseidon2 Section: hashing (~1,271 rows)

Poseidon2 is a hash function designed specifically for efficient STARK/SNARK proving. It
operates on a width-8 state over Goldilocks with degree-7 S-boxes (x^7) and 30 rounds:

- **4 initial full rounds**: S-box applied to all 8 state elements
- **22 partial rounds**: S-box applied to only element 0 (much cheaper)
- **4 terminal full rounds**: S-box applied to all 8 state elements

After each round, a linear mixing layer is applied:
- **Full rounds**: Horizen Labs 4×4 MDS matrix applied to blocks of 4, then cross-mixed
- **Partial rounds**: Diagonal matrix multiplication plus a sum-all operation

**Why 30 rounds?** The number of rounds provides a security margin against algebraic attacks
(e.g., Gröbner basis, interpolation attacks). 8 full + 22 partial rounds is the standard
parameterization for Goldilocks with security margin > 2.

**S-box degree decomposition**: The S-box computes x^7. We decompose the computation and
store intermediates as trace columns, keeping the maximum constraint degree at 4 (which
allows a FRI blowup factor of just 4 instead of 8):

```
x2 = x + round_constant    (degree 1, stored in trace)
x3 = x2²                   (degree 2, constrained)
x6 = x2 × x3               (degree 3, constrained)
x7 = x3² × x6              (degree 3, stored as trace column)
```

The key optimization: x7 is stored as a trace column (degree 1 when read) and verified
via `gate × (x7 - x3² × x6)` at degree 4. The transition constraints use x7 directly
for the linear mixing layer, keeping full_next at degree 1 (linear in stored columns).
This avoids the degree-5 blow-up that would occur from `gate × is_full × x3² × x6`.

**Hash computations:**

| Hash | Input | Permutations | Purpose |
|---|---|---|---|
| K-derivation | Master key k → k_1, ..., k_8 | 8 | Derive per-field encryption keys |
| Vote ID | (process_id, address, k_limbs) | 2-4 | Unique deterministic voter identifier |
| Inputs hash | All ballot data (pk, ciphertexts, etc.) | ~28 | Commitment to private data |

For the first 8 permutations (the `k`-derivation chain), the permutation output row is
also bound to the hidden global `k_i` values used by the EC section.

### Ballot Validation Section (BV): 9 rows

The BV section implements all the ballot validity rules from the DAVINCI protocol. It occupies
only 9 rows by packing all checks densely.

**Per-field rows (rows 0-7):** Each row validates one vote field:

- **Range check**: `min_value ≤ field ≤ max_value`. Decompose `(field - min)` and
  `(max - field)` into 48-bit binary representations. If either value doesn't fit in
  48 bits (i.e., is negative in the field), the binary decomposition won't match and
  the constraint fails.

- **Power computation**: `field^cost_exponent` via an 8-step squaring chain and binary
  exponentiation accumulator. The exponent (up to 255) is decomposed into 8 bits.

- **Uniqueness**: For each pair (i, j) where i ≠ j, the constraint
  `diff² × inv - diff = 0` proves all active fields are distinct. When fields differ,
  this forces `inv = 1/diff`. When i = j, `diff = 0` and the equation trivially holds.

- **Cost accumulation**: `cost_sum` transitions across rows, accumulating
  `mask × field^exponent` per active field.

- **Row binding**: one-hot BV row selectors force row order `0..7,8`, identify the
  unique bounds row, and force the checked field to equal both `BV_FIELDS[row_idx]`
  and the hidden global field value shared with the EC section.

**Bounds row (row 8):** Checks aggregate ballot cost:

- **Upper bound**: `cost_sum ≤ limit` via 63-bit binary decomposition of `(limit - cost_sum)`.
  The limit is `max_value_sum` or `weight`, selected by the `cost_from_weight` flag.
- **Lower bound**: `cost_sum ≥ min_value_sum` via 63-bit decomposition.
- **Group size**: `group_size ≤ num_fields` via 8-bit decomposition.

**Maximum constraint degree**: 4. The BV accumulator uses stored intermediate columns
(`acc_x_eb = prev_acc × exp_bit`) to keep the degree within budget.

### Public values (123 Goldilocks elements)

These expose the verifier-visible statement:

| Index | Name | Description |
|---|---|---|
| 0-3 | `inputs_hash[4]` | Poseidon2 hash of the public ballot statement |
| 4-7 | `address[4]` | Voter address (256-bit as 4 Goldilocks elements) |
| 8 | `vote_id` | Deterministic vote identifier |
| 9-122 | `inputs_hash_preimage[114]` | Full Circom-compatible preimage used to recompute `inputs_hash` |

The AIR binds the entire preimage `{process_id, packed_ballot_mode, PK, address, vote_id,
C1[0..7], C2[0..7], weight}` to the trace. The verifier then recomputes `inputs_hash`
externally with the same Poseidon2 permutation and checks that it matches public values `0..3`.

The verifier does not see the hidden linkage columns. They exist only to ensure that:
- Poseidon-derived `k_i` values are the same scalars used in EC phases `k_i * G` and `k_i * PK`
- ballot field values checked by BV are the same scalars used in EC phases `field_i * G`

### Private inputs

| Input | Encoding | Description |
|---|---|---|
| `k` | 320-bit scalar (reduced mod curve order) | ElGamal encryption randomness |
| `fields[8]` | 8 × u64 LE | Vote field values (the actual choices) |
| `pk` | ecgfp5 point (5 × u64 LE) | Election encryption public key |
| `process_id` | 4 × u64 LE | Election identifier |
| `address` | 4 × u64 LE | Voter address |
| `weight` | u64 LE | Voter weight |
| `packed_ballot_mode` | 4 × u64 LE (248 bits) | Packed ballot configuration |

The `packed_ballot_mode` encodes all ballot rules in 248 bits split across 4 Goldilocks
elements (62 bits each):

```
Bits [0:8]     num_fields        (how many vote fields are active, 1-8)
Bits [8:16]    group_size        (minimum group size)
Bit  [16]      unique_values     (1 = all active fields must be distinct)
Bit  [17]      cost_from_weight  (1 = use voter weight as cost limit)
Bits [18:26]   cost_exponent     (exponent for cost computation)
Bits [26:74]   max_value         (48-bit upper bound per field)
Bits [74:122]  min_value         (48-bit lower bound per field)
Bits [122:185] max_value_sum     (63-bit upper bound on total cost)
Bits [185:248] min_value_sum     (63-bit lower bound on total cost)
```

## Zero-Knowledge: hiding private inputs

A standard (non-hiding) STARK reveals actual trace values at the positions queried by
the FRI verifier. For a voting protocol, this would be catastrophic -- the verifier could
learn scalar bits (and reconstruct the encryption key), Poseidon2 intermediate states
(and reconstruct vote field values), or ballot validation data.

We use **HidingFriPcs** from Plonky3 to achieve real zero-knowledge:

1. **Blinding codewords**: The PCS adds a random polynomial to the committed trace
   evaluations. Opened values at query positions are a sum of the real trace and random
   noise, so the verifier cannot extract the true witness.

2. **Entropy seeding**: The blinding RNG is seeded from 8 bytes of system entropy via
   `getrandom`. On WASM this calls `crypto.getRandomValues()`; on native Linux it reads
   `/dev/urandom`. Each proof uses a fresh seed.

3. **Verifier independence**: The verifier never generates blinding codewords, so it can
   reconstruct the STARK configuration with a fixed seed.

Without HidingFriPcs, the 34 FRI query positions would each reveal 379 Goldilocks field
elements of the actual execution trace. With it, the verifier sees only random-looking
values that satisfy the constraint checks but reveal nothing about the private inputs.

## Verification

Verification requires only the serialized proof bytes and the public values. The
verifier does not need any private inputs or the execution trace.

```rust
use davinci_stark::config::make_verifier_config;
use davinci_stark::air::BallotAir;
use p3_uni_stark::verify;

// Deserialize proof and public values from bytes...
let config = make_verifier_config();
match verify(&config, &BallotAir::new(), &proof, &public_values) {
    Ok(()) => println!("Valid ballot proof!"),
    Err(e) => println!("Invalid: {:?}", e),
}
```

**What the verifier checks:**

1. Deserializes the proof (Merkle commitments, FRI query responses, PoW witness)
2. Rebuilds the STARK config deterministically (same FRI parameters, same hash function)
3. Re-derives all Fiat-Shamir challenges from the proof transcript
4. Checks the AIR constraints at queried out-of-domain evaluation points
5. Runs the FRI low-degree test (verifies polynomial consistency)
6. Verifies the hidden cross-section bindings between Poseidon, EC, and BV sections
7. Verifies the final output-row constraints (public values match trace outputs)

The verifier learns only the public statement: the inputs hash, the voter address, the vote ID,
and the full inputs-hash preimage. Everything else, including the hidden linkage columns,
stays hidden.

**Important STARK property**: Unlike SNARKs, the STARK prover *can* produce proof bytes
from an invalid trace -- it just commits to polynomials via Merkle trees. However, the
verifier will detect constraint violations and reject the proof. In our tests,
`test_out_of_range_ballot_rejected` confirms that a ballot with `field=5, max_value=2`
produces proof bytes but verification fails with `OodEvaluationMismatch`.

## Security parameters

This repository intentionally uses a single proving profile, because proofs are generated
only in the browser. We do not maintain separate `native` and `browser` security modes.

| Parameter | Value | Notes |
|---|---|---|
| FRI blowup | 8 (`log_blowup = 3`) | Needed by the completed AIR |
| FRI queries | 34 | `34 x log2(8) = 102` conjectured bits from query soundness |
| Proof-of-work bits | 0 | Disabled for browser practicality |
| Blinding codewords | 1 | Sufficient for zero-knowledge |
| Extension degree | 2 | Quadratic extension (~128-bit field security) |
| **FRI soundness target** | **~102 bits** | **Conjectured, via the ethSTARK heuristic** |

### How FRI security works

FRI (Fast Reed-Solomon IOP of Proximity) proves that a committed function is close to a
low-degree polynomial. The verifier samples random query positions and checks consistency.
Each query provides `log2(blowup_factor)` bits of conjectured soundness under the ethSTARK
heuristic. With blowup factor 8 and 34 queries, the profile used by this repo targets
roughly `34 x 3 = 102` bits of conjectured soundness without relying on proof-of-work.

This is the statement we rely on for the STARK layer:
- it is a conjectured soundness estimate, not a formal proof bound
- it applies to the FRI/query-soundness component of the protocol
- it is separate from the curve security (`ecgfp5`) and the extension-field size

In other words:
- `ecgfp5` still has about 160-bit discrete-log security
- the Goldilocks quadratic extension still gives a 128-bit challenge field
- the overall proof system is still bottlenecked by the FRI soundness target, so we
  describe the deployed profile as approximately 102-bit conjectured security

### Plonky3 PoW Bug on WASM (p3-challenger patch)

> **Note**: This repo still ships a local `p3-challenger` patch for the upstream wasm32
> proof-of-work grinding bug, but the current browser profile keeps PoW disabled.

**Where**: `p3-challenger-0.4.2/src/grinding_challenger.rs`, line 126.

**Root cause**: The PoW grinder iterates over field elements in SIMD-style batches to find
a nonce whose hash has the required number of leading zero bits. The total number of batches
is computed as:

```rust
let num_batches = (F::ORDER_U64 as usize).div_ceil(lanes);
```

On native 64-bit targets, `usize` is 64 bits, so this works fine — `F::ORDER_U64` for
Goldilocks is `2^64 - 2^32 + 1 ≈ 1.8 × 10^19`, and `num_batches` is a huge number (the
loop almost always exits early after ~2^16 iterations for 16 PoW bits).

On `wasm32` targets, **`usize` is only 32 bits**. The cast `F::ORDER_U64 as usize` silently
truncates the 64-bit order to its lower 32 bits, yielding `1` (since the Goldilocks order
mod 2^32 = 1). The grinder therefore tries exactly **one batch** (typically 4 candidates)
and almost certainly fails to find a valid PoW nonce, causing `RuntimeError: unreachable`.

**Why this matters**: If PoW is re-enabled in the future, this patch is still required on
`wasm32`. The current production profile avoids PoW entirely and instead gets its security
from `log_blowup = 3` and `num_queries = 34`.

**Fix**: Perform the division in `u64` (where no truncation occurs), then clamp the result
to `usize::MAX` before converting. This gives up to ~4 billion batches on wasm32, which is
more than enough (the PoW search exits after ~65K iterations on average for 16 bits):

```rust
// Original (broken on wasm32 — truncates to 1):
let num_batches = (F::ORDER_U64 as usize).div_ceil(lanes);

// Patched (correct on both wasm32 and native):
let num_batches = F::ORDER_U64.div_ceil(lanes as u64).min(usize::MAX as u64) as usize;
```

**How we ship the fix**: The patched file lives in `vendor/p3-challenger/`, a copy of the
upstream `p3-challenger` crate with only line 126 changed. `Cargo.toml` uses a
`[patch.crates-io]` section to redirect the dependency:

```toml
[patch.crates-io]
p3-challenger = { path = "vendor/p3-challenger" }
```

This means `cargo build` automatically picks up our fix with zero changes to any other
dependency. When Plonky3 merges an upstream fix, the vendor directory can be removed and
the patch entry deleted.

**Impact**: Zero memory overhead, zero performance cost. The only change is that the
loop iteration limit is computed correctly. Native builds are unaffected (the value was
already correct on 64-bit targets).

### Security assumptions

1. **Goldilocks field**: The prime `p = 2^64 - 2^32 + 1` gives ~64 bits of field security.
   The degree-2 extension provides ~128-bit security against algebraic attacks.

2. **ecgfp5 curve**: Group order is approximately 2^319, providing ~160-bit discrete log
   security. This exceeds the STARK proof security target.

3. **Poseidon2**: Width 8, S-box degree 7 (x^7), 30 rounds (8 full + 22 partial). S-box
   outputs are stored as trace columns to keep AIR constraint degree at 4. Constants are
   the published Horizen Labs values used by Zisk, not randomly generated.

4. **Statement binding**: Security of the ballot statement relies on the hidden-link
   columns and their AIR constraints. These bind:
   - Poseidon `k`-chain outputs to EC `k_i` scalar-mul phases
   - BV field values to EC `field_i * G` phases
   - the packed ballot mode to its exact decoded BV rule set via 248 in-circuit bits
   - vote-id preimage rows to the vote-id Poseidon section
   - the public `inputs_hash` preimage to the full shared statement
   - the `k_i * PK` EC phases to the shared public key
   - the encoded `C1_i` / `C2_i` ciphertexts to the EC phase outputs
   - public values to the final output row

5. **Blinding RNG**: Seeded from system entropy (`getrandom` -> `crypto.getRandomValues()`
   on WASM). Each proof gets a fresh unpredictable seed. The RNG is a SplitMix64 PRNG
   seeded from OS entropy for each proof.

Restrictions:
- Vote field values must fit in 48 bits (`max_value < 2^48`).
- Scalar muls use 64-bit keys (derived from the master key via Poseidon2).

## Zisk compatibility

The Poseidon2 implementation in this project uses the **exact same parameters** as the
[Zisk zkVM](https://github.com/0xPolygonHermez/zisk) Poseidon2 precompile, enabling
cross-system hash compatibility with the Zisk Poseidon2 precompile.

### What matches

| Parameter | davinci-stark | Zisk (pil2-proofman Poseidon8) |
|---|---|---|
| Width | 8 | 8 |
| Full rounds | 8 (4 + 4) | 8 (4 + 4) |
| Partial rounds | 22 | 22 |
| S-box degree | 7 (x^7) | 7 (x^7) |
| Diagonal matrix (D_8) | Upstream Plonky3 Goldilocks constants | Hardcoded |
| Round constants (RC_8) | Upstream Plonky3 HL constants | 86 hardcoded hex values |
| 4×4 MDS matrix | Horizen Labs `[[5,7,1,3],[4,6,1,1],[1,3,5,7],[1,1,4,6]]` | Same |
| Initial `matmul_external` | Applied before first round | Applied before first round |

The `test_poseidon2_zisk_compatibility` test verifies that our permutation output matches
Zisk's test vector for input `[0, 1, 2, 3, 4, 5, 6, 7]`.

### Two Poseidon2 instances

This project uses Poseidon2 in two separate contexts:

1. **Ballot circuit** (width 8): K-derivation, vote ID, and verifier-side `inputs_hash`
   recomputation. Uses the Zisk-compatible Horizen Labs constants.

2. **STARK infrastructure** (width 16): Merkle tree hashing and Fiat-Shamir challenger.
   Uses Plonky3's built-in `Poseidon2Goldilocks<16>`. These are internal to the proof system
   and do not need to match Zisk.

## Performance

| Metric | Value | Notes |
|---|---|---|
| Trace size | 2,048 × 379 | Includes selector bits, shared statement columns, and dedicated packed-mode rows |
| Max constraint degree | 4 | Stored x7 columns + BV intermediates |
| FRI blowup factor | 8 (`log_blowup = 3`) | Required by the completed AIR |
| FRI queries | 34 | ~102-bit conjectured soundness, no PoW |
| Native prove time | ~3.2s | Release mode, full 8-field ballot proof |
| Native verify time | ~12ms | Release mode, full 8-field ballot proof |
| WASM binary | ~1.36 MB | `wasm-pack build --target web --release`, no wasm-opt |
| Proof size | ~533 KB | Current release build, browser-oriented profile |

HidingFriPcs (ZK mode) roughly doubles proving time compared to non-hiding mode because
the trace polynomial is extended with blinding codewords.

## Comparison with davinci-circom

| Aspect | davinci-circom (zkSNARK) | davinci-stark (this project) |
|---|---|---|
| Proof system | Groth16 via snarkjs | STARK via Plonky3 |
| Curve | BabyJubJub over BN254 | ecgfp5 over Goldilocks |
| Hash | Poseidon (BN254 scalar field) | Poseidon2 (Goldilocks, Zisk-compatible) |
| Trusted setup | Required (powers of tau ceremony) | **None** (transparent) |
| Proof size | ~200 bytes | ~533 KB |
| Prover time (browser) | Browser-dependent | Use the webapp timing panel on the target device |
| Verifier time | ~5ms | ~12ms |
| Ballot validation | Full (range, uniqueness, cost) | Full (range, uniqueness, cost, bounds) |
| Post-quantum | No (relies on pairing assumptions) | Plausibly yes (hash-based) |
| Aggregation | Not natively supported | FRI-based recursion via Zisk zkVM |
| Language | Circom DSL | Rust (AIR constraints) |

## Project structure

```
davinci-stark/
├── src/
│   ├── air.rs            AIR constraint definitions (~1,100 lines)
│   │                     EC, Poseidon2, and BV constraint sections
│   ├── columns.rs        Trace column layout (379 columns, named constants)
│   ├── config.rs         STARK configuration (HidingFriPcs, FRI params, RNG)
│   ├── ecgfp5_ops.rs     ecgfp5 point doubling/addition for trace generation
│   ├── elgamal.rs        ElGamal keygen/encrypt helpers
│   ├── gfp5.rs           GF(p^5) arithmetic constraint helpers
│   ├── lib.rs            Public API: prove_full_ballot, verify_ballot
│   ├── poseidon2.rs      Poseidon2 permutation tracer and sponge wrapper
│   │                     Upstream Plonky3 HL constants, Zisk-compatible behavior
│   ├── trace.rs          Trace generation (~940 lines, BallotInputs → matrix)
│   └── wasm.rs           WASM bindings via wasm-bindgen
├── tests/
│   ├── ballot_e2e.rs     End-to-end ballot proofs + adversarial binding regressions
│   ├── ec_test.rs        EC scalar multiplication correctness
│   ├── fibonacci_smoke.rs  2 Plonky3 integration smoke tests
│   ├── gfp5_test.rs      3 GF(p^5) multiplication tests
│   └── poseidon2_test.rs Poseidon2 compatibility + adversarial gadget tests
├── webapp/
│   ├── index.html        Web UI (dark theme, ballot form)
│   ├── src/
│   │   ├── main.js       UI logic, input packing, worker communication
│   │   └── worker.js     Web Worker for non-blocking WASM proving
│   ├── vite.config.js    Vite configuration
│   └── package.json      JS dependencies
├── pkg/                  WASM output (generated by wasm-pack build)
├── Cargo.toml            Rust dependencies + [patch] for p3-challenger
├── Makefile              Build commands (build, test, serve, clean)
└── README.md             This file
```

## Dependencies

### Rust (Cargo)

| Crate | Version | Purpose |
|---|---|---|
| `p3-uni-stark` | 0.4.2 | STARK prover and verifier |
| `p3-air` | 0.4.2 | AIR trait definitions |
| `p3-fri` | 0.4.2 | FRI PCS (includes HidingFriPcs) |
| `p3-goldilocks` | 0.4.2 | Goldilocks field + width-16 Poseidon2 permutation |
| `p3-field` | 0.4.2 | Field traits and extension fields |
| `p3-matrix` | 0.4.2 | Row-major matrix for execution traces |
| `p3-challenger` | 0.4.2 (patched) | Fiat-Shamir challenger; patch retained for wasm32 PoW correctness |
| `ecgfp5` | vendored local crate | ecgfp5 STARK-friendly elliptic curve |
| `serde` + `postcard` | 1.x | Compact binary serialization |
| `wasm-bindgen` | 0.2 | WASM bindings (wasm32 only) |
| `getrandom` | 0.2 | System entropy (`crypto.getRandomValues` on WASM) |
| `console_error_panic_hook` | 0.1 | Readable WASM panic messages |

### JavaScript (npm)

| Package | Purpose |
|---|---|
| `vite` | Dev server and bundler for the webapp |

### Build tools

| Tool | Version | Purpose |
|---|---|---|
| Rust | ≥ 1.85 | Compiler (2024 edition) |
| Node.js | ≥ 18 | Webapp dev server |

---

## Building and running

### Prerequisites

```bash
# Rust (if not installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Webapp dependencies
cd webapp && npm install && cd ..
```

### Quick start

```bash
make build    # Build WASM package (auto-installs wasm-pack via cargo if needed)
make test     # Run the Rust test suite in release mode
make serve    # Build WASM + start the Vite dev server
make clean    # Remove all build artifacts
```

### Manual commands

```bash
# Run tests in release mode
cargo test --release

# Build WASM for the browser
~/.cargo/bin/wasm-pack build --target web --release

# Start the webapp dev server
cd webapp && npx vite --host 0.0.0.0
```

---

## References

- [DAVINCI Protocol Specification](https://vocdoni.github.io/davinci-paper/) -- the e-voting protocol
- [Plonky3](https://github.com/Plonky3/Plonky3) -- the STARK framework we build on
- [ecgfp5](https://github.com/pornin/ecgfp5) -- STARK-friendly elliptic curve by Thomas Pornin
- [Poseidon2](https://eprint.iacr.org/2023/323) -- hash function specification
- [On the Applicability of STARKs to e-Voting](https://fc24.ifca.ai/voting/papers/Voting24_HH_On_the_Applicability_of_STARKs_to_Counted-as-Collected_Verification_in_Exisitng_Homomorphically_E-Voting_Systems.pdf) -- academic reference
- [Zisk zkVM](https://github.com/0xPolygonHermez/zisk) -- target zkVM for proof aggregation
- [FRI protocol](https://eccc.weizmann.ac.il/report/2017/134/) -- the low-degree test underlying STARK soundness
- [STARK paper](https://eprint.iacr.org/2018/046) -- original STARK construction by Ben-Sasson et al.
