//! Trace generation for the ballot proof STARK.
//!
//! This module builds the execution trace: a big matrix of Goldilocks values
//! that the STARK prover commits to and proves satisfies the AIR constraints.
//!
//! The main entry point is `generate_full_ballot_trace`, which takes all the
//! ballot inputs (votes, encryption key, process ID, etc.) and produces:
//!   1. The trace matrix (4096 x 180 Goldilocks elements)
//!   2. The public values vector (9 elements)
//!   3. Computed outputs (C1/C2 points, vote_id, inputs_hash, derived keys)
//!
//! The trace has three sections:
//!   - EC rows: 24 scalar multiplications (8 fields x 3 ops each)
//!   - P2 rows: ~40 Poseidon2 permutations (k-chain + vote ID + inputs hash)
//!   - Padding: zero-constraint filler to reach the next power of 2

use ecgfp5::curve::Point;
use ecgfp5::scalar::Scalar;
use p3_goldilocks::Goldilocks;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;

use crate::air::*;
use crate::columns::*;
use crate::ecgfp5_ops::fill_scalar_mul_row;
use crate::poseidon2::{self, Poseidon2Constants, Poseidon2Trace};

/// Extract bit i from a 320-bit scalar (stored as [u64; 5]).
/// Extract bit `bit_index` from a 320-bit scalar (stored as five u64 limbs).
/// Returns 0 or 1 as a u64.
fn scalar_bit(s: &Scalar, bit_index: usize) -> u64 {
    let word = bit_index / 64;
    let bit = bit_index % 64;
    (s.0[word] >> bit) & 1
}

/// Generate a single scalar multiplication trace (k * base_point).
///
/// Processes `num_bits` bits of the scalar from MSB to LSB. Each bit produces
/// one trace row containing:
///   - The current accumulator point
///   - The doubled and (conditionally) added intermediate points
///   - The scalar bit and phase index
///
/// Returns the raw row data (flattened) and the resulting EC point.
pub fn generate_scalar_mul_trace_nbits(
    scalar: &Scalar,
    base_point: &Point,
    phase: u64,
    num_bits: usize,
) -> (Vec<Goldilocks>, Point) {
    let mut rows = vec![Goldilocks::ZERO; num_bits * TRACE_WIDTH];
    let mut acc = Point::NEUTRAL;

    for i in 0..num_bits {
        let bit_idx = num_bits - 1 - i;
        let bit = scalar_bit(scalar, bit_idx);

        let row_start = i * TRACE_WIDTH;
        let row = &mut rows[row_start..row_start + TRACE_WIDTH];

        let (doubled, added) = fill_scalar_mul_row(row, &acc, base_point, bit, phase);

        row[IS_EC] = Goldilocks::ONE;
        row[IS_P2] = Goldilocks::ZERO;

        if i == num_bits - 1 {
            row[IS_LAST_IN_PHASE] = Goldilocks::ONE;
        }

        acc = if bit == 1 { added } else { doubled };
    }

    (rows, acc)
}

/// Generate a single scalar multiplication trace with full 319-bit scalar.
pub fn generate_scalar_mul_trace(
    scalar: &Scalar,
    base_point: &Point,
    phase: u64,
) -> (Vec<Goldilocks>, Point) {
    generate_scalar_mul_trace_nbits(scalar, base_point, phase, SCALAR_BITS)
}

/// All inputs needed to generate a full ballot proof.
///
/// These correspond to the private inputs in the circom ballot_proof circuit.
/// The prover knows all of these; the verifier only sees the public values
/// derived from them (inputs_hash, address, vote_id).
pub struct BallotInputs {
    /// Encryption randomness (320-bit scalar)
    pub k: Scalar,
    /// Vote field values (as scalars for EC scalar mul)
    pub fields: [Scalar; NUM_FIELDS],
    /// Encryption public key (ecgfp5 point)
    pub pk: Point,
    /// Process ID (4 Goldilocks elements for 256-bit value)
    pub process_id: [Goldilocks; 4],
    /// Voter address (4 Goldilocks elements for 256-bit value)
    pub address: [Goldilocks; 4],
    /// Voter weight
    pub weight: Goldilocks,
    /// Packed ballot mode (248-bit configuration packed into 4 Goldilocks elements)
    pub packed_ballot_mode: [Goldilocks; 4],
}

/// Everything the prover computes and makes available after proof generation.
/// The verifier uses a subset of these (inputs_hash, address, vote_id) as
/// public values baked into the proof. The C1/C2 points and derived keys
/// are returned so the caller can publish them alongside the proof.
pub struct BallotOutputs {
    /// C1 points for each field
    pub c1: [Point; NUM_FIELDS],
    /// C2 points for each field
    pub c2: [Point; NUM_FIELDS],
    /// Vote ID
    pub vote_id: Goldilocks,
    /// Inputs hash (4 Goldilocks elements)
    pub inputs_hash: [Goldilocks; 4],
    /// Derived k values for each field
    pub k_derived: [Goldilocks; NUM_FIELDS],
}

/// Generate the full 8-field ballot proof trace.
///
/// This is the main trace generator. It builds a 4096 x 180 matrix covering:
///
///   1. K-derivation chain: Poseidon2(k) -> k1, Poseidon2(k1) -> k2, ... k8
///      Each derived key is a single Goldilocks element (64 bits).
///
///   2. EC scalar multiplications (24 total, 64 bits each):
///      For each field i in 0..8:
///        - k_i * G         -> C1[i]   (encryption ephemeral point)
///        - k_i * PK        -> S[i]    (shared secret)
///        - field[i] * G    -> M[i]    (message point)
///      Then C2[i] = M[i] + S[i] is computed outside the STARK.
///
///   3. Vote ID: Poseidon2 sponge of (process_id, address, k) -> truncated hash
///
///   4. Inputs hash: Poseidon2 sponge of all inputs in circom-compatible order
///
///   5. Padding rows to reach next power of 2
///
/// Returns (trace_matrix, public_values, outputs).
pub fn generate_full_ballot_trace(
    inputs: &BallotInputs,
) -> (RowMajorMatrix<Goldilocks>, Vec<Goldilocks>, BallotOutputs) {
    let g = Point::GENERATOR;
    let constants = Poseidon2Constants::from_seed(42);

    // ============================================================
    // Step 1: Derive k-chain via Poseidon2
    // k_1 = Poseidon2([k_limb0..4, 0, 0, 0])[0]
    // k_i = Poseidon2([k_{i-1}, 0, 0, 0, 0, 0, 0, 0])[0]
    // ============================================================
    let k_limbs = inputs.k.0;
    let mut k_derived = [Goldilocks::ZERO; NUM_FIELDS];
    let mut k_p2_traces = Vec::with_capacity(NUM_FIELDS);

    // First k: hash the full scalar (5 limbs in rate positions)
    let mut p2_input = [Goldilocks::ZERO; poseidon2::WIDTH];
    for i in 0..5 {
        p2_input[i] = Goldilocks::from_u64(k_limbs[i]);
    }
    let trace = poseidon2::poseidon2_permute_traced(&p2_input, &constants);
    k_derived[0] = trace.states[poseidon2::TOTAL_ROUNDS][0];
    k_p2_traces.push(trace);

    // Subsequent k values: hash previous k
    for i in 1..NUM_FIELDS {
        let mut p2_input = [Goldilocks::ZERO; poseidon2::WIDTH];
        p2_input[0] = k_derived[i - 1];
        let trace = poseidon2::poseidon2_permute_traced(&p2_input, &constants);
        k_derived[i] = trace.states[poseidon2::TOTAL_ROUNDS][0];
        k_p2_traces.push(trace);
    }

    // ============================================================
    // Step 2: Generate EC scalar muls (24 total, 64-bit scalars)
    // k_derived values are Goldilocks elements (64 bits).
    // field values are u64s (64 bits).
    // Using 64-bit scalar muls: 24 x 64 = 1,536 EC rows.
    // ============================================================
    let mut ec_rows: Vec<Vec<Goldilocks>> = Vec::new();
    let mut ec_row_counts: Vec<usize> = Vec::new();
    let mut c1_points = [Point::NEUTRAL; NUM_FIELDS];
    let mut s_points = [Point::NEUTRAL; NUM_FIELDS];
    let mut m_points = [Point::NEUTRAL; NUM_FIELDS];

    for i in 0..NUM_FIELDS {
        let ki_scalar = goldilocks_to_scalar(k_derived[i]);

        // k_i * G -> C1_i (64-bit scalar)
        let (rows, c1) = generate_scalar_mul_trace_nbits(&ki_scalar, &g, (3 * i) as u64, SMALL_SCALAR_BITS);
        ec_row_counts.push(SMALL_SCALAR_BITS);
        ec_rows.push(rows);
        c1_points[i] = c1;

        // k_i * PK -> S_i (64-bit scalar)
        let (rows, s) = generate_scalar_mul_trace_nbits(&ki_scalar, &inputs.pk, (3 * i + 1) as u64, SMALL_SCALAR_BITS);
        ec_row_counts.push(SMALL_SCALAR_BITS);
        ec_rows.push(rows);
        s_points[i] = s;

        // field_i * G -> M_i (64-bit scalar)
        let (rows, m) = generate_scalar_mul_trace_nbits(&inputs.fields[i], &g, (3 * i + 2) as u64, SMALL_SCALAR_BITS);
        ec_row_counts.push(SMALL_SCALAR_BITS);
        ec_rows.push(rows);
        m_points[i] = m;
    }

    // C2 = M + S (computed outside STARK, verified via public values)
    let mut c2_points = [Point::NEUTRAL; NUM_FIELDS];
    for i in 0..NUM_FIELDS {
        c2_points[i] = add_points(&m_points[i], &s_points[i]);
    }

    // ============================================================
    // Step 3: Vote ID via Poseidon2
    // hash(process_id[0..3], address[0..3], k_limbs[0..4]) -> truncate + offset
    // Uses sponge: 4 + 4 + 5 = 13 elements, ceil(13/4) = 4 permutations
    // ============================================================
    let mut vote_id_input = Vec::with_capacity(13);
    vote_id_input.extend_from_slice(&inputs.process_id);
    vote_id_input.extend_from_slice(&inputs.address);
    for i in 0..5 {
        vote_id_input.push(Goldilocks::from_u64(k_limbs[i]));
    }
    let (vote_id_hash, vote_id_p2_traces) = poseidon2::poseidon2_hash_traced(&vote_id_input, 1, &constants);
    // vote_id = hash[0] mod 2^63 + 2^63
    let vote_id_raw = vote_id_hash[0].as_canonical_u64();
    let vote_id_val = (vote_id_raw & ((1u64 << 63) - 1)) | (1u64 << 63);
    let vote_id = Goldilocks::from_u64(vote_id_val);

    // ============================================================
    // Step 4: Input hash via Poseidon2 sponge
    // Order matches circom: process_id, packed_ballot_mode, pk, address, vote_id, cipherfields, weight
    // ============================================================
    let mut hash_input = Vec::new();
    hash_input.extend_from_slice(&inputs.process_id); // 4
    hash_input.extend_from_slice(&inputs.packed_ballot_mode); // 4
    // PK (encode as 5 Goldilocks per coordinate, 4 coordinates = 20)
    push_point_encoded(&mut hash_input, &inputs.pk);
    hash_input.extend_from_slice(&inputs.address); // 4
    hash_input.push(vote_id); // 1
    // C1 and C2 encodings interleaved per field (5 each x 8 fields x 2 = 80)
    for i in 0..NUM_FIELDS {
        let enc = c1_points[i].encode();
        for j in 0..5 { hash_input.push(Goldilocks::from_u64(enc.0[j].to_u64())); }
        let enc = c2_points[i].encode();
        for j in 0..5 { hash_input.push(Goldilocks::from_u64(enc.0[j].to_u64())); }
    }
    hash_input.push(inputs.weight); // 1
    let (inputs_hash_vec, inputs_hash_p2_traces) = poseidon2::poseidon2_hash_traced(&hash_input, 4, &constants);
    let inputs_hash: [Goldilocks; 4] = [inputs_hash_vec[0], inputs_hash_vec[1], inputs_hash_vec[2], inputs_hash_vec[3]];

    // ============================================================
    // Step 5: Build trace matrix
    // ============================================================
    // Compute actual row counts
    let ec_total_rows: usize = ec_row_counts.iter().sum();
    let p2_perms = k_p2_traces.len() + vote_id_p2_traces.len() + inputs_hash_p2_traces.len();
    let p2_total_rows = p2_perms * (poseidon2::TOTAL_ROUNDS + 1);
    let data_rows = ec_total_rows + p2_total_rows;
    let total_rows = data_rows.next_power_of_two().max(64);
    let mut values = vec![Goldilocks::ZERO; total_rows * TRACE_WIDTH];

    // Copy EC rows
    let mut row_offset = 0;
    for (idx, phase_rows) in ec_rows.iter().enumerate() {
        let start = row_offset * TRACE_WIDTH;
        values[start..start + phase_rows.len()].copy_from_slice(phase_rows);
        row_offset += ec_row_counts[idx];
    }
    let ec_end = row_offset;

    // Fill Poseidon2 section
    let mut p2_row = ec_end;
    let mut perm_id = 0u64;

    // K-derivation chain (8 permutations)
    for trace in &k_p2_traces {
        p2_row = fill_poseidon2_rows(&mut values, trace, &constants, perm_id, p2_row);
        perm_id += 1;
    }

    // Vote ID hash (variable number of permutations)
    for trace in &vote_id_p2_traces {
        p2_row = fill_poseidon2_rows(&mut values, trace, &constants, perm_id, p2_row);
        perm_id += 1;
    }

    // Input hash (variable number of permutations)
    for trace in &inputs_hash_p2_traces {
        p2_row = fill_poseidon2_rows(&mut values, trace, &constants, perm_id, p2_row);
        perm_id += 1;
    }

    // Padding rows
    let neutral = Point::NEUTRAL;
    let mut pad_acc = c2_points[0];
    for i in p2_row..total_rows {
        let row_start = i * TRACE_WIDTH;
        let row = &mut values[row_start..row_start + TRACE_WIDTH];
        let (doubled, _) = fill_scalar_mul_row(row, &pad_acc, &neutral, 0, 3);
        row[IS_LAST_IN_PHASE] = Goldilocks::ONE;
        row[IS_EC] = Goldilocks::ZERO;
        row[IS_P2] = Goldilocks::ZERO;
        pad_acc = doubled;
    }

    // ============================================================
    // Step 6: Build public values -- matches circom: {inputs_hash, address, vote_id}
    // ============================================================
    let mut pv = vec![Goldilocks::ZERO; PV_COUNT];

    // Inputs hash (4 elements)
    for i in 0..4 {
        pv[PV_INPUTS_HASH + i] = inputs_hash[i];
    }

    // Address (4 elements)
    for i in 0..4 {
        pv[PV_ADDRESS + i] = inputs.address[i];
    }

    // Vote ID
    pv[PV_VOTE_ID] = vote_id;

    let outputs = BallotOutputs {
        c1: c1_points,
        c2: c2_points,
        vote_id,
        inputs_hash,
        k_derived,
    };

    (RowMajorMatrix::new(values, TRACE_WIDTH), pv, outputs)
}

/// Convert a Goldilocks element to an ecgfp5 Scalar (64-bit value -> 320-bit scalar).
fn goldilocks_to_scalar(g: Goldilocks) -> Scalar {
    let val = g.as_canonical_u64();
    Scalar([val, 0, 0, 0, 0])
}

/// Push an ecgfp5 point's coordinates as Goldilocks elements.
fn push_point_encoded(out: &mut Vec<Goldilocks>, p: &Point) {
    for limb in &p.X.0 { out.push(Goldilocks::from_u64(limb.to_u64())); }
    for limb in &p.Z.0 { out.push(Goldilocks::from_u64(limb.to_u64())); }
    for limb in &p.U.0 { out.push(Goldilocks::from_u64(limb.to_u64())); }
    for limb in &p.T.0 { out.push(Goldilocks::from_u64(limb.to_u64())); }
}

/// Legacy single-field ballot trace generator (used by older tests).
///
/// Generates a trace with 3 full 319-bit scalar multiplications:
///   Phase 0: k * G -> C1
///   Phase 1: k * PK -> shared secret
///   Phase 2: field * G -> message point
/// No Poseidon2 hashing, no k-derivation. Public values are all zero.
pub fn generate_ballot_trace(
    k: &Scalar,
    field_val: &Scalar,
    pk: &Point,
) -> (RowMajorMatrix<Goldilocks>, Vec<Goldilocks>) {
    let g = Point::GENERATOR;

    // Phase 0: C1 = k * G
    let (rows0, c1_point) = generate_scalar_mul_trace(k, &g, 0);

    // Phase 1: k * PK
    let (rows1, k_pk_point) = generate_scalar_mul_trace(k, pk, 1);

    // Phase 2: field * G
    let (rows2, field_g_point) = generate_scalar_mul_trace(field_val, &g, 2);

    // C2 = field*G + k*PK
    let c2_point = add_points(&field_g_point, &k_pk_point);

    let c1_enc = c1_point.encode();
    let c2_enc = c2_point.encode();

    // Build full trace
    let total_rows = TRACE_HEIGHT;
    let mut values = vec![Goldilocks::ZERO; total_rows * TRACE_WIDTH];

    // Copy phase 0 rows
    values[..SCALAR_BITS * TRACE_WIDTH].copy_from_slice(&rows0);

    // Copy phase 1 rows
    let offset1 = SCALAR_BITS * TRACE_WIDTH;
    values[offset1..offset1 + SCALAR_BITS * TRACE_WIDTH].copy_from_slice(&rows1);

    // Copy phase 2 rows
    let offset2 = 2 * SCALAR_BITS * TRACE_WIDTH;
    values[offset2..offset2 + SCALAR_BITS * TRACE_WIDTH].copy_from_slice(&rows2);

    // Padding rows: fill with section=PAD (3) and valid EC data
    let ec_end = 3 * SCALAR_BITS;
    let mut pad_acc = c2_point;
    let neutral = Point::NEUTRAL;
    for i in ec_end..total_rows {
        let row_start = i * TRACE_WIDTH;
        let row = &mut values[row_start..row_start + TRACE_WIDTH];
        let (doubled, _) = fill_scalar_mul_row(row, &pad_acc, &neutral, 0, 3);
        row[IS_LAST_IN_PHASE] = Goldilocks::ONE;
        row[IS_EC] = Goldilocks::ZERO;
        row[IS_P2] = Goldilocks::ZERO;
        pad_acc = doubled;
    }

    // Build public values (simplified -- legacy single-field doesn't have full inputs_hash)
    let mut pv = vec![Goldilocks::ZERO; PV_COUNT];
    // For legacy mode, inputs_hash = 0 (no Poseidon2 hashing in single-field mode)
    // Address and vote_id also 0 (not computed in single-field mode)

    (RowMajorMatrix::new(values, TRACE_WIDTH), pv)
}

/// Fill trace rows for a single Poseidon2 permutation (30 rounds = 30 rows).
///
/// The row at `start_row` corresponds to round 0, and the row at `start_row + 29`
/// corresponds to round 29. An additional "output row" at `start_row + 30` stores
/// the permutation output in P2_STATE with IS_P2=1, so the transition constraint
/// on round 29 verifies the output.
///
/// Returns the row index AFTER the output row (i.e., `start_row + 31`).
pub fn fill_poseidon2_rows(
    values: &mut [Goldilocks],
    trace: &Poseidon2Trace,
    constants: &Poseidon2Constants,
    perm_id: u64,
    start_row: usize,
) -> usize {
    let total_rounds = poseidon2::TOTAL_ROUNDS; // 30
    let rf_half = poseidon2::ROUNDS_F_HALF; // 4
    let rp = poseidon2::ROUNDS_P; // 22

    for r in 0..total_rounds {
        let row_idx = start_row + r;
        let row_start = row_idx * TRACE_WIDTH;
        let row = &mut values[row_start..row_start + TRACE_WIDTH];

        let state = &trace.states[r];

        // Determine round type
        let is_full = r < rf_half || r >= rf_half + rp;
        let is_partial = !is_full;

        // Fill P2_STATE
        for i in 0..poseidon2::WIDTH {
            row[P2_STATE + i] = state[i];
        }

        // Fill round metadata
        row[P2_ROUND] = Goldilocks::from_u64(r as u64);
        row[P2_ROUND_TYPE] = if is_partial { Goldilocks::ONE } else { Goldilocks::ZERO };
        row[P2_PERM_ID] = Goldilocks::from_u64(perm_id);

        // Compute and fill S-box intermediates
        for i in 0..poseidon2::WIDTH {
            let x2 = if is_full {
                // Full round: x2 = state[i] + external_rc[round_idx][i]
                let rc_idx = if r < rf_half { r } else { rf_half + (r - rf_half - rp) };
                state[i] + constants.external_rc[rc_idx][i]
            } else if i == 0 {
                // Partial round, element 0: x2 = state[0] + internal_rc[r - rf_half]
                state[0] + constants.internal_rc[r - rf_half]
            } else {
                // Partial round, elements 1..7: identity (no S-box)
                Goldilocks::ZERO
            };

            let x3 = if is_full || i == 0 {
                x2 * x2
            } else {
                Goldilocks::ZERO
            };

            let x6 = if is_full || i == 0 {
                x2 * x3
            } else {
                Goldilocks::ZERO
            };

            row[P2_SBOX_X2 + i] = x2;
            row[P2_SBOX_X3 + i] = x3;
            row[P2_SBOX_X6 + i] = x6;
        }

        // Section flags
        row[IS_EC] = Goldilocks::ZERO;
        row[IS_P2] = Goldilocks::ONE;
    }

    // Gap row after permutation: stores the output state for later cross-linking
    // but has IS_P2=0 so no Poseidon2 constraints fire (preventing unwanted
    // transitions between different permutations).
    let out_row_idx = start_row + total_rounds;
    let out_start = out_row_idx * TRACE_WIDTH;
    let out_row = &mut values[out_start..out_start + TRACE_WIDTH];
    let output_state = &trace.states[total_rounds]; // states[30]

    // Store output state for potential boundary constraint verification
    for i in 0..poseidon2::WIDTH {
        out_row[P2_STATE + i] = output_state[i];
    }
    // Fill valid EC padding data for the remaining columns
    let neutral = Point::NEUTRAL;
    let (_, _) = fill_scalar_mul_row(out_row, &neutral, &neutral, 0, 3);
    out_row[IS_LAST_IN_PHASE] = Goldilocks::ONE;
    out_row[IS_EC] = Goldilocks::ZERO;
    out_row[IS_P2] = Goldilocks::ZERO;

    start_row + total_rounds + 1 // 31 rows total per permutation
}

/// Generate a Poseidon2-only trace for testing: one or more permutations + padding.
pub fn generate_poseidon2_trace(
    inputs: &[[Goldilocks; poseidon2::WIDTH]],
    constants: &Poseidon2Constants,
) -> (RowMajorMatrix<Goldilocks>, Vec<Goldilocks>) {
    let rows_per_perm = poseidon2::TOTAL_ROUNDS + 1; // 31
    let p2_rows = inputs.len() * rows_per_perm;
    let trace_height = p2_rows.next_power_of_two().max(16); // min 16 rows

    let mut values = vec![Goldilocks::ZERO; trace_height * TRACE_WIDTH];

    let mut next_row = 0;
    for (perm_idx, input) in inputs.iter().enumerate() {
        let trace = poseidon2::poseidon2_permute_traced(input, constants);
        next_row = fill_poseidon2_rows(&mut values, &trace, constants, perm_idx as u64, next_row);
    }

    // Padding rows: IS_EC=0, IS_P2=0 (already zero from initialization)
    // Fill valid EC data for padding to avoid any constraint issues
    let neutral = Point::NEUTRAL;
    let mut pad_acc = neutral;
    for i in next_row..trace_height {
        let row_start = i * TRACE_WIDTH;
        let row = &mut values[row_start..row_start + TRACE_WIDTH];
        let (doubled, _) = fill_scalar_mul_row(row, &pad_acc, &neutral, 0, 3);
        row[IS_LAST_IN_PHASE] = Goldilocks::ONE;
        row[IS_EC] = Goldilocks::ZERO;
        row[IS_P2] = Goldilocks::ZERO;
        pad_acc = doubled;
    }

    let pv = vec![Goldilocks::ZERO; PV_COUNT];
    (RowMajorMatrix::new(values, TRACE_WIDTH), pv)
}

/// Add two ecgfp5 points using the complete addition formula for Jacobi quartic curves.
///
/// This uses the same formulas as ecgfp5_ops::fill_add_row but operates on
/// actual field elements rather than trace columns. Used to compute C2 = M + S
/// outside the STARK (the point addition result is published, not proved inline).
pub fn add_points(a: &Point, b: &Point) -> Point {
    let (x1, z1, u1, t1) = (&a.X, &a.Z, &a.U, &a.T);
    let (x2, z2, u2, t2) = (&b.X, &b.Z, &b.U, &b.T);

    let at1 = *x1 * *x2;
    let at2 = *z1 * *z2;
    let at3 = *u1 * *u2;
    let at4 = *t1 * *t2;
    let t5 = (*x1 + *z1) * (*x2 + *z2) - at1 - at2;
    let t6 = (*u1 + *t1) * (*u2 + *t2) - at3 - at4;
    let t7 = at1 + at2.mul_small_k1(Point::B1);
    let t8 = at4 * t7;
    let t9 = at3 * (t5.mul_small_k1(2 * Point::B1) + t7.double());
    let t10 = (at4 + at3.double()) * (t5 + t7);
    let u_pre = t6 * (at2.mul_small_k1(Point::B1) - at1);

    Point {
        X: (t10 - t8).mul_small_k1(Point::B1),
        Z: t8 - t9,
        U: u_pre,
        T: t8 + t9,
    }
}
