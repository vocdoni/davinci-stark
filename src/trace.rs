//! Trace generation for the browser ballot prover.
//!
//! `generate_full_ballot_trace` builds the execution trace, public values, and
//! derived ballot outputs for the single proving statement used by this crate.

use ecgfp5::curve::Point;
use ecgfp5::scalar::Scalar;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;

use crate::air::{
    NUM_FIELDS, PV_ADDRESS, PV_COUNT, PV_INPUTS_HASH, PV_INPUTS_PREIMAGE, PV_VOTE_ID,
    SMALL_SCALAR_BITS,
};
use crate::columns::*;
use crate::ecgfp5_ops::{fill_addition, fill_scalar_mul_row};
use crate::poseidon2::{self, Poseidon2Constants, Poseidon2Trace};

/// Extract bit `bit_index` from a 320-bit scalar stored as five u64 limbs.
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
    bind_active: bool,
    scalar_target: u64,
) -> (Vec<Goldilocks>, Point) {
    let mut rows = vec![Goldilocks::ZERO; num_bits * TRACE_WIDTH];
    let mut acc = Point::NEUTRAL;
    let mut scalar_acc = 0u64;

    for i in 0..num_bits {
        let bit_idx = num_bits - 1 - i;
        let bit = scalar_bit(scalar, bit_idx);

        let row_start = i * TRACE_WIDTH;
        let row = &mut rows[row_start..row_start + TRACE_WIDTH];

        let (doubled, added) = fill_scalar_mul_row(row, &acc, base_point, bit, phase);

        row[IS_EC] = Goldilocks::ONE;
        row[IS_P2] = Goldilocks::ZERO;
        if bind_active {
            scalar_acc = scalar_acc.wrapping_mul(2).wrapping_add(bit);
            row[EC_BIND_ACTIVE] = Goldilocks::ONE;
            row[EC_SCALAR_ACC] = Goldilocks::from_u64(scalar_acc);
            row[EC_SCALAR_TARGET] = Goldilocks::from_u64(scalar_target);
            if (phase as usize) < EC_PHASE_SEL_COUNT {
                row[EC_PHASE_SEL + phase as usize] = Goldilocks::ONE;
            }
        }

        if i == num_bits - 1 {
            row[IS_LAST_IN_PHASE] = Goldilocks::ONE;
        }

        acc = if bit == 1 { added } else { doubled };
    }

    (rows, acc)
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

/// Unpacked ballot mode: all configuration parameters decoded from the packed
/// 248-bit ballot mode value. Matches the circom UnpackBallotMode output.
#[derive(Clone, Debug)]
pub struct BallotMode {
    pub num_fields: u64,
    pub group_size: u64,
    pub unique_values: u64,
    pub cost_from_weight: u64,
    pub cost_exponent: u64,
    pub max_value: u64,
    pub min_value: u64,
    pub max_value_sum: u64,
    pub min_value_sum: u64,
}

impl BallotMode {
    /// Unpack ballot mode from 4 Goldilocks elements (each holding a 62-bit chunk).
    pub fn unpack(packed: &[Goldilocks; 4]) -> Self {
        // Reconstruct the 248-bit integer from four 62-bit chunks.
        let c0 = packed[0].as_canonical_u64() as u128;
        let c1 = packed[1].as_canonical_u64() as u128;
        let c2 = packed[2].as_canonical_u64() as u128;
        let c3 = packed[3].as_canonical_u64() as u128;

        // Full 248-bit value spread across 4 x 62-bit chunks:
        // value = c0 + c1*2^62 + c2*2^124 + c3*2^186
        // Extract fields by bit position:
        let extract = |start: u32, width: u32| -> u64 {
            // Which chunk does this bit range start in?
            let chunk_bits = 62u32;
            let mut val: u128 = 0;
            let mut remaining = width;
            let mut pos = start;
            while remaining > 0 {
                let chunk_idx = pos / chunk_bits;
                let bit_in_chunk = pos % chunk_bits;
                let chunk_val = match chunk_idx {
                    0 => c0,
                    1 => c1,
                    2 => c2,
                    3 => c3,
                    _ => 0,
                };
                let available = chunk_bits - bit_in_chunk;
                let take = remaining.min(available);
                let mask = if take >= 128 {
                    u128::MAX
                } else {
                    (1u128 << take) - 1
                };
                let bits_from_chunk = (chunk_val >> bit_in_chunk) & mask;
                val |= bits_from_chunk << (width - remaining);
                pos += take;
                remaining -= take;
            }
            val as u64
        };

        BallotMode {
            num_fields: extract(0, 8),
            group_size: extract(8, 8),
            unique_values: extract(16, 1),
            cost_from_weight: extract(17, 1),
            cost_exponent: extract(18, 8),
            max_value: extract(26, 48),
            min_value: extract(74, 48),
            max_value_sum: extract(122, 63),
            min_value_sum: extract(185, 63),
        }
    }

    /// Pack ballot mode into 4 Goldilocks elements (each holding a 62-bit chunk).
    /// Inverse of unpack().
    pub fn pack(&self) -> [Goldilocks; 4] {
        // Build a 248-bit integer from the individual fields.
        // Bit layout (LSB first):
        //   [0..8)    num_fields
        //   [8..16)   group_size
        //   [16]      unique_values
        //   [17]      cost_from_weight
        //   [18..26)  cost_exponent
        //   [26..74)  max_value (48 bits)
        //   [74..122) min_value (48 bits)
        //   [122..185) max_value_sum (63 bits)
        //   [185..248) min_value_sum (63 bits)

        // Use a [u64; 4] as a 256-bit accumulator, then split into 62-bit chunks.
        let mut bits = [0u64; 4]; // 256 bits total

        let set_bits = |bits: &mut [u64; 4], start: u32, width: u32, val: u64| {
            for b in 0..width {
                let bit_pos = start + b;
                let word = (bit_pos / 64) as usize;
                let bit = bit_pos % 64;
                if (val >> b) & 1 == 1 {
                    bits[word] |= 1u64 << bit;
                }
            }
        };

        set_bits(&mut bits, 0, 8, self.num_fields);
        set_bits(&mut bits, 8, 8, self.group_size);
        set_bits(&mut bits, 16, 1, self.unique_values);
        set_bits(&mut bits, 17, 1, self.cost_from_weight);
        set_bits(&mut bits, 18, 8, self.cost_exponent);
        set_bits(&mut bits, 26, 48, self.max_value);
        set_bits(&mut bits, 74, 48, self.min_value);
        set_bits(&mut bits, 122, 63, self.max_value_sum);
        set_bits(&mut bits, 185, 63, self.min_value_sum);

        // Now extract four 62-bit chunks from the 256-bit value.
        // chunk_k = bits[k*62 .. (k+1)*62)
        let extract_chunk = |bits: &[u64; 4], chunk_start: u32| -> u64 {
            let mut val = 0u64;
            for b in 0..62u32 {
                let bit_pos = chunk_start + b;
                let word = (bit_pos / 64) as usize;
                let bit = bit_pos % 64;
                if word < 4 && (bits[word] >> bit) & 1 == 1 {
                    val |= 1u64 << b;
                }
            }
            val
        };

        [
            Goldilocks::from_u64(extract_chunk(&bits, 0)),
            Goldilocks::from_u64(extract_chunk(&bits, 62)),
            Goldilocks::from_u64(extract_chunk(&bits, 124)),
            Goldilocks::from_u64(extract_chunk(&bits, 186)),
        ]
    }
}

/// Generate the full 8-field ballot proof trace.
///
/// This is the main trace generator. It builds a padded trace covering:
///
///   1. K-derivation chain: Poseidon2(k) -> k1, Poseidon2(k1) -> k2, ... k8
///      Each derived key is a single Goldilocks element (64 bits).
///
///   2. EC scalar multiplications (24 total, 64 bits each):
///      For each field i in 0..8:
///        - k_i * G         -> C1[i]   (encryption ephemeral point)
///        - k_i * PK        -> S[i]    (shared secret)
///        - field[i] * G    -> M[i]    (message point)
///      Each `M_i` phase is followed by a dedicated binding row that proves
///      `C2[i] = M[i] + S[i]` and binds the encoded ciphertext used by the
///      inputs-hash section.
///
///   3. Vote ID: Poseidon2 sponge of (process_id, address, k) -> truncated hash
///
///   4. Inputs hash: Poseidon2 hash of the full public preimage in circom-compatible
///      order. The preimage itself is exposed as public values and the verifier
///      recomputes the hash externally.
///
///   5. Padding rows to reach the next power of 2
///
/// Returns (trace_matrix, public_values, outputs).
pub fn generate_full_ballot_trace(
    inputs: &BallotInputs,
) -> (RowMajorMatrix<Goldilocks>, Vec<Goldilocks>, BallotOutputs) {
    let g = Point::GENERATOR;
    let constants = Poseidon2Constants::new();

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
        let ki_target = k_derived[i].as_canonical_u64();
        let (rows, c1) = generate_scalar_mul_trace_nbits(
            &ki_scalar,
            &g,
            (3 * i) as u64,
            SMALL_SCALAR_BITS,
            true,
            ki_target,
        );
        ec_row_counts.push(SMALL_SCALAR_BITS);
        ec_rows.push(rows);
        c1_points[i] = c1;

        // k_i * PK -> S_i (64-bit scalar)
        let (rows, s) = generate_scalar_mul_trace_nbits(
            &ki_scalar,
            &inputs.pk,
            (3 * i + 1) as u64,
            SMALL_SCALAR_BITS,
            true,
            ki_target,
        );
        ec_row_counts.push(SMALL_SCALAR_BITS);
        ec_rows.push(rows);
        s_points[i] = s;

        // field_i * G -> M_i (64-bit scalar)
        let (rows, m) = generate_scalar_mul_trace_nbits(
            &inputs.fields[i],
            &g,
            (3 * i + 2) as u64,
            SMALL_SCALAR_BITS,
            true,
            inputs.fields[i].0[0],
        );
        ec_row_counts.push(SMALL_SCALAR_BITS);
        ec_rows.push(rows);
        m_points[i] = m;
    }

    // C2 = M + S
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
    let (vote_id_hash, vote_id_p2_traces) =
        poseidon2::poseidon2_hash_traced(&vote_id_input, 1, &constants);
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
        for j in 0..5 {
            hash_input.push(Goldilocks::from_u64(enc.0[j].to_u64()));
        }
        let enc = c2_points[i].encode();
        for j in 0..5 {
            hash_input.push(Goldilocks::from_u64(enc.0[j].to_u64()));
        }
    }
    hash_input.push(inputs.weight); // 1
    let inputs_hash_vec = poseidon2::poseidon2_hash(&hash_input, 4, &constants);
    let inputs_hash: [Goldilocks; 4] = [
        inputs_hash_vec[0],
        inputs_hash_vec[1],
        inputs_hash_vec[2],
        inputs_hash_vec[3],
    ];

    // ============================================================
    // Step 5: Build trace matrix
    // ============================================================
    // Compute actual row counts
    let ec_total_rows: usize = ec_row_counts.iter().sum::<usize>() + NUM_FIELDS;
    let p2_perms = k_p2_traces.len() + vote_id_p2_traces.len();
    let p2_total_rows = p2_perms * (poseidon2::TOTAL_ROUNDS + 1);
    let bv_rows = NUM_FIELDS + 1; // 8 field rows + 1 bounds row
    let public_row_count = 1;
    let packed_mode_rows = 4;
    let data_rows = packed_mode_rows + ec_total_rows + p2_total_rows + bv_rows + public_row_count;
    let total_rows = data_rows.next_power_of_two().max(64);
    let mut values = vec![Goldilocks::ZERO; total_rows * TRACE_WIDTH];

    fill_packed_mode_rows(&mut values, &inputs.packed_ballot_mode);

    // Copy EC rows
    let mut row_offset = packed_mode_rows;
    for (idx, phase_rows) in ec_rows.iter().enumerate() {
        let start = row_offset * TRACE_WIDTH;
        values[start..start + phase_rows.len()].copy_from_slice(phase_rows);
        let phase_start_row = row_offset;
        row_offset += ec_row_counts[idx];
        if idx % 3 == 2 {
            let field_idx = idx / 3;
            for row in phase_start_row..row_offset {
                let row_start = row * TRACE_WIDTH;
                let row = &mut values[row_start..row_start + TRACE_WIDTH];
                write_point_coords(row, CURRENT_S, &s_points[field_idx]);
            }
            let row_start = row_offset * TRACE_WIDTH;
            let row = &mut values[row_start..row_start + TRACE_WIDTH];
            fill_c2_binding_row(
                row,
                field_idx,
                &m_points[field_idx],
                &s_points[field_idx],
                &c2_points[field_idx],
            );
            write_point_coords(row, CURRENT_S, &s_points[field_idx]);
            row_offset += 1;
        }
    }
    let ec_end = row_offset;

    // Fill Poseidon2 section
    let mut p2_row = ec_end;
    let mut perm_id = 0u64;

    // K-derivation chain (8 permutations)
    for trace in &k_p2_traces {
        p2_row = fill_poseidon2_rows(&mut values, trace, &constants, perm_id, p2_row, None);
        perm_id += 1;
    }

    // Vote ID hash (4 permutations)
    for (idx, trace) in vote_id_p2_traces.iter().enumerate() {
        let mut chunk = [Goldilocks::ZERO; 4];
        for j in 0..4 {
            if let Some(v) = vote_id_input.get(idx * 4 + j) {
                chunk[j] = *v;
            }
        }
        annotate_poseidon_preperm_row(&mut values, p2_row - 1, &chunk, Some(idx));
        p2_row = fill_poseidon2_rows(
            &mut values,
            trace,
            &constants,
            perm_id,
            p2_row,
            Some(idx),
        );
        perm_id += 1;
    }
    values[(p2_row - 1) * TRACE_WIDTH + P2_VOTE_ID_OUT] = Goldilocks::ONE;
    for b in 0..64 {
        values[(p2_row - 1) * TRACE_WIDTH + P2_VOTE_ID_BITS + b] =
            Goldilocks::from_bool(((vote_id_raw >> b) & 1) != 0);
    }

    // ============================================================
    // Step 5b: Ballot validation rows
    // ============================================================
    let bv_start = p2_row;
    let mode = BallotMode::unpack(&inputs.packed_ballot_mode);
    let field_vals: Vec<u64> = inputs.fields.iter().map(|s| s.0[0]).collect();

    for row in 0..total_rows {
        let row_start = row * TRACE_WIDTH;
        for i in 0..NUM_FIELDS {
            values[row_start + GLOBAL_KS + i] = k_derived[i];
            values[row_start + GLOBAL_FIELDS + i] = Goldilocks::from_u64(field_vals[i]);
        }
        values[row_start + GLOBAL_BV_NUM_FIELDS] = Goldilocks::from_u64(mode.num_fields);
        values[row_start + GLOBAL_BV_MIN_VALUE] = Goldilocks::from_u64(mode.min_value);
        values[row_start + GLOBAL_BV_MAX_VALUE] = Goldilocks::from_u64(mode.max_value);
        values[row_start + GLOBAL_BV_UNIQUE] = Goldilocks::from_u64(mode.unique_values);
        values[row_start + GLOBAL_BV_COST_FROM_WEIGHT] =
            Goldilocks::from_u64(mode.cost_from_weight);
        values[row_start + GLOBAL_BV_COST_EXP] = Goldilocks::from_u64(mode.cost_exponent);
        values[row_start + GLOBAL_BV_MAX_SUM] = Goldilocks::from_u64(mode.max_value_sum);
        values[row_start + GLOBAL_BV_MIN_SUM] = Goldilocks::from_u64(mode.min_value_sum);
        values[row_start + GLOBAL_BV_GROUP_SIZE] = Goldilocks::from_u64(mode.group_size);
        values[row_start + GLOBAL_BV_WEIGHT] = inputs.weight;
        for i in 0..5 {
            values[row_start + GLOBAL_K_LIMBS + i] = Goldilocks::from_u64(k_limbs[i]);
        }
    }

    fill_ballot_validation_rows(
        &mut values,
        bv_start,
        &field_vals,
        &mode,
        inputs.weight.as_canonical_u64(),
    );
    let bv_end = bv_start + bv_rows;
    let public_row = bv_end;

    // Padding rows
    let neutral = Point::NEUTRAL;
    let mut pad_acc = c2_points[0];
    for i in (public_row + 1)..total_rows {
        let row_start = i * TRACE_WIDTH;
        let row = &mut values[row_start..row_start + TRACE_WIDTH];
        let (doubled, _) = fill_scalar_mul_row(row, &pad_acc, &neutral, 0, 3);
        row[IS_LAST_IN_PHASE] = Goldilocks::ONE;
        row[IS_EC] = Goldilocks::ZERO;
        row[IS_P2] = Goldilocks::ZERO;
        row[IS_BV] = Goldilocks::ZERO;
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

    // Full inputs-hash preimage for external verifier recomputation.
    pv[PV_INPUTS_PREIMAGE..PV_INPUTS_PREIMAGE + hash_input.len()].copy_from_slice(&hash_input);

    {
        let row_start = (total_rows - 1) * TRACE_WIDTH;
        let row = &mut values[row_start..row_start + TRACE_WIDTH];
        row[PUB_OUTPUTS..PUB_OUTPUTS + PV_COUNT].copy_from_slice(&pv);
        row[IS_EC] = Goldilocks::ZERO;
        row[IS_P2] = Goldilocks::ZERO;
        row[IS_BV] = Goldilocks::ZERO;
    }

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
    for limb in &p.X.0 {
        out.push(Goldilocks::from_u64(limb.to_u64()));
    }
    for limb in &p.Z.0 {
        out.push(Goldilocks::from_u64(limb.to_u64()));
    }
    for limb in &p.U.0 {
        out.push(Goldilocks::from_u64(limb.to_u64()));
    }
    for limb in &p.T.0 {
        out.push(Goldilocks::from_u64(limb.to_u64()));
    }
}

fn write_point_coords(row: &mut [Goldilocks], offset: usize, p: &Point) {
    let mut idx = offset;
    for limb in &p.X.0 {
        row[idx] = Goldilocks::from_u64(limb.to_u64());
        idx += 1;
    }
    for limb in &p.Z.0 {
        row[idx] = Goldilocks::from_u64(limb.to_u64());
        idx += 1;
    }
    for limb in &p.U.0 {
        row[idx] = Goldilocks::from_u64(limb.to_u64());
        idx += 1;
    }
    for limb in &p.T.0 {
        row[idx] = Goldilocks::from_u64(limb.to_u64());
        idx += 1;
    }
}

fn write_point_encoding(row: &mut [Goldilocks], offset: usize, p: &Point) {
    let enc = p.encode();
    for (i, limb) in enc.0.iter().enumerate() {
        row[offset + i] = Goldilocks::from_u64(limb.to_u64());
    }
}

fn fill_packed_mode_rows(values: &mut [Goldilocks], packed_mode: &[Goldilocks; 4]) {
    for chunk in 0..4 {
        let row_start = chunk * TRACE_WIDTH;
        let row = &mut values[row_start..row_start + TRACE_WIDTH];
        row[P2_VOTE_ID_PRE_SEL + chunk] = Goldilocks::ONE;
        let chunk_val = packed_mode[chunk].as_canonical_u64();
        for bit in 0..62 {
            row[P2_VOTE_ID_BITS + bit] = Goldilocks::from_bool(((chunk_val >> bit) & 1) != 0);
        }
    }
}

fn fill_c2_binding_row(
    row: &mut [Goldilocks],
    field_idx: usize,
    m_point: &Point,
    s_point: &Point,
    c2_point: &Point,
) {
    write_point_coords(row, ACC_X, m_point);
    write_point_coords(row, BASE_X, s_point);
    fill_addition(row, m_point, s_point);
    write_point_encoding(row, C2_BIND_ENC, c2_point);
    row[EC_BIND_ACTIVE] = Goldilocks::ONE;
    row[BV_ROW_SEL + field_idx] = Goldilocks::ONE;
}

fn annotate_poseidon_preperm_row(
    values: &mut [Goldilocks],
    row_idx: usize,
    chunk: &[Goldilocks; 4],
    vote_id_sel: Option<usize>,
) {
    let row_start = row_idx * TRACE_WIDTH;
    let row = &mut values[row_start..row_start + TRACE_WIDTH];
    row[P2_ABSORB_CHUNK..P2_ABSORB_CHUNK + 4].copy_from_slice(chunk);
    if let Some(idx) = vote_id_sel {
        row[P2_VOTE_ID_PRE_SEL + idx] = Goldilocks::ONE;
    }
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
    vote_id_sel: Option<usize>,
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
        row[P2_ROUND_TYPE] = if is_partial {
            Goldilocks::ONE
        } else {
            Goldilocks::ZERO
        };
        row[P2_PERM_ID] = Goldilocks::from_u64(perm_id);
        row[P2_ROUND_SEL + r] = Goldilocks::ONE;
        if (perm_id as usize) < P2_K_SEL_COUNT {
            row[P2_K_SEL + perm_id as usize] = Goldilocks::ONE;
        }
        if let Some(idx) = vote_id_sel {
            row[P2_VOTE_ID_PRE_SEL + idx] = Goldilocks::ONE;
        }

        // Compute and fill S-box intermediates
        for i in 0..poseidon2::WIDTH {
            let x2 = if is_full {
                // Full round: x2 = state[i] + external_rc[round_idx][i]
                let rc_idx = if r < rf_half {
                    r
                } else {
                    rf_half + (r - rf_half - rp)
                };
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
            // x7 = x3^2 * x6 = (x2^2)^2 * (x2 * x2^2) = x2^7
            let x7 = if is_full || i == 0 {
                x3 * x3 * x6
            } else {
                Goldilocks::ZERO
            };
            row[P2_SBOX_X7 + i] = x7;
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

    // Fill valid EC padding data for the remaining columns
    let neutral = Point::NEUTRAL;
    let (_, _) = fill_scalar_mul_row(out_row, &neutral, &neutral, 0, 3);
    // Store the permutation output after filling overlapping EC columns.
    for i in 0..poseidon2::WIDTH {
        out_row[P2_STATE + i] = output_state[i];
    }
    out_row[P2_PERM_ID] = Goldilocks::from_u64(perm_id);
    if (perm_id as usize) < P2_K_SEL_COUNT {
        out_row[P2_K_SEL + perm_id as usize] = Goldilocks::ONE;
    }
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
    let public_row_count = 1;
    let p2_rows = inputs.len() * rows_per_perm + public_row_count;
    let trace_height = p2_rows.next_power_of_two().max(16); // min 16 rows

    let mut values = vec![Goldilocks::ZERO; trace_height * TRACE_WIDTH];
    let mut tracked_outputs = [Goldilocks::ZERO; P2_K_SEL_COUNT];

    let mut next_row = 0;
    for (perm_idx, input) in inputs.iter().enumerate() {
        let trace = poseidon2::poseidon2_permute_traced(input, constants);
        if perm_idx < P2_K_SEL_COUNT {
            tracked_outputs[perm_idx] = trace.states[poseidon2::TOTAL_ROUNDS][0];
        }
        next_row = fill_poseidon2_rows(&mut values, &trace, constants, perm_idx as u64, next_row, None);
    }

    for row in 0..trace_height {
        let row_start = row * TRACE_WIDTH;
        values[row_start + GLOBAL_KS..row_start + GLOBAL_KS + P2_K_SEL_COUNT]
            .copy_from_slice(&tracked_outputs);
    }
    if let Some(first_input) = inputs.first() {
        for row in 0..trace_height {
            let row_start = row * TRACE_WIDTH;
            for i in 0..5 {
                values[row_start + GLOBAL_K_LIMBS + i] = first_input[i];
            }
        }
    }
    for row in 0..trace_height {
        let row_start = row * TRACE_WIDTH;
        for i in 0..P2_K_SEL_COUNT {
            values[row_start + P2_K_SEL + i] = Goldilocks::ZERO;
        }
        values[row_start + P2_VOTE_ID_OUT] = Goldilocks::ZERO;
        for i in 0..P2_VOTE_ID_PRE_SEL_COUNT {
            values[row_start + P2_VOTE_ID_PRE_SEL + i] = Goldilocks::ZERO;
        }
    }

    let public_row = next_row;
    {
        let row_start = public_row * TRACE_WIDTH;
        let row = &mut values[row_start..row_start + TRACE_WIDTH];
        let neutral = Point::NEUTRAL;
        let _ = fill_scalar_mul_row(row, &neutral, &neutral, 0, 3);
        row[IS_LAST_IN_PHASE] = Goldilocks::ONE;
        row[IS_EC] = Goldilocks::ZERO;
        row[IS_P2] = Goldilocks::ZERO;
    }
    // Padding rows: IS_EC=0, IS_P2=0 (already zero from initialization)
    // Fill valid EC data for padding to avoid any constraint issues
    let neutral = Point::NEUTRAL;
    let mut pad_acc = neutral;
    for i in (public_row + 1)..trace_height {
        let row_start = i * TRACE_WIDTH;
        let row = &mut values[row_start..row_start + TRACE_WIDTH];
        let (doubled, _) = fill_scalar_mul_row(row, &pad_acc, &neutral, 0, 3);
        row[IS_LAST_IN_PHASE] = Goldilocks::ONE;
        row[IS_EC] = Goldilocks::ZERO;
        row[IS_P2] = Goldilocks::ZERO;
        pad_acc = doubled;
    }

    let pv = vec![Goldilocks::ZERO; PV_COUNT];
    values[(trace_height - 1) * TRACE_WIDTH + PUB_OUTPUTS
        ..(trace_height - 1) * TRACE_WIDTH + PUB_OUTPUTS + PV_COUNT]
        .copy_from_slice(&pv);
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

// ==========================================================================
// Ballot validation trace generation
// ==========================================================================

/// Binary exponentiation: compute base^exp using the 8-bit exponent.
/// Returns (result, squaring_chain, exponent_bits, accumulator_chain).
fn binary_exp_goldilocks(base: u64, exp: u64) -> (u64, [u64; 8], [u64; 8], [u64; 8]) {
    let p = Goldilocks::ORDER_U64;
    let mut sq = [0u64; 8];
    let mut exp_bits = [0u64; 8];
    let mut acc = [0u64; 8];

    // Squaring chain: sq[0] = base, sq[k] = sq[k-1]^2 mod p
    sq[0] = base % p;
    for k in 1..8 {
        sq[k] = ((sq[k - 1] as u128 * sq[k - 1] as u128) % p as u128) as u64;
    }

    // Exponent bits (LSB first)
    for k in 0..8 {
        exp_bits[k] = (exp >> k) & 1;
    }

    // Running product: acc[k] = product of (exp_bit[j] ? sq[j] : 1) for j=0..k
    let selector = |k: usize| -> u64 { if exp_bits[k] == 1 { sq[k] } else { 1 } };
    acc[0] = selector(0);
    for k in 1..8 {
        acc[k] = ((acc[k - 1] as u128 * selector(k) as u128) % p as u128) as u64;
    }

    (acc[7], sq, exp_bits, acc)
}

/// Fill the 9 ballot validation rows into the trace.
///
/// Rows 0..7: per-field validation (range checks, power computation, uniqueness)
/// Row 8: cost sum bounds check + group_size check
pub fn fill_ballot_validation_rows(
    values: &mut [Goldilocks],
    start_row: usize,
    field_vals: &[u64],
    mode: &BallotMode,
    weight: u64,
) {
    let p = Goldilocks::ORDER_U64;
    let g = |v: u64| Goldilocks::from_u64(v % p);

    // Compute all field powers and running cost sum
    let mut powers = [0u64; NUM_FIELDS];
    let mut cost_sums = [0u64; NUM_FIELDS];
    let mut running = 0u64;

    for i in 0..NUM_FIELDS {
        let mask = if (i as u64) < mode.num_fields {
            1u64
        } else {
            0u64
        };
        let (power, _, _, _) = binary_exp_goldilocks(field_vals[i], mode.cost_exponent);
        powers[i] = power;
        running = (running + mask * power) % p;
        cost_sums[i] = running;
    }
    let total_cost = running;

    // Rows 0..7: per-field validation
    for i in 0..NUM_FIELDS {
        let row_idx = start_row + i;
        let row_start = row_idx * TRACE_WIDTH;
        let row = &mut values[row_start..row_start + TRACE_WIDTH];

        let mask = if (i as u64) < mode.num_fields {
            1u64
        } else {
            0u64
        };
        let fv = field_vals[i];

        // All 8 field values (for uniqueness cross-referencing)
        for j in 0..NUM_FIELDS {
            row[BV_FIELDS + j] = g(field_vals[j]);
            row[BV_FIELD_MASKS + j] = g(((j as u64) < mode.num_fields) as u64);
        }

        // Config values (constant across all BV rows)
        row[BV_NUM_FIELDS] = g(mode.num_fields);
        row[BV_ROW_INDEX] = g(i as u64);
        row[BV_ROW_SEL + i] = Goldilocks::ONE;
        row[BV_MASK] = g(mask);
        row[BV_MIN_VALUE] = g(mode.min_value);
        row[BV_MAX_VALUE] = g(mode.max_value);
        row[BV_UNIQUE] = g(mode.unique_values);
        row[BV_COST_FROM_WEIGHT] = g(mode.cost_from_weight);
        row[BV_COST_EXP] = g(mode.cost_exponent);
        row[BV_MAX_SUM] = g(mode.max_value_sum);
        row[BV_MIN_SUM] = g(mode.min_value_sum);
        row[BV_WEIGHT] = g(weight);
        row[BV_GROUP_SIZE] = g(mode.group_size);

        // Range check: decompose (fv - min_value) into 48 bits
        if mask == 1 {
            let low = fv.wrapping_sub(mode.min_value);
            for b in 0..BV_LOW_BITS_COUNT {
                row[BV_LOW_BITS + b] = g((low >> b) & 1);
            }
            let high = mode.max_value.wrapping_sub(fv);
            for b in 0..BV_HIGH_BITS_COUNT {
                row[BV_HIGH_BITS + b] = g((high >> b) & 1);
            }
        }

        // Binary exponentiation
        let (power, sq, exp_bits, acc) = binary_exp_goldilocks(fv, mode.cost_exponent);
        for k in 0..8 {
            row[BV_EXP_BITS + k] = g(exp_bits[k]);
            row[BV_SQ + k] = g(sq[k]);
            row[BV_ACC + k] = g(acc[k]);
        }
        // acc_x_eb[k] = acc[k-1] * exp_bits[k] (intermediates for degree reduction)
        for k in 1..8usize {
            let inter = acc[k - 1].wrapping_mul(exp_bits[k]) % p;
            row[BV_ACC_INTER + (k - 1)] = g(inter);
        }
        row[BV_POWER] = g(power);
        row[BV_COST_SUM] = g(cost_sums[i]);

        // Uniqueness: compute inverses of (field[i] - field[j]) for all j
        for j in 0..NUM_FIELDS {
            if j == i {
                row[BV_INV_DIFF + j] = Goldilocks::ZERO;
            } else {
                let mask_j = if (j as u64) < mode.num_fields {
                    1u64
                } else {
                    0u64
                };
                if mask == 1 && mask_j == 1 && mode.unique_values == 1 && fv != field_vals[j] {
                    // Compute modular inverse of (fv - field_vals[j]) mod p
                    let diff = (fv as i128 - field_vals[j] as i128).rem_euclid(p as i128) as u64;
                    let inv = mod_inverse(diff, p);
                    row[BV_INV_DIFF + j] = g(inv);
                } else {
                    row[BV_INV_DIFF + j] = Goldilocks::ZERO;
                }
            }
        }

        // Section flags
        row[IS_EC] = Goldilocks::ZERO;
        row[IS_P2] = Goldilocks::ZERO;
        row[IS_BV] = Goldilocks::ONE;
    }

    // Row 8: bounds check
    let bounds_idx = start_row + NUM_FIELDS;
    let bounds_start = bounds_idx * TRACE_WIDTH;
    let bounds_row = &mut values[bounds_start..bounds_start + TRACE_WIDTH];

    // Replicate field values and config
    for j in 0..NUM_FIELDS {
        bounds_row[BV_FIELDS + j] = g(field_vals[j]);
        bounds_row[BV_FIELD_MASKS + j] = g(((j as u64) < mode.num_fields) as u64);
    }
    bounds_row[BV_NUM_FIELDS] = g(mode.num_fields);
    bounds_row[BV_ROW_INDEX] = g(NUM_FIELDS as u64); // index = 8 marks bounds row
    bounds_row[BV_ROW_SEL + NUM_FIELDS] = Goldilocks::ONE;
    bounds_row[BV_MASK] = Goldilocks::ZERO; // not a field row
    bounds_row[BV_MIN_VALUE] = g(mode.min_value);
    bounds_row[BV_MAX_VALUE] = g(mode.max_value);
    bounds_row[BV_UNIQUE] = g(mode.unique_values);
    bounds_row[BV_COST_FROM_WEIGHT] = g(mode.cost_from_weight);
    bounds_row[BV_COST_EXP] = g(mode.cost_exponent);
    bounds_row[BV_MAX_SUM] = g(mode.max_value_sum);
    bounds_row[BV_MIN_SUM] = g(mode.min_value_sum);
    bounds_row[BV_WEIGHT] = g(weight);
    bounds_row[BV_GROUP_SIZE] = g(mode.group_size);

    // Compute the limit based on cost_from_weight flag
    let limit = if mode.cost_from_weight == 1 {
        weight
    } else {
        mode.max_value_sum
    };
    bounds_row[BV_LIMIT] = g(limit);
    bounds_row[BV_BOUNDS_COST] = g(total_cost);

    // Decompose (limit - total_cost) into 63 bits
    // Only meaningful when max_value_sum > 0 (i.e., there's an upper bound)
    let upper_diff = if limit >= total_cost {
        limit - total_cost
    } else {
        0
    };
    for b in 0..BV_LIMIT_BITS_COUNT {
        bounds_row[BV_LIMIT_BITS + b] = g((upper_diff >> b) & 1);
    }

    // Decompose (total_cost - min_sum) into 63 bits
    let lower_diff = if total_cost >= mode.min_value_sum {
        total_cost - mode.min_value_sum
    } else {
        0
    };
    for b in 0..BV_MINSUB_BITS_COUNT {
        bounds_row[BV_MINSUB_BITS + b] = g((lower_diff >> b) & 1);
    }

    // Group size check: decompose (num_fields - group_size) into 8 bits
    let gs_diff = if mode.num_fields >= mode.group_size {
        mode.num_fields - mode.group_size
    } else {
        0
    };
    for b in 0..BV_GS_BITS_COUNT {
        bounds_row[BV_GS_BITS + b] = g((gs_diff >> b) & 1);
    }

    // Is max_sum zero? (meaning no upper bound)
    let max_sum_is_zero = if mode.max_value_sum == 0 { 1u64 } else { 0u64 };
    bounds_row[BV_MAX_SUM_IS_ZERO] = g(max_sum_is_zero);
    if mode.max_value_sum != 0 {
        bounds_row[BV_MAX_SUM_INV] = g(mod_inverse(mode.max_value_sum % p, p));
    }

    bounds_row[BV_IS_BOUNDS] = Goldilocks::ONE; // marks this as the bounds row
    bounds_row[IS_EC] = Goldilocks::ZERO;
    bounds_row[IS_P2] = Goldilocks::ZERO;
    bounds_row[IS_BV] = Goldilocks::ONE;
}

/// Compute modular inverse of a mod p using extended Euclidean algorithm.
fn mod_inverse(a: u64, p: u64) -> u64 {
    if a == 0 {
        return 0;
    }
    let mut old_r = a as i128;
    let mut r = p as i128;
    let mut old_s: i128 = 1;
    let mut s: i128 = 0;
    while r != 0 {
        let q = old_r / r;
        let tmp = r;
        r = old_r - q * r;
        old_r = tmp;
        let tmp = s;
        s = old_s - q * s;
        old_s = tmp;
    }
    ((old_s % p as i128 + p as i128) % p as i128) as u64
}
