//! Column index definitions for the ballot proof trace.
//!
//! The trace is a flat matrix where each row contains all the data for one step
//! of computation. The columns are laid out so that EC scalar mul data and
//! Poseidon2 hash data can share physical columns (they never run in the same
//! row), while selectors and hidden linkage columns expand the full row width to 1,581.
//!
//! This file just defines named constants for column offsets. The actual
//! constraint logic that reads these columns lives in air.rs.

use p3_field::Field;

// ==========================================================================
// GF(p^5) geometry
// ==========================================================================

/// Each GF(p^5) element takes 5 consecutive columns (one per limb).
pub const GFP5_WIDTH: usize = 5;

/// An ecgfp5 point in extended coordinates (X:Z:U:T) needs 4 x 5 = 20 columns.
pub const POINT_WIDTH: usize = 4 * GFP5_WIDTH;

// ==========================================================================
// EC scalar multiplication columns (active when IS_EC = 1)
//
// Each row represents one bit of a double-and-add scalar multiplication.
// We store the accumulator, base point, scalar bit, doubled result with all
// its intermediates, and added result with all its intermediates.
// ==========================================================================

/// Accumulator point going into this row's computation.
pub const ACC_X: usize = 0;
pub const ACC_Z: usize = ACC_X + GFP5_WIDTH; // 5
pub const ACC_U: usize = ACC_Z + GFP5_WIDTH; // 10
pub const ACC_T: usize = ACC_U + GFP5_WIDTH; // 15

/// Base point. Stays constant throughout a single scalar multiplication phase.
pub const BASE_X: usize = ACC_T + GFP5_WIDTH; // 20
pub const BASE_Z: usize = BASE_X + GFP5_WIDTH; // 25
pub const BASE_U: usize = BASE_Z + GFP5_WIDTH; // 30
pub const BASE_T: usize = BASE_U + GFP5_WIDTH; // 35

/// The current scalar bit (0 or 1). Determines whether the accumulator picks
/// up the doubled point or the added point for the next row.
pub const BIT: usize = BASE_T + GFP5_WIDTH; // 40

/// Doubled point = double(accumulator).
pub const DBL_X: usize = BIT + 1; // 41
pub const DBL_Z: usize = DBL_X + GFP5_WIDTH; // 46
pub const DBL_U: usize = DBL_Z + GFP5_WIDTH; // 51
pub const DBL_T: usize = DBL_U + GFP5_WIDTH; // 56

/// Intermediate products from the ecgfp5 doubling formula.
///
/// The Jacobi quartic doubling on ecgfp5 decomposes into 9 GF(p^5) products
/// (4 multiplications + 5 squarings). We store each intermediate so the AIR
/// constraints can verify them at degree 2 per product.
///
/// Formula sketch (see ecgfp5 paper for the full derivation):
///   t1 = Z*T,  t2 = t1*T,  X1 = t2^2,  Z1 = t1*U,  t3 = U^2,
///   xz_t3 = (X+Z)*t3,  W1 = t2 - 2*xz_t3,
///   t4 = Z1^2,  W1sq = W1^2,  wz_sq = (W1+Z1)^2
pub const DBL_T1: usize = DBL_T + GFP5_WIDTH; // 61
pub const DBL_T2: usize = DBL_T1 + GFP5_WIDTH; // 66
pub const DBL_X1: usize = DBL_T2 + GFP5_WIDTH; // 71
pub const DBL_Z1: usize = DBL_X1 + GFP5_WIDTH; // 76
pub const DBL_T3: usize = DBL_Z1 + GFP5_WIDTH; // 81
pub const DBL_XZ_T3: usize = DBL_T3 + GFP5_WIDTH; // 86
pub const DBL_T4: usize = DBL_XZ_T3 + GFP5_WIDTH; // 91
pub const DBL_W1SQ: usize = DBL_T4 + GFP5_WIDTH; // 96
pub const DBL_WZ_SQ: usize = DBL_W1SQ + GFP5_WIDTH; // 101

/// Added point = add(doubled, base).
pub const ADD_X: usize = DBL_WZ_SQ + GFP5_WIDTH; // 106
pub const ADD_Z: usize = ADD_X + GFP5_WIDTH; // 111
pub const ADD_U: usize = ADD_Z + GFP5_WIDTH; // 116
pub const ADD_T: usize = ADD_U + GFP5_WIDTH; // 121

/// Intermediate products from the ecgfp5 addition formula.
///
/// The Jacobi quartic addition decomposes into 10 GF(p^5) products.
/// Same idea as doubling: store each product so constraints stay degree 2.
///
/// at1 = X1*X2,  at2 = Z1*Z2,  at3 = U1*U2,  at4 = T1*T2,
/// at5_raw = (X1+Z1)*(X2+Z2),  at6_raw = (U1+T1)*(U2+T2),
/// t5 = at5_raw - at1 - at2 (Karatsuba trick),
/// t6 = at6_raw - at3 - at4,
/// t7 = at1 + B1*at2,
/// at8 = at4*t7,  at9 = at3*(2*B1*t5 + 2*t7),  at10 = (at4+2*at3)*(t5+t7),
/// u_pre = t6*(B1*at2 - at1)
pub const ADD_AT1: usize = ADD_T + GFP5_WIDTH; // 126
pub const ADD_AT2: usize = ADD_AT1 + GFP5_WIDTH; // 131
pub const ADD_AT3: usize = ADD_AT2 + GFP5_WIDTH; // 136
pub const ADD_AT4: usize = ADD_AT3 + GFP5_WIDTH; // 141
pub const ADD_AT5_RAW: usize = ADD_AT4 + GFP5_WIDTH; // 146
pub const ADD_AT6_RAW: usize = ADD_AT5_RAW + GFP5_WIDTH; // 151
pub const ADD_AT8: usize = ADD_AT6_RAW + GFP5_WIDTH; // 156
pub const ADD_AT9: usize = ADD_AT8 + GFP5_WIDTH; // 161
pub const ADD_AT10: usize = ADD_AT9 + GFP5_WIDTH; // 166
pub const ADD_U_PRE: usize = ADD_AT10 + GFP5_WIDTH; // 171

/// Phase indicator: identifies which scalar multiplication this row belongs to.
/// Ranges from 0 to 23 in the full ballot (8 fields x 3 scalar muls each).
pub const PHASE: usize = ADD_U_PRE + GFP5_WIDTH; // 176

/// Set to 1 on the last row of each scalar mul phase (and on padding rows).
/// Prevents the accumulator transition constraint from firing across phase
/// boundaries, which would be nonsensical.
pub const IS_LAST_IN_PHASE: usize = PHASE + 1; // 177

// ==========================================================================
// Section flags: tell the AIR which constraints to apply on each row.
// Exactly one of these can be 1, or both can be 0 (padding).
// ==========================================================================

/// 1 when this row is an EC scalar mul row, 0 otherwise.
pub const IS_EC: usize = IS_LAST_IN_PHASE + 1; // 178

/// 1 when this row is a Poseidon2 hash row, 0 otherwise.
pub const IS_P2: usize = IS_EC + 1; // 179

/// 1 when this row is a ballot validation row, 0 otherwise.
pub const IS_BV: usize = IS_P2 + 1; // 180

// When IS_EC=0 and IS_P2=0 and IS_BV=0, the row is padding (no constraints).

/// One-hot Poseidon round selectors. Only meaningful on IS_P2 rows.
pub const P2_ROUND_SEL: usize = IS_BV + 1; // 181
pub const P2_ROUND_SEL_COUNT: usize = 30;

/// One-hot ballot-validation row selectors. Only meaningful on IS_BV rows.
pub const BV_ROW_SEL: usize = P2_ROUND_SEL + P2_ROUND_SEL_COUNT; // 211
pub const BV_ROW_SEL_COUNT: usize = 9;

/// Extra EC binding columns used only in the full-ballot path.
pub const EC_BIND_ACTIVE: usize = BV_ROW_SEL + BV_ROW_SEL_COUNT; // 220
pub const EC_SCALAR_ACC: usize = EC_BIND_ACTIVE + 1; // 221
pub const EC_SCALAR_TARGET: usize = EC_SCALAR_ACC + 1; // 222
pub const EC_PHASE_SEL: usize = EC_SCALAR_TARGET + 1; // 223
pub const EC_PHASE_SEL_COUNT: usize = 24;

/// Hidden global values replicated on every row and linked to multiple sections.
pub const GLOBAL_KS: usize = EC_PHASE_SEL + EC_PHASE_SEL_COUNT; // 247
pub const GLOBAL_KS_COUNT: usize = 8;
pub const GLOBAL_FIELDS: usize = GLOBAL_KS + GLOBAL_KS_COUNT; // 255
pub const GLOBAL_FIELDS_COUNT: usize = 8;
pub const GLOBAL_BV_PARAMS: usize = GLOBAL_FIELDS + GLOBAL_FIELDS_COUNT; // 263
pub const GLOBAL_BV_PARAMS_COUNT: usize = 10;
pub const GLOBAL_BV_NUM_FIELDS: usize = GLOBAL_BV_PARAMS;
pub const GLOBAL_BV_MIN_VALUE: usize = GLOBAL_BV_PARAMS + 1;
pub const GLOBAL_BV_MAX_VALUE: usize = GLOBAL_BV_PARAMS + 2;
pub const GLOBAL_BV_UNIQUE: usize = GLOBAL_BV_PARAMS + 3;
pub const GLOBAL_BV_COST_FROM_WEIGHT: usize = GLOBAL_BV_PARAMS + 4;
pub const GLOBAL_BV_COST_EXP: usize = GLOBAL_BV_PARAMS + 5;
pub const GLOBAL_BV_MAX_SUM: usize = GLOBAL_BV_PARAMS + 6;
pub const GLOBAL_BV_MIN_SUM: usize = GLOBAL_BV_PARAMS + 7;
pub const GLOBAL_BV_GROUP_SIZE: usize = GLOBAL_BV_PARAMS + 8;
pub const GLOBAL_BV_WEIGHT: usize = GLOBAL_BV_PARAMS + 9;
pub const GLOBAL_PACKED_MODE: usize = GLOBAL_BV_PARAMS + GLOBAL_BV_PARAMS_COUNT; // 273
pub const GLOBAL_PACKED_MODE_COUNT: usize = 4;
pub const GLOBAL_PROCESS_ID: usize = GLOBAL_PACKED_MODE + GLOBAL_PACKED_MODE_COUNT; // 277
pub const GLOBAL_PROCESS_ID_COUNT: usize = 4;
pub const GLOBAL_K_LIMBS: usize = GLOBAL_PROCESS_ID + GLOBAL_PROCESS_ID_COUNT; // 281
pub const GLOBAL_K_LIMBS_COUNT: usize = 5;
pub const GLOBAL_PK: usize = GLOBAL_K_LIMBS + GLOBAL_K_LIMBS_COUNT; // 286
pub const GLOBAL_PK_COUNT: usize = 20;
pub const GLOBAL_S_POINTS: usize = GLOBAL_PK + GLOBAL_PK_COUNT; // 306
pub const GLOBAL_S_POINTS_COUNT: usize = 8 * 20;
pub const GLOBAL_C2_POINTS: usize = GLOBAL_S_POINTS + GLOBAL_S_POINTS_COUNT; // 466
pub const GLOBAL_C2_POINTS_COUNT: usize = 8 * 20;
pub const GLOBAL_C1_ENC: usize = GLOBAL_C2_POINTS + GLOBAL_C2_POINTS_COUNT; // 626
pub const GLOBAL_C1_ENC_COUNT: usize = 8 * 5;
pub const GLOBAL_C2_ENC: usize = GLOBAL_C1_ENC + GLOBAL_C1_ENC_COUNT; // 666
pub const GLOBAL_C2_ENC_COUNT: usize = 8 * 5;
pub const GLOBAL_HASH_INPUT: usize = GLOBAL_C2_ENC + GLOBAL_C2_ENC_COUNT; // 706
pub const GLOBAL_HASH_INPUT_COUNT: usize = 116;
pub const GLOBAL_C2_ADD_INTER: usize = GLOBAL_HASH_INPUT + GLOBAL_HASH_INPUT_COUNT; // 822
pub const GLOBAL_C2_ADD_INTER_COUNT: usize = 8 * 50;
pub const GLOBAL_PACKED_MODE_BITS: usize = GLOBAL_C2_ADD_INTER + GLOBAL_C2_ADD_INTER_COUNT; // 1222
pub const GLOBAL_PACKED_MODE_BITS_COUNT: usize = 248;

/// Selectors for the first 8 Poseidon permutations (the k-derivation chain).
pub const P2_K_SEL: usize = GLOBAL_PACKED_MODE_BITS + GLOBAL_PACKED_MODE_BITS_COUNT; // 1470
pub const P2_K_SEL_COUNT: usize = 8;
pub const P2_INPUTS_HASH_OUT: usize = P2_K_SEL + P2_K_SEL_COUNT; // 1230
pub const P2_VOTE_ID_OUT: usize = P2_INPUTS_HASH_OUT + 1; // 1231
pub const P2_ABSORB_CHUNK: usize = P2_VOTE_ID_OUT + 1; // 1232
pub const P2_ABSORB_CHUNK_COUNT: usize = 4;
pub const P2_VOTE_ID_PRE_SEL: usize = P2_ABSORB_CHUNK + P2_ABSORB_CHUNK_COUNT; // 1236
pub const P2_VOTE_ID_PRE_SEL_COUNT: usize = 4;
pub const P2_INPUTS_PREFIX_SEL: usize = P2_VOTE_ID_PRE_SEL + P2_VOTE_ID_PRE_SEL_COUNT; // 1240
pub const P2_INPUTS_PREFIX_SEL_COUNT: usize = 29;
pub const P2_VOTE_ID_BITS: usize = P2_INPUTS_PREFIX_SEL + P2_INPUTS_PREFIX_SEL_COUNT; // 1269
pub const P2_VOTE_ID_BITS_COUNT: usize = 64;

// ==========================================================================
// Poseidon2 columns (active when IS_P2 = 1)
//
// These physically overlap with the EC columns because EC and Poseidon2
// never share a row. Section gating ensures the constraints stay separate.
// ==========================================================================

/// Poseidon2 state: 8 Goldilocks elements in columns 0..7.
/// Overlaps with ACC_X[0..4] and part of ACC_Z -- safe because section-gated.
pub const P2_STATE: usize = 0;
pub const P2_STATE_WIDTH: usize = 8;

/// Round index within the current permutation (0..29).
pub const P2_ROUND: usize = 8;

/// Round type flag: 0 = full round (all 8 S-boxes active),
/// 1 = partial round (only element 0 goes through the S-box).
pub const P2_ROUND_TYPE: usize = 9;

/// Permutation ID: which hash call this row belongs to. Lets us track
/// separate permutations (k-derivation, vote ID, inputs hash) in the trace.
pub const P2_PERM_ID: usize = 10;

/// S-box intermediate columns for degree reduction.
///
/// Computing x^7 directly would be degree 7 and, combined with the IS_P2
/// gating flag, would push total constraint degree above our budget.
/// We decompose the S-box into stored intermediates:
///   x2[i] = state[i] + round_constant  (the "activated" input)
///   x3[i] = x2[i]^2                    (stored, verified at degree 2)
///   x6[i] = x2[i] * x3[i]             (stored, verified at degree 2)
///   x7[i] = x3[i]^2 * x6[i]           (stored, verified at degree 3)
///
/// Storing x7 keeps the max constraint degree at 4 (= 3 + 1 for gating),
/// which allows log_blowup=2 (4× domain) instead of 3 (8× domain).
pub const P2_SBOX_X2: usize = 11; // 8 columns (11..18)
pub const P2_SBOX_X3: usize = 19; // 8 columns (19..26)
pub const P2_SBOX_X6: usize = 27; // 8 columns (27..34)
pub const P2_SBOX_X7: usize = 35; // 8 columns (35..42)

// ==========================================================================
// Ballot validation columns (active when IS_BV = 1)
//
// The BV section checks that vote field values satisfy the ballot rules:
// range bounds, uniqueness, cost/sum limits. It uses 9 rows (one per field
// plus a bounds-check row). These columns physically overlap with EC/P2
// columns since the sections never share a row.
// ==========================================================================

/// All 8 field values, replicated on every BV row for cross-referencing
/// (e.g. uniqueness checks need access to all fields from each row).
pub const BV_FIELDS: usize = 0; // cols 0..7

/// Active-field mask replicated on every BV row. This is the Circom
/// `MaskGeneratorBounded` output for the current `num_fields`.
pub const BV_FIELD_MASKS: usize = 8; // cols 8..15
pub const BV_FIELD_MASKS_COUNT: usize = 8;

/// Number of active vote fields (num_fields from ballot mode).
pub const BV_NUM_FIELDS: usize = BV_FIELD_MASKS + BV_FIELD_MASKS_COUNT; // 16

/// Index of the field being checked on this row (0..7 for field rows, 8 for bounds row).
pub const BV_ROW_INDEX: usize = BV_NUM_FIELDS + 1; // 17

/// Mask bit: 1 if this field is active (index < num_fields), 0 otherwise.
pub const BV_MASK: usize = BV_ROW_INDEX + 1; // 18

/// Minimum allowed field value (from ballot mode, replicated on each row).
pub const BV_MIN_VALUE: usize = BV_MASK + 1; // 19

/// Maximum allowed field value (from ballot mode, replicated on each row).
pub const BV_MAX_VALUE: usize = BV_MIN_VALUE + 1; // 20

/// unique_values flag from ballot mode (1 = enforce uniqueness).
pub const BV_UNIQUE: usize = BV_MAX_VALUE + 1; // 21

/// cost_from_weight flag (0 = use max_value_sum as limit, 1 = use weight).
pub const BV_COST_FROM_WEIGHT: usize = BV_UNIQUE + 1; // 22

/// Cost exponent (the power to raise each field value to).
pub const BV_COST_EXP: usize = BV_COST_FROM_WEIGHT + 1; // 23

/// Maximum sum of field^exponent values (upper bound on total cost).
pub const BV_MAX_SUM: usize = BV_COST_EXP + 1; // 24

/// Minimum sum of field^exponent values (lower bound on total cost).
pub const BV_MIN_SUM: usize = BV_MAX_SUM + 1; // 25

/// Voter weight (alternative upper bound when cost_from_weight=1).
pub const BV_WEIGHT: usize = BV_MIN_SUM + 1; // 26

/// Group size from ballot mode.
pub const BV_GROUP_SIZE: usize = BV_WEIGHT + 1; // 27

/// 48-bit decomposition of (field_value - min_value). Proves field >= min.
/// These 48 columns each hold a single bit.
pub const BV_LOW_BITS: usize = BV_GROUP_SIZE + 1; // 28
pub const BV_LOW_BITS_COUNT: usize = 48;

/// 48-bit decomposition of (max_value - field_value). Proves field <= max.
/// These 48 columns (68..115) each hold a single bit.
pub const BV_HIGH_BITS: usize = BV_LOW_BITS + BV_LOW_BITS_COUNT; // 68
pub const BV_HIGH_BITS_COUNT: usize = 48;

/// 8-bit decomposition of the cost exponent (for binary exponentiation).
pub const BV_EXP_BITS: usize = BV_HIGH_BITS + BV_HIGH_BITS_COUNT; // 116
pub const BV_EXP_BITS_COUNT: usize = 8;

/// Squaring chain for binary exponentiation: sq[0]=field_val, sq[k]=sq[k-1]^2.
pub const BV_SQ: usize = BV_EXP_BITS + BV_EXP_BITS_COUNT; // 124
pub const BV_SQ_COUNT: usize = 8;

/// Running product for binary exponentiation:
/// acc[0] = exp_bit[0]*sq[0] + (1-exp_bit[0])
/// acc[k] = acc[k-1] * (exp_bit[k]*sq[k] + (1-exp_bit[k]))
pub const BV_ACC: usize = BV_SQ + BV_SQ_COUNT; // 132
pub const BV_ACC_COUNT: usize = 8;

/// The final power result: field^exponent = acc[7].
pub const BV_POWER: usize = BV_ACC + BV_ACC_COUNT; // 140

/// Running cost sum: cost_sum[i] = sum of mask[j]*power[j] for j=0..i.
/// On the last field row (index=7), this holds the total cost.
pub const BV_COST_SUM: usize = BV_POWER + 1; // 141

/// Inverses for uniqueness: inv_diff[j] = 1/(field[i] - field[j]) for j=0..7, j!=i.
/// Only meaningful when both fields are active and unique_values=1.
/// We store 8 values (using 0 for the self-position j==i).
pub const BV_INV_DIFF: usize = BV_COST_SUM + 1; // 142
pub const BV_INV_DIFF_COUNT: usize = 8;

/// On the bounds row (BV_ROW_INDEX=8):
/// 63-bit decomposition of (limit - total_cost). Proves cost <= limit.
pub const BV_LIMIT_BITS: usize = BV_LOW_BITS; // reuse low_bits columns on bounds row
pub const BV_LIMIT_BITS_COUNT: usize = 63;

/// On the bounds row: 63-bit decomposition of (total_cost - min_sum).
/// Proves cost >= min_sum.
pub const BV_MINSUB_BITS: usize = BV_LIMIT_BITS + BV_LIMIT_BITS_COUNT; // 83
pub const BV_MINSUB_BITS_COUNT: usize = 63;

/// On the bounds row: the computed limit value (max_value_sum or weight).
pub const BV_LIMIT: usize = BV_MINSUB_BITS + BV_MINSUB_BITS_COUNT; // 146

/// On the bounds row: the total cost (carried from last field row).
pub const BV_BOUNDS_COST: usize = BV_LIMIT + 1; // 147

/// On the bounds row: 8-bit decomposition of (num_fields - group_size).
/// Proves group_size <= num_fields.
pub const BV_GS_BITS: usize = BV_BOUNDS_COST + 1; // 148
pub const BV_GS_BITS_COUNT: usize = 8;

/// Flag: 1 if max_value_sum is zero (means no upper bound on cost).
pub const BV_MAX_SUM_IS_ZERO: usize = BV_GS_BITS + BV_GS_BITS_COUNT; // 156

/// Inverse of max_value_sum (used to prove max_sum_is_zero is correct).
pub const BV_MAX_SUM_INV: usize = BV_MAX_SUM_IS_ZERO + 1; // 157

/// Flag: 1 on the bounds row (row_idx == NUM_FIELDS), 0 on field rows.
/// Distinguishes the bounds row from inactive field rows (both have mask=0).
pub const BV_IS_BOUNDS: usize = BV_MAX_SUM_INV + 1; // 158

/// Intermediate products for binary exponentiation accumulator.
///
/// Storing acc_x_eb[k] = acc[k-1] * exp_bit[k] reduces the accumulator
/// constraint degree from 5 to 4, enabling log_blowup=2.
/// 7 columns for k=1..7 (k=0 doesn't need an intermediate).
pub const BV_ACC_INTER: usize = BV_IS_BOUNDS + 1; // 159
pub const BV_ACC_INTER_COUNT: usize = 7; // columns 159..165

// ==========================================================================
// Public-output row columns (active on the dedicated final binding row)
// ==========================================================================

/// Dedicated output row storage for the 9 public values.
/// This row has all section flags set to 0, so these columns do not overlap
/// with any active constraints from EC, Poseidon2, or ballot validation.
pub const PUB_OUTPUTS: usize = 0;

// ==========================================================================
// Total trace width
// ==========================================================================

/// Total trace width including section flags and selector bits.
pub const TRACE_WIDTH: usize = P2_VOTE_ID_BITS + P2_VOTE_ID_BITS_COUNT; // 1581

// ==========================================================================
// Helpers
// ==========================================================================

/// Pull a GF(p^5) element (5 consecutive field values) out of a row slice.
#[inline]
pub fn gfp5_slice<T: Clone>(row: &[T], offset: usize) -> [T; 5] {
    [
        row[offset].clone(),
        row[offset + 1].clone(),
        row[offset + 2].clone(),
        row[offset + 3].clone(),
        row[offset + 4].clone(),
    ]
}

/// The curve constant B1 = 263 from the ecgfp5 specification.
/// The full curve parameter is b = 263*z where z is the GF(p^5) generator,
/// and B1 is just the integer coefficient. Shows up everywhere in the
/// doubling/addition formulas.
pub const B1: u64 = 263;

/// Convert a GF(p^5) element from the ecgfp5 crate to 5 Goldilocks field values.
/// Needed when moving data between the ecgfp5 library (its own GFp5 type) and
/// the Plonky3 world (arrays of Goldilocks).
pub fn gfp5_to_felts<F: Field>(g: &ecgfp5::field::GFp5) -> [F; 5] {
    let arr = &g.0;
    [
        F::from_u64(arr[0].to_u64()),
        F::from_u64(arr[1].to_u64()),
        F::from_u64(arr[2].to_u64()),
        F::from_u64(arr[3].to_u64()),
        F::from_u64(arr[4].to_u64()),
    ]
}
