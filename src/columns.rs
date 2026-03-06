//! Column index definitions for the ballot proof trace.
//!
//! The trace is a flat matrix where each row contains all the data for one step
//! of computation. The columns are laid out so that EC scalar mul data and
//! Poseidon2 hash data can share physical columns (they never run in the same
//! row), which keeps the total width at 180 instead of ~220.
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

// When both IS_EC=0 and IS_P2=0 the row is padding (no constraints enforced).

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
/// gating flag, would push total constraint degree above 7. Instead we
/// decompose the S-box into stored intermediates:
///   x2[i] = state[i] + round_constant  (the "activated" input)
///   x3[i] = x2[i]^2
///   x6[i] = x2[i] * x3[i]             (= x2^3)
///   x7    = x3[i]^2 * x6[i]           (computed inline, degree 3)
/// The inline x7 computation keeps the max constraint degree at
/// 3 (x7) * 2 (gating) + 1 = 7.
pub const P2_SBOX_X2: usize = 11; // 8 columns (11..18)
pub const P2_SBOX_X3: usize = 19; // 8 columns (19..26)
pub const P2_SBOX_X6: usize = 27; // 8 columns (27..34)

// ==========================================================================
// Ballot validation columns (future use, overlapping via section gating)
// ==========================================================================

/// Vote field values for the 8 fields, used in ballot validation constraints.
/// Not yet enforced -- planned for Phase 5 (range checks, uniqueness, etc.).
pub const BV_FIELDS: usize = 0;
pub const BV_NUM_FIELDS: usize = 8;

// ==========================================================================
// Total trace width
// ==========================================================================

/// The widest section (EC) uses 178 columns, plus IS_EC and IS_P2 = 180.
pub const TRACE_WIDTH: usize = IS_P2 + 1; // 180

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

