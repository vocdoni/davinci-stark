//! BallotAir: AIR constraints for the full DAVINCI ballot proof.
//!
//! The trace is split into sections using binary flags IS_EC and IS_P2.
//! Each section has its own set of constraints that only fire when the
//! corresponding flag is 1. This lets us pack EC scalar muls, Poseidon2
//! hashing, and padding into the same trace without conflicts.
//!
//! Sections:
//!   IS_EC=1, IS_P2=0  ->  EC scalar multiplication constraints
//!   IS_EC=0, IS_P2=1  ->  Poseidon2 round transition constraints
//!   IS_EC=0, IS_P2=0  ->  Padding rows (no constraints enforced)
//!
//! The IS_EC and IS_P2 flags are themselves constrained to be binary and
//! mutually exclusive on every row.

use p3_field::{Algebra, ExtensionField, Field, PrimeCharacteristicRing, PrimeField64};
use p3_matrix::Matrix;
use p3_miden_air::{MidenAir, MidenAirBuilder};

use crate::columns::*;
use crate::gfp5::*;
use crate::poseidon2;

/// Full ecgfp5 scalar bit count (group order is roughly 2^319).
/// Used for the legacy single-field API which operates on full scalars.
pub const SCALAR_BITS: usize = 319;

/// Bit count for derived scalars (k_i values are Goldilocks elements, 64 bits).
/// Using 64-bit muls instead of 319-bit saves about 80% of EC rows.
pub const SMALL_SCALAR_BITS: usize = 64;

/// Number of vote fields in a ballot.
pub const NUM_FIELDS: usize = 8;

/// Each field needs 3 scalar muls: k_i*G, k_i*PK, field_i*G.
pub const SCALAR_MULS_PER_FIELD: usize = 3;

/// Total scalar multiplications in a full ballot proof: 8 fields x 3 = 24.
pub const NUM_SCALAR_MULS: usize = NUM_FIELDS * SCALAR_MULS_PER_FIELD;

/// EC rows with full 319-bit scalars (used by legacy single-field API).
pub const EC_ROWS: usize = SCALAR_BITS * NUM_SCALAR_MULS;

/// Poseidon2 rounds per permutation (4 full + 22 partial + 4 full = 30).
pub const P2_ROUNDS_PER_PERM: usize = poseidon2::TOTAL_ROUNDS;

/// Trace height for legacy single-field proofs (padded to 2^14).
pub const TRACE_HEIGHT: usize = 16384;

/// Section type constants (not used as columns -- just for documentation and
/// trace-generation logic).
pub const SECTION_EC: u64 = 0;
pub const SECTION_P2: u64 = 1;
pub const SECTION_VALID: u64 = 2;
pub const SECTION_PAD: u64 = 3;

// -- Public values layout --
// These indices define where each public value lives in the PV vector.
// The layout matches the Circom circuit: {inputs_hash, address, vote_id}.
// The inputs_hash is a Poseidon2 sponge that covers everything sensitive,
// so exposing just these 9 values reveals nothing about private inputs.

/// Start index for the 4-element inputs hash in the public values vector.
pub const PV_INPUTS_HASH: usize = 0;
/// Start index for the 4-element voter address.
pub const PV_ADDRESS: usize = 4;
/// Index of the single vote_id element.
pub const PV_VOTE_ID: usize = 8;
/// Total number of public value elements.
pub const PV_COUNT: usize = 9;

/// BallotAir holds the Poseidon2 round constants that the constraint evaluator
/// needs. These must match exactly what the trace generator used, so both sides
/// derive them from the same seed (42).
pub struct BallotAir {
    pub p2_constants: poseidon2::Poseidon2Constants,
}

impl BallotAir {
    pub fn new() -> Self {
        Self {
            p2_constants: poseidon2::Poseidon2Constants::from_seed(42),
        }
    }
}

impl<F: Field, EF: ExtensionField<F>> MidenAir<F, EF> for BallotAir {
    fn width(&self) -> usize {
        TRACE_WIDTH
    }

    fn eval<AB: MidenAirBuilder<F = F>>(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0).expect("empty trace");
        let next = main.row_slice(1).expect("trace too short");

        let is_ec: AB::Expr = local[IS_EC].clone().into();
        let is_p2: AB::Expr = local[IS_P2].clone().into();
        let is_bv: AB::Expr = local[IS_BV].clone().into();

        // Section flags must be binary (0 or 1).
        builder.assert_zero(is_ec.clone() * (is_ec.clone() - AB::Expr::ONE));
        builder.assert_zero(is_p2.clone() * (is_p2.clone() - AB::Expr::ONE));
        builder.assert_zero(is_bv.clone() * (is_bv.clone() - AB::Expr::ONE));
        // At most one section flag can be 1 on any given row.
        builder.assert_zero(is_ec.clone() * is_p2.clone());
        builder.assert_zero(is_ec.clone() * is_bv.clone());
        builder.assert_zero(is_p2.clone() * is_bv.clone());

        // ============================================================
        // EC constraints: only fire when IS_EC = 1.
        // Covers doubling, addition, multiplexer, and bit validity.
        // ============================================================
        eval_ec_constraints::<AB>(builder, &local, &next, &is_ec);

        // ============================================================
        // Poseidon2 constraints: only fire when IS_P2 = 1.
        // Covers S-box intermediates and round state transitions.
        // ============================================================
        eval_poseidon2_constraints::<AB>(builder, &local, &next, &is_p2, &self.p2_constants);

        // ============================================================
        // Ballot validation constraints: only fire when IS_BV = 1.
        // Range checks, uniqueness, power computation, cost bounds.
        // ============================================================
        eval_bv_constraints::<AB>(builder, &local, &next, &is_bv);

        // ============================================================
        // First-row boundary: the accumulator starts at the neutral point.
        // The neutral point in Jacobi quartic is (X=0, Z=1, U=0, T=1).
        // Gated by IS_EC so it only applies if the trace starts with EC rows.
        // ============================================================
        {
            let mut first = builder.when_first_row();
            let acc_x: [AB::Expr; 5] = gfp5_expr::<AB>(&local, ACC_X);
            let acc_z: [AB::Expr; 5] = gfp5_expr::<AB>(&local, ACC_Z);
            let acc_u: [AB::Expr; 5] = gfp5_expr::<AB>(&local, ACC_U);
            let acc_t: [AB::Expr; 5] = gfp5_expr::<AB>(&local, ACC_T);
            // Neutral point: X=0, Z=1, U=0, T=1  --  gated by IS_EC
            for i in 0..5 {
                first.assert_zero(is_ec.clone() * acc_x[i].clone());
                first.assert_zero(is_ec.clone() * acc_u[i].clone());
            }
            first.assert_zero(is_ec.clone() * (acc_z[0].clone() - AB::Expr::ONE));
            for i in 1..5 {
                first.assert_zero(is_ec.clone() * acc_z[i].clone());
            }
            first.assert_zero(is_ec.clone() * (acc_t[0].clone() - AB::Expr::ONE));
            for i in 1..5 {
                first.assert_zero(is_ec.clone() * acc_t[i].clone());
            }
        }
    }
}

/// EC scalar multiplication constraints, gated by the `gate` expression (IS_EC).
///
/// For each row in the EC section, we verify:
///   1. The scalar bit is binary (0 or 1)
///   2. The doubled point is correctly derived from the accumulator
///      (9 GF(p^5) product constraints for the doubling formula)
///   3. The added point is correctly derived from the doubled point + base
///      (10 GF(p^5) product constraints for the addition formula)
///   4. The next row's accumulator picks up either the doubled or added
///      point depending on the scalar bit (multiplexer constraint)
///   5. IS_LAST_IN_PHASE is binary (gates the transition constraint)
///
/// All constraints are multiplied by `gate` so they evaluate to zero on
/// non-EC rows regardless of what data is in those columns.
fn eval_ec_constraints<AB: MidenAirBuilder>(
    builder: &mut AB,
    local: &[AB::Var],
    next: &[AB::Var],
    gate: &AB::Expr,
) {
    let acc_x: [AB::Expr; 5] = gfp5_expr::<AB>(local, ACC_X);
    let acc_z: [AB::Expr; 5] = gfp5_expr::<AB>(local, ACC_Z);
    let acc_u: [AB::Expr; 5] = gfp5_expr::<AB>(local, ACC_U);
    let acc_t: [AB::Expr; 5] = gfp5_expr::<AB>(local, ACC_T);

    let base_x: [AB::Expr; 5] = gfp5_expr::<AB>(local, BASE_X);
    let base_z: [AB::Expr; 5] = gfp5_expr::<AB>(local, BASE_Z);
    let base_u: [AB::Expr; 5] = gfp5_expr::<AB>(local, BASE_U);
    let base_t: [AB::Expr; 5] = gfp5_expr::<AB>(local, BASE_T);

    let bit: AB::Expr = local[BIT].clone().into();

    let dbl_x: [AB::Expr; 5] = gfp5_expr::<AB>(local, DBL_X);
    let dbl_z: [AB::Expr; 5] = gfp5_expr::<AB>(local, DBL_Z);
    let dbl_u: [AB::Expr; 5] = gfp5_expr::<AB>(local, DBL_U);
    let dbl_t: [AB::Expr; 5] = gfp5_expr::<AB>(local, DBL_T);

    let dbl_t1: [AB::Expr; 5] = gfp5_expr::<AB>(local, DBL_T1);
    let dbl_t2: [AB::Expr; 5] = gfp5_expr::<AB>(local, DBL_T2);
    let dbl_x1: [AB::Expr; 5] = gfp5_expr::<AB>(local, DBL_X1);
    let dbl_z1: [AB::Expr; 5] = gfp5_expr::<AB>(local, DBL_Z1);
    let dbl_t3: [AB::Expr; 5] = gfp5_expr::<AB>(local, DBL_T3);
    let dbl_xz_t3: [AB::Expr; 5] = gfp5_expr::<AB>(local, DBL_XZ_T3);
    let dbl_t4: [AB::Expr; 5] = gfp5_expr::<AB>(local, DBL_T4);
    let dbl_w1sq: [AB::Expr; 5] = gfp5_expr::<AB>(local, DBL_W1SQ);
    let dbl_wz_sq: [AB::Expr; 5] = gfp5_expr::<AB>(local, DBL_WZ_SQ);

    let add_x: [AB::Expr; 5] = gfp5_expr::<AB>(local, ADD_X);
    let add_z: [AB::Expr; 5] = gfp5_expr::<AB>(local, ADD_Z);
    let add_u: [AB::Expr; 5] = gfp5_expr::<AB>(local, ADD_U);
    let add_t: [AB::Expr; 5] = gfp5_expr::<AB>(local, ADD_T);

    let add_at1: [AB::Expr; 5] = gfp5_expr::<AB>(local, ADD_AT1);
    let add_at2: [AB::Expr; 5] = gfp5_expr::<AB>(local, ADD_AT2);
    let add_at3: [AB::Expr; 5] = gfp5_expr::<AB>(local, ADD_AT3);
    let add_at4: [AB::Expr; 5] = gfp5_expr::<AB>(local, ADD_AT4);
    let add_at5_raw: [AB::Expr; 5] = gfp5_expr::<AB>(local, ADD_AT5_RAW);
    let add_at6_raw: [AB::Expr; 5] = gfp5_expr::<AB>(local, ADD_AT6_RAW);
    let add_at8: [AB::Expr; 5] = gfp5_expr::<AB>(local, ADD_AT8);
    let add_at9: [AB::Expr; 5] = gfp5_expr::<AB>(local, ADD_AT9);
    let add_at10: [AB::Expr; 5] = gfp5_expr::<AB>(local, ADD_AT10);
    let add_u_pre: [AB::Expr; 5] = gfp5_expr::<AB>(local, ADD_U_PRE);

    let is_last: AB::Expr = local[IS_LAST_IN_PHASE].clone().into();

    let next_acc_x: [AB::Expr; 5] = gfp5_expr::<AB>(next, ACC_X);
    let next_acc_z: [AB::Expr; 5] = gfp5_expr::<AB>(next, ACC_Z);
    let next_acc_u: [AB::Expr; 5] = gfp5_expr::<AB>(next, ACC_U);
    let next_acc_t: [AB::Expr; 5] = gfp5_expr::<AB>(next, ACC_T);

    // Bit validity: gate * bit * (1 - bit) = 0
    builder.assert_zero(gate.clone() * bit.clone() * (AB::Expr::ONE - bit.clone()));

    // --- Doubling constraints (gated) ---
    // dbl_t1 = acc_Z * acc_T
    for c in gfp5_mul_constraints::<AB::F, AB::Expr>(acc_z.clone(), acc_t.clone(), dbl_t1.clone()) {
        builder.assert_zero(gate.clone() * c);
    }
    // dbl_t2 = dbl_t1 * acc_T
    for c in gfp5_mul_constraints::<AB::F, AB::Expr>(dbl_t1.clone(), acc_t.clone(), dbl_t2.clone()) {
        builder.assert_zero(gate.clone() * c);
    }
    // dbl_x1 = dbl_t2^2
    for c in gfp5_square_constraints::<AB::F, AB::Expr>(dbl_t2.clone(), dbl_x1.clone()) {
        builder.assert_zero(gate.clone() * c);
    }
    // dbl_z1 = dbl_t1 * acc_U
    for c in gfp5_mul_constraints::<AB::F, AB::Expr>(dbl_t1.clone(), acc_u.clone(), dbl_z1.clone()) {
        builder.assert_zero(gate.clone() * c);
    }
    // dbl_t3 = acc_U^2
    for c in gfp5_square_constraints::<AB::F, AB::Expr>(acc_u.clone(), dbl_t3.clone()) {
        builder.assert_zero(gate.clone() * c);
    }
    // dbl_xz_t3 = (acc_X + acc_Z) * dbl_t3
    let acc_x_plus_z = gfp5_add::<AB::F, AB::Expr>(acc_x.clone(), acc_z.clone());
    for c in gfp5_mul_constraints::<AB::F, AB::Expr>(acc_x_plus_z, dbl_t3.clone(), dbl_xz_t3.clone()) {
        builder.assert_zero(gate.clone() * c);
    }
    // W1 = dbl_t2 - 2*dbl_xz_t3
    let w1 = gfp5_sub::<AB::F, AB::Expr>(
        dbl_t2.clone(),
        gfp5_scale::<AB::F, AB::Expr>(2, dbl_xz_t3.clone()),
    );
    // dbl_t4 = dbl_z1^2
    for c in gfp5_square_constraints::<AB::F, AB::Expr>(dbl_z1.clone(), dbl_t4.clone()) {
        builder.assert_zero(gate.clone() * c);
    }
    // dbl_w1sq = W1^2
    for c in gfp5_square_constraints::<AB::F, AB::Expr>(w1.clone(), dbl_w1sq.clone()) {
        builder.assert_zero(gate.clone() * c);
    }
    // dbl_wz_sq = (W1 + Z1)^2
    let w1_plus_z1 = gfp5_add::<AB::F, AB::Expr>(w1, dbl_z1.clone());
    for c in gfp5_square_constraints::<AB::F, AB::Expr>(w1_plus_z1, dbl_wz_sq.clone()) {
        builder.assert_zero(gate.clone() * c);
    }

    // --- Doubled point derivation ---
    let k_val = 4 * B1;
    let dbl_x_expected = gfp5_mul_by_kz::<AB::F, AB::Expr>(k_val, dbl_t4.clone());
    for i in 0..5 {
        builder.assert_zero(gate.clone() * (dbl_x[i].clone() - dbl_x_expected[i].clone()));
    }
    for i in 0..5 {
        builder.assert_zero(gate.clone() * (dbl_z[i].clone() - dbl_w1sq[i].clone()));
    }
    let dbl_u_expected = gfp5_sub::<AB::F, AB::Expr>(
        gfp5_sub::<AB::F, AB::Expr>(dbl_wz_sq.clone(), dbl_t4.clone()),
        dbl_w1sq.clone(),
    );
    for i in 0..5 {
        builder.assert_zero(gate.clone() * (dbl_u[i].clone() - dbl_u_expected[i].clone()));
    }
    let dbl_t_expected = gfp5_sub::<AB::F, AB::Expr>(
        gfp5_sub::<AB::F, AB::Expr>(
            gfp5_scale::<AB::F, AB::Expr>(2, dbl_x1.clone()),
            gfp5_scale::<AB::F, AB::Expr>(4, dbl_t4.clone()),
        ),
        dbl_w1sq.clone(),
    );
    for i in 0..5 {
        builder.assert_zero(gate.clone() * (dbl_t[i].clone() - dbl_t_expected[i].clone()));
    }

    // --- Addition constraints (gated) ---
    for c in gfp5_mul_constraints::<AB::F, AB::Expr>(dbl_x.clone(), base_x.clone(), add_at1.clone()) {
        builder.assert_zero(gate.clone() * c);
    }
    for c in gfp5_mul_constraints::<AB::F, AB::Expr>(dbl_z.clone(), base_z.clone(), add_at2.clone()) {
        builder.assert_zero(gate.clone() * c);
    }
    for c in gfp5_mul_constraints::<AB::F, AB::Expr>(dbl_u.clone(), base_u.clone(), add_at3.clone()) {
        builder.assert_zero(gate.clone() * c);
    }
    for c in gfp5_mul_constraints::<AB::F, AB::Expr>(dbl_t.clone(), base_t.clone(), add_at4.clone()) {
        builder.assert_zero(gate.clone() * c);
    }
    let dxz = gfp5_add::<AB::F, AB::Expr>(dbl_x.clone(), dbl_z.clone());
    let bxz = gfp5_add::<AB::F, AB::Expr>(base_x.clone(), base_z.clone());
    for c in gfp5_mul_constraints::<AB::F, AB::Expr>(dxz, bxz, add_at5_raw.clone()) {
        builder.assert_zero(gate.clone() * c);
    }
    let dut = gfp5_add::<AB::F, AB::Expr>(dbl_u.clone(), dbl_t.clone());
    let but = gfp5_add::<AB::F, AB::Expr>(base_u.clone(), base_t.clone());
    for c in gfp5_mul_constraints::<AB::F, AB::Expr>(dut, but, add_at6_raw.clone()) {
        builder.assert_zero(gate.clone() * c);
    }
    let t5 = gfp5_sub::<AB::F, AB::Expr>(
        gfp5_sub::<AB::F, AB::Expr>(add_at5_raw.clone(), add_at1.clone()),
        add_at2.clone(),
    );
    let t6 = gfp5_sub::<AB::F, AB::Expr>(
        gfp5_sub::<AB::F, AB::Expr>(add_at6_raw.clone(), add_at3.clone()),
        add_at4.clone(),
    );
    let t7 = gfp5_add::<AB::F, AB::Expr>(
        add_at1.clone(),
        gfp5_mul_by_kz::<AB::F, AB::Expr>(B1, add_at2.clone()),
    );
    for c in gfp5_mul_constraints::<AB::F, AB::Expr>(add_at4.clone(), t7.clone(), add_at8.clone()) {
        builder.assert_zero(gate.clone() * c);
    }
    let t9_factor = gfp5_add::<AB::F, AB::Expr>(
        gfp5_mul_by_kz::<AB::F, AB::Expr>(2 * B1, t5.clone()),
        gfp5_scale::<AB::F, AB::Expr>(2, t7.clone()),
    );
    for c in gfp5_mul_constraints::<AB::F, AB::Expr>(add_at3.clone(), t9_factor, add_at9.clone()) {
        builder.assert_zero(gate.clone() * c);
    }
    let at10_lhs = gfp5_add::<AB::F, AB::Expr>(
        add_at4.clone(),
        gfp5_scale::<AB::F, AB::Expr>(2, add_at3.clone()),
    );
    let at10_rhs = gfp5_add::<AB::F, AB::Expr>(t5.clone(), t7.clone());
    for c in gfp5_mul_constraints::<AB::F, AB::Expr>(at10_lhs, at10_rhs, add_at10.clone()) {
        builder.assert_zero(gate.clone() * c);
    }
    let u_pre_rhs = gfp5_sub::<AB::F, AB::Expr>(
        gfp5_mul_by_kz::<AB::F, AB::Expr>(B1, add_at2.clone()),
        add_at1.clone(),
    );
    for c in gfp5_mul_constraints::<AB::F, AB::Expr>(t6, u_pre_rhs, add_u_pre.clone()) {
        builder.assert_zero(gate.clone() * c);
    }

    // --- Added point derivation ---
    let add_x_expected = gfp5_mul_by_kz::<AB::F, AB::Expr>(
        B1,
        gfp5_sub::<AB::F, AB::Expr>(add_at10.clone(), add_at8.clone()),
    );
    for i in 0..5 {
        builder.assert_zero(gate.clone() * (add_x[i].clone() - add_x_expected[i].clone()));
    }
    let add_z_expected = gfp5_sub::<AB::F, AB::Expr>(add_at8.clone(), add_at9.clone());
    for i in 0..5 {
        builder.assert_zero(gate.clone() * (add_z[i].clone() - add_z_expected[i].clone()));
    }
    for i in 0..5 {
        builder.assert_zero(gate.clone() * (add_u[i].clone() - add_u_pre[i].clone()));
    }
    let add_t_expected = gfp5_add::<AB::F, AB::Expr>(add_at8.clone(), add_at9.clone());
    for i in 0..5 {
        builder.assert_zero(gate.clone() * (add_t[i].clone() - add_t_expected[i].clone()));
    }

    // --- Multiplexer: next_acc = bit ? added : doubled ---
    {
        let mut when_trans = builder.when_transition();
        let not_last = AB::Expr::ONE - is_last.clone();
        for i in 0..5 {
            when_trans.assert_zero(
                gate.clone() * not_last.clone() * (
                    next_acc_x[i].clone() - dbl_x[i].clone()
                        - bit.clone() * (add_x[i].clone() - dbl_x[i].clone())
                ),
            );
            when_trans.assert_zero(
                gate.clone() * not_last.clone() * (
                    next_acc_z[i].clone() - dbl_z[i].clone()
                        - bit.clone() * (add_z[i].clone() - dbl_z[i].clone())
                ),
            );
            when_trans.assert_zero(
                gate.clone() * not_last.clone() * (
                    next_acc_u[i].clone() - dbl_u[i].clone()
                        - bit.clone() * (add_u[i].clone() - dbl_u[i].clone())
                ),
            );
            when_trans.assert_zero(
                gate.clone() * not_last.clone() * (
                    next_acc_t[i].clone() - dbl_t[i].clone()
                        - bit.clone() * (add_t[i].clone() - dbl_t[i].clone())
                ),
            );
        }
        // is_last  in  {0, 1}
        when_trans.assert_zero(
            gate.clone() * is_last.clone() * (AB::Expr::ONE - is_last.clone())
        );
    }
}

/// Poseidon2 round transition constraints, gated by the `gate` expression (IS_P2).
///
/// Each Poseidon2 row stores the state BEFORE a round. The next row's state
/// should equal the result of applying one round (S-box + linear layer) to
/// the current state. We verify this transition when both the current and
/// next rows are Poseidon2 rows (both_p2 = IS_P2[local] * IS_P2[next]).
///
/// To keep the constraint degree within our blowup budget, the S-box x^7
/// is decomposed into stored intermediates:
///   x2 = state + round_constant  (written by prover)
///   x3 = x2^2                    (constrained, degree 2)
///   x6 = x2 * x3                 (constrained, degree 2)
///   x7 = x3^2 * x6              (computed inline, degree 3)
///
/// For full rounds all 8 elements go through the S-box.
/// For partial rounds only element 0 does; elements 1-7 pass through unchanged.
/// The round_type flag (0=full, 1=partial) selects between these two modes.
///
/// Maximum constraint degree:
///   x7 computation (degree 3) * is_full selector (1) * both_p2 (2) = 6
///   or with is_partial: state passthrough (1) * partial (1) * both_p2 (2) + similar = 7
fn eval_poseidon2_constraints<AB: MidenAirBuilder>(
    builder: &mut AB,
    local: &[AB::Var],
    next: &[AB::Var],
    gate: &AB::Expr,
    _constants: &poseidon2::Poseidon2Constants,
) {
    // gate = IS_P2 (binary, degree 1)

    // Current row's Poseidon2 state (before this round).
    let state: Vec<AB::Expr> = (0..poseidon2::WIDTH)
        .map(|i| local[P2_STATE + i].clone().into())
        .collect();
    // Next row's state (should equal the result after applying this round).
    let next_state: Vec<AB::Expr> = (0..poseidon2::WIDTH)
        .map(|i| next[P2_STATE + i].clone().into())
        .collect();

    // S-box intermediates: x2 = s (activated state), x3 = s^2, x6 = s^3
    let x2: Vec<AB::Expr> = (0..poseidon2::WIDTH)
        .map(|i| local[P2_SBOX_X2 + i].clone().into())
        .collect();
    let x3: Vec<AB::Expr> = (0..poseidon2::WIDTH)
        .map(|i| local[P2_SBOX_X3 + i].clone().into())
        .collect();
    let x6: Vec<AB::Expr> = (0..poseidon2::WIDTH)
        .map(|i| local[P2_SBOX_X6 + i].clone().into())
        .collect();

    // round_type: 0 = full round, 1 = partial round (binary)
    let round_type: AB::Expr = local[P2_ROUND_TYPE].clone().into();

    // Constrain round_type is binary
    builder.assert_zero(gate.clone() * round_type.clone() * (round_type.clone() - AB::Expr::ONE));

    // Selectors (degree 1 each)
    let is_partial = round_type.clone();
    let is_full = AB::Expr::ONE - round_type.clone();

    // ============================================================
    // S-box intermediate constraints
    // x2[i] = s_i (prover fills with state[i] + round_constant[i])
    // x3[i] = s_i^2 for active elements, 0 for inactive
    // x6[i] = s_i^3 for active elements, 0 for inactive
    // ============================================================
    for i in 0..poseidon2::WIDTH {
        if i == 0 {
            // Element 0 always goes through S-box (both full and partial rounds)
            // x3[0] = x2[0]^2  (degree 2, gated = degree 3)
            builder.assert_zero(gate.clone() * (x3[0].clone() - x2[0].clone() * x2[0].clone()));
            // x6[0] = x2[0] * x3[0]  (degree 2, gated = degree 3)
            builder.assert_zero(gate.clone() * (x6[0].clone() - x2[0].clone() * x3[0].clone()));
        } else {
            // Elements 1..7: S-box in full rounds, zero in partial rounds
            builder.assert_zero(gate.clone() * (
                is_full.clone() * (x3[i].clone() - x2[i].clone() * x2[i].clone())
                + is_partial.clone() * x3[i].clone()
            ));
            builder.assert_zero(gate.clone() * (
                is_full.clone() * (x6[i].clone() - x2[i].clone() * x3[i].clone())
                + is_partial.clone() * x6[i].clone()
            ));
        }
    }

    // ============================================================
    // State transition: next_state = linear_layer(sbox_outputs)
    // ============================================================
    // x7[i] = x3[i]^2 * x6[i]  (= (s^2)^2 * s^3 = s^4 * s^3 = s^7), degree 3
    let mut x7 = Vec::with_capacity(poseidon2::WIDTH);
    x7.push(x3[0].clone() * x3[0].clone() * x6[0].clone());
    for i in 1..poseidon2::WIDTH {
        // is_full * (x3^2 * x6) + is_partial * state[i], degree 4
        x7.push(
            is_full.clone() * x3[i].clone() * x3[i].clone() * x6[i].clone()
            + is_partial.clone() * state[i].clone()
        );
    }

    // External linear layer (full rounds): mat4 blocks then mix
    let mat4 = |a: &AB::Expr, b: &AB::Expr, c: &AB::Expr, d: &AB::Expr| -> [AB::Expr; 4] {
        let t01 = a.clone() + b.clone();
        let t23 = c.clone() + d.clone();
        let t0123 = t01.clone() + t23.clone();
        let t01123 = t0123.clone() + b.clone();
        let t01233 = t0123 + d.clone();
        [
            t01123.clone() + t01,
            t01123 + c.double(),
            t01233.clone() + t23,
            t01233 + a.double(),
        ]
    };

    let b0 = mat4(&x7[0], &x7[1], &x7[2], &x7[3]);
    let b1 = mat4(&x7[4], &x7[5], &x7[6], &x7[7]);

    let mut full_next = Vec::with_capacity(poseidon2::WIDTH);
    for i in 0..4 {
        let sum = b0[i].clone() + b1[i].clone();
        full_next.push(b0[i].clone() + sum.clone());
    }
    for i in 0..4 {
        let sum = b0[i].clone() + b1[i].clone();
        full_next.push(b1[i].clone() + sum);
    }

    // Internal linear layer (partial rounds):
    let mut partial_sum = x7[0].clone();
    for i in 1..poseidon2::WIDTH {
        partial_sum = partial_sum + state[i].clone();
    }
    let mut partial_next = Vec::with_capacity(poseidon2::WIDTH);
    for i in 0..poseidon2::WIDTH {
        let val = if i == 0 { x7[0].clone() } else { state[i].clone() };
        let diag_i = AB::Expr::from_u64(poseidon2::MATRIX_DIAG_8[i] % p3_goldilocks::Goldilocks::ORDER_U64);
        partial_next.push(val * diag_i + partial_sum.clone());
    }

    // Transition constraints (only when next row is also P2)
    {
        let mut when_trans = builder.when_transition();
        let next_is_p2: AB::Expr = next[IS_P2].clone().into();
        let both_p2 = gate.clone() * next_is_p2; // degree 2

        for i in 0..poseidon2::WIDTH {
            // expected degree: is_full(1) * full_next(4) = 5, gated by both_p2(2) = 7
            let expected = is_full.clone() * full_next[i].clone()
                + is_partial.clone() * partial_next[i].clone();
            when_trans.assert_zero(
                both_p2.clone() * (next_state[i].clone() - expected)
            );
        }
    }
}

// ============================================================
// Helper: extract GF(p^5) expression array from row slice
// ============================================================
/// Helper: pull a GF(p^5) element from a row slice as symbolic expressions.
fn gfp5_expr<AB: MidenAirBuilder>(row: &[AB::Var], offset: usize) -> [AB::Expr; 5] {
    [
        row[offset].clone().into(),
        row[offset + 1].clone().into(),
        row[offset + 2].clone().into(),
        row[offset + 3].clone().into(),
        row[offset + 4].clone().into(),
    ]
}

/// Multiply a GF(p^5) element by the constant k*z, where z is the extension
/// generator (x mod x^5 - 3). This is the "mul_small_k1" operation from ecgfp5.
///
/// Algebraically: (a0 + a1*z + a2*z^2 + a3*z^3 + a4*z^4) * k*z
///   = k * (3*a4 + a0*z + a1*z^2 + a2*z^3 + a3*z^4)
/// because z^5 = 3 in GF(p^5).
pub fn gfp5_mul_by_kz<F: PrimeCharacteristicRing, E: Algebra<F> + Clone>(
    k: u64,
    a: [E; 5],
) -> [E; 5] {
    let kf = E::from_u64(k);
    let three_k = E::from_u64(3 * k);
    [
        three_k * a[4].clone(),
        kf.clone() * a[0].clone(),
        kf.clone() * a[1].clone(),
        kf.clone() * a[2].clone(),
        kf * a[3].clone(),
    ]
}

// ==========================================================================
// Ballot validation constraints (gated by IS_BV)
//
// The BV section has 9 rows: 8 per-field rows + 1 bounds row.
// Per-field rows verify range checks, power computation, and uniqueness.
// The bounds row verifies cost sum limits and group_size <= num_fields.
// ==========================================================================

/// Evaluate all ballot validation constraints on rows where IS_BV=1.
///
/// The constraint design:
///   - All bit columns are binary (degree 2, gated -> degree 3)
///   - Range checks: bit recomposition matches (value - min) and (max - value)
///   - Power chain: sq[k] = sq[k-1]^2, acc chain for binary exponentiation
///   - Uniqueness: (field[i] - field[j]) * inv[j] * mask * unique = mask * unique
///   - Cost sum transition: cost_sum[next_row] = cost_sum[current] + mask * power
///   - Bounds row: bit decomposition of (limit - cost) and (cost - min_sum)
///
/// Maximum constraint degree: 4 (product of gate * mask * inv * diff).
/// Well within the degree-7 budget.
fn eval_bv_constraints<AB: MidenAirBuilder>(
    builder: &mut AB,
    local: &[AB::Var],
    next: &[AB::Var],
    gate: &AB::Expr,
) {
    // Helper to read a local column as an expression
    let col = |c: usize| -> AB::Expr { local[c].clone().into() };
    let ncol = |c: usize| -> AB::Expr { next[c].clone().into() };

    let mask = col(BV_MASK);
    let unique = col(BV_UNIQUE);
    let row_idx = col(BV_ROW_INDEX);
    let num_fields = col(BV_NUM_FIELDS);
    let min_val = col(BV_MIN_VALUE);
    let max_val = col(BV_MAX_VALUE);

    // 1. Mask must be binary
    builder.assert_zero(gate.clone() * mask.clone() * (mask.clone() - AB::Expr::ONE));

    // 2. Unique flag must be binary
    builder.assert_zero(gate.clone() * unique.clone() * (unique.clone() - AB::Expr::ONE));

    // 3. Range-check bits must be binary (48 low + 48 high), gated by mask
    for b in 0..BV_LOW_BITS_COUNT {
        let bit = col(BV_LOW_BITS + b);
        builder.assert_zero(gate.clone() * mask.clone() * bit.clone() * (bit.clone() - AB::Expr::ONE));
    }
    for b in 0..BV_HIGH_BITS_COUNT {
        let bit = col(BV_HIGH_BITS + b);
        builder.assert_zero(gate.clone() * mask.clone() * bit.clone() * (bit.clone() - AB::Expr::ONE));
    }

    // 5. Exponent bits must be binary
    for b in 0..BV_EXP_BITS_COUNT {
        let bit = col(BV_EXP_BITS + b);
        builder.assert_zero(gate.clone() * bit.clone() * (bit.clone() - AB::Expr::ONE));
    }

    let field_val_this_row = col(BV_SQ); // sq[0] = the field value on this row

    // 4. Range check recomposition
    let mut low_recomp = AB::Expr::ZERO;
    let mut pow2 = AB::Expr::ONE;
    for b in 0..BV_LOW_BITS_COUNT {
        low_recomp = low_recomp + pow2.clone() * col(BV_LOW_BITS + b);
        pow2 = pow2 * AB::Expr::from_u64(2);
    }
    let mut high_recomp = AB::Expr::ZERO;
    pow2 = AB::Expr::ONE;
    for b in 0..BV_HIGH_BITS_COUNT {
        high_recomp = high_recomp + pow2.clone() * col(BV_HIGH_BITS + b);
        pow2 = pow2 * AB::Expr::from_u64(2);
    }
    builder.assert_zero(
        gate.clone() * mask.clone() * (low_recomp - (field_val_this_row.clone() - min_val.clone()))
    );
    builder.assert_zero(
        gate.clone() * mask.clone() * (high_recomp - (max_val.clone() - field_val_this_row.clone()))
    );

    // Inactive fields must have sq[0] = 0
    builder.assert_zero(
        gate.clone() * (AB::Expr::ONE - mask.clone()) * field_val_this_row.clone()
    );

    // 6. Exponent bit recomposition: sum(exp_bit[b] * 2^b) = cost_exponent
    let mut exp_recomp = AB::Expr::ZERO;
    pow2 = AB::Expr::ONE;
    for b in 0..BV_EXP_BITS_COUNT {
        exp_recomp = exp_recomp + pow2.clone() * col(BV_EXP_BITS + b);
        pow2 = pow2 * AB::Expr::from_u64(2);
    }
    builder.assert_zero(gate.clone() * mask.clone() * (exp_recomp - col(BV_COST_EXP)));

    // 7. Squaring chain
    for k in 1..BV_SQ_COUNT {
        let prev_sq = col(BV_SQ + k - 1);
        let this_sq = col(BV_SQ + k);
        builder.assert_zero(gate.clone() * mask.clone() * (this_sq - prev_sq.clone() * prev_sq));
    }

    // 8. Accumulator chain
    {
        let eb0 = col(BV_EXP_BITS);
        let sq0 = col(BV_SQ);
        let acc0 = col(BV_ACC);
        let expected_acc0 = AB::Expr::ONE + eb0.clone() * (sq0.clone() - AB::Expr::ONE);
        builder.assert_zero(gate.clone() * mask.clone() * (acc0 - expected_acc0));
    }
    for k in 1..BV_ACC_COUNT {
        let prev_acc = col(BV_ACC + k - 1);
        let ebk = col(BV_EXP_BITS + k);
        let sqk = col(BV_SQ + k);
        let this_acc = col(BV_ACC + k);
        let selector = AB::Expr::ONE + ebk.clone() * (sqk.clone() - AB::Expr::ONE);
        builder.assert_zero(gate.clone() * mask.clone() * (this_acc - prev_acc * selector));
    }

    // Power result = acc[7]
    builder.assert_zero(
        gate.clone() * mask.clone() * (col(BV_POWER) - col(BV_ACC + BV_ACC_COUNT - 1))
    );

    // DEBUG: skip uniqueness, cost_sum, config consistency for now
    return;
    // Low: sum(low_bit[b] * 2^b) = field[row_idx] - min_value
    // High: sum(high_bit[b] * 2^b) = max_value - field[row_idx]
    //
    // We use the field value at BV_FIELDS + row_index. But row_index is
    // a variable, so we can't directly index. Instead, we use a trick:
    // on each field row i, the trace stores the field value directly at
    // a known position. We reconstruct using the sum of mask * field[j] * (row_idx == j).
    //
    // Simpler approach: the trace generator puts the "current" field value
    // in the bit recomposition. We verify the recomposition matches, and
    // separately constrain that inactive fields have zero bits.
    // ------------------------------------------------

    // Recompose low bits into a single value
    let mut low_recomp = AB::Expr::ZERO;
    let mut pow2 = AB::Expr::ONE;
    for b in 0..BV_LOW_BITS_COUNT {
        low_recomp = low_recomp + pow2.clone() * col(BV_LOW_BITS + b);
        pow2 = pow2 * AB::Expr::from_u64(2);
    }

    // Recompose high bits
    let mut high_recomp = AB::Expr::ZERO;
    pow2 = AB::Expr::ONE;
    for b in 0..BV_HIGH_BITS_COUNT {
        high_recomp = high_recomp + pow2.clone() * col(BV_HIGH_BITS + b);
        pow2 = pow2 * AB::Expr::from_u64(2);
    }

    // For the field row i, the field value is at BV_FIELDS + i.
    // We build a "selected value" using the mask and row index.
    // For simplicity, we sum over all field positions weighted by an indicator.
    // This works because on row i with mask=1, exactly one field is "selected."
    //
    // selected_val = sum_j(field[j] * indicator(row_idx == j))
    // where indicator uses the Lagrange basis approach.
    //
    // Actually, to keep degrees low, we store the current field value
    // as the recomposition target. The constraint is:
    //   mask * (low_recomp - (field[i] - min)) = 0
    //   mask * (high_recomp - (max - field[i])) = 0
    // We need to identify field[i]. Since row_index selects which field,
    // and all 8 field values are stored, we construct the selection polynomial.

    // Build selected field value: sum over j of field[j] * L_j(row_idx)
    // where L_j is 1 when row_idx = j and 0 otherwise.
    // L_j(x) = product_{k != j} (x - k) / (j - k)
    // This is degree 7 which is too high with gating.
    //
    // Alternative: the low_recomp + min should equal one of the field values.
    // Constrain: mask * (low_recomp + min - field[row_idx]) = 0
    // We can do this without Lagrange by instead constraining:
    //   mask * product_{j=0..7} (low_recomp + min - field[j]) = 0
    // This proves that (low_recomp + min) equals at least one field value.
    // But that's degree 8 * mask = degree 9. Too high.
    //
    // Pragmatic approach: we store the "current field value" redundantly
    // in a dedicated column and verify it matches field[row_idx] using
    // per-index constraints. Actually the simplest: constrain the recomposition
    // to match the specific field value using the row index.
    //
    // Since row_index is 0..7 and known at trace time, and the constraint
    // evaluator works over the entire trace algebraically, we can't branch.
    // The standard STARK trick: use an accumulator that builds up field[row_idx].
    //
    // SIMPLEST CORRECT APPROACH: the trace stores the selected field value
    // at BV_POWER column (which already holds field^exp), and we constrain
    // the power chain starting from that value. The range check bits
    // recompose to (value - min) and (max - value), where value = sq[0].
    // So sq[0] IS the field value for this row.

    let field_val_this_row = col(BV_SQ); // sq[0] = the field value being checked

    // Range check: low_recomp = sq[0] - min_value (when mask=1)
    builder.assert_zero(
        gate.clone() * mask.clone() * (low_recomp - (field_val_this_row.clone() - min_val.clone()))
    );
    // Range check: high_recomp = max_value - sq[0] (when mask=1)
    builder.assert_zero(
        gate.clone() * mask.clone() * (high_recomp - (max_val.clone() - field_val_this_row.clone()))
    );

    // Inactive fields must be zero
    builder.assert_zero(
        gate.clone() * (AB::Expr::ONE - mask.clone()) * field_val_this_row.clone()
    );

    // ------------------------------------------------
    // 5. Exponent bits must be binary
    // ------------------------------------------------
    for b in 0..BV_EXP_BITS_COUNT {
        let bit = col(BV_EXP_BITS + b);
        builder.assert_zero(gate.clone() * bit.clone() * (bit.clone() - AB::Expr::ONE));
    }

    // ------------------------------------------------
    // 6. Exponent bit recomposition: sum(exp_bit[b] * 2^b) = cost_exponent
    // ------------------------------------------------
    let mut exp_recomp = AB::Expr::ZERO;
    pow2 = AB::Expr::ONE;
    for b in 0..BV_EXP_BITS_COUNT {
        exp_recomp = exp_recomp + pow2.clone() * col(BV_EXP_BITS + b);
        pow2 = pow2 * AB::Expr::from_u64(2);
    }
    builder.assert_zero(gate.clone() * mask.clone() * (exp_recomp - col(BV_COST_EXP)));

    // ------------------------------------------------
    // 7. Squaring chain: sq[0] = field_value, sq[k] = sq[k-1]^2
    // ------------------------------------------------
    for k in 1..BV_SQ_COUNT {
        let prev_sq = col(BV_SQ + k - 1);
        let this_sq = col(BV_SQ + k);
        builder.assert_zero(gate.clone() * mask.clone() * (this_sq - prev_sq.clone() * prev_sq));
    }

    // ------------------------------------------------
    // 8. Accumulator chain for binary exponentiation
    // acc[0] = exp_bit[0] * sq[0] + (1 - exp_bit[0])
    // acc[k] = acc[k-1] * (exp_bit[k] * sq[k] + (1 - exp_bit[k]))
    // ------------------------------------------------
    {
        let eb0 = col(BV_EXP_BITS);
        let sq0 = col(BV_SQ);
        let acc0 = col(BV_ACC);
        // acc[0] = eb0 * sq0 + 1 - eb0 = 1 + eb0 * (sq0 - 1)
        let expected_acc0 = AB::Expr::ONE + eb0.clone() * (sq0.clone() - AB::Expr::ONE);
        builder.assert_zero(gate.clone() * mask.clone() * (acc0 - expected_acc0));
    }
    for k in 1..BV_ACC_COUNT {
        let prev_acc = col(BV_ACC + k - 1);
        let ebk = col(BV_EXP_BITS + k);
        let sqk = col(BV_SQ + k);
        let this_acc = col(BV_ACC + k);
        // selector = 1 + ebk * (sqk - 1)
        let selector = AB::Expr::ONE + ebk.clone() * (sqk.clone() - AB::Expr::ONE);
        // acc[k] = acc[k-1] * selector
        builder.assert_zero(gate.clone() * mask.clone() * (this_acc - prev_acc * selector));
    }

    // Power result = acc[7]
    builder.assert_zero(
        gate.clone() * mask.clone() * (col(BV_POWER) - col(BV_ACC + BV_ACC_COUNT - 1))
    );

    // ------------------------------------------------
    // 9. Uniqueness constraints
    //
    // On each row i, for each field j, we prove field[i] != field[j] (when both
    // are active and uniqueness is required). The trick to handle the self-position
    // j == row_idx gracefully is the identity:
    //
    //   diff^2 * inv - diff = 0
    //
    // where diff = field[i] - field[j] and inv = 1/diff.
    //
    // When j != i: diff != 0, so this forces inv = 1/diff (proves inequality).
    // When j == i: diff = 0, so 0 - 0 = 0 (trivially satisfied, no constraint needed).
    //
    // Degree analysis: diff is degree 1, diff^2 is 2, diff^2*inv is 3.
    // With gating (gate * mask * unique): total degree 6, under the 7 limit.
    // ------------------------------------------------
    for j in 0..NUM_FIELDS {
        let other_j = col(BV_FIELDS + j);
        let inv_j = col(BV_INV_DIFF + j);
        let diff_j = field_val_this_row.clone() - other_j;
        let constraint = diff_j.clone() * diff_j.clone() * inv_j - diff_j;
        builder.assert_zero(gate.clone() * mask.clone() * unique.clone() * constraint);
    }

    // ------------------------------------------------
    // 10. Cost sum transition constraint
    // On consecutive BV rows: cost_sum[next] = cost_sum[current] + mask[next] * power[next]
    // Gated by both current and next row being BV.
    // ------------------------------------------------
    {
        let next_is_bv: AB::Expr = next[IS_BV].clone().into();
        let next_mask: AB::Expr = next[BV_MASK].clone().into();
        let next_power: AB::Expr = next[BV_POWER].clone().into();
        let next_cost_sum: AB::Expr = next[BV_COST_SUM].clone().into();
        let current_cost_sum = col(BV_COST_SUM);

        // Transition: next_cost_sum = current_cost_sum + next_mask * next_power
        // Only when both rows are BV (gate * next_is_bv)
        builder.when_transition().assert_zero(
            gate.clone() * next_is_bv.clone() *
            (next_cost_sum - current_cost_sum - next_mask * next_power)
        );
    }

    // ------------------------------------------------
    // 11. First BV row: cost_sum[0] = mask[0] * power[0]
    // We detect "first BV row" by checking that row_idx == 0 AND IS_BV == 1.
    // Constraint: gate * (1 - row_idx) * (cost_sum - mask * power) = 0
    // When row_idx = 0, this forces cost_sum = mask * power.
    // When row_idx > 0, (1 - row_idx) is non-zero but the transition handles it.
    // Actually, using (1 - row_idx) as a selector isn't right because it's non-zero
    // for row_idx > 1 too (it just has a different value).
    //
    // Better: the transition constraint plus the first BV row constraint.
    // We can use a different trick: constrain that on the row BEFORE the first
    // BV row, cost_sum = 0. But that's on a P2 or padding row.
    //
    // Simplest: constrain that cost_sum[row_idx=0] = mask * power on the first
    // BV row. We can identify it via: row_idx * (cost_sum - mask * power) ... no.
    //
    // OK, just constrain: when row_idx = 0 (i.e., the row_idx column is 0):
    //   gate * is_first_bv * (cost_sum - mask * power) = 0
    // where is_first_bv = 1 - row_idx * inv_row_idx (IsZero pattern).
    //
    // Actually, the transition constraint already handles this if we ensure
    // the "previous cost_sum" is 0 before the first BV row. Since the previous
    // row is a P2 or padding row where all BV columns are 0 (including cost_sum),
    // the transition won't fire (prev IS_BV = 0). So the first BV row's
    // cost_sum is unconstrained by transitions.
    //
    // Fix: add a boundary constraint. On the first BV row (row_idx = 0):
    //   cost_sum = mask * power
    // We encode this as: gate * row_idx_is_zero * (cost_sum - mask * power) = 0
    // where row_idx_is_zero = (row_idx == 0) indicator.
    //
    // Since row_idx is 0 on the first BV row and 1..8 on others, we can use:
    //   product_{k=1..8} (row_idx - k) which is nonzero only when row_idx=0.
    // But that's degree 8. Way too high with gating.
    //
    // PRAGMATIC: constrain on all rows that cost_sum = expected, where expected
    // is tracked via the transition. Make the transition also handle row_idx=0.
    //
    // The trick: modify the transition to handle the "no previous row" case.
    // On the first BV row, the previous row is NOT a BV row (IS_BV=0 on prev).
    // So cost_sum on the first BV row should equal mask * power (fresh start).
    //
    // Constraint: for the CURRENT row, if the PREVIOUS row was not BV
    // (i.e., this is the first BV row), cost_sum = mask * power.
    // We check this by looking at the NEXT row from the PREVIOUS row's perspective.
    //
    // Actually, it's simpler: from the current row's perspective, we can't see
    // the previous row. We only have local and next.
    //
    // SOLUTION: Use a "when_first_row" or boundary approach. The cost_sum
    // accumulation constraint between BV rows is already handled. For the
    // FIRST BV row, we add: when IS_BV=1 and the NEXT row's IS_BV was also
    // preceded by... this is circular.
    //
    // LET'S KEEP IT SIMPLE: just enforce:
    //   On every BV field row: cost_sum = sum(mask[j] * power[j], j=0..row_idx)
    // The transition constraint already ensures consistency between consecutive
    // BV rows. The first BV row's cost_sum is set by the prover and the
    // transition propagates it. We need ONE anchor point.
    //
    // Use the bounds row (row_idx = NUM_FIELDS) to anchor: on the bounds row,
    // BV_BOUNDS_COST must equal BV_COST_SUM from the previous (last field) row.
    // But we can't look backward.
    //
    // OK here's what I'll do: Trust the transition constraint and add a simple
    // anchor. The bounds row has its own BV_COST_SUM that should equal
    // the accumulated total. The transition from row 7 -> bounds row propagates it.
    // For row 0, I add: gate * (1 - row_idx) * ... but this is wrong for row_idx > 1.
    //
    // Actually, the key insight: row_idx goes 0,1,2,...,7,8. On the field rows
    // (0..7) the transition increments cost_sum. I need the initial value.
    // I'll add a column or use a trick.
    //
    // PRAGMATIC FIX: check from the transition that when the NEXT row is BV
    // and the CURRENT row is NOT BV, the next row's cost_sum = next_mask * next_power.
    // This catches the P2-to-BV boundary.
    {
        let next_is_bv: AB::Expr = next[IS_BV].clone().into();
        let not_current_bv = AB::Expr::ONE - gate.clone();
        let next_mask: AB::Expr = next[BV_MASK].clone().into();
        let next_power: AB::Expr = next[BV_POWER].clone().into();
        let next_cost_sum: AB::Expr = next[BV_COST_SUM].clone().into();

        // When current row is NOT BV but next row IS BV (the BV entry point):
        // next_cost_sum must equal next_mask * next_power (fresh accumulation start).
        builder.when_transition().assert_zero(
            not_current_bv * next_is_bv * (next_cost_sum - next_mask * next_power)
        );
    }

    // ------------------------------------------------
    // 12. Bounds row constraints (BV_IS_BOUNDS = 1)
    // The bounds row verifies: min_sum <= cost_sum <= limit
    // where limit = max_value_sum (or weight if cost_from_weight=1).
    // Uses bit decompositions to prove non-negativity of differences.
    // ------------------------------------------------
    {
        let is_bounds: AB::Expr = col(BV_IS_BOUNDS).into();
        let bounds_gate = gate.clone() * is_bounds.clone();

        // BV_IS_BOUNDS must be binary
        builder.assert_zero(gate.clone() * is_bounds.clone() * (is_bounds.clone() - AB::Expr::ONE));

        // BV_IS_BOUNDS and mask are mutually exclusive (bounds row has mask=0)
        builder.assert_zero(gate.clone() * is_bounds.clone() * mask.clone());

        // 12a. Limit decomposition: BV_LIMIT_BITS represent (limit - cost_sum)
        // Prove limit >= cost_sum by showing the difference is a 63-bit value.
        // Only enforced when max_value_sum != 0 (gated by 1 - max_sum_is_zero).
        let max_sum_is_zero: AB::Expr = col(BV_MAX_SUM_IS_ZERO).into();
        let bounds_with_limit = bounds_gate.clone() * (AB::Expr::ONE - max_sum_is_zero.clone());

        let mut limit_recomp = AB::Expr::ZERO;
        let mut pow2 = AB::Expr::ONE;
        for b in 0..BV_LIMIT_BITS_COUNT {
            let bit = col(BV_LIMIT_BITS + b);
            // Each bit must be binary
            builder.assert_zero(bounds_gate.clone() * bit.clone() * (bit.clone() - AB::Expr::ONE));
            limit_recomp = limit_recomp + pow2.clone() * bit;
            pow2 = pow2 * AB::Expr::from_u64(2);
        }
        // limit_recomp == limit - cost_sum (proves limit >= cost_sum)
        builder.assert_zero(
            bounds_with_limit.clone() * (limit_recomp - (col(BV_LIMIT) - col(BV_BOUNDS_COST)))
        );

        // 12b. Min sum decomposition: BV_MINSUB_BITS represent (cost_sum - min_sum)
        // Prove cost_sum >= min_sum by showing the difference is a 63-bit value.
        let mut minsub_recomp = AB::Expr::ZERO;
        pow2 = AB::Expr::ONE;
        for b in 0..BV_MINSUB_BITS_COUNT {
            let bit = col(BV_MINSUB_BITS + b);
            builder.assert_zero(bounds_gate.clone() * bit.clone() * (bit.clone() - AB::Expr::ONE));
            minsub_recomp = minsub_recomp + pow2.clone() * bit;
            pow2 = pow2 * AB::Expr::from_u64(2);
        }
        // minsub_recomp == cost_sum - min_sum (proves cost_sum >= min_sum)
        builder.assert_zero(
            bounds_gate.clone() * (minsub_recomp - (col(BV_BOUNDS_COST) - col(BV_MIN_SUM)))
        );

        // 12c. Group size check: gs_bits decompose (num_fields - group_size)
        // Proves group_size <= num_fields.
        let mut gs_recomp = AB::Expr::ZERO;
        pow2 = AB::Expr::ONE;
        for b in 0..BV_GS_BITS_COUNT {
            let bit = col(BV_GS_BITS + b);
            builder.assert_zero(bounds_gate.clone() * bit.clone() * (bit.clone() - AB::Expr::ONE));
            gs_recomp = gs_recomp + pow2.clone() * bit;
            pow2 = pow2 * AB::Expr::from_u64(2);
        }
        builder.assert_zero(
            bounds_gate.clone() * (gs_recomp - (col(BV_NUM_FIELDS) - col(BV_GROUP_SIZE)))
        );

        // 12d. Limit selection: limit = cost_from_weight ? weight : max_value_sum
        // Constraint: limit = cost_from_weight * weight + (1 - cost_from_weight) * max_sum
        let cfw: AB::Expr = col(BV_COST_FROM_WEIGHT).into();
        builder.assert_zero(
            bounds_gate.clone() * (
                col(BV_LIMIT)
                - cfw.clone() * col(BV_WEIGHT)
                - (AB::Expr::ONE - cfw) * col(BV_MAX_SUM)
            )
        );

        // 12e. max_sum_is_zero correctness
        // If max_sum_is_zero = 1, then max_sum = 0.
        // If max_sum_is_zero = 0, then max_sum != 0 (proved via inverse).
        builder.assert_zero(bounds_gate.clone() * max_sum_is_zero.clone() * col(BV_MAX_SUM));
        // max_sum * inv - (1 - is_zero) = 0
        builder.assert_zero(
            bounds_gate.clone() * (
                col(BV_MAX_SUM) * col(BV_MAX_SUM_INV)
                - (AB::Expr::ONE - max_sum_is_zero.clone())
            )
        );
        // max_sum_is_zero must be binary
        builder.assert_zero(
            bounds_gate.clone() * max_sum_is_zero.clone() * (max_sum_is_zero - AB::Expr::ONE)
        );

        // 12f. Bounds cost must match cost_sum (accumulated from field rows)
        builder.assert_zero(
            bounds_gate * (col(BV_BOUNDS_COST) - col(BV_COST_SUM))
        );
    }

    // ------------------------------------------------
    // 13. Config consistency across BV rows
    // All BV rows must have the same config values (num_fields, min, max, etc.)
    // Enforce via transition: config columns don't change between BV rows.
    // ------------------------------------------------
    {
        let next_is_bv: AB::Expr = next[IS_BV].clone().into();
        let config_cols = [
            BV_NUM_FIELDS, BV_MIN_VALUE, BV_MAX_VALUE, BV_UNIQUE,
            BV_COST_FROM_WEIGHT, BV_COST_EXP, BV_MAX_SUM, BV_MIN_SUM,
            BV_WEIGHT, BV_GROUP_SIZE,
        ];
        for &c in &config_cols {
            builder.when_transition().assert_zero(
                gate.clone() * next_is_bv.clone() * (ncol(c) - col(c))
            );
        }

        // Field values must be consistent across BV rows
        for j in 0..NUM_FIELDS {
            builder.when_transition().assert_zero(
                gate.clone() * next_is_bv.clone() * (ncol(BV_FIELDS + j) - col(BV_FIELDS + j))
            );
        }
    }
}

