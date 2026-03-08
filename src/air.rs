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

use ecgfp5::curve::Point;
use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir, BaseAirWithPublicValues};
use p3_field::{Algebra, PrimeCharacteristicRing};
use p3_matrix::Matrix;

use crate::columns::*;
use crate::gfp5::*;
use crate::poseidon2;

/// Bit count for derived scalars (k_i values are Goldilocks elements, 64 bits).
/// Using 64-bit muls instead of 319-bit saves about 80% of EC rows.
pub const SMALL_SCALAR_BITS: usize = 64;

/// Number of vote fields in a ballot.
pub const NUM_FIELDS: usize = 8;

/// Poseidon2 rounds per permutation (4 full + 22 partial + 4 full = 30).
pub const P2_ROUNDS_PER_PERM: usize = poseidon2::TOTAL_ROUNDS;

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
/// needs. These must match exactly what the trace generator used (the upstream
/// Plonky3 Horizen Labs constants used by ZisK).
pub struct BallotAir {
    pub p2_constants: poseidon2::Poseidon2Constants,
}

impl BallotAir {
    pub fn new() -> Self {
        Self {
            p2_constants: poseidon2::Poseidon2Constants::new(),
        }
    }
}

impl<F> BaseAir<F> for BallotAir
where
    F: PrimeCharacteristicRing,
{
    fn width(&self) -> usize {
        TRACE_WIDTH
    }
}

impl<F> BaseAirWithPublicValues<F> for BallotAir
where
    F: PrimeCharacteristicRing,
{
    fn num_public_values(&self) -> usize {
        PV_COUNT
    }
}

impl<AB> Air<AB> for BallotAir
where
    AB: AirBuilder + AirBuilderWithPublicValues,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0).expect("empty trace");
        let next = main.row_slice(1).expect("trace too short");
        let public_values = builder.public_values().to_vec();

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
        eval_global_bindings::<AB>(builder, &local, &next);
        eval_poseidon_statement_bindings::<AB>(builder, &local, &next, &public_values);

        let inputs_hash_out: AB::Expr = local[P2_INPUTS_HASH_OUT].clone().into();
        builder.assert_zero(inputs_hash_out.clone() * (inputs_hash_out.clone() - AB::Expr::ONE));
        builder.assert_zero(inputs_hash_out.clone() * is_ec.clone());
        builder.assert_zero(inputs_hash_out.clone() * is_p2.clone());
        builder.assert_zero(inputs_hash_out.clone() * is_bv.clone());
        builder.assert_zero(inputs_hash_out.clone() * (AB::Expr::ONE - next[IS_BV].clone().into()));
        for i in 0..4 {
            builder.assert_zero(
                inputs_hash_out.clone()
                    * (local[P2_STATE + i].clone().into()
                        - public_values[PV_INPUTS_HASH + i].clone().into()),
            );
        }

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
            first.assert_zero(is_ec.clone() * local[PHASE].clone());
        }

        {
            let mut last = builder.when_last_row();
            for i in 0..PV_COUNT {
                last.assert_eq(local[PUB_OUTPUTS + i].clone(), public_values[i]);
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
fn eval_ec_constraints<AB: AirBuilder>(
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
    let phase: AB::Expr = local[PHASE].clone().into();
    let bind_active: AB::Expr = local[EC_BIND_ACTIVE].clone().into();
    let scalar_acc: AB::Expr = local[EC_SCALAR_ACC].clone().into();
    let scalar_target: AB::Expr = local[EC_SCALAR_TARGET].clone().into();
    let phase_selectors: Vec<AB::Expr> = (0..EC_PHASE_SEL_COUNT)
        .map(|i| local[EC_PHASE_SEL + i].clone().into())
        .collect();
    let global_ks: Vec<AB::Expr> = (0..GLOBAL_KS_COUNT)
        .map(|i| local[GLOBAL_KS + i].clone().into())
        .collect();
    let global_fields: Vec<AB::Expr> = (0..GLOBAL_FIELDS_COUNT)
        .map(|i| local[GLOBAL_FIELDS + i].clone().into())
        .collect();
    let global_pk_x: [AB::Expr; 5] = gfp5_expr::<AB>(local, GLOBAL_PK);
    let global_pk_z: [AB::Expr; 5] = gfp5_expr::<AB>(local, GLOBAL_PK + 5);
    let global_pk_u: [AB::Expr; 5] = gfp5_expr::<AB>(local, GLOBAL_PK + 10);
    let global_pk_t: [AB::Expr; 5] = gfp5_expr::<AB>(local, GLOBAL_PK + 15);

    let next_acc_x: [AB::Expr; 5] = gfp5_expr::<AB>(next, ACC_X);
    let next_acc_z: [AB::Expr; 5] = gfp5_expr::<AB>(next, ACC_Z);
    let next_acc_u: [AB::Expr; 5] = gfp5_expr::<AB>(next, ACC_U);
    let next_acc_t: [AB::Expr; 5] = gfp5_expr::<AB>(next, ACC_T);
    let next_base_x: [AB::Expr; 5] = gfp5_expr::<AB>(next, BASE_X);
    let next_base_z: [AB::Expr; 5] = gfp5_expr::<AB>(next, BASE_Z);
    let next_base_u: [AB::Expr; 5] = gfp5_expr::<AB>(next, BASE_U);
    let next_base_t: [AB::Expr; 5] = gfp5_expr::<AB>(next, BASE_T);
    let next_phase: AB::Expr = next[PHASE].clone().into();
    let next_bind_active: AB::Expr = next[EC_BIND_ACTIVE].clone().into();
    let next_scalar_acc: AB::Expr = next[EC_SCALAR_ACC].clone().into();

    // Bit validity: gate * bit * (1 - bit) = 0
    builder.assert_zero(gate.clone() * bit.clone() * (AB::Expr::ONE - bit.clone()));
    builder.assert_zero(gate.clone() * (bind_active.clone() - AB::Expr::ONE));

    let selected_out_x = (0..5)
        .map(|i| (AB::Expr::ONE - bit.clone()) * dbl_x[i].clone() + bit.clone() * add_x[i].clone())
        .collect::<Vec<_>>();
    let selected_out_z = (0..5)
        .map(|i| (AB::Expr::ONE - bit.clone()) * dbl_z[i].clone() + bit.clone() * add_z[i].clone())
        .collect::<Vec<_>>();
    let selected_out_u = (0..5)
        .map(|i| (AB::Expr::ONE - bit.clone()) * dbl_u[i].clone() + bit.clone() * add_u[i].clone())
        .collect::<Vec<_>>();
    let selected_out_t = (0..5)
        .map(|i| (AB::Expr::ONE - bit.clone()) * dbl_t[i].clone() + bit.clone() * add_t[i].clone())
        .collect::<Vec<_>>();

    let mut phase_sel_sum = AB::Expr::ZERO;
    let mut expected_phase = AB::Expr::ZERO;
    let mut expected_target = AB::Expr::ZERO;
    for (p, sel) in phase_selectors.iter().enumerate() {
        phase_sel_sum = phase_sel_sum + sel.clone();
        expected_phase = expected_phase + sel.clone() * AB::Expr::from_u64(p as u64);
        let source = if p % 3 < 2 {
            global_ks[p / 3].clone()
        } else {
            global_fields[p / 3].clone()
        };
        expected_target = expected_target + sel.clone() * source;
        builder.assert_zero(gate.clone() * sel.clone() * (sel.clone() - AB::Expr::ONE));
    }
    builder.assert_zero(gate.clone() * (phase_sel_sum - bind_active.clone()));
    builder.assert_zero(gate.clone() * bind_active.clone() * (phase.clone() - expected_phase));
    builder.assert_zero(
        gate.clone() * bind_active.clone() * (scalar_target.clone() - expected_target),
    );
    let mut pk_phase_sel = AB::Expr::ZERO;
    for (p, sel) in phase_selectors.iter().enumerate() {
        if p % 3 == 1 {
            pk_phase_sel = pk_phase_sel + sel.clone();
        }
    }
    let generator = Point::GENERATOR;
    let gen_x = [
        AB::Expr::from_u64(generator.X.0[0].to_u64()),
        AB::Expr::from_u64(generator.X.0[1].to_u64()),
        AB::Expr::from_u64(generator.X.0[2].to_u64()),
        AB::Expr::from_u64(generator.X.0[3].to_u64()),
        AB::Expr::from_u64(generator.X.0[4].to_u64()),
    ];
    let gen_z = [
        AB::Expr::from_u64(generator.Z.0[0].to_u64()),
        AB::Expr::from_u64(generator.Z.0[1].to_u64()),
        AB::Expr::from_u64(generator.Z.0[2].to_u64()),
        AB::Expr::from_u64(generator.Z.0[3].to_u64()),
        AB::Expr::from_u64(generator.Z.0[4].to_u64()),
    ];
    let gen_u = [
        AB::Expr::from_u64(generator.U.0[0].to_u64()),
        AB::Expr::from_u64(generator.U.0[1].to_u64()),
        AB::Expr::from_u64(generator.U.0[2].to_u64()),
        AB::Expr::from_u64(generator.U.0[3].to_u64()),
        AB::Expr::from_u64(generator.U.0[4].to_u64()),
    ];
    let gen_t = [
        AB::Expr::from_u64(generator.T.0[0].to_u64()),
        AB::Expr::from_u64(generator.T.0[1].to_u64()),
        AB::Expr::from_u64(generator.T.0[2].to_u64()),
        AB::Expr::from_u64(generator.T.0[3].to_u64()),
        AB::Expr::from_u64(generator.T.0[4].to_u64()),
    ];
    for i in 0..5 {
        let is_generator_phase = phase_selectors
            .iter()
            .enumerate()
            .filter(|(p, _)| p % 3 != 1)
            .fold(AB::Expr::ZERO, |acc, (_, sel)| acc + sel.clone());
        builder.assert_zero(
            gate.clone() * is_generator_phase.clone() * (base_x[i].clone() - gen_x[i].clone()),
        );
        builder.assert_zero(
            gate.clone() * is_generator_phase.clone() * (base_z[i].clone() - gen_z[i].clone()),
        );
        builder.assert_zero(
            gate.clone() * is_generator_phase.clone() * (base_u[i].clone() - gen_u[i].clone()),
        );
        builder.assert_zero(
            gate.clone() * is_generator_phase.clone() * (base_t[i].clone() - gen_t[i].clone()),
        );
        builder.assert_zero(
            gate.clone() * pk_phase_sel.clone() * (base_x[i].clone() - global_pk_x[i].clone()),
        );
        builder.assert_zero(
            gate.clone() * pk_phase_sel.clone() * (base_z[i].clone() - global_pk_z[i].clone()),
        );
        builder.assert_zero(
            gate.clone() * pk_phase_sel.clone() * (base_u[i].clone() - global_pk_u[i].clone()),
        );
        builder.assert_zero(
            gate.clone() * pk_phase_sel.clone() * (base_t[i].clone() - global_pk_t[i].clone()),
        );
    }
    builder.assert_zero(
        gate.clone()
            * bind_active.clone()
            * is_last.clone()
            * (scalar_acc.clone() - scalar_target.clone()),
    );

    let c1_phase_sel: Vec<AB::Expr> = (0..NUM_FIELDS)
        .map(|i| phase_selectors[3 * i].clone())
        .collect();
    let s_phase_sel: Vec<AB::Expr> = (0..NUM_FIELDS)
        .map(|i| phase_selectors[3 * i + 1].clone())
        .collect();
    let m_phase_sel: Vec<AB::Expr> = (0..NUM_FIELDS)
        .map(|i| phase_selectors[3 * i + 2].clone())
        .collect();
    let c1_phase_gate: AB::Expr = c1_phase_sel.iter().cloned().sum();
    let s_phase_gate: AB::Expr = s_phase_sel.iter().cloned().sum();
    let m_phase_gate: AB::Expr = m_phase_sel.iter().cloned().sum();

    let mut expected_c1_enc: [AB::Expr; 5] = core::array::from_fn(|_| AB::Expr::ZERO);
    let mut expected_s_x: [AB::Expr; 5] = core::array::from_fn(|_| AB::Expr::ZERO);
    let mut expected_s_z: [AB::Expr; 5] = core::array::from_fn(|_| AB::Expr::ZERO);
    let mut expected_s_u: [AB::Expr; 5] = core::array::from_fn(|_| AB::Expr::ZERO);
    let mut expected_s_t: [AB::Expr; 5] = core::array::from_fn(|_| AB::Expr::ZERO);
    let mut expected_m_s_x: [AB::Expr; 5] = core::array::from_fn(|_| AB::Expr::ZERO);
    let mut expected_m_s_z: [AB::Expr; 5] = core::array::from_fn(|_| AB::Expr::ZERO);
    let mut expected_m_s_u: [AB::Expr; 5] = core::array::from_fn(|_| AB::Expr::ZERO);
    let mut expected_m_s_t: [AB::Expr; 5] = core::array::from_fn(|_| AB::Expr::ZERO);
    let mut expected_c2_x: [AB::Expr; 5] = core::array::from_fn(|_| AB::Expr::ZERO);
    let mut expected_c2_z: [AB::Expr; 5] = core::array::from_fn(|_| AB::Expr::ZERO);
    let mut expected_c2_u: [AB::Expr; 5] = core::array::from_fn(|_| AB::Expr::ZERO);
    let mut expected_c2_t: [AB::Expr; 5] = core::array::from_fn(|_| AB::Expr::ZERO);
    let mut expected_c2_enc: [AB::Expr; 5] = core::array::from_fn(|_| AB::Expr::ZERO);
    let mut expected_c2_inter: [[AB::Expr; 5]; 10] =
        core::array::from_fn(|_| core::array::from_fn(|_| AB::Expr::ZERO));

    for i in 0..NUM_FIELDS {
        for j in 0..5 {
            expected_c1_enc[j] = expected_c1_enc[j].clone()
                + c1_phase_sel[i].clone() * local[GLOBAL_C1_ENC + i * 5 + j].clone().into();
            expected_s_x[j] = expected_s_x[j].clone()
                + s_phase_sel[i].clone() * local[GLOBAL_S_POINTS + i * 20 + j].clone().into();
            expected_s_z[j] = expected_s_z[j].clone()
                + s_phase_sel[i].clone() * local[GLOBAL_S_POINTS + i * 20 + 5 + j].clone().into();
            expected_s_u[j] = expected_s_u[j].clone()
                + s_phase_sel[i].clone() * local[GLOBAL_S_POINTS + i * 20 + 10 + j].clone().into();
            expected_s_t[j] = expected_s_t[j].clone()
                + s_phase_sel[i].clone() * local[GLOBAL_S_POINTS + i * 20 + 15 + j].clone().into();
            expected_m_s_x[j] = expected_m_s_x[j].clone()
                + m_phase_sel[i].clone() * local[GLOBAL_S_POINTS + i * 20 + j].clone().into();
            expected_m_s_z[j] = expected_m_s_z[j].clone()
                + m_phase_sel[i].clone() * local[GLOBAL_S_POINTS + i * 20 + 5 + j].clone().into();
            expected_m_s_u[j] = expected_m_s_u[j].clone()
                + m_phase_sel[i].clone() * local[GLOBAL_S_POINTS + i * 20 + 10 + j].clone().into();
            expected_m_s_t[j] = expected_m_s_t[j].clone()
                + m_phase_sel[i].clone() * local[GLOBAL_S_POINTS + i * 20 + 15 + j].clone().into();
            expected_c2_x[j] = expected_c2_x[j].clone()
                + m_phase_sel[i].clone() * local[GLOBAL_C2_POINTS + i * 20 + j].clone().into();
            expected_c2_z[j] = expected_c2_z[j].clone()
                + m_phase_sel[i].clone() * local[GLOBAL_C2_POINTS + i * 20 + 5 + j].clone().into();
            expected_c2_u[j] = expected_c2_u[j].clone()
                + m_phase_sel[i].clone() * local[GLOBAL_C2_POINTS + i * 20 + 10 + j].clone().into();
            expected_c2_t[j] = expected_c2_t[j].clone()
                + m_phase_sel[i].clone() * local[GLOBAL_C2_POINTS + i * 20 + 15 + j].clone().into();
            expected_c2_enc[j] = expected_c2_enc[j].clone()
                + m_phase_sel[i].clone() * local[GLOBAL_C2_ENC + i * 5 + j].clone().into();
            for k in 0..10 {
                expected_c2_inter[k][j] = expected_c2_inter[k][j].clone()
                    + m_phase_sel[i].clone()
                        * local[GLOBAL_C2_ADD_INTER + i * 50 + k * 5 + j].clone().into();
            }
        }
    }

    for c in gfp5_mul_constraints::<AB::F, AB::Expr>(
        expected_c1_enc.clone(),
        selected_out_u.clone().try_into().unwrap(),
        selected_out_t.clone().try_into().unwrap(),
    ) {
        builder.assert_zero(gate.clone() * is_last.clone() * c1_phase_gate.clone() * c);
    }

    for i in 0..5 {
        builder.assert_zero(
            gate.clone() * is_last.clone() * s_phase_gate.clone() * (selected_out_x[i].clone() - expected_s_x[i].clone()),
        );
        builder.assert_zero(
            gate.clone() * is_last.clone() * s_phase_gate.clone() * (selected_out_z[i].clone() - expected_s_z[i].clone()),
        );
        builder.assert_zero(
            gate.clone() * is_last.clone() * s_phase_gate.clone() * (selected_out_u[i].clone() - expected_s_u[i].clone()),
        );
        builder.assert_zero(
            gate.clone() * is_last.clone() * s_phase_gate.clone() * (selected_out_t[i].clone() - expected_s_t[i].clone()),
        );
    }

    let c2_at1 = expected_c2_inter[0].clone();
    let c2_at2 = expected_c2_inter[1].clone();
    let c2_at3 = expected_c2_inter[2].clone();
    let c2_at4 = expected_c2_inter[3].clone();
    let c2_at5_raw = expected_c2_inter[4].clone();
    let c2_at6_raw = expected_c2_inter[5].clone();
    let c2_at8 = expected_c2_inter[6].clone();
    let c2_at9 = expected_c2_inter[7].clone();
    let c2_at10 = expected_c2_inter[8].clone();
    let c2_u_pre = expected_c2_inter[9].clone();

    let selected_out_x_arr: [AB::Expr; 5] = selected_out_x.clone().try_into().unwrap();
    let selected_out_z_arr: [AB::Expr; 5] = selected_out_z.clone().try_into().unwrap();
    let selected_out_u_arr: [AB::Expr; 5] = selected_out_u.clone().try_into().unwrap();
    let selected_out_t_arr: [AB::Expr; 5] = selected_out_t.clone().try_into().unwrap();

    for c in gfp5_mul_constraints::<AB::F, AB::Expr>(selected_out_x_arr.clone(), expected_m_s_x.clone(), c2_at1.clone()) {
        builder.assert_zero(gate.clone() * is_last.clone() * m_phase_gate.clone() * c);
    }
    for c in gfp5_mul_constraints::<AB::F, AB::Expr>(selected_out_z_arr.clone(), expected_m_s_z.clone(), c2_at2.clone()) {
        builder.assert_zero(gate.clone() * is_last.clone() * m_phase_gate.clone() * c);
    }
    for c in gfp5_mul_constraints::<AB::F, AB::Expr>(selected_out_u_arr.clone(), expected_m_s_u.clone(), c2_at3.clone()) {
        builder.assert_zero(gate.clone() * is_last.clone() * m_phase_gate.clone() * c);
    }
    for c in gfp5_mul_constraints::<AB::F, AB::Expr>(selected_out_t_arr.clone(), expected_m_s_t.clone(), c2_at4.clone()) {
        builder.assert_zero(gate.clone() * is_last.clone() * m_phase_gate.clone() * c);
    }
    let acc_x_plus_z = gfp5_add::<AB::F, AB::Expr>(selected_out_x_arr.clone(), selected_out_z_arr.clone());
    let s_x_plus_z = gfp5_add::<AB::F, AB::Expr>(expected_m_s_x.clone(), expected_m_s_z.clone());
    for c in gfp5_mul_constraints::<AB::F, AB::Expr>(acc_x_plus_z, s_x_plus_z, c2_at5_raw.clone()) {
        builder.assert_zero(gate.clone() * is_last.clone() * m_phase_gate.clone() * c);
    }
    let acc_u_plus_t = gfp5_add::<AB::F, AB::Expr>(selected_out_u_arr.clone(), selected_out_t_arr.clone());
    let s_u_plus_t = gfp5_add::<AB::F, AB::Expr>(expected_m_s_u.clone(), expected_m_s_t.clone());
    for c in gfp5_mul_constraints::<AB::F, AB::Expr>(acc_u_plus_t, s_u_plus_t, c2_at6_raw.clone()) {
        builder.assert_zero(gate.clone() * is_last.clone() * m_phase_gate.clone() * c);
    }
    let c2_t5 = gfp5_sub::<AB::F, AB::Expr>(
        gfp5_sub::<AB::F, AB::Expr>(c2_at5_raw.clone(), c2_at1.clone()),
        c2_at2.clone(),
    );
    let c2_t6 = gfp5_sub::<AB::F, AB::Expr>(
        gfp5_sub::<AB::F, AB::Expr>(c2_at6_raw.clone(), c2_at3.clone()),
        c2_at4.clone(),
    );
    let c2_t7 = gfp5_add::<AB::F, AB::Expr>(
        c2_at1.clone(),
        gfp5_mul_by_kz::<AB::F, AB::Expr>(B1, c2_at2.clone()),
    );
    for c in gfp5_mul_constraints::<AB::F, AB::Expr>(c2_at4.clone(), c2_t7.clone(), c2_at8.clone()) {
        builder.assert_zero(gate.clone() * is_last.clone() * m_phase_gate.clone() * c);
    }
    for c in gfp5_mul_constraints::<AB::F, AB::Expr>(
        c2_at3.clone(),
        gfp5_add::<AB::F, AB::Expr>(
            gfp5_mul_by_kz::<AB::F, AB::Expr>(2 * B1, c2_t5.clone()),
            gfp5_scale::<AB::F, AB::Expr>(2, c2_t7.clone()),
        ),
        c2_at9.clone(),
    ) {
        builder.assert_zero(gate.clone() * is_last.clone() * m_phase_gate.clone() * c);
    }
    for c in gfp5_mul_constraints::<AB::F, AB::Expr>(
        gfp5_add::<AB::F, AB::Expr>(c2_at4.clone(), gfp5_scale::<AB::F, AB::Expr>(2, c2_at3.clone())),
        gfp5_add::<AB::F, AB::Expr>(c2_t5.clone(), c2_t7.clone()),
        c2_at10.clone(),
    ) {
        builder.assert_zero(gate.clone() * is_last.clone() * m_phase_gate.clone() * c);
    }
    for c in gfp5_mul_constraints::<AB::F, AB::Expr>(
        c2_t6.clone(),
        gfp5_sub::<AB::F, AB::Expr>(
            gfp5_mul_by_kz::<AB::F, AB::Expr>(B1, c2_at2.clone()),
            c2_at1.clone(),
        ),
        c2_u_pre.clone(),
    ) {
        builder.assert_zero(gate.clone() * is_last.clone() * m_phase_gate.clone() * c);
    }
    let expected_sum_x = gfp5_mul_by_kz::<AB::F, AB::Expr>(
        B1,
        gfp5_sub::<AB::F, AB::Expr>(c2_at10.clone(), c2_at8.clone()),
    );
    let expected_sum_z = gfp5_sub::<AB::F, AB::Expr>(c2_at8.clone(), c2_at9.clone());
    let expected_sum_t = gfp5_add::<AB::F, AB::Expr>(c2_at8.clone(), c2_at9.clone());
    for i in 0..5 {
        builder.assert_zero(
            gate.clone() * is_last.clone() * m_phase_gate.clone() * (expected_c2_x[i].clone() - expected_sum_x[i].clone()),
        );
        builder.assert_zero(
            gate.clone() * is_last.clone() * m_phase_gate.clone() * (expected_c2_z[i].clone() - expected_sum_z[i].clone()),
        );
        builder.assert_zero(
            gate.clone() * is_last.clone() * m_phase_gate.clone() * (expected_c2_u[i].clone() - c2_u_pre[i].clone()),
        );
        builder.assert_zero(
            gate.clone() * is_last.clone() * m_phase_gate.clone() * (expected_c2_t[i].clone() - expected_sum_t[i].clone()),
        );
    }
    for c in gfp5_mul_constraints::<AB::F, AB::Expr>(
        expected_c2_enc.clone(),
        expected_c2_u.clone(),
        expected_c2_t.clone(),
    ) {
        builder.assert_zero(gate.clone() * is_last.clone() * m_phase_gate.clone() * c);
    }

    // --- Doubling constraints (gated) ---
    // dbl_t1 = acc_Z * acc_T
    for c in gfp5_mul_constraints::<AB::F, AB::Expr>(acc_z.clone(), acc_t.clone(), dbl_t1.clone()) {
        builder.assert_zero(gate.clone() * c);
    }
    // dbl_t2 = dbl_t1 * acc_T
    for c in gfp5_mul_constraints::<AB::F, AB::Expr>(dbl_t1.clone(), acc_t.clone(), dbl_t2.clone())
    {
        builder.assert_zero(gate.clone() * c);
    }
    // dbl_x1 = dbl_t2^2
    for c in gfp5_square_constraints::<AB::F, AB::Expr>(dbl_t2.clone(), dbl_x1.clone()) {
        builder.assert_zero(gate.clone() * c);
    }
    // dbl_z1 = dbl_t1 * acc_U
    for c in gfp5_mul_constraints::<AB::F, AB::Expr>(dbl_t1.clone(), acc_u.clone(), dbl_z1.clone())
    {
        builder.assert_zero(gate.clone() * c);
    }
    // dbl_t3 = acc_U^2
    for c in gfp5_square_constraints::<AB::F, AB::Expr>(acc_u.clone(), dbl_t3.clone()) {
        builder.assert_zero(gate.clone() * c);
    }
    // dbl_xz_t3 = (acc_X + acc_Z) * dbl_t3
    let acc_x_plus_z = gfp5_add::<AB::F, AB::Expr>(acc_x.clone(), acc_z.clone());
    for c in
        gfp5_mul_constraints::<AB::F, AB::Expr>(acc_x_plus_z, dbl_t3.clone(), dbl_xz_t3.clone())
    {
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
    for c in gfp5_mul_constraints::<AB::F, AB::Expr>(dbl_x.clone(), base_x.clone(), add_at1.clone())
    {
        builder.assert_zero(gate.clone() * c);
    }
    for c in gfp5_mul_constraints::<AB::F, AB::Expr>(dbl_z.clone(), base_z.clone(), add_at2.clone())
    {
        builder.assert_zero(gate.clone() * c);
    }
    for c in gfp5_mul_constraints::<AB::F, AB::Expr>(dbl_u.clone(), base_u.clone(), add_at3.clone())
    {
        builder.assert_zero(gate.clone() * c);
    }
    for c in gfp5_mul_constraints::<AB::F, AB::Expr>(dbl_t.clone(), base_t.clone(), add_at4.clone())
    {
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
        let next_is_ec: AB::Expr = next[IS_EC].clone().into();
        let not_last = AB::Expr::ONE - is_last.clone();
        for i in 0..5 {
            when_trans.assert_zero(
                gate.clone()
                    * not_last.clone()
                    * (next_acc_x[i].clone()
                        - dbl_x[i].clone()
                        - bit.clone() * (add_x[i].clone() - dbl_x[i].clone())),
            );
            when_trans.assert_zero(
                gate.clone()
                    * not_last.clone()
                    * (next_acc_z[i].clone()
                        - dbl_z[i].clone()
                        - bit.clone() * (add_z[i].clone() - dbl_z[i].clone())),
            );
            when_trans.assert_zero(
                gate.clone()
                    * not_last.clone()
                    * (next_acc_u[i].clone()
                        - dbl_u[i].clone()
                        - bit.clone() * (add_u[i].clone() - dbl_u[i].clone())),
            );
            when_trans.assert_zero(
                gate.clone()
                    * not_last.clone()
                    * (next_acc_t[i].clone()
                        - dbl_t[i].clone()
                        - bit.clone() * (add_t[i].clone() - dbl_t[i].clone())),
            );
        }
        // is_last  in  {0, 1}
        when_trans.assert_zero(gate.clone() * is_last.clone() * (AB::Expr::ONE - is_last.clone()));

        // Phase bookkeeping is part of the EC statement.
        when_trans.assert_zero(
            gate.clone()
                * next_is_ec.clone()
                * not_last.clone()
                * (next_phase.clone() - phase.clone()),
        );
        when_trans.assert_zero(
            gate.clone()
                * next_is_ec.clone()
                * is_last.clone()
                * (next_phase.clone() - phase.clone() - AB::Expr::ONE),
        );
        when_trans.assert_zero(
            gate.clone() * next_is_ec.clone() * (next_bind_active.clone() - bind_active.clone()),
        );

        when_trans.assert_zero(
            gate.clone()
                * next_is_ec.clone()
                * not_last.clone()
                * (next_scalar_acc
                    - (scalar_acc.clone() * AB::Expr::from_u64(2) + next[BIT].clone().into())),
        );
        when_trans.assert_zero(
            gate.clone()
                * next_is_ec.clone()
                * is_last.clone()
                * (next[EC_SCALAR_ACC].clone().into() - next[BIT].clone().into()),
        );

        // Base point must stay fixed within a phase.
        for i in 0..5 {
            when_trans.assert_zero(
                gate.clone()
                    * next_is_ec.clone()
                    * not_last.clone()
                    * (next_base_x[i].clone() - base_x[i].clone()),
            );
            when_trans.assert_zero(
                gate.clone()
                    * next_is_ec.clone()
                    * not_last.clone()
                    * (next_base_z[i].clone() - base_z[i].clone()),
            );
            when_trans.assert_zero(
                gate.clone()
                    * next_is_ec.clone()
                    * not_last.clone()
                    * (next_base_u[i].clone() - base_u[i].clone()),
            );
            when_trans.assert_zero(
                gate.clone()
                    * next_is_ec.clone()
                    * not_last.clone()
                    * (next_base_t[i].clone() - base_t[i].clone()),
            );
        }

        // Each new phase must restart from the neutral accumulator.
        for i in 0..5 {
            when_trans.assert_zero(
                gate.clone() * next_is_ec.clone() * is_last.clone() * next_acc_x[i].clone(),
            );
            when_trans.assert_zero(
                gate.clone() * next_is_ec.clone() * is_last.clone() * next_acc_u[i].clone(),
            );
        }
        when_trans.assert_zero(
            gate.clone()
                * next_is_ec.clone()
                * is_last.clone()
                * (next_acc_z[0].clone() - AB::Expr::ONE),
        );
        when_trans.assert_zero(
            gate.clone()
                * next_is_ec.clone()
                * is_last.clone()
                * (next_acc_t[0].clone() - AB::Expr::ONE),
        );
        for i in 1..5 {
            when_trans.assert_zero(
                gate.clone() * next_is_ec.clone() * is_last.clone() * next_acc_z[i].clone(),
            );
            when_trans.assert_zero(
                gate.clone() * next_is_ec.clone() * is_last.clone() * next_acc_t[i].clone(),
            );
        }
    }
}

/// Poseidon2 round transition constraints, gated by the `gate` expression (IS_P2).
///
/// Each Poseidon2 row stores the state BEFORE a round. The next row's state
/// should equal the result of applying one round (S-box + linear layer) to
/// the current state. We verify this transition when both the current and
/// next rows are Poseidon2 rows (both_p2 = IS_P2[local] * IS_P2[next]).
///
/// The S-box x^7 is fully decomposed into stored columns:
///   x2 = state + round_constant  (written by prover)
///   x3 = x2^2                    (stored, verified at degree 2)
///   x6 = x2 * x3                 (stored, verified at degree 2)
///   x7 = x3^2 * x6              (stored, verified at degree 3)
///
/// Storing x7 as a column means the transition constraint (which applies
/// MDS to x7 values) stays at degree 1 for linear combinations, and the
/// total constraint degree (with gating) is 4. This enables log_blowup=2.
///
/// Maximum constraint degree: 4
///   x7 verification: gate(1) * (x7 - x3^2*x6)(3) = degree 4
///   transition: both_p2(2) * (next_state - linear(x7))(2) = degree 4
fn eval_poseidon2_constraints<AB: AirBuilder>(
    builder: &mut AB,
    local: &[AB::Var],
    next: &[AB::Var],
    gate: &AB::Expr,
    constants: &poseidon2::Poseidon2Constants,
) {
    let state: Vec<AB::Expr> = (0..poseidon2::WIDTH)
        .map(|i| local[P2_STATE + i].clone().into())
        .collect();
    let next_state: Vec<AB::Expr> = (0..poseidon2::WIDTH)
        .map(|i| next[P2_STATE + i].clone().into())
        .collect();
    let x2: Vec<AB::Expr> = (0..poseidon2::WIDTH)
        .map(|i| local[P2_SBOX_X2 + i].clone().into())
        .collect();
    let x3: Vec<AB::Expr> = (0..poseidon2::WIDTH)
        .map(|i| local[P2_SBOX_X3 + i].clone().into())
        .collect();
    let x6: Vec<AB::Expr> = (0..poseidon2::WIDTH)
        .map(|i| local[P2_SBOX_X6 + i].clone().into())
        .collect();
    let x7: Vec<AB::Expr> = (0..poseidon2::WIDTH)
        .map(|i| local[P2_SBOX_X7 + i].clone().into())
        .collect();
    let round: AB::Expr = local[P2_ROUND].clone().into();
    let round_type: AB::Expr = local[P2_ROUND_TYPE].clone().into();
    let perm_id: AB::Expr = local[P2_PERM_ID].clone().into();
    let selectors: Vec<AB::Expr> = (0..P2_ROUND_SEL_COUNT)
        .map(|i| local[P2_ROUND_SEL + i].clone().into())
        .collect();
    let k_selectors: Vec<AB::Expr> = (0..P2_K_SEL_COUNT)
        .map(|i| local[P2_K_SEL + i].clone().into())
        .collect();
    let vote_selectors: Vec<AB::Expr> = (0..P2_VOTE_ID_PRE_SEL_COUNT)
        .map(|i| local[P2_VOTE_ID_PRE_SEL + i].clone().into())
        .collect();
    let input_selectors: Vec<AB::Expr> = (0..P2_INPUTS_PREFIX_SEL_COUNT)
        .map(|i| local[P2_INPUTS_PREFIX_SEL + i].clone().into())
        .collect();

    let mut selector_sum = AB::Expr::ZERO;
    for sel in &selectors {
        selector_sum = selector_sum + sel.clone();
        builder.assert_zero(gate.clone() * sel.clone() * (sel.clone() - AB::Expr::ONE));
    }
    builder.assert_zero(selector_sum - gate.clone());

    let mut expected_round = AB::Expr::ZERO;
    let mut expected_round_type = AB::Expr::ZERO;
    for (r, sel) in selectors.iter().enumerate() {
        expected_round = expected_round + sel.clone() * AB::Expr::from_u64(r as u64);
        let is_partial_round = if (poseidon2::ROUNDS_F_HALF
            ..poseidon2::ROUNDS_F_HALF + poseidon2::ROUNDS_P)
            .contains(&r)
        {
            1
        } else {
            0
        };
        expected_round_type =
            expected_round_type + sel.clone() * AB::Expr::from_u64(is_partial_round);
    }

    builder.assert_zero(gate.clone() * (round.clone() - expected_round));
    builder.assert_zero(gate.clone() * (round_type.clone() - expected_round_type.clone()));
    builder.assert_zero(gate.clone() * round_type.clone() * (round_type.clone() - AB::Expr::ONE));

    for sel in &k_selectors {
        builder.assert_zero(sel.clone() * (sel.clone() - AB::Expr::ONE));
    }

    let is_partial = round_type.clone();
    let is_full = AB::Expr::ONE - round_type.clone();

    for i in 0..poseidon2::WIDTH {
        let mut expected_x2 = AB::Expr::ZERO;
        for (r, sel) in selectors.iter().enumerate() {
            let round_term = if r < poseidon2::ROUNDS_F_HALF {
                state[i].clone()
                    + AB::Expr::from_u64(p3_field::PrimeField64::as_canonical_u64(
                        &constants.external_rc[r][i],
                    ))
            } else if r < poseidon2::ROUNDS_F_HALF + poseidon2::ROUNDS_P {
                if i == 0 {
                    state[0].clone()
                        + AB::Expr::from_u64(p3_field::PrimeField64::as_canonical_u64(
                            &constants.internal_rc[r - poseidon2::ROUNDS_F_HALF],
                        ))
                } else {
                    AB::Expr::ZERO
                }
            } else {
                state[i].clone()
                    + AB::Expr::from_u64(p3_field::PrimeField64::as_canonical_u64(
                        &constants.external_rc[r - poseidon2::ROUNDS_P][i],
                    ))
            };
            expected_x2 = expected_x2 + sel.clone() * round_term;
        }
        builder.assert_zero(gate.clone() * (x2[i].clone() - expected_x2));
    }

    for i in 0..poseidon2::WIDTH {
        if i == 0 {
            builder.assert_zero(gate.clone() * (x3[0].clone() - x2[0].clone() * x2[0].clone()));
            builder.assert_zero(gate.clone() * (x6[0].clone() - x2[0].clone() * x3[0].clone()));
            builder.assert_zero(
                gate.clone() * (x7[0].clone() - x3[0].clone() * x3[0].clone() * x6[0].clone()),
            );
        } else {
            builder.assert_zero(
                gate.clone()
                    * (is_full.clone() * (x3[i].clone() - x2[i].clone() * x2[i].clone())
                        + is_partial.clone() * x3[i].clone()),
            );
            builder.assert_zero(
                gate.clone()
                    * (is_full.clone() * (x6[i].clone() - x2[i].clone() * x3[i].clone())
                        + is_partial.clone() * x6[i].clone()),
            );
            builder.assert_zero(
                gate.clone() * (x7[i].clone() - x3[i].clone() * x3[i].clone() * x6[i].clone()),
            );
        }
    }

    // ============================================================
    // State transition: next_state = linear_layer(sbox_outputs)
    //
    // To keep the constraint degree ≤ 4, we compute full_next from x7 columns
    // directly (degree 1) rather than from sbox_out (which would be degree 2
    // due to the is_full*x7+is_partial*state multiplexer).
    //
    // Degree analysis:
    //   full_next = linear(x7[0..7]) → degree 1
    //   partial_next = linear(x7[0], state[1..7]) → degree 1
    //   expected = is_full(1) * full_next(1) + is_partial(1) * partial_next(1) → degree 2
    //   both_p2(2) * (next_state(1) - expected(2)) → degree 4 ✓
    // ============================================================

    // External linear layer (full rounds): apply to x7 values directly.
    // Horizen Labs 4x4 MDS blocks then mix.
    // Matrix: [[5,7,1,3],[4,6,1,1],[1,3,5,7],[1,1,4,6]] (matches Zisk's matmul_m4).
    let mat4 = |a: &AB::Expr, b: &AB::Expr, c: &AB::Expr, d: &AB::Expr| -> [AB::Expr; 4] {
        let t0 = a.clone() + b.clone();
        let t1 = c.clone() + d.clone();
        let t2 = b.clone() + b.clone() + t1.clone(); // 2b + c + d
        let t3 = d.clone() + d.clone() + t0.clone(); // a + b + 2d
        let t1_2 = t1.clone() + t1; // 2c + 2d
        let t0_2 = t0.clone() + t0; // 2a + 2b
        let t4 = t1_2.clone() + t1_2 + t3.clone(); // a + b + 4c + 6d
        let t5 = t0_2.clone() + t0_2 + t2.clone(); // 4a + 6b + c + d
        let t6 = t3 + t5.clone(); // 5a + 7b + c + 3d
        let t7 = t2 + t4.clone(); // a + 3b + 5c + 7d
        [t6, t5, t7, t4]
    };

    // Full round: linear layer applied to all x7 values (degree 1 each)
    let fb0 = mat4(&x7[0], &x7[1], &x7[2], &x7[3]);
    let fb1 = mat4(&x7[4], &x7[5], &x7[6], &x7[7]);

    let mut full_next = Vec::with_capacity(poseidon2::WIDTH);
    for i in 0..4 {
        let sum = fb0[i].clone() + fb1[i].clone();
        full_next.push(fb0[i].clone() + sum.clone());
    }
    for i in 0..4 {
        let sum = fb0[i].clone() + fb1[i].clone();
        full_next.push(fb1[i].clone() + sum);
    }

    // Internal linear layer (partial rounds): x7[0] is the S-box output,
    // elements 1-7 pass through unchanged (state[i]).
    let mut partial_sum = x7[0].clone();
    for i in 1..poseidon2::WIDTH {
        partial_sum = partial_sum + state[i].clone();
    }
    let mut partial_next = Vec::with_capacity(poseidon2::WIDTH);
    for i in 0..poseidon2::WIDTH {
        let val = if i == 0 {
            x7[0].clone()
        } else {
            state[i].clone()
        };
        let diag_i = AB::Expr::from_u64(p3_field::PrimeField64::as_canonical_u64(
            &p3_goldilocks::MATRIX_DIAG_8_GOLDILOCKS[i],
        ));
        partial_next.push(val * diag_i + partial_sum.clone());
    }

    {
        let mut when_trans = builder.when_transition();
        let next_is_p2: AB::Expr = next[IS_P2].clone().into();
        let next_round: AB::Expr = next[P2_ROUND].clone().into();
        let next_perm_id: AB::Expr = next[P2_PERM_ID].clone().into();
        let next_k_selectors: Vec<AB::Expr> = (0..P2_K_SEL_COUNT)
            .map(|i| next[P2_K_SEL + i].clone().into())
            .collect();
        let next_vote_selectors: Vec<AB::Expr> = (0..P2_VOTE_ID_PRE_SEL_COUNT)
            .map(|i| next[P2_VOTE_ID_PRE_SEL + i].clone().into())
            .collect();
        let next_input_selectors: Vec<AB::Expr> = (0..P2_INPUTS_PREFIX_SEL_COUNT)
            .map(|i| next[P2_INPUTS_PREFIX_SEL + i].clone().into())
            .collect();
        let both_p2 = gate.clone() * next_is_p2.clone();

        for i in 0..poseidon2::WIDTH {
            let expected = is_full.clone() * full_next[i].clone()
                + is_partial.clone() * partial_next[i].clone();
            when_trans.assert_zero(both_p2.clone() * (next_state[i].clone() - expected));
        }

        when_trans
            .assert_zero(both_p2.clone() * (next_round.clone() - round.clone() - AB::Expr::ONE));
        when_trans.assert_zero(both_p2.clone() * (next_perm_id - perm_id.clone()));

        let current_not_p2 = AB::Expr::ONE - gate.clone();
        when_trans.assert_zero(current_not_p2 * next_is_p2 * next_round);

        for i in 0..P2_K_SEL_COUNT {
            when_trans.assert_zero(
                both_p2.clone() * (next_k_selectors[i].clone() - k_selectors[i].clone()),
            );
        }
        for i in 0..P2_VOTE_ID_PRE_SEL_COUNT {
            when_trans.assert_zero(
                both_p2.clone() * (next_vote_selectors[i].clone() - vote_selectors[i].clone()),
            );
        }
        for i in 0..P2_INPUTS_PREFIX_SEL_COUNT {
            when_trans.assert_zero(
                both_p2.clone() * (next_input_selectors[i].clone() - input_selectors[i].clone()),
            );
        }
    }

    {
        let mut when_trans = builder.when_transition();
        let next_is_p2: AB::Expr = next[IS_P2].clone().into();
        let local_to_gap = gate.clone() * (AB::Expr::ONE - next_is_p2.clone());
        when_trans.assert_zero(
            local_to_gap.clone()
                * (round.clone() - AB::Expr::from_u64((poseidon2::TOTAL_ROUNDS - 1) as u64)),
        );
        for i in 0..poseidon2::WIDTH {
            let expected = is_full.clone() * full_next[i].clone()
                + is_partial.clone() * partial_next[i].clone();
            when_trans.assert_zero(local_to_gap.clone() * (next_state[i].clone() - expected));
        }
        for i in 0..P2_K_SEL_COUNT {
            when_trans.assert_zero(
                local_to_gap.clone() * (next[P2_K_SEL + i].clone().into() - k_selectors[i].clone()),
            );
            when_trans.assert_zero(
                local_to_gap.clone()
                    * k_selectors[i].clone()
                    * (next[GLOBAL_KS + i].clone().into()
                        - full_next[0].clone() * is_full.clone()
                        - partial_next[0].clone() * is_partial.clone()),
            );
        }

        let mut expected_next_vote = vec![AB::Expr::ZERO; P2_VOTE_ID_PRE_SEL_COUNT];
        let mut expected_next_input = vec![AB::Expr::ZERO; P2_INPUTS_PREFIX_SEL_COUNT];
        expected_next_vote[0] = k_selectors[7].clone();
        for i in 0..P2_VOTE_ID_PRE_SEL_COUNT {
            if i + 1 < P2_VOTE_ID_PRE_SEL_COUNT {
                expected_next_vote[i + 1] = expected_next_vote[i + 1].clone() + vote_selectors[i].clone();
            } else {
                expected_next_input[0] = expected_next_input[0].clone() + vote_selectors[i].clone();
            }
        }
        for i in 0..P2_INPUTS_PREFIX_SEL_COUNT {
            if i + 1 < P2_INPUTS_PREFIX_SEL_COUNT {
                expected_next_input[i + 1] =
                    expected_next_input[i + 1].clone() + input_selectors[i].clone();
            }
        }

        for i in 0..P2_VOTE_ID_PRE_SEL_COUNT {
            when_trans.assert_zero(
                local_to_gap.clone()
                    * (next[P2_VOTE_ID_PRE_SEL + i].clone().into() - expected_next_vote[i].clone()),
            );
        }
        for i in 0..P2_INPUTS_PREFIX_SEL_COUNT {
            when_trans.assert_zero(
                local_to_gap.clone()
                    * (next[P2_INPUTS_PREFIX_SEL + i].clone().into()
                        - expected_next_input[i].clone()),
            );
        }
        when_trans.assert_zero(
            local_to_gap.clone()
                * (next[P2_VOTE_ID_OUT].clone().into()
                    - vote_selectors[P2_VOTE_ID_PRE_SEL_COUNT - 1].clone()),
        );
        when_trans.assert_zero(
            local_to_gap
                * (next[P2_INPUTS_HASH_OUT].clone().into()
                    - input_selectors[P2_INPUTS_PREFIX_SEL_COUNT - 1].clone()),
        );
    }
}

fn eval_global_bindings<AB: AirBuilder>(builder: &mut AB, local: &[AB::Var], next: &[AB::Var]) {
    let mut when_trans = builder.when_transition();
    let is_ec: AB::Expr = local[IS_EC].clone().into();
    let is_p2: AB::Expr = local[IS_P2].clone().into();
    let is_bv: AB::Expr = local[IS_BV].clone().into();
    let next_is_p2: AB::Expr = next[IS_P2].clone().into();
    for i in 0..GLOBAL_KS_COUNT {
        when_trans
            .assert_zero(next[GLOBAL_KS + i].clone().into() - local[GLOBAL_KS + i].clone().into());
    }
    for i in 0..GLOBAL_FIELDS_COUNT {
        when_trans.assert_zero(
            next[GLOBAL_FIELDS + i].clone().into() - local[GLOBAL_FIELDS + i].clone().into(),
        );
    }
    for i in 0..GLOBAL_BV_PARAMS_COUNT {
        when_trans.assert_zero(
            next[GLOBAL_BV_PARAMS + i].clone().into() - local[GLOBAL_BV_PARAMS + i].clone().into(),
        );
    }
    for i in 0..GLOBAL_PACKED_MODE_COUNT {
        when_trans.assert_zero(
            next[GLOBAL_PACKED_MODE + i].clone().into()
                - local[GLOBAL_PACKED_MODE + i].clone().into(),
        );
    }
    for i in 0..GLOBAL_PROCESS_ID_COUNT {
        when_trans.assert_zero(
            next[GLOBAL_PROCESS_ID + i].clone().into()
                - local[GLOBAL_PROCESS_ID + i].clone().into(),
        );
    }
    for i in 0..GLOBAL_K_LIMBS_COUNT {
        when_trans.assert_zero(
            next[GLOBAL_K_LIMBS + i].clone().into() - local[GLOBAL_K_LIMBS + i].clone().into(),
        );
    }
    for i in 0..GLOBAL_PK_COUNT {
        when_trans
            .assert_zero(next[GLOBAL_PK + i].clone().into() - local[GLOBAL_PK + i].clone().into());
    }
    for i in 0..GLOBAL_S_POINTS_COUNT {
        when_trans.assert_zero(
            next[GLOBAL_S_POINTS + i].clone().into() - local[GLOBAL_S_POINTS + i].clone().into(),
        );
    }
    for i in 0..GLOBAL_C2_POINTS_COUNT {
        when_trans.assert_zero(
            next[GLOBAL_C2_POINTS + i].clone().into() - local[GLOBAL_C2_POINTS + i].clone().into(),
        );
    }
    for i in 0..GLOBAL_C1_ENC_COUNT {
        when_trans.assert_zero(
            next[GLOBAL_C1_ENC + i].clone().into() - local[GLOBAL_C1_ENC + i].clone().into(),
        );
    }
    for i in 0..GLOBAL_C2_ENC_COUNT {
        when_trans.assert_zero(
            next[GLOBAL_C2_ENC + i].clone().into() - local[GLOBAL_C2_ENC + i].clone().into(),
        );
    }
    for i in 0..GLOBAL_HASH_INPUT_COUNT {
        when_trans.assert_zero(
            next[GLOBAL_HASH_INPUT + i].clone().into()
                - local[GLOBAL_HASH_INPUT + i].clone().into(),
        );
    }
    for i in 0..GLOBAL_C2_ADD_INTER_COUNT {
        when_trans.assert_zero(
            next[GLOBAL_C2_ADD_INTER + i].clone().into()
                - local[GLOBAL_C2_ADD_INTER + i].clone().into(),
        );
    }
    for i in 0..GLOBAL_PACKED_MODE_BITS_COUNT {
        when_trans.assert_zero(
            next[GLOBAL_PACKED_MODE_BITS + i].clone().into()
                - local[GLOBAL_PACKED_MODE_BITS + i].clone().into(),
        );
    }

    let current_gap = AB::Expr::ONE - is_ec.clone() - is_p2.clone() - is_bv.clone();
    when_trans.assert_zero(
        is_ec.clone() * next_is_p2.clone() * (next[P2_K_SEL].clone().into() - AB::Expr::ONE),
    );
    for i in 1..P2_K_SEL_COUNT {
        when_trans
            .assert_zero(is_ec.clone() * next_is_p2.clone() * next[P2_K_SEL + i].clone().into());
    }

    when_trans
        .assert_zero(current_gap.clone() * next_is_p2.clone() * next[P2_K_SEL].clone().into());
    for i in 1..P2_K_SEL_COUNT {
        when_trans.assert_zero(
            current_gap.clone()
                * next_is_p2.clone()
                * (next[P2_K_SEL + i].clone().into() - local[P2_K_SEL + i - 1].clone().into()),
        );
    }
}

fn eval_poseidon_statement_bindings<AB: AirBuilder + AirBuilderWithPublicValues>(
    builder: &mut AB,
    local: &[AB::Var],
    next: &[AB::Var],
    public_values: &[AB::PublicVar],
) {
    let col = |c: usize| -> AB::Expr { local[c].clone().into() };
    let ncol = |c: usize| -> AB::Expr { next[c].clone().into() };
    let mat4 = |a: &AB::Expr, b: &AB::Expr, c: &AB::Expr, d: &AB::Expr| -> [AB::Expr; 4] {
        let t0 = a.clone() + b.clone();
        let t1 = c.clone() + d.clone();
        let t2 = b.clone() + b.clone() + t1.clone();
        let t3 = d.clone() + d.clone() + t0.clone();
        let t1_2 = t1.clone() + t1;
        let t0_2 = t0.clone() + t0;
        let t4 = t1_2.clone() + t1_2 + t3.clone();
        let t5 = t0_2.clone() + t0_2 + t2.clone();
        let t6 = t3 + t5.clone();
        let t7 = t2 + t4.clone();
        [t6, t5, t7, t4]
    };

    {
        let mut first = builder.when_first_row();
        let mut expected_hash_input = Vec::with_capacity(GLOBAL_HASH_INPUT_COUNT);
        for i in 0..4 {
            expected_hash_input.push(col(GLOBAL_PROCESS_ID + i));
        }
        for i in 0..4 {
            expected_hash_input.push(col(GLOBAL_PACKED_MODE + i));
        }
        for i in 0..GLOBAL_PK_COUNT {
            expected_hash_input.push(col(GLOBAL_PK + i));
        }
        for i in 0..4 {
            expected_hash_input.push(public_values[PV_ADDRESS + i].clone().into());
        }
        expected_hash_input.push(public_values[PV_VOTE_ID].clone().into());
        for i in 0..NUM_FIELDS {
            for j in 0..5 {
                expected_hash_input.push(col(GLOBAL_C1_ENC + i * 5 + j));
            }
            for j in 0..5 {
                expected_hash_input.push(col(GLOBAL_C2_ENC + i * 5 + j));
            }
        }
        expected_hash_input.push(col(GLOBAL_BV_WEIGHT));
        while expected_hash_input.len() < GLOBAL_HASH_INPUT_COUNT {
            expected_hash_input.push(AB::Expr::ZERO);
        }
        for (i, expected) in expected_hash_input.into_iter().enumerate() {
            first.assert_zero(col(GLOBAL_HASH_INPUT + i) - expected);
        }

        for bit_idx in 0..GLOBAL_PACKED_MODE_BITS_COUNT {
            let bit = col(GLOBAL_PACKED_MODE_BITS + bit_idx);
            first.assert_zero(bit.clone() * (bit.clone() - AB::Expr::ONE));
        }

        for chunk in 0..GLOBAL_PACKED_MODE_COUNT {
            let mut chunk_value = AB::Expr::ZERO;
            let mut pow2 = AB::Expr::ONE;
            for bit in 0..62 {
                chunk_value = chunk_value + pow2.clone() * col(GLOBAL_PACKED_MODE_BITS + chunk * 62 + bit);
                pow2 = pow2 * AB::Expr::from_u64(2);
            }
            first.assert_zero(col(GLOBAL_PACKED_MODE + chunk) - chunk_value);
        }

        let decode_bits = |start: usize, width: usize| -> AB::Expr {
            let mut acc = AB::Expr::ZERO;
            let mut pow2 = AB::Expr::ONE;
            for bit_idx in 0..width {
                acc = acc + pow2.clone() * col(GLOBAL_PACKED_MODE_BITS + start + bit_idx);
                pow2 = pow2 * AB::Expr::from_u64(2);
            }
            acc
        };

        first.assert_zero(col(GLOBAL_BV_NUM_FIELDS) - decode_bits(0, 8));
        first.assert_zero(col(GLOBAL_BV_GROUP_SIZE) - decode_bits(8, 8));
        first.assert_zero(col(GLOBAL_BV_UNIQUE) - decode_bits(16, 1));
        first.assert_zero(col(GLOBAL_BV_COST_FROM_WEIGHT) - decode_bits(17, 1));
        first.assert_zero(col(GLOBAL_BV_COST_EXP) - decode_bits(18, 8));
        first.assert_zero(col(GLOBAL_BV_MAX_VALUE) - decode_bits(26, 48));
        first.assert_zero(col(GLOBAL_BV_MIN_VALUE) - decode_bits(74, 48));
        first.assert_zero(col(GLOBAL_BV_MAX_SUM) - decode_bits(122, 63));
        first.assert_zero(col(GLOBAL_BV_MIN_SUM) - decode_bits(185, 63));
    }

    for k_idx in 0..P2_K_SEL_COUNT {
        let gate = col(IS_P2) * col(P2_ROUND_SEL) * col(P2_K_SEL + k_idx);
        let mut input = [
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
        ];
        if k_idx == 0 {
            for i in 0..5 {
                input[i] = col(GLOBAL_K_LIMBS + i);
            }
        } else {
            input[0] = col(GLOBAL_KS + k_idx - 1);
        }
        let fb0 = mat4(&input[0], &input[1], &input[2], &input[3]);
        let fb1 = mat4(&input[4], &input[5], &input[6], &input[7]);
        for i in 0..4 {
            let sum = fb0[i].clone() + fb1[i].clone();
            builder.assert_zero(gate.clone() * (col(P2_STATE + i) - (fb0[i].clone() + sum.clone())));
            builder.assert_zero(gate.clone() * (col(P2_STATE + 4 + i) - (fb1[i].clone() + sum)));
        }
    }

    let vote_out = col(P2_VOTE_ID_OUT);
    builder.assert_zero(vote_out.clone() * (vote_out.clone() - AB::Expr::ONE));
    builder.assert_zero(vote_out.clone() * col(IS_EC));
    builder.assert_zero(vote_out.clone() * col(IS_P2));
    builder.assert_zero(vote_out.clone() * col(IS_BV));

    let mut raw_bits = AB::Expr::ZERO;
    let mut low63 = AB::Expr::ZERO;
    let mut pow2 = AB::Expr::ONE;
    for b in 0..P2_VOTE_ID_BITS_COUNT {
        let bit = col(P2_VOTE_ID_BITS + b);
        builder.assert_zero(vote_out.clone() * bit.clone() * (bit.clone() - AB::Expr::ONE));
        raw_bits = raw_bits + pow2.clone() * bit.clone();
        if b < 63 {
            low63 = low63 + pow2.clone() * bit;
        }
        pow2 = pow2 * AB::Expr::from_u64(2);
    }
    builder.assert_zero(vote_out.clone() * (col(P2_STATE) - raw_bits));
    builder.assert_zero(
        vote_out.clone()
            * (public_values[PV_VOTE_ID].clone().into()
                - (low63 + AB::Expr::from_u64(1u64 << 63))),
    );

    let vote_sel: Vec<AB::Expr> = (0..P2_VOTE_ID_PRE_SEL_COUNT)
        .map(|i| col(P2_VOTE_ID_PRE_SEL + i))
        .collect();
    let inputs_sel: Vec<AB::Expr> = (0..P2_INPUTS_PREFIX_SEL_COUNT)
        .map(|i| col(P2_INPUTS_PREFIX_SEL + i))
        .collect();
    let current_gap = AB::Expr::ONE - col(IS_EC) - col(IS_P2) - col(IS_BV);
    let preperm_gate = current_gap.clone() * ncol(IS_P2) * (AB::Expr::ONE - ncol(P2_ROUND));
    let mut active = AB::Expr::ZERO;
    for sel in vote_sel.iter().chain(inputs_sel.iter()) {
        builder.assert_zero(sel.clone() * (sel.clone() - AB::Expr::ONE));
        active = active + sel.clone();
    }
    builder.assert_zero(active.clone() * (active.clone() - AB::Expr::ONE));
    for i in 0..P2_VOTE_ID_PRE_SEL_COUNT {
        builder.assert_zero(preperm_gate.clone() * (ncol(P2_VOTE_ID_PRE_SEL + i) - vote_sel[i].clone()));
    }
    for i in 0..P2_INPUTS_PREFIX_SEL_COUNT {
        builder.assert_zero(
            preperm_gate.clone() * (ncol(P2_INPUTS_PREFIX_SEL + i) - inputs_sel[i].clone()),
        );
    }
    builder.assert_zero(preperm_gate.clone() * (ncol(P2_PERM_ID) - col(P2_PERM_ID) - AB::Expr::ONE));
    builder.assert_zero(preperm_gate.clone() * ncol(P2_INPUTS_HASH_OUT));
    builder.assert_zero(preperm_gate.clone() * ncol(P2_VOTE_ID_OUT));

    let mut expected_chunk = [AB::Expr::ZERO, AB::Expr::ZERO, AB::Expr::ZERO, AB::Expr::ZERO];
    for i in 0..4 {
        expected_chunk[i] = expected_chunk[i].clone()
            + vote_sel[0].clone() * col(GLOBAL_PROCESS_ID + i)
            + vote_sel[1].clone() * public_values[PV_ADDRESS + i].clone().into()
            ;
    }
    for i in 0..4 {
        expected_chunk[i] = expected_chunk[i].clone() + vote_sel[2].clone() * col(GLOBAL_K_LIMBS + i);
    }
    expected_chunk[0] = expected_chunk[0].clone() + vote_sel[3].clone() * col(GLOBAL_K_LIMBS + 4);
    for chunk_idx in 0..P2_INPUTS_PREFIX_SEL_COUNT {
        for i in 0..4 {
            expected_chunk[i] = expected_chunk[i].clone()
                + inputs_sel[chunk_idx].clone() * col(GLOBAL_HASH_INPUT + chunk_idx * 4 + i);
        }
    }
    for i in 0..4 {
        builder.assert_zero(preperm_gate.clone() * active.clone() * (col(P2_ABSORB_CHUNK + i) - expected_chunk[i].clone()));
    }

    let first_hash = vote_sel[0].clone() + inputs_sel[0].clone();
    let continuing = active.clone() - first_hash.clone();
    let mut absorbed = [
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        AB::Expr::ZERO,
        AB::Expr::ZERO,
    ];
    for i in 0..8 {
        let prev_lane = col(P2_STATE + i);
        let chunk = if i < 4 {
            col(P2_ABSORB_CHUNK + i)
        } else {
            AB::Expr::ZERO
        };
        absorbed[i] = continuing.clone() * (prev_lane.clone() + chunk.clone()) + first_hash.clone() * chunk;
    }

    let fb0 = mat4(&absorbed[0], &absorbed[1], &absorbed[2], &absorbed[3]);
    let fb1 = mat4(&absorbed[4], &absorbed[5], &absorbed[6], &absorbed[7]);
    for i in 0..4 {
        let sum = fb0[i].clone() + fb1[i].clone();
        builder.assert_zero(preperm_gate.clone() * active.clone() * (ncol(P2_STATE + i) - (fb0[i].clone() + sum.clone())));
        builder.assert_zero(preperm_gate.clone() * active.clone() * (ncol(P2_STATE + 4 + i) - (fb1[i].clone() + sum)));
    }
}

// ============================================================
// Helper: extract GF(p^5) expression array from row slice
// ============================================================
/// Helper: pull a GF(p^5) element from a row slice as symbolic expressions.
fn gfp5_expr<AB: AirBuilder>(row: &[AB::Var], offset: usize) -> [AB::Expr; 5] {
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
///   - Uniqueness: for active j != i, (field[i] - field[j]) * inv[j] = 1
///   - Cost sum transition: cost_sum[next_row] = cost_sum[current] + mask * power
///   - Bounds row: bit decomposition of (limit - cost) and (cost - min_sum)
///
/// Maximum constraint degree: 4 (product of gate * mask * inv * diff).
/// Well within the degree-7 budget.
fn eval_bv_constraints<AB: AirBuilder>(
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
    let global_num_fields = col(GLOBAL_BV_NUM_FIELDS);
    let global_min_value = col(GLOBAL_BV_MIN_VALUE);
    let global_max_value = col(GLOBAL_BV_MAX_VALUE);
    let global_unique = col(GLOBAL_BV_UNIQUE);
    let global_cost_from_weight = col(GLOBAL_BV_COST_FROM_WEIGHT);
    let global_cost_exp = col(GLOBAL_BV_COST_EXP);
    let global_max_sum = col(GLOBAL_BV_MAX_SUM);
    let global_min_sum = col(GLOBAL_BV_MIN_SUM);
    let global_group_size = col(GLOBAL_BV_GROUP_SIZE);
    let global_weight = col(GLOBAL_BV_WEIGHT);
    let field_masks: Vec<AB::Expr> = (0..BV_FIELD_MASKS_COUNT)
        .map(|i| col(BV_FIELD_MASKS + i))
        .collect();
    let row_selectors: Vec<AB::Expr> = (0..BV_ROW_SEL_COUNT).map(|i| col(BV_ROW_SEL + i)).collect();

    let mut row_sel_sum = AB::Expr::ZERO;
    let mut expected_row_idx = AB::Expr::ZERO;
    for (i, sel) in row_selectors.iter().enumerate() {
        row_sel_sum = row_sel_sum + sel.clone();
        expected_row_idx = expected_row_idx + sel.clone() * AB::Expr::from_u64(i as u64);
        builder.assert_zero(gate.clone() * sel.clone() * (sel.clone() - AB::Expr::ONE));
    }
    builder.assert_zero(gate.clone() * (row_sel_sum - AB::Expr::ONE));
    builder.assert_zero(gate.clone() * (row_idx.clone() - expected_row_idx));
    builder.assert_zero(gate.clone() * (num_fields.clone() - global_num_fields));
    builder.assert_zero(gate.clone() * (min_val.clone() - global_min_value));
    builder.assert_zero(gate.clone() * (max_val.clone() - global_max_value));
    builder.assert_zero(gate.clone() * (unique.clone() - global_unique));
    builder.assert_zero(gate.clone() * (col(BV_COST_FROM_WEIGHT) - global_cost_from_weight));
    builder.assert_zero(gate.clone() * (col(BV_COST_EXP) - global_cost_exp));
    builder.assert_zero(gate.clone() * (col(BV_MAX_SUM) - global_max_sum));
    builder.assert_zero(gate.clone() * (col(BV_MIN_SUM) - global_min_sum));
    builder.assert_zero(gate.clone() * (col(BV_GROUP_SIZE) - global_group_size));
    builder.assert_zero(gate.clone() * (col(BV_WEIGHT) - global_weight));

    // 1. Mask must be binary
    builder.assert_zero(gate.clone() * mask.clone() * (mask.clone() - AB::Expr::ONE));

    let mut mask_sum = AB::Expr::ZERO;
    for j in 0..BV_FIELD_MASKS_COUNT {
        let field_mask = field_masks[j].clone();
        builder
            .assert_zero(gate.clone() * field_mask.clone() * (field_mask.clone() - AB::Expr::ONE));
        mask_sum = mask_sum + field_mask.clone();
        if j + 1 < BV_FIELD_MASKS_COUNT {
            builder.assert_zero(
                gate.clone() * field_masks[j + 1].clone() * (AB::Expr::ONE - field_mask.clone()),
            );
        }
    }
    builder.assert_zero(gate.clone() * (mask_sum - num_fields.clone()));

    let mut selected_mask = AB::Expr::ZERO;
    for j in 0..NUM_FIELDS {
        selected_mask = selected_mask + row_selectors[j].clone() * field_masks[j].clone();
    }
    builder.assert_zero(
        gate.clone()
            * (AB::Expr::ONE - row_selectors[NUM_FIELDS].clone())
            * (mask.clone() - selected_mask),
    );
    builder.assert_zero(gate.clone() * row_selectors[NUM_FIELDS].clone() * mask.clone());

    // 2. Unique flag must be binary
    builder.assert_zero(gate.clone() * unique.clone() * (unique.clone() - AB::Expr::ONE));

    // 3. Range-check bits must be binary (48 low + 48 high), gated by mask
    for b in 0..BV_LOW_BITS_COUNT {
        let bit = col(BV_LOW_BITS + b);
        builder
            .assert_zero(gate.clone() * mask.clone() * bit.clone() * (bit.clone() - AB::Expr::ONE));
    }
    for b in 0..BV_HIGH_BITS_COUNT {
        let bit = col(BV_HIGH_BITS + b);
        builder
            .assert_zero(gate.clone() * mask.clone() * bit.clone() * (bit.clone() - AB::Expr::ONE));
    }

    // 5. Exponent bits must be binary
    for b in 0..BV_EXP_BITS_COUNT {
        let bit = col(BV_EXP_BITS + b);
        builder.assert_zero(gate.clone() * bit.clone() * (bit.clone() - AB::Expr::ONE));
    }

    let field_val_this_row = col(BV_SQ); // sq[0] = the field value on this row
    let mut selected_field = AB::Expr::ZERO;
    for j in 0..NUM_FIELDS {
        selected_field = selected_field + row_selectors[j].clone() * col(BV_FIELDS + j);
        builder.assert_zero(gate.clone() * (col(BV_FIELDS + j) - col(GLOBAL_FIELDS + j)));
    }
    builder.assert_zero(
        gate.clone()
            * (AB::Expr::ONE - row_selectors[NUM_FIELDS].clone())
            * (field_val_this_row.clone() - selected_field),
    );

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
        gate.clone() * mask.clone() * (low_recomp - (field_val_this_row.clone() - min_val.clone())),
    );
    builder.assert_zero(
        gate.clone()
            * mask.clone()
            * (high_recomp - (max_val.clone() - field_val_this_row.clone())),
    );

    // Inactive fields must have sq[0] = 0
    builder.assert_zero(gate.clone() * (AB::Expr::ONE - mask.clone()) * field_val_this_row.clone());

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
        let inter = col(BV_ACC_INTER + k - 1); // stored: acc[k-1] * eb[k]
        // Verify intermediate: inter = prev_acc * ebk (degree 2, gated = 4)
        builder.assert_zero(
            gate.clone() * mask.clone() * (inter.clone() - prev_acc.clone() * ebk.clone()),
        );
        // Accumulator: acc[k] = prev_acc + inter * (sqk - 1) (degree 2, gated = 4)
        builder.assert_zero(
            gate.clone() * mask.clone() * (this_acc - prev_acc - inter * (sqk - AB::Expr::ONE)),
        );
    }

    // Power result = acc[7]
    builder.assert_zero(
        gate.clone() * mask.clone() * (col(BV_POWER) - col(BV_ACC + BV_ACC_COUNT - 1)),
    );

    // ------------------------------------------------
    // 9. Uniqueness constraints
    //
    // On each row i, for each active field j != i, prove diff != 0 by forcing
    // inv = 1 / diff:
    //
    //   diff * inv - 1 = 0
    //
    // The one-hot row selectors identify the self-position, which is gated out.
    //
    // Degree analysis: diff is degree 1 and diff*inv is degree 2.
    // With gating (gate * mask_i * mask_j * unique * not_self): total degree 6.
    // ------------------------------------------------
    for j in 0..NUM_FIELDS {
        let other_j = col(BV_FIELDS + j);
        let inv_j = col(BV_INV_DIFF + j);
        let diff_j = field_val_this_row.clone() - other_j;
        let not_self = AB::Expr::ONE - row_selectors[j].clone();
        let constraint = diff_j * inv_j - AB::Expr::ONE;
        builder.assert_zero(
            gate.clone()
                * mask.clone()
                * field_masks[j].clone()
                * unique.clone()
                * not_self
                * constraint,
        );
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
        let next_is_bounds: AB::Expr = next[BV_IS_BOUNDS].clone().into();
        let next_running_total = next_is_bounds.clone() * next[BV_BOUNDS_COST].clone().into()
            + (AB::Expr::ONE - next_is_bounds) * next[BV_COST_SUM].clone().into();
        let current_cost_sum = col(BV_COST_SUM);

        // Transition: next_cost_sum = current_cost_sum + next_mask * next_power
        // Only when both rows are BV (gate * next_is_bv)
        builder.when_transition().assert_zero(
            gate.clone()
                * next_is_bv.clone()
                * (next_running_total - current_cost_sum - next_mask * next_power),
        );
    }

    // ------------------------------------------------
    // 11. First BV row: cost_sum[0] = mask[0] * power[0]
    // We detect "first BV row" by checking that row_idx == 0 AND IS_BV == 1.
    // Constraint: gate * (1 - row_idx) * (cost_sum - mask * power) = 0
    // When row_idx = 0, this forces cost_sum = mask * power.
    // When row_idx > 0, (1 - row_idx) is non-zero but the transition handles it.
    // Anchor the BV accumulator at the first BV row. The transition constraints
    // handle BV-to-BV propagation; this entry constraint handles the row where
    // the trace crosses from a non-BV section into ballot validation.
    {
        let next_is_bv: AB::Expr = next[IS_BV].clone().into();
        let not_current_bv = AB::Expr::ONE - gate.clone();
        let next_mask: AB::Expr = next[BV_MASK].clone().into();
        let next_power: AB::Expr = next[BV_POWER].clone().into();
        let next_cost_sum: AB::Expr = next[BV_COST_SUM].clone().into();

        // When current row is NOT BV but next row IS BV (the BV entry point):
        // next_cost_sum must equal next_mask * next_power (fresh accumulation start).
        builder
            .when_transition()
            .assert_zero(not_current_bv * next_is_bv * (next_cost_sum - next_mask * next_power));
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
        builder.assert_zero(gate.clone() * (is_bounds.clone() - row_selectors[NUM_FIELDS].clone()));

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
            bounds_with_limit.clone() * (limit_recomp - (col(BV_LIMIT) - col(BV_BOUNDS_COST))),
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
            bounds_gate.clone() * (minsub_recomp - (col(BV_BOUNDS_COST) - col(BV_MIN_SUM))),
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
            bounds_gate.clone() * (gs_recomp - (num_fields.clone() - col(BV_GROUP_SIZE))),
        );

        // 12d. Limit selection: limit = cost_from_weight ? weight : max_value_sum
        // Constraint: limit = cost_from_weight * weight + (1 - cost_from_weight) * max_sum
        let cfw: AB::Expr = col(BV_COST_FROM_WEIGHT).into();
        builder.assert_zero(
            bounds_gate.clone()
                * (col(BV_LIMIT)
                    - cfw.clone() * col(BV_WEIGHT)
                    - (AB::Expr::ONE - cfw) * col(BV_MAX_SUM)),
        );

        // 12e. max_sum_is_zero correctness
        // If max_sum_is_zero = 1, then max_sum = 0.
        // If max_sum_is_zero = 0, then max_sum != 0 (proved via inverse).
        builder.assert_zero(bounds_gate.clone() * max_sum_is_zero.clone() * col(BV_MAX_SUM));
        // max_sum * inv - (1 - is_zero) = 0
        builder.assert_zero(
            bounds_gate.clone()
                * (col(BV_MAX_SUM) * col(BV_MAX_SUM_INV)
                    - (AB::Expr::ONE - max_sum_is_zero.clone())),
        );
        // max_sum_is_zero must be binary
        builder.assert_zero(
            bounds_gate.clone() * max_sum_is_zero.clone() * (max_sum_is_zero - AB::Expr::ONE),
        );
    }

    // ------------------------------------------------
    // 13. Config consistency across BV rows
    // All BV rows must have the same config values (num_fields, min, max, etc.)
    // Enforce via transition: config columns don't change between BV rows.
    // ------------------------------------------------
    {
        let next_is_bv: AB::Expr = next[IS_BV].clone().into();
        let next_row_selectors: Vec<AB::Expr> = (0..BV_ROW_SEL_COUNT)
            .map(|i| next[BV_ROW_SEL + i].clone().into())
            .collect();
        let config_cols = [
            BV_NUM_FIELDS,
            BV_MIN_VALUE,
            BV_MAX_VALUE,
            BV_UNIQUE,
            BV_COST_FROM_WEIGHT,
            BV_COST_EXP,
            BV_MAX_SUM,
            BV_MIN_SUM,
            BV_WEIGHT,
            BV_GROUP_SIZE,
        ];
        for &c in &config_cols {
            builder
                .when_transition()
                .assert_zero(gate.clone() * next_is_bv.clone() * (ncol(c) - col(c)));
        }

        // Field values must be consistent across BV rows
        for j in 0..NUM_FIELDS {
            builder.when_transition().assert_zero(
                gate.clone() * next_is_bv.clone() * (ncol(BV_FIELDS + j) - col(BV_FIELDS + j)),
            );
            builder.when_transition().assert_zero(
                gate.clone()
                    * next_is_bv.clone()
                    * (ncol(BV_FIELD_MASKS + j) - col(BV_FIELD_MASKS + j)),
            );
        }

        for i in 0..BV_ROW_SEL_COUNT {
            let expected_next = if i == 0 {
                AB::Expr::ZERO
            } else {
                row_selectors[i - 1].clone()
            };
            builder.when_transition().assert_zero(
                gate.clone() * next_is_bv.clone() * (next_row_selectors[i].clone() - expected_next),
            );
        }

        builder.when_transition().assert_zero(
            (AB::Expr::ONE - gate.clone())
                * next_is_bv.clone()
                * (next_row_selectors[0].clone() - AB::Expr::ONE),
        );
        for i in 1..BV_ROW_SEL_COUNT {
            builder.when_transition().assert_zero(
                (AB::Expr::ONE - gate.clone()) * next_is_bv.clone() * next_row_selectors[i].clone(),
            );
        }
    }
}
