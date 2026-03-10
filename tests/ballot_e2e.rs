//! End-to-end ballot proof test: prove and verify ElGamal encryption.

use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_matrix::Matrix;
use p3_uni_stark::{prove, verify};

use ecgfp5::curve::Point;
use ecgfp5::scalar::Scalar;

use davinci_stark::air::{
    BallotAir, NUM_FIELDS, PV_INPUTS_PREIMAGE, PV_VOTE_ID, SMALL_SCALAR_BITS,
};
use davinci_stark::columns::{
    BV_FIELDS, BV_ROW_INDEX, EC_BIND_ACTIVE, GLOBAL_FIELDS, GLOBAL_KS, IS_BV, IS_P2, P2_K_SEL,
    P2_PERM_ID, P2_ROUND, P2_VOTE_ID_PRE_SEL, P2_VOTE_ID_PRE_SEL_COUNT, PHASE, TRACE_WIDTH,
};
use davinci_stark::config::{make_prover_config, make_verifier_config};
use davinci_stark::trace::{BallotInputs, BallotMode, generate_full_ballot_trace};

fn base_ballot_inputs(fields: [Scalar; 8], mode: BallotMode, weight: u64) -> BallotInputs {
    let sk = Scalar([12345, 0, 0, 0, 0]);
    let pk = Point::mulgen(sk);

    BallotInputs {
        k: Scalar([42, 0, 0, 0, 0]),
        fields,
        pk,
        process_id: [
            Goldilocks::from_u64(1001),
            Goldilocks::ZERO,
            Goldilocks::ZERO,
            Goldilocks::ZERO,
        ],
        address: [
            Goldilocks::from_u64(0xDEADBEEF),
            Goldilocks::ZERO,
            Goldilocks::ZERO,
            Goldilocks::ZERO,
        ],
        weight: Goldilocks::from_u64(weight),
        packed_ballot_mode: mode.pack(),
    }
}

fn assert_invalid_ballot_rejected(inputs: BallotInputs, reason: &str) {
    let (trace, pv, _) = generate_full_ballot_trace(&inputs);
    let prover_config = make_prover_config();
    let verifier_config = make_verifier_config();
    let prove_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        prove(&prover_config, &BallotAir::new(), trace, &pv)
    }));

    match prove_result {
        Ok(proof) => {
            let result = verify(&verifier_config, &BallotAir::new(), &proof, &pv);
            assert!(
                result.is_err(),
                "{reason}: verifier accepted invalid ballot"
            );
        }
        Err(_) => {}
    }
}

fn assert_tampered_trace_rejected(
    trace: p3_matrix::dense::RowMajorMatrix<Goldilocks>,
    pv: Vec<Goldilocks>,
    reason: &str,
) {
    let prover_config = make_prover_config();
    let verifier_config = make_verifier_config();
    let prove_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        prove(&prover_config, &BallotAir::new(), trace, &pv)
    }));

    match prove_result {
        Ok(proof) => {
            let verify_result = verify(&verifier_config, &BallotAir::new(), &proof, &pv);
            assert!(
                verify_result.is_err(),
                "{reason}: verifier accepted tampered trace"
            );
        }
        Err(_) => {}
    }
}

fn replace_bv_rows(
    mut base: p3_matrix::dense::RowMajorMatrix<Goldilocks>,
    donor: &p3_matrix::dense::RowMajorMatrix<Goldilocks>,
) -> p3_matrix::dense::RowMajorMatrix<Goldilocks> {
    assert_eq!(base.height(), donor.height());
    assert_eq!(base.width(), donor.width());
    for row in 0..base.height() {
        let row_start = row * TRACE_WIDTH;
        if base.values[row_start + IS_BV] == Goldilocks::ONE {
            let donor_row = &donor.values[row_start..row_start + TRACE_WIDTH];
            base.values[row_start..row_start + TRACE_WIDTH].copy_from_slice(donor_row);
        }
    }
    base
}

fn replace_poseidon_permutations(
    mut base: p3_matrix::dense::RowMajorMatrix<Goldilocks>,
    donor: &p3_matrix::dense::RowMajorMatrix<Goldilocks>,
    perm_start: u64,
    perm_end: u64,
) -> p3_matrix::dense::RowMajorMatrix<Goldilocks> {
    assert_eq!(base.height(), donor.height());
    assert_eq!(base.width(), donor.width());
    for row in 0..base.height() {
        let row_start = row * TRACE_WIDTH;
        let perm_id = base.values[row_start + P2_PERM_ID].as_canonical_u64();
        let is_p2 = base.values[row_start + IS_P2] == Goldilocks::ONE;
        let is_gap_after_p2 =
            row > 0 && base.values[(row - 1) * TRACE_WIDTH + IS_P2] == Goldilocks::ONE;
        if (perm_start..perm_end).contains(&perm_id) && (is_p2 || is_gap_after_p2) {
            let base_globals = base.values[row_start + GLOBAL_KS..row_start + P2_K_SEL].to_vec();
            let donor_row = &donor.values[row_start..row_start + TRACE_WIDTH];
            base.values[row_start..row_start + TRACE_WIDTH].copy_from_slice(donor_row);
            base.values[row_start + GLOBAL_KS..row_start + P2_K_SEL].copy_from_slice(&base_globals);
        }
    }
    base
}

fn replace_ec_phases(
    mut base: p3_matrix::dense::RowMajorMatrix<Goldilocks>,
    donor: &p3_matrix::dense::RowMajorMatrix<Goldilocks>,
    phases: &[u64],
) -> p3_matrix::dense::RowMajorMatrix<Goldilocks> {
    assert_eq!(base.height(), donor.height());
    assert_eq!(base.width(), donor.width());
    for row in 0..base.height() {
        let row_start = row * TRACE_WIDTH;
        let phase = base.values[row_start + PHASE].as_canonical_u64();
        let is_ec = base.values[row_start + davinci_stark::columns::IS_EC] == Goldilocks::ONE;
        if is_ec && phases.contains(&phase) {
            let donor_row = &donor.values[row_start..row_start + TRACE_WIDTH];
            base.values[row_start..row_start + TRACE_WIDTH].copy_from_slice(donor_row);
        }
    }
    base
}

#[test]
fn test_public_values_must_match_trace_outputs() {
    let inputs = base_ballot_inputs(
        [
            Scalar([1, 0, 0, 0, 0]),
            Scalar([2, 0, 0, 0, 0]),
            Scalar([3, 0, 0, 0, 0]),
            Scalar([4, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
        ],
        BallotMode {
            num_fields: 4,
            group_size: 4,
            unique_values: 0,
            cost_from_weight: 0,
            cost_exponent: 1,
            max_value: 16,
            min_value: 0,
            max_value_sum: 100,
            min_value_sum: 0,
        },
        1,
    );

    let (trace, mut pv, outputs) = generate_full_ballot_trace(&inputs);
    pv[PV_VOTE_ID] = outputs.vote_id + Goldilocks::ONE;

    let prover_config = make_prover_config();
    let verifier_config = make_verifier_config();
    let prove_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        prove(&prover_config, &BallotAir::new(), trace, &pv)
    }));

    match prove_result {
        Ok(proof) => {
            let result = verify(&verifier_config, &BallotAir::new(), &proof, &pv);
            assert!(
                result.is_err(),
                "AIR must bind claimed public values to the trace outputs"
            );
        }
        Err(_) => {}
    }
}

#[test]
fn test_ec_phase_id_must_be_constrained() {
    let inputs = base_ballot_inputs(
        [Scalar([1, 0, 0, 0, 0]); NUM_FIELDS],
        BallotMode {
            num_fields: 8,
            group_size: 8,
            unique_values: 0,
            cost_from_weight: 0,
            cost_exponent: 1,
            max_value: 16,
            min_value: 0,
            max_value_sum: 200,
            min_value_sum: 0,
        },
        1,
    );

    let (mut trace, pv, _) = generate_full_ballot_trace(&inputs);
    let second_phase_first_row = SMALL_SCALAR_BITS;
    trace.values[second_phase_first_row * TRACE_WIDTH + PHASE] += Goldilocks::ONE;

    assert_tampered_trace_rejected(trace, pv, "EC phase id");
}

#[test]
fn test_ec_statement_binding_cannot_be_disabled() {
    let inputs = base_ballot_inputs(
        [Scalar([1, 0, 0, 0, 0]); NUM_FIELDS],
        BallotMode {
            num_fields: 8,
            group_size: 8,
            unique_values: 0,
            cost_from_weight: 0,
            cost_exponent: 1,
            max_value: 16,
            min_value: 0,
            max_value_sum: 200,
            min_value_sum: 0,
        },
        1,
    );

    let (mut trace, pv, _) = generate_full_ballot_trace(&inputs);
    for row in 0..trace.height() {
        let row_start = row * TRACE_WIDTH;
        if trace.values[row_start + davinci_stark::columns::IS_EC] == Goldilocks::ONE {
            trace.values[row_start + EC_BIND_ACTIVE] = Goldilocks::ZERO;
        }
    }

    assert_tampered_trace_rejected(trace, pv, "EC statement binding");
}

#[test]
fn test_bv_row_index_must_be_constrained() {
    let inputs = base_ballot_inputs(
        [
            Scalar([1, 0, 0, 0, 0]),
            Scalar([2, 0, 0, 0, 0]),
            Scalar([3, 0, 0, 0, 0]),
            Scalar([4, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
        ],
        BallotMode {
            num_fields: 4,
            group_size: 4,
            unique_values: 0,
            cost_from_weight: 0,
            cost_exponent: 1,
            max_value: 16,
            min_value: 0,
            max_value_sum: 100,
            min_value_sum: 0,
        },
        1,
    );

    let (mut trace, pv, _) = generate_full_ballot_trace(&inputs);
    let bv_row = (0..trace.height())
        .find(|&row| trace.values[row * TRACE_WIDTH + IS_BV] == Goldilocks::ONE)
        .expect("missing BV section");
    trace.values[bv_row * TRACE_WIDTH + BV_ROW_INDEX] += Goldilocks::ONE;

    assert_tampered_trace_rejected(trace, pv, "BV row index");
}

#[test]
fn test_bv_fields_array_must_bind_to_checked_rows() {
    let inputs = base_ballot_inputs(
        [
            Scalar([1, 0, 0, 0, 0]),
            Scalar([2, 0, 0, 0, 0]),
            Scalar([3, 0, 0, 0, 0]),
            Scalar([4, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
        ],
        BallotMode {
            num_fields: 4,
            group_size: 4,
            unique_values: 0,
            cost_from_weight: 0,
            cost_exponent: 1,
            max_value: 16,
            min_value: 0,
            max_value_sum: 100,
            min_value_sum: 0,
        },
        1,
    );

    let (mut trace, pv, _) = generate_full_ballot_trace(&inputs);
    for row in 0..trace.height() {
        if trace.values[row * TRACE_WIDTH + IS_BV] == Goldilocks::ONE {
            trace.values[row * TRACE_WIDTH + BV_FIELDS] += Goldilocks::ONE;
        }
    }

    assert_tampered_trace_rejected(trace, pv, "BV replicated fields array");
}

#[test]
fn test_derived_k_values_must_bind_poseidon_to_ec() {
    let inputs = base_ballot_inputs(
        [Scalar([1, 0, 0, 0, 0]); NUM_FIELDS],
        BallotMode {
            num_fields: 8,
            group_size: 8,
            unique_values: 0,
            cost_from_weight: 0,
            cost_exponent: 1,
            max_value: 16,
            min_value: 0,
            max_value_sum: 200,
            min_value_sum: 0,
        },
        1,
    );

    let (mut trace, pv, _) = generate_full_ballot_trace(&inputs);
    for row in 0..trace.height() {
        trace.values[row * TRACE_WIDTH + GLOBAL_KS] += Goldilocks::ONE;
    }

    assert_tampered_trace_rejected(trace, pv, "derived k binding");
}

#[test]
fn test_field_values_must_bind_bv_to_ec() {
    let inputs = base_ballot_inputs(
        [
            Scalar([1, 0, 0, 0, 0]),
            Scalar([2, 0, 0, 0, 0]),
            Scalar([3, 0, 0, 0, 0]),
            Scalar([4, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
        ],
        BallotMode {
            num_fields: 4,
            group_size: 4,
            unique_values: 0,
            cost_from_weight: 0,
            cost_exponent: 1,
            max_value: 16,
            min_value: 0,
            max_value_sum: 100,
            min_value_sum: 0,
        },
        1,
    );

    let (mut trace, pv, _) = generate_full_ballot_trace(&inputs);
    for row in 0..trace.height() {
        trace.values[row * TRACE_WIDTH + GLOBAL_FIELDS + 1] += Goldilocks::ONE;
    }

    assert_tampered_trace_rejected(trace, pv, "field binding");
}

#[test]
fn test_packed_ballot_mode_hash_must_bind_to_bv_rules() {
    let duplicate_fields = [
        Scalar([1, 0, 0, 0, 0]),
        Scalar([1, 0, 0, 0, 0]),
        Scalar([2, 0, 0, 0, 0]),
        Scalar([0, 0, 0, 0, 0]),
        Scalar([0, 0, 0, 0, 0]),
        Scalar([0, 0, 0, 0, 0]),
        Scalar([0, 0, 0, 0, 0]),
        Scalar([0, 0, 0, 0, 0]),
    ];

    let strict_inputs = base_ballot_inputs(
        duplicate_fields,
        BallotMode {
            num_fields: 3,
            group_size: 3,
            unique_values: 1,
            cost_from_weight: 0,
            cost_exponent: 1,
            max_value: 10,
            min_value: 0,
            max_value_sum: 10,
            min_value_sum: 0,
        },
        1,
    );
    let permissive_inputs = base_ballot_inputs(
        duplicate_fields,
        BallotMode {
            num_fields: 3,
            group_size: 3,
            unique_values: 0,
            cost_from_weight: 0,
            cost_exponent: 1,
            max_value: 10,
            min_value: 0,
            max_value_sum: 10,
            min_value_sum: 0,
        },
        1,
    );

    let (strict_trace, strict_pv, _) = generate_full_ballot_trace(&strict_inputs);
    let (permissive_trace, _permissive_pv, _) = generate_full_ballot_trace(&permissive_inputs);
    let mixed_trace = replace_bv_rows(strict_trace, &permissive_trace);

    assert_tampered_trace_rejected(
        mixed_trace,
        strict_pv,
        "packed_ballot_mode hash must bind to the BV rules",
    );
}

#[test]
fn test_packed_ballot_mode_must_decode_to_the_bv_rule_set() {
    let duplicate_fields = [
        Scalar([1, 0, 0, 0, 0]),
        Scalar([1, 0, 0, 0, 0]),
        Scalar([2, 0, 0, 0, 0]),
        Scalar([0, 0, 0, 0, 0]),
        Scalar([0, 0, 0, 0, 0]),
        Scalar([0, 0, 0, 0, 0]),
        Scalar([0, 0, 0, 0, 0]),
        Scalar([0, 0, 0, 0, 0]),
    ];

    let strict_inputs = base_ballot_inputs(
        duplicate_fields,
        BallotMode {
            num_fields: 3,
            group_size: 3,
            unique_values: 1,
            cost_from_weight: 0,
            cost_exponent: 1,
            max_value: 10,
            min_value: 0,
            max_value_sum: 10,
            min_value_sum: 0,
        },
        1,
    );
    let permissive_inputs = base_ballot_inputs(
        duplicate_fields,
        BallotMode {
            num_fields: 3,
            group_size: 3,
            unique_values: 0,
            cost_from_weight: 0,
            cost_exponent: 1,
            max_value: 10,
            min_value: 0,
            max_value_sum: 10,
            min_value_sum: 0,
        },
        1,
    );

    let (strict_trace, _strict_pv, _) = generate_full_ballot_trace(&strict_inputs);
    let (_permissive_trace, permissive_pv, _) = generate_full_ballot_trace(&permissive_inputs);

    assert_tampered_trace_rejected(
        strict_trace,
        permissive_pv,
        "packed_ballot_mode must decode to the BV rule set",
    );
}

#[test]
fn test_weight_hash_must_bind_to_bv_weight_rule() {
    let fields = [
        Scalar([3, 0, 0, 0, 0]),
        Scalar([3, 0, 0, 0, 0]),
        Scalar([0, 0, 0, 0, 0]),
        Scalar([0, 0, 0, 0, 0]),
        Scalar([0, 0, 0, 0, 0]),
        Scalar([0, 0, 0, 0, 0]),
        Scalar([0, 0, 0, 0, 0]),
        Scalar([0, 0, 0, 0, 0]),
    ];

    let strict_inputs = base_ballot_inputs(
        fields,
        BallotMode {
            num_fields: 2,
            group_size: 2,
            unique_values: 0,
            cost_from_weight: 1,
            cost_exponent: 1,
            max_value: 10,
            min_value: 0,
            max_value_sum: 999,
            min_value_sum: 0,
        },
        5,
    );
    let permissive_inputs = base_ballot_inputs(
        fields,
        BallotMode {
            num_fields: 2,
            group_size: 2,
            unique_values: 0,
            cost_from_weight: 1,
            cost_exponent: 1,
            max_value: 10,
            min_value: 0,
            max_value_sum: 999,
            min_value_sum: 0,
        },
        6,
    );

    let (strict_trace, strict_pv, _) = generate_full_ballot_trace(&strict_inputs);
    let (permissive_trace, _permissive_pv, _) = generate_full_ballot_trace(&permissive_inputs);
    let mixed_trace = replace_bv_rows(strict_trace, &permissive_trace);

    assert_tampered_trace_rejected(mixed_trace, strict_pv, "weight hash must bind to BV weight");
}

#[test]
fn test_inputs_hash_public_values_must_bind_to_the_public_preimage() {
    let strict_inputs = base_ballot_inputs(
        [
            Scalar([1, 0, 0, 0, 0]),
            Scalar([2, 0, 0, 0, 0]),
            Scalar([3, 0, 0, 0, 0]),
            Scalar([4, 0, 0, 0, 0]),
            Scalar([5, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
        ],
        BallotMode {
            num_fields: 5,
            group_size: 1,
            unique_values: 1,
            cost_from_weight: 0,
            cost_exponent: 2,
            max_value: 15,
            min_value: 0,
            max_value_sum: 1125,
            min_value_sum: 5,
        },
        1,
    );
    let altered_inputs = base_ballot_inputs(
        [
            Scalar([1, 0, 0, 0, 0]),
            Scalar([2, 0, 0, 0, 0]),
            Scalar([3, 0, 0, 0, 0]),
            Scalar([4, 0, 0, 0, 0]),
            Scalar([5, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
        ],
        BallotMode {
            num_fields: 5,
            group_size: 1,
            unique_values: 1,
            cost_from_weight: 0,
            cost_exponent: 2,
            max_value: 15,
            min_value: 0,
            max_value_sum: 1125,
            min_value_sum: 5,
        },
        9,
    );

    let (strict_trace, _strict_pv, _) = generate_full_ballot_trace(&strict_inputs);
    let (_altered_trace, altered_pv, _) = generate_full_ballot_trace(&altered_inputs);
    assert_tampered_trace_rejected(
        strict_trace,
        altered_pv,
        "inputs_hash public values must bind to the public preimage",
    );
}

#[test]
fn test_vote_id_public_value_must_bind_to_poseidon_section() {
    let inputs = base_ballot_inputs(
        [
            Scalar([1, 0, 0, 0, 0]),
            Scalar([2, 0, 0, 0, 0]),
            Scalar([3, 0, 0, 0, 0]),
            Scalar([4, 0, 0, 0, 0]),
            Scalar([5, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
        ],
        BallotMode {
            num_fields: 5,
            group_size: 1,
            unique_values: 1,
            cost_from_weight: 0,
            cost_exponent: 2,
            max_value: 15,
            min_value: 0,
            max_value_sum: 1125,
            min_value_sum: 5,
        },
        1,
    );
    let mut altered_inputs = base_ballot_inputs(
        [
            Scalar([1, 0, 0, 0, 0]),
            Scalar([2, 0, 0, 0, 0]),
            Scalar([3, 0, 0, 0, 0]),
            Scalar([4, 0, 0, 0, 0]),
            Scalar([5, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
        ],
        BallotMode {
            num_fields: 5,
            group_size: 1,
            unique_values: 1,
            cost_from_weight: 0,
            cost_exponent: 2,
            max_value: 15,
            min_value: 0,
            max_value_sum: 1125,
            min_value_sum: 5,
        },
        1,
    );
    altered_inputs.address[0] += Goldilocks::ONE;

    let (strict_trace, _strict_pv, _) = generate_full_ballot_trace(&inputs);
    let (_altered_trace, altered_pv, _) = generate_full_ballot_trace(&altered_inputs);
    assert_tampered_trace_rejected(
        strict_trace,
        altered_pv,
        "vote_id public value must bind to the vote-id Poseidon section",
    );
}

#[test]
fn test_vote_id_absorb_schedule_must_exist() {
    let inputs = base_ballot_inputs(
        [
            Scalar([1, 0, 0, 0, 0]),
            Scalar([2, 0, 0, 0, 0]),
            Scalar([3, 0, 0, 0, 0]),
            Scalar([4, 0, 0, 0, 0]),
            Scalar([5, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
        ],
        BallotMode {
            num_fields: 5,
            group_size: 1,
            unique_values: 1,
            cost_from_weight: 0,
            cost_exponent: 2,
            max_value: 15,
            min_value: 0,
            max_value_sum: 1125,
            min_value_sum: 5,
        },
        1,
    );

    let (mut trace, pv, _) = generate_full_ballot_trace(&inputs);
    for row in 0..(trace.height() - 1) {
        let next_row_start = (row + 1) * TRACE_WIDTH;
        if trace.values[next_row_start + davinci_stark::columns::IS_P2] == Goldilocks::ONE
            && trace.values[next_row_start + P2_ROUND] == Goldilocks::ZERO
        {
            let perm_id = trace.values[next_row_start + P2_PERM_ID].as_canonical_u64();
            if (8..12).contains(&perm_id) {
                let row_start = row * TRACE_WIDTH;
                for i in 0..P2_VOTE_ID_PRE_SEL_COUNT {
                    trace.values[row_start + P2_VOTE_ID_PRE_SEL + i] = Goldilocks::ZERO;
                }
            }
        }
    }

    assert_tampered_trace_rejected(trace, pv, "vote-id absorb schedule");
}

#[test]
fn test_master_k_must_bind_to_the_k_derivation_chain() {
    let inputs = base_ballot_inputs(
        [
            Scalar([1, 0, 0, 0, 0]),
            Scalar([2, 0, 0, 0, 0]),
            Scalar([3, 0, 0, 0, 0]),
            Scalar([4, 0, 0, 0, 0]),
            Scalar([5, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
        ],
        BallotMode {
            num_fields: 5,
            group_size: 1,
            unique_values: 1,
            cost_from_weight: 0,
            cost_exponent: 2,
            max_value: 15,
            min_value: 0,
            max_value_sum: 1125,
            min_value_sum: 5,
        },
        1,
    );
    let altered_inputs = BallotInputs {
        k: Scalar([77, 0, 0, 0, 0]),
        fields: inputs.fields,
        pk: inputs.pk,
        process_id: inputs.process_id,
        address: inputs.address,
        weight: inputs.weight,
        packed_ballot_mode: inputs.packed_ballot_mode,
    };

    let (strict_trace, strict_pv, _) = generate_full_ballot_trace(&inputs);
    let (altered_trace, _, _) = generate_full_ballot_trace(&altered_inputs);
    let mixed_trace = replace_poseidon_permutations(strict_trace, &altered_trace, 0, 8);
    assert_tampered_trace_rejected(
        mixed_trace,
        strict_pv,
        "master k must bind to the k-derivation Poseidon chain",
    );
}

#[test]
fn test_public_key_must_bind_to_ec_cipher_phases() {
    let inputs = base_ballot_inputs(
        [
            Scalar([1, 0, 0, 0, 0]),
            Scalar([2, 0, 0, 0, 0]),
            Scalar([3, 0, 0, 0, 0]),
            Scalar([4, 0, 0, 0, 0]),
            Scalar([5, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
        ],
        BallotMode {
            num_fields: 5,
            group_size: 1,
            unique_values: 1,
            cost_from_weight: 0,
            cost_exponent: 2,
            max_value: 15,
            min_value: 0,
            max_value_sum: 1125,
            min_value_sum: 5,
        },
        1,
    );
    let mut altered_inputs = base_ballot_inputs(
        [
            Scalar([1, 0, 0, 0, 0]),
            Scalar([2, 0, 0, 0, 0]),
            Scalar([3, 0, 0, 0, 0]),
            Scalar([4, 0, 0, 0, 0]),
            Scalar([5, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
        ],
        BallotMode {
            num_fields: 5,
            group_size: 1,
            unique_values: 1,
            cost_from_weight: 0,
            cost_exponent: 2,
            max_value: 15,
            min_value: 0,
            max_value_sum: 1125,
            min_value_sum: 5,
        },
        1,
    );
    let other_sk = Scalar([54321, 0, 0, 0, 0]);
    altered_inputs.pk = Point::mulgen(other_sk);

    let (strict_trace, strict_pv, _) = generate_full_ballot_trace(&inputs);
    let (altered_trace, _, _) = generate_full_ballot_trace(&altered_inputs);

    let pk_phases: Vec<u64> = (0..NUM_FIELDS).map(|i| (3 * i + 1) as u64).collect();
    let mixed_trace = replace_ec_phases(strict_trace, &altered_trace, &pk_phases);
    assert_tampered_trace_rejected(
        mixed_trace,
        strict_pv,
        "public key must bind to the EC cipher phases",
    );
}

#[test]
fn test_ciphertexts_must_bind_to_ec_phase_outputs() {
    let inputs = base_ballot_inputs(
        [
            Scalar([1, 0, 0, 0, 0]),
            Scalar([2, 0, 0, 0, 0]),
            Scalar([3, 0, 0, 0, 0]),
            Scalar([4, 0, 0, 0, 0]),
            Scalar([5, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
        ],
        BallotMode {
            num_fields: 5,
            group_size: 1,
            unique_values: 1,
            cost_from_weight: 0,
            cost_exponent: 2,
            max_value: 15,
            min_value: 0,
            max_value_sum: 1125,
            min_value_sum: 5,
        },
        1,
    );
    let mut altered_inputs = base_ballot_inputs(
        [
            Scalar([1, 0, 0, 0, 0]),
            Scalar([2, 0, 0, 0, 0]),
            Scalar([3, 0, 0, 0, 0]),
            Scalar([4, 0, 0, 0, 0]),
            Scalar([5, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
        ],
        BallotMode {
            num_fields: 5,
            group_size: 1,
            unique_values: 1,
            cost_from_weight: 0,
            cost_exponent: 2,
            max_value: 15,
            min_value: 0,
            max_value_sum: 1125,
            min_value_sum: 5,
        },
        1,
    );
    let other_sk = Scalar([54321, 0, 0, 0, 0]);
    altered_inputs.pk = Point::mulgen(other_sk);

    let (strict_trace, _strict_pv, _) = generate_full_ballot_trace(&inputs);
    let (_altered_trace, altered_pv, _) = generate_full_ballot_trace(&altered_inputs);
    assert_tampered_trace_rejected(
        strict_trace,
        altered_pv,
        "ciphertexts hashed into inputs_hash must bind to the EC phase outputs",
    );
}

#[test]
fn test_ballot_wrong_vote_fails() {
    // If we generate a proof but tamper with the public vote_id,
    // verification should fail.
    use davinci_stark::trace::{BallotInputs, generate_full_ballot_trace};
    let sk = Scalar([12345, 0, 0, 0, 0]);
    let pk = Point::mulgen(sk);

    let inputs = BallotInputs {
        k: Scalar([42, 0, 0, 0, 0]),
        fields: [Scalar([1, 0, 0, 0, 0]); NUM_FIELDS],
        pk,
        process_id: [
            Goldilocks::from_u64(1001),
            Goldilocks::ZERO,
            Goldilocks::ZERO,
            Goldilocks::ZERO,
        ],
        address: [
            Goldilocks::from_u64(0xDEADBEEF),
            Goldilocks::ZERO,
            Goldilocks::ZERO,
            Goldilocks::ZERO,
        ],
        weight: Goldilocks::from_u64(1),
        packed_ballot_mode: {
            use davinci_stark::trace::BallotMode;
            BallotMode {
                num_fields: 8,
                group_size: 8,
                unique_values: 0,
                cost_from_weight: 0,
                cost_exponent: 1,
                max_value: 16,
                min_value: 0,
                max_value_sum: 200,
                min_value_sum: 0,
            }
            .pack()
        },
    };

    let (trace, correct_pv, _) = generate_full_ballot_trace(&inputs);

    // Tamper with vote_id in public values
    let mut wrong_pv = correct_pv.clone();
    wrong_pv[PV_VOTE_ID] = Goldilocks::from_u64(999999);

    let prover_config = make_prover_config();
    let verifier_config = make_verifier_config();
    let proof = prove(&prover_config, &BallotAir::new(), trace, &correct_pv);

    let result = verify(&verifier_config, &BallotAir::new(), &proof, &wrong_pv);

    assert!(
        result.is_err(),
        "Verification should fail with wrong public values"
    );
    println!("✅ Wrong vote correctly rejected!");
}

#[test]
fn test_full_8field_ballot_proof() {
    use davinci_stark::air::NUM_FIELDS;
    use davinci_stark::trace::{BallotInputs, generate_full_ballot_trace};

    let sk = Scalar([12345, 0, 0, 0, 0]);
    let pk = Point::mulgen(sk);

    let inputs = BallotInputs {
        k: Scalar([42, 0, 0, 0, 0]),
        fields: [
            Scalar([1, 0, 0, 0, 0]),
            Scalar([2, 0, 0, 0, 0]),
            Scalar([3, 0, 0, 0, 0]),
            Scalar([4, 0, 0, 0, 0]),
            Scalar([5, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]), // zero vote
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
        ],
        pk,
        process_id: [
            Goldilocks::from_u64(1001),
            Goldilocks::from_u64(0),
            Goldilocks::from_u64(0),
            Goldilocks::from_u64(0),
        ],
        address: [
            Goldilocks::from_u64(0xDEADBEEF),
            Goldilocks::from_u64(0),
            Goldilocks::from_u64(0),
            Goldilocks::from_u64(0),
        ],
        weight: Goldilocks::from_u64(1),
        packed_ballot_mode: {
            use davinci_stark::trace::BallotMode;
            BallotMode {
                num_fields: 5,
                group_size: 5,
                unique_values: 0,
                cost_from_weight: 0,
                cost_exponent: 2,
                max_value: 16,
                min_value: 0,
                max_value_sum: 100,
                min_value_sum: 0,
            }
            .pack()
        },
    };

    println!("Generating 8-field ballot trace...");
    let start = std::time::Instant::now();
    let (trace, pv, outputs) = generate_full_ballot_trace(&inputs);
    let trace_time = start.elapsed();
    println!(
        "Trace: {} rows × {} cols in {:?}",
        trace.height(),
        trace.width(),
        trace_time
    );
    println!("Vote ID: {:?}", outputs.vote_id);
    println!("Inputs hash: {:?}", outputs.inputs_hash);

    // Verify k-chain produces different keys
    for i in 0..NUM_FIELDS {
        for j in (i + 1)..NUM_FIELDS {
            assert_ne!(
                outputs.k_derived[i], outputs.k_derived[j],
                "k-derived values must be unique"
            );
        }
    }

    // Verify C1 and C2 are computed (check non-zero via u64 conversion)
    for i in 0..5 {
        let c1_enc = outputs.c1[i].encode();
        let nonzero = c1_enc.0.iter().any(|x| x.to_u64() != 0);
        assert!(nonzero, "C1[{}] should not be neutral", i);
    }

    let prover_config = make_prover_config();
    let verifier_config = make_verifier_config();
    println!("Proving 8-field ballot...");
    let start = std::time::Instant::now();
    let proof = prove(&prover_config, &BallotAir::new(), trace, &pv);
    let prove_time = start.elapsed();
    println!("Proof generated in {:?}", prove_time);

    println!("Verifying...");
    let start = std::time::Instant::now();
    verify(&verifier_config, &BallotAir::new(), &proof, &pv)
        .expect("8-field ballot verification failed");
    let verify_time = start.elapsed();
    println!("Verified in {:?}", verify_time);

    println!("\n✅ Full 8-field ballot proof E2E test passed!");
    println!("  Trace gen: {:?}", trace_time);
    println!("  Prove:     {:?}", prove_time);
    println!("  Verify:    {:?}", verify_time);
}

/// Test with the exact webapp default config (group_size=1, max_sum=1125, min_sum=5).
#[test]
fn test_webapp_defaults() {
    use davinci_stark::trace::{BallotInputs, BallotMode, generate_full_ballot_trace};

    let sk = Scalar([12345, 0, 0, 0, 0]);
    let pk = Point::mulgen(sk);

    let inputs = BallotInputs {
        k: Scalar([42, 0, 0, 0, 0]),
        fields: [
            Scalar([1, 0, 0, 0, 0]),
            Scalar([2, 0, 0, 0, 0]),
            Scalar([3, 0, 0, 0, 0]),
            Scalar([4, 0, 0, 0, 0]),
            Scalar([5, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
        ],
        pk,
        process_id: [
            Goldilocks::from_u64(1001),
            Goldilocks::from_u64(0),
            Goldilocks::from_u64(0),
            Goldilocks::from_u64(0),
        ],
        address: [
            Goldilocks::from_u64(3735928559),
            Goldilocks::from_u64(0),
            Goldilocks::from_u64(0),
            Goldilocks::from_u64(0),
        ],
        weight: Goldilocks::from_u64(1),
        packed_ballot_mode: BallotMode {
            num_fields: 5,
            group_size: 1,
            unique_values: 0,
            cost_from_weight: 0,
            cost_exponent: 2,
            max_value: 16,
            min_value: 0,
            max_value_sum: 1125,
            min_value_sum: 5,
        }
        .pack(),
    };

    println!("Generating webapp-defaults ballot trace...");
    let (trace, pv, _) = generate_full_ballot_trace(&inputs);

    let prover_config = make_prover_config();
    let verifier_config = make_verifier_config();
    println!("Proving...");
    let proof = prove(&prover_config, &BallotAir::new(), trace, &pv);

    println!("Verifying...");
    verify(&verifier_config, &BallotAir::new(), &proof, &pv)
        .expect("Webapp-defaults verification failed");
    println!("✅ Webapp-defaults test passed!");
}

/// Test that an out-of-range ballot (field values > max_value) is rejected by the verifier.
///
/// This confirms that the BV range-check constraints work: the prover CAN produce bytes
/// from an invalid trace (STARKs don't prevent this), but verify() must return Err.
#[test]
fn test_out_of_range_ballot_rejected() {
    let inputs = base_ballot_inputs(
        [
            Scalar([1, 0, 0, 0, 0]),
            Scalar([2, 0, 0, 0, 0]),
            Scalar([3, 0, 0, 0, 0]), // INVALID: > max_value=2
            Scalar([4, 0, 0, 0, 0]), // INVALID
            Scalar([5, 0, 0, 0, 0]), // INVALID
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
        ],
        BallotMode {
            num_fields: 5,
            group_size: 1,
            unique_values: 0,
            cost_from_weight: 0,
            cost_exponent: 2,
            max_value: 2,
            min_value: 0,
            max_value_sum: 0,
            min_value_sum: 0,
        },
        1,
    );
    assert_invalid_ballot_rejected(inputs, "out-of-range field values");
}

#[test]
fn test_duplicate_values_rejected_when_uniqueness_enabled() {
    let inputs = base_ballot_inputs(
        [
            Scalar([1, 0, 0, 0, 0]),
            Scalar([1, 0, 0, 0, 0]), // duplicate active value
            Scalar([2, 0, 0, 0, 0]),
            Scalar([3, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
        ],
        BallotMode {
            num_fields: 4,
            group_size: 1,
            unique_values: 1,
            cost_from_weight: 0,
            cost_exponent: 1,
            max_value: 10,
            min_value: 0,
            max_value_sum: 20,
            min_value_sum: 0,
        },
        1,
    );

    assert_invalid_ballot_rejected(inputs, "duplicate active values with uniqueness enabled");
}

#[test]
fn test_cost_sum_above_max_rejected() {
    let inputs = base_ballot_inputs(
        [
            Scalar([5, 0, 0, 0, 0]),
            Scalar([5, 0, 0, 0, 0]),
            Scalar([5, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
        ],
        BallotMode {
            num_fields: 3,
            group_size: 1,
            unique_values: 0,
            cost_from_weight: 0,
            cost_exponent: 2,
            max_value: 10,
            min_value: 0,
            max_value_sum: 50, // 5^2 + 5^2 + 5^2 = 75
            min_value_sum: 0,
        },
        1,
    );

    assert_invalid_ballot_rejected(inputs, "cost sum above max_value_sum");
}

#[test]
fn test_cost_sum_below_min_rejected() {
    let inputs = base_ballot_inputs(
        [
            Scalar([1, 0, 0, 0, 0]),
            Scalar([1, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
        ],
        BallotMode {
            num_fields: 2,
            group_size: 1,
            unique_values: 0,
            cost_from_weight: 0,
            cost_exponent: 1,
            max_value: 10,
            min_value: 0,
            max_value_sum: 100,
            min_value_sum: 5, // total cost is 2
        },
        1,
    );

    assert_invalid_ballot_rejected(inputs, "cost sum below min_value_sum");
}

#[test]
fn test_cost_from_weight_uses_weight_limit() {
    let inputs = base_ballot_inputs(
        [
            Scalar([3, 0, 0, 0, 0]),
            Scalar([3, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
        ],
        BallotMode {
            num_fields: 2,
            group_size: 1,
            unique_values: 0,
            cost_from_weight: 1,
            cost_exponent: 1,
            max_value: 10,
            min_value: 0,
            max_value_sum: 999, // should be ignored when cost_from_weight=1
            min_value_sum: 0,
        },
        5, // total cost is 6, should fail
    );

    assert_invalid_ballot_rejected(inputs, "cost_from_weight upper bound");
}

#[test]
fn test_group_size_cannot_exceed_num_fields() {
    let inputs = base_ballot_inputs(
        [
            Scalar([1, 0, 0, 0, 0]),
            Scalar([2, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
        ],
        BallotMode {
            num_fields: 2,
            group_size: 3, // invalid
            unique_values: 0,
            cost_from_weight: 0,
            cost_exponent: 1,
            max_value: 10,
            min_value: 0,
            max_value_sum: 100,
            min_value_sum: 0,
        },
        1,
    );

    assert_invalid_ballot_rejected(inputs, "group_size greater than num_fields");
}

#[test]
fn test_circom_ballot_checker_simple_valid_unique_ballot() {
    let inputs = base_ballot_inputs(
        [
            Scalar([3, 0, 0, 0, 0]),
            Scalar([2, 0, 0, 0, 0]),
            Scalar([5, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
        ],
        BallotMode {
            num_fields: 3,
            group_size: 3,
            unique_values: 1,
            cost_from_weight: 0,
            cost_exponent: 1,
            max_value: 5,
            min_value: 0,
            max_value_sum: 15,
            min_value_sum: 0,
        },
        0,
    );

    let (proof, _) = davinci_stark::prove_full_ballot(&inputs);
    davinci_stark::verify_ballot(&proof).expect("simple valid unique ballot should verify");
}

#[test]
fn test_circom_ballot_checker_zero_max_sum_disables_upper_bound() {
    let inputs = base_ballot_inputs(
        [
            Scalar([50, 0, 0, 0, 0]),
            Scalar([49, 0, 0, 0, 0]),
            Scalar([48, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
        ],
        BallotMode {
            num_fields: 3,
            group_size: 3,
            unique_values: 0,
            cost_from_weight: 0,
            cost_exponent: 1,
            max_value: 50,
            min_value: 0,
            max_value_sum: 0,
            min_value_sum: 0,
        },
        0,
    );

    let (proof, _) = davinci_stark::prove_full_ballot(&inputs);
    davinci_stark::verify_ballot(&proof)
        .expect("max_value_sum = 0 should disable the upper bound, matching circom");
}

#[test]
fn test_circom_ballot_checker_duplicates_allowed_when_uniqueness_disabled() {
    let inputs = base_ballot_inputs(
        [
            Scalar([5, 0, 0, 0, 0]),
            Scalar([5, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
        ],
        BallotMode {
            num_fields: 3,
            group_size: 3,
            unique_values: 0,
            cost_from_weight: 0,
            cost_exponent: 1,
            max_value: 5,
            min_value: 0,
            max_value_sum: 15,
            min_value_sum: 0,
        },
        0,
    );

    let (proof, _) = davinci_stark::prove_full_ballot(&inputs);
    davinci_stark::verify_ballot(&proof)
        .expect("duplicates should be allowed when uniqueness is disabled");
}

#[test]
fn test_circom_ballot_checker_approval_exact_sum_valid() {
    let inputs = base_ballot_inputs(
        [
            Scalar([1, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([1, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([1, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
        ],
        BallotMode {
            num_fields: 6,
            group_size: 6,
            unique_values: 0,
            cost_from_weight: 0,
            cost_exponent: 1,
            max_value: 1,
            min_value: 0,
            max_value_sum: 3,
            min_value_sum: 3,
        },
        0,
    );

    let (proof, _) = davinci_stark::prove_full_ballot(&inputs);
    davinci_stark::verify_ballot(&proof)
        .expect("approval ballot with exact required sum should verify");
}

#[test]
fn test_circom_ballot_checker_ranked_choice_valid() {
    let inputs = base_ballot_inputs(
        [
            Scalar([1, 0, 0, 0, 0]),
            Scalar([2, 0, 0, 0, 0]),
            Scalar([3, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
        ],
        BallotMode {
            num_fields: 3,
            group_size: 3,
            unique_values: 1,
            cost_from_weight: 0,
            cost_exponent: 1,
            max_value: 3,
            min_value: 1,
            max_value_sum: 6,
            min_value_sum: 6,
        },
        0,
    );

    let (proof, _) = davinci_stark::prove_full_ballot(&inputs);
    davinci_stark::verify_ballot(&proof)
        .expect("ranked-choice ballot with unique ranks should verify");
}

#[test]
fn test_circom_ballot_checker_approval_overflow_invalid() {
    let inputs = base_ballot_inputs(
        [
            Scalar([1, 0, 0, 0, 0]),
            Scalar([1, 0, 0, 0, 0]),
            Scalar([1, 0, 0, 0, 0]),
            Scalar([1, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
        ],
        BallotMode {
            num_fields: 6,
            group_size: 6,
            unique_values: 0,
            cost_from_weight: 0,
            cost_exponent: 1,
            max_value: 1,
            min_value: 0,
            max_value_sum: 3,
            min_value_sum: 3,
        },
        0,
    );

    assert_invalid_ballot_rejected(inputs, "approval ballot exceeding exact sum should fail");
}

#[test]
fn test_circom_ballot_checker_ranked_choice_duplicate_invalid() {
    let inputs = base_ballot_inputs(
        [
            Scalar([1, 0, 0, 0, 0]),
            Scalar([1, 0, 0, 0, 0]),
            Scalar([2, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
        ],
        BallotMode {
            num_fields: 3,
            group_size: 3,
            unique_values: 1,
            cost_from_weight: 0,
            cost_exponent: 1,
            max_value: 3,
            min_value: 1,
            max_value_sum: 6,
            min_value_sum: 6,
        },
        0,
    );

    assert_invalid_ballot_rejected(inputs, "ranked-choice duplicate rank should fail");
}

#[test]
fn test_circom_ballot_checker_all_zero_with_positive_min_cost_invalid() {
    let inputs = base_ballot_inputs(
        [Scalar([0, 0, 0, 0, 0]); NUM_FIELDS],
        BallotMode {
            num_fields: 3,
            group_size: 3,
            unique_values: 0,
            cost_from_weight: 0,
            cost_exponent: 1,
            max_value: 5,
            min_value: 0,
            max_value_sum: 10,
            min_value_sum: 1,
        },
        0,
    );

    assert_invalid_ballot_rejected(inputs, "all-zero ballot with positive min total cost should fail");
}

#[test]
fn test_circom_style_full_ballot_proof() {
    let inputs = base_ballot_inputs(
        [
            Scalar([1, 0, 0, 0, 0]),
            Scalar([2, 0, 0, 0, 0]),
            Scalar([3, 0, 0, 0, 0]),
            Scalar([4, 0, 0, 0, 0]),
            Scalar([5, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
        ],
        BallotMode {
            num_fields: 5,
            group_size: 1,
            unique_values: 1,
            cost_from_weight: 0,
            cost_exponent: 2,
            max_value: 16,
            min_value: 0,
            max_value_sum: 1125,
            min_value_sum: 5,
        },
        1,
    );

    let (proof, outputs) = davinci_stark::prove_full_ballot(&inputs);
    davinci_stark::verify_ballot(&proof).expect("circom-style full ballot proof should verify");

    assert_eq!(proof.public_values[davinci_stark::air::PV_VOTE_ID], outputs.vote_id);
    assert_eq!(
        &proof.public_values[davinci_stark::air::PV_INPUTS_HASH
            ..davinci_stark::air::PV_INPUTS_HASH + 4],
        &outputs.inputs_hash
    );
    assert_eq!(
        &proof.public_values[davinci_stark::air::PV_ADDRESS
            ..davinci_stark::air::PV_ADDRESS + 4],
        &inputs.address
    );
}

#[test]
fn test_inputs_hash_must_match_the_public_preimage() {
    let inputs = base_ballot_inputs(
        [
            Scalar([1, 0, 0, 0, 0]),
            Scalar([2, 0, 0, 0, 0]),
            Scalar([3, 0, 0, 0, 0]),
            Scalar([4, 0, 0, 0, 0]),
            Scalar([5, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
        ],
        BallotMode {
            num_fields: 5,
            group_size: 1,
            unique_values: 1,
            cost_from_weight: 0,
            cost_exponent: 2,
            max_value: 16,
            min_value: 0,
            max_value_sum: 1125,
            min_value_sum: 5,
        },
        1,
    );

    let (mut proof, _) = davinci_stark::prove_full_ballot(&inputs);
    proof.public_values[PV_INPUTS_PREIMAGE + 33] =
        proof.public_values[PV_INPUTS_PREIMAGE + 33] + Goldilocks::ONE;

    assert!(
        davinci_stark::verify_ballot(&proof).is_err(),
        "verifier must reject proofs whose public inputs-hash preimage is tampered",
    );
}
