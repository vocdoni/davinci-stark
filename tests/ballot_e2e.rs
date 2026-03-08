//! End-to-end ballot proof test: prove and verify ElGamal encryption.

use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_matrix::Matrix;
use p3_uni_stark::{prove, verify};

use ecgfp5::curve::Point;
use ecgfp5::scalar::Scalar;

use davinci_stark::air::{BallotAir, NUM_FIELDS, PV_VOTE_ID, SMALL_SCALAR_BITS};
use davinci_stark::columns::{
    BV_FIELDS, BV_ROW_INDEX, GLOBAL_FIELDS, GLOBAL_KS, IS_BV, PHASE, TRACE_WIDTH,
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
