//! End-to-end ballot proof test: prove and verify ElGamal encryption.

use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_matrix::Matrix;
use p3_miden_prover::{prove, verify};

use ecgfp5::curve::Point;
use ecgfp5::scalar::Scalar;

use davinci_stark::air::{BallotAir, PV_VOTE_ID};
use davinci_stark::config::{make_config, Val};
use davinci_stark::trace::generate_ballot_trace;

#[test]
fn test_full_ballot_proof() {
    // ElGamal parameters:
    // sk = 12345 (private key scalar)
    // PK = sk * G (public key)
    // k = 42 (encryption randomness)
    // field_val = 1 (vote value)
    //
    // C1 = k * G
    // C2 = field_val * G + k * PK

    let sk = Scalar([12345, 0, 0, 0, 0]);
    let k = Scalar([42, 0, 0, 0, 0]);
    let field_val = Scalar([1, 0, 0, 0, 0]);

    // Compute PK = sk * G
    let pk = Point::mulgen(sk);
    println!("PK computed. Encoded: {:?}", pk.encode());

    println!("Generating ballot trace...");
    let start = std::time::Instant::now();
    let (trace, pv) = generate_ballot_trace(&k, &field_val, &pk);
    let trace_time = start.elapsed();
    println!("Trace generated in {:?}: {} rows × {} cols", trace_time, trace.height(), trace.width());
    println!("Public values: {} elements", pv.len());

    let config = make_config();
    let var_len_pis: Vec<&[&[Val]]> = vec![];

    println!("Proving...");
    let start = std::time::Instant::now();
    let proof = prove(&config, &BallotAir::new(), &trace, &pv);
    let prove_time = start.elapsed();
    println!("Proof generated in {:?}", prove_time);

    println!("Verifying...");
    let start = std::time::Instant::now();
    verify(&config, &BallotAir::new(), &proof, &pv, &var_len_pis)
        .expect("verification failed");
    let verify_time = start.elapsed();
    println!("Verified in {:?}", verify_time);

    println!("\n✅ Full ballot proof E2E test passed!");
    println!("  Trace gen: {:?}", trace_time);
    println!("  Prove:     {:?}", prove_time);
    println!("  Verify:    {:?}", verify_time);
}

#[test]
fn test_ballot_wrong_vote_fails() {
    // If we generate a proof but tamper with the public vote_id,
    // verification should fail.
    use davinci_stark::trace::{generate_full_ballot_trace, BallotInputs};
    use davinci_stark::air::NUM_FIELDS;

    let sk = Scalar([12345, 0, 0, 0, 0]);
    let pk = Point::mulgen(sk);

    let inputs = BallotInputs {
        k: Scalar([42, 0, 0, 0, 0]),
        fields: [Scalar([1, 0, 0, 0, 0]); NUM_FIELDS],
        pk,
        process_id: [Goldilocks::from_u64(1001), Goldilocks::ZERO, Goldilocks::ZERO, Goldilocks::ZERO],
        address: [Goldilocks::from_u64(0xDEADBEEF), Goldilocks::ZERO, Goldilocks::ZERO, Goldilocks::ZERO],
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
            }.pack()
        },
    };

    let (trace, correct_pv, _) = generate_full_ballot_trace(&inputs);

    // Tamper with vote_id in public values
    let mut wrong_pv = correct_pv.clone();
    wrong_pv[PV_VOTE_ID] = Goldilocks::from_u64(999999);

    let config = make_config();
    let proof = prove(&config, &BallotAir::new(), &trace, &correct_pv);

    let var_len_pis: Vec<&[&[Val]]> = vec![];
    let result = verify(&config, &BallotAir::new(), &proof, &wrong_pv, &var_len_pis);

    assert!(result.is_err(), "Verification should fail with wrong public values");
    println!("✅ Wrong vote correctly rejected!");
}

#[test]
fn test_full_8field_ballot_proof() {
    use davinci_stark::trace::{generate_full_ballot_trace, BallotInputs};
    use davinci_stark::air::NUM_FIELDS;

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
            }.pack()
        },
    };

    println!("Generating 8-field ballot trace...");
    let start = std::time::Instant::now();
    let (trace, pv, outputs) = generate_full_ballot_trace(&inputs);
    let trace_time = start.elapsed();
    println!("Trace: {} rows × {} cols in {:?}", trace.height(), trace.width(), trace_time);
    println!("Vote ID: {:?}", outputs.vote_id);
    println!("Inputs hash: {:?}", outputs.inputs_hash);

    // Verify k-chain produces different keys
    for i in 0..NUM_FIELDS {
        for j in (i+1)..NUM_FIELDS {
            assert_ne!(outputs.k_derived[i], outputs.k_derived[j],
                "k-derived values must be unique");
        }
    }

    // Verify C1 and C2 are computed (check non-zero via u64 conversion)
    for i in 0..5 {
        let c1_enc = outputs.c1[i].encode();
        let nonzero = c1_enc.0.iter().any(|x| x.to_u64() != 0);
        assert!(nonzero, "C1[{}] should not be neutral", i);
    }

    let config = make_config();
    let var_len_pis: Vec<&[&[Val]]> = vec![];

    println!("Proving 8-field ballot...");
    let start = std::time::Instant::now();
    let proof = prove(&config, &BallotAir::new(), &trace, &pv);
    let prove_time = start.elapsed();
    println!("Proof generated in {:?}", prove_time);

    println!("Verifying...");
    let start = std::time::Instant::now();
    verify(&config, &BallotAir::new(), &proof, &pv, &var_len_pis)
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
    use davinci_stark::trace::{generate_full_ballot_trace, BallotInputs, BallotMode};
    use davinci_stark::air::NUM_FIELDS;

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
        }.pack(),
    };

    println!("Generating webapp-defaults ballot trace...");
    let (trace, pv, _) = generate_full_ballot_trace(&inputs);

    let config = make_config();
    let var_len_pis: Vec<&[&[Val]]> = vec![];

    println!("Proving...");
    let proof = prove(&config, &BallotAir::new(), &trace, &pv);

    println!("Verifying...");
    verify(&config, &BallotAir::new(), &proof, &pv, &var_len_pis)
        .expect("Webapp-defaults verification failed");
    println!("✅ Webapp-defaults test passed!");
}

/// Test that an out-of-range ballot (field values > max_value) is rejected by the verifier.
///
/// This confirms that the BV range-check constraints work: the prover CAN produce bytes
/// from an invalid trace (STARKs don't prevent this), but verify() must return Err.
#[test]
fn test_out_of_range_ballot_rejected() {
    use davinci_stark::trace::{generate_full_ballot_trace, BallotInputs, BallotMode};
    use davinci_stark::air::NUM_FIELDS;

    let sk = Scalar([12345, 0, 0, 0, 0]);
    let pk = Point::mulgen(sk);

    let inputs = BallotInputs {
        k: Scalar([42, 0, 0, 0, 0]),
        fields: [
            Scalar([1, 0, 0, 0, 0]),
            Scalar([2, 0, 0, 0, 0]),
            Scalar([3, 0, 0, 0, 0]), // INVALID: > max_value=2
            Scalar([4, 0, 0, 0, 0]), // INVALID
            Scalar([5, 0, 0, 0, 0]), // INVALID
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
        ],
        pk,
        process_id: [Goldilocks::from_u64(1001), Goldilocks::ZERO, Goldilocks::ZERO, Goldilocks::ZERO],
        address: [Goldilocks::from_u64(0xDEADBEEF), Goldilocks::ZERO, Goldilocks::ZERO, Goldilocks::ZERO],
        weight: Goldilocks::from_u64(1),
        packed_ballot_mode: BallotMode {
            num_fields: 5,
            group_size: 1,
            unique_values: 0,
            cost_from_weight: 0,
            cost_exponent: 2,
            max_value: 2,    // Only 0, 1, 2 are valid choices
            min_value: 0,
            max_value_sum: 0,
            min_value_sum: 0,
        }.pack(),
    };

    let (trace, pv, _) = generate_full_ballot_trace(&inputs);

    let config = make_config();
    let var_len_pis: Vec<&[&[Val]]> = vec![];

    println!("Proving invalid ballot (fields 3,4,5 exceed max_value=2)...");
    let proof = prove(&config, &BallotAir::new(), &trace, &pv);
    println!("Proof bytes produced. Now verifying (should FAIL)...");

    let result = verify(&config, &BallotAir::new(), &proof, &pv, &var_len_pis);
    assert!(result.is_err(), "Verification must reject out-of-range ballot, but it passed!");
    println!("✅ Out-of-range ballot correctly rejected by verifier: {:?}", result.unwrap_err());
}
