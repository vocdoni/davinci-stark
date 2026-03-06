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
        packed_ballot_mode: [Goldilocks::ZERO; 4],
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
        packed_ballot_mode: [
            Goldilocks::from_u64(0),
            Goldilocks::from_u64(0),
            Goldilocks::from_u64(0),
            Goldilocks::from_u64(0),
        ],
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
