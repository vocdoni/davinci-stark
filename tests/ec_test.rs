//! Test EC point operations and scalar multiplication prove/verify.

use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_miden_prover::{prove, verify};

use ecgfp5::curve::Point;
use ecgfp5::scalar::Scalar;

use davinci_stark::air::BallotAir;
use davinci_stark::columns::{TRACE_WIDTH, IS_LAST_IN_PHASE, IS_EC};
use davinci_stark::config::{make_config, Val};
use davinci_stark::trace::generate_scalar_mul_trace;
use davinci_stark::ecgfp5_ops::fill_scalar_mul_row;

/// Build a single scalar mul trace padded to 1024 rows (2^10).
fn build_single_scalar_mul_trace(scalar: &Scalar, base: &Point) -> RowMajorMatrix<Goldilocks> {
    let (rows, result) = generate_scalar_mul_trace(scalar, base, 0);

    let total = 1024;
    let mut values = vec![Goldilocks::ZERO; total * TRACE_WIDTH];
    values[..rows.len()].copy_from_slice(&rows);

    // Set IS_EC=1 for the first 319 rows (scalar mul rows)
    for i in 0..319 {
        values[i * TRACE_WIDTH + IS_EC] = Goldilocks::from_u64(1);
    }

    // Chain padding rows from the last computation result.
    // Each padding row doubles the current acc with bit=0, so next_acc = doubled.
    let mut acc = result;
    let neutral_base = Point::NEUTRAL;
    for i in 319..total {
        let start = i * TRACE_WIDTH;
        let row = &mut values[start..start + TRACE_WIDTH];
        let (doubled, _added) = fill_scalar_mul_row(row, &acc, &neutral_base, 0, 0);
        row[IS_LAST_IN_PHASE] = Goldilocks::from_u64(1); // padding rows are "last"
        row[IS_EC] = Goldilocks::from_u64(1); // mark as EC section
        acc = doubled; // bit=0 → select doubled
    }

    RowMajorMatrix::new(values, TRACE_WIDTH)
}

#[test]
fn test_scalar_mul_k_times_g() {
    // k = 42 (small scalar for testing)
    let k = Scalar([42, 0, 0, 0, 0]);
    let g = Point::GENERATOR;

    println!("Generating scalar mul trace for k=42, base=G...");
    let trace = build_single_scalar_mul_trace(&k, &g);
    println!("Trace: {} rows × {} cols", trace.height(), trace.width());

    let config = make_config();
    let pis: Vec<Val> = vec![];
    let var_len_pis: Vec<&[&[Val]]> = vec![];

    println!("Proving...");
    let proof = prove(&config, &BallotAir::new(), &trace, &pis);
    println!("Proof generated! Verifying...");

    verify(&config, &BallotAir::new(), &proof, &pis, &var_len_pis)
        .expect("verification failed");
    println!("✅ Scalar multiplication proof verified!");
}

#[test]
fn test_scalar_mul_result_correct() {
    // Verify that our trace generator produces the correct scalar mul result
    let k = Scalar([42, 0, 0, 0, 0]);
    let g = Point::GENERATOR;

    let (_rows, result) = generate_scalar_mul_trace(&k, &g, 0);

    // Compare with ecgfp5 reference: Point::mulgen(k) should give same result
    let reference = Point::mulgen(k);

    // Compare encoded values (since projective coords may differ by scaling)
    let result_enc = result.encode();
    let ref_enc = reference.encode();

    for i in 0..5 {
        assert_eq!(
            result_enc.0[i].to_u64(),
            ref_enc.0[i].to_u64(),
            "Encoded limb {} mismatch",
            i
        );
    }
    println!("✅ Scalar mul result matches ecgfp5 reference!");
}
