//! Test EC point arithmetic used by the ballot prover.

use ecgfp5::curve::Point;
use ecgfp5::scalar::Scalar;

use davinci_stark::air::SMALL_SCALAR_BITS;
use davinci_stark::trace::generate_scalar_mul_trace_nbits;

#[test]
fn test_scalar_mul_result_correct() {
    let k = Scalar([42, 0, 0, 0, 0]);
    let g = Point::GENERATOR;

    let (_rows, result) = generate_scalar_mul_trace_nbits(&k, &g, 0, SMALL_SCALAR_BITS, false, 0);

    let reference = Point::mulgen(k);
    let result_enc = result.encode();
    let ref_enc = reference.encode();

    for i in 0..5 {
        assert_eq!(
            result_enc.0[i].to_u64(),
            ref_enc.0[i].to_u64(),
            "encoded limb {} mismatch",
            i
        );
    }
}
