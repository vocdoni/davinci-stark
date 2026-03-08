//! Fibonacci AIR smoke test — verifies Plonky3 prove/verify works correctly.
//! This mirrors a small upstream Plonky3 prove/verify example.

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_fri::{TwoAdicFriPcs, create_test_fri_params};
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{StarkConfig, prove, verify};
use rand::SeedableRng;
use rand::rngs::SmallRng;

// --- Fibonacci AIR definition ---

pub struct FibonacciAir;

impl<F: PrimeCharacteristicRing> BaseAir<F> for FibonacciAir {
    fn width(&self) -> usize {
        2
    }
}

impl<AB> Air<AB> for FibonacciAir
where
    AB: AirBuilder + AirBuilderWithPublicValues,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0).expect("Matrix is empty?");
        let next = main.row_slice(1).expect("Matrix only has 1 row?");
        let local: &FibRow<AB::Var> = (*local).borrow();
        let next: &FibRow<AB::Var> = (*next).borrow();

        // Clone public values to avoid borrow conflicts
        let a_init = builder.public_values()[0];
        let b_init = builder.public_values()[1];
        let b_final = builder.public_values()[2];

        // Boundary: a[0] = pis[0], b[0] = pis[1]
        let mut when_first_row = builder.when_first_row();
        when_first_row.assert_eq(local.a.clone(), a_init);
        when_first_row.assert_eq(local.b.clone(), b_init);

        // Transition: a' = b, b' = a + b
        let mut when_transition = builder.when_transition();
        when_transition.assert_eq(next.a.clone(), local.b.clone());
        when_transition.assert_eq(next.b.clone(), local.a.clone() + local.b.clone());

        // Final: b[last] = pis[2]
        builder.when_last_row().assert_eq(local.b.clone(), b_final);
    }
}

#[repr(C)]
pub struct FibRow<F> {
    pub a: F,
    pub b: F,
}

impl<F> Borrow<FibRow<F>> for [F] {
    fn borrow(&self) -> &FibRow<F> {
        debug_assert_eq!(self.len(), 2);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<FibRow<F>>() };
        debug_assert!(prefix.is_empty());
        debug_assert!(suffix.is_empty());
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

fn generate_fibonacci_trace<F: PrimeField64>(a: u64, b: u64, n: usize) -> RowMajorMatrix<F> {
    assert!(n.is_power_of_two());
    let mut values = F::zero_vec(n * 2);
    values[0] = F::from_u64(a);
    values[1] = F::from_u64(b);
    for i in 1..n {
        values[i * 2] = values[(i - 1) * 2 + 1];
        values[i * 2 + 1] = values[(i - 1) * 2] + values[(i - 1) * 2 + 1];
    }
    RowMajorMatrix::new(values, 2)
}

// --- Type aliases for STARK config ---

type Val = Goldilocks;
type Perm = Poseidon2Goldilocks<16>;
type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
type ValMmcs =
    MerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, MyHash, MyCompress, 8>;
type Challenge = BinomialExtensionField<Val, 2>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Challenger = DuplexChallenger<Val, Perm, 16, 8>;
type Dft = Radix2DitParallel<Val>;
type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;

fn prove_and_verify_fibonacci(a: u64, b: u64, n: usize, expected: u64, log_final_poly_len: usize) {
    let mut rng = SmallRng::seed_from_u64(1);
    let perm = Perm::new_from_rng_128(&mut rng);
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    let trace = generate_fibonacci_trace::<Val>(a, b, n);
    let fri_params = create_test_fri_params(challenge_mmcs, log_final_poly_len);
    let pcs = Pcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::new(perm);

    let config = MyConfig::new(pcs, challenger);
    let pis = vec![
        Goldilocks::from_u64(a),
        Goldilocks::from_u64(b),
        Goldilocks::from_u64(expected),
    ];
    let air = FibonacciAir;
    let proof = prove(&config, &air, trace, &pis);
    verify(&config, &air, &proof, &pis).expect("verification failed");
}

#[test]
fn test_fibonacci_smoke() {
    // fib(8) starting from (0,1) = 21
    prove_and_verify_fibonacci(0, 1, 8, 21, 2);
}

#[test]
fn test_fibonacci_larger() {
    // fib(32) starting from (0,1) = 2178309
    prove_and_verify_fibonacci(0, 1, 32, 2178309, 3);
}
