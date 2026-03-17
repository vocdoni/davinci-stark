//! Test GF(p^5) multiplication constraints in a minimal AIR.

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_fri::{TwoAdicFriPcs, create_test_fri_params};
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{StarkConfig, prove, verify};
use rand::SeedableRng;
use rand::rngs::SmallRng;

use davinci_stark::gfp5::gfp5_mul_constraints;

// A minimal AIR that verifies one GF(p^5) multiplication per row: c = a * b
// Width: 15 columns (a: 5, b: 5, c: 5)
struct Gfp5MulAir;

#[repr(C)]
struct Gfp5MulRow<T> {
    a: [T; 5],
    b: [T; 5],
    c: [T; 5],
}

impl<T> Borrow<Gfp5MulRow<T>> for [T] {
    fn borrow(&self) -> &Gfp5MulRow<T> {
        debug_assert_eq!(self.len(), 15);
        let (prefix, rows, suffix) = unsafe { self.align_to::<Gfp5MulRow<T>>() };
        debug_assert!(prefix.is_empty());
        debug_assert!(suffix.is_empty());
        &rows[0]
    }
}

impl<F: PrimeCharacteristicRing> BaseAir<F> for Gfp5MulAir {
    fn width(&self) -> usize {
        15
    }
}

impl<AB: AirBuilder> Air<AB> for Gfp5MulAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &Gfp5MulRow<AB::Var> = (*local).borrow();

        let a: [AB::Expr; 5] = local.a.clone().map(|v: AB::Var| v.into());
        let b: [AB::Expr; 5] = local.b.clone().map(|v: AB::Var| v.into());
        let c: [AB::Expr; 5] = local.c.clone().map(|v: AB::Var| v.into());

        // Constrain c = a * b in GF(p^5)
        let constraints = gfp5_mul_constraints::<AB::F, AB::Expr>(a, b, c);
        for expr in constraints {
            builder.assert_zero(expr);
        }
    }
}

// Compute GF(p^5) multiplication using the ecgfp5 crate
fn gfp5_mul_reference(a: [u64; 5], b: [u64; 5]) -> [u64; 5] {
    use ecgfp5::field::{GFp, GFp5};
    let fa = GFp5([
        GFp::from_u64_reduce(a[0]),
        GFp::from_u64_reduce(a[1]),
        GFp::from_u64_reduce(a[2]),
        GFp::from_u64_reduce(a[3]),
        GFp::from_u64_reduce(a[4]),
    ]);
    let fb = GFp5([
        GFp::from_u64_reduce(b[0]),
        GFp::from_u64_reduce(b[1]),
        GFp::from_u64_reduce(b[2]),
        GFp::from_u64_reduce(b[3]),
        GFp::from_u64_reduce(b[4]),
    ]);
    let fc = fa * fb;
    [
        fc.0[0].to_u64(),
        fc.0[1].to_u64(),
        fc.0[2].to_u64(),
        fc.0[3].to_u64(),
        fc.0[4].to_u64(),
    ]
}

fn generate_gfp5_mul_trace(pairs: &[([u64; 5], [u64; 5])]) -> RowMajorMatrix<Goldilocks> {
    let n = pairs.len().next_power_of_two();
    let mut values = vec![Goldilocks::ZERO; n * 15];
    for (i, (a, b)) in pairs.iter().enumerate() {
        let c = gfp5_mul_reference(*a, *b);
        for j in 0..5 {
            values[i * 15 + j] = Goldilocks::from_u64(a[j]);
            values[i * 15 + 5 + j] = Goldilocks::from_u64(b[j]);
            values[i * 15 + 10 + j] = Goldilocks::from_u64(c[j]);
        }
    }
    // Pad remaining rows with valid identity multiplications (1 * 1 = 1)
    for i in pairs.len()..n {
        values[i * 15] = Goldilocks::ONE; // a0 = 1
        values[i * 15 + 5] = Goldilocks::ONE; // b0 = 1
        values[i * 15 + 10] = Goldilocks::ONE; // c0 = 1
    }
    RowMajorMatrix::new(values, 15)
}

// --- STARK config types ---
type Val = Goldilocks;
type Perm = Poseidon2Goldilocks<16>;
type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
type ValMmcs =
    MerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, MyHash, MyCompress, 2, 8>;
type Challenge = BinomialExtensionField<Val, 2>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Challenger = DuplexChallenger<Val, Perm, 16, 8>;
type Dft = Radix2DitParallel<Val>;
type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;

fn make_config() -> MyConfig {
    let mut rng = SmallRng::seed_from_u64(42);
    let perm = Perm::new_from_rng_128(&mut rng);
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    let fri_params = create_test_fri_params(challenge_mmcs, 0);
    let pcs = Pcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::new(perm);
    MyConfig::new(pcs, challenger)
}

#[test]
fn test_gfp5_mul_simple() {
    // Test: (2, 0, 0, 0, 0) * (3, 0, 0, 0, 0) = (6, 0, 0, 0, 0)
    let pairs = vec![([2, 0, 0, 0, 0], [3, 0, 0, 0, 0])];
    let trace = generate_gfp5_mul_trace(&pairs);
    let config = make_config();
    let pis: Vec<Val> = vec![];
    let proof = prove(&config, &Gfp5MulAir, trace, &pis);
    verify(&config, &Gfp5MulAir, &proof, &pis).expect("verification failed");
    println!("GF(p^5) simple multiplication proof verified!");
}

#[test]
fn test_gfp5_mul_extension() {
    // Test multiplication with non-zero extension components
    // (1, 2, 3, 4, 5) * (6, 7, 8, 9, 10)
    let pairs = vec![([1, 2, 3, 4, 5], [6, 7, 8, 9, 10])];
    let trace = generate_gfp5_mul_trace(&pairs);
    let config = make_config();
    let pis: Vec<Val> = vec![];
    let proof = prove(&config, &Gfp5MulAir, trace, &pis);
    verify(&config, &Gfp5MulAir, &proof, &pis).expect("verification failed");
    println!("GF(p^5) extension multiplication proof verified!");
}

#[test]
fn test_gfp5_mul_multiple_rows() {
    // Multiple multiplications in the same trace
    let pairs = vec![
        ([1, 0, 0, 0, 0], [1, 0, 0, 0, 0]), // 1 * 1 = 1
        ([2, 0, 0, 0, 0], [3, 0, 0, 0, 0]), // 2 * 3 = 6
        ([1, 1, 0, 0, 0], [1, 1, 0, 0, 0]), // (1+z) * (1+z)
        ([0, 1, 0, 0, 0], [0, 0, 0, 0, 1]), // z * z^4 = z^5 = 3
    ];
    let trace = generate_gfp5_mul_trace(&pairs);
    let config = make_config();
    let pis: Vec<Val> = vec![];
    let proof = prove(&config, &Gfp5MulAir, trace, &pis);
    verify(&config, &Gfp5MulAir, &proof, &pis).expect("verification failed");
    println!("GF(p^5) multiple multiplications proof verified!");
}
