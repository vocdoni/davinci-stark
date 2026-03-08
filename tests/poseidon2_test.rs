//! Tests for the Poseidon2 implementation.

use davinci_stark::columns::{P2_PERM_ID, P2_STATE, TRACE_WIDTH};
use davinci_stark::poseidon2::*;
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::{Field, PrimeCharacteristicRing, extension::BinomialExtensionField};
use p3_fri::TwoAdicFriPcs;
use p3_goldilocks::Goldilocks;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_poseidon2::{ExternalLayerConstants, Poseidon2};
use p3_symmetric::{PaddingFreeSponge, Permutation, TruncatedPermutation};
use p3_uni_stark::{StarkConfig, prove, verify};

type UpstreamPoseidon2GoldilocksHL8 = p3_goldilocks::Poseidon2GoldilocksHL<8>;
type Val = Goldilocks;
type Perm16 = p3_goldilocks::Poseidon2Goldilocks<16>;
type MyHash = PaddingFreeSponge<Perm16, 16, 8, 8>;
type MyCompress = TruncatedPermutation<Perm16, 2, 8, 16>;
type ValMmcs =
    MerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, MyHash, MyCompress, 8>;
type Challenge = BinomialExtensionField<Val, 2>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Challenger = DuplexChallenger<Val, Perm16, 16, 8>;
type Dft = Radix2DitParallel<Val>;
type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
type TestConfig = StarkConfig<Pcs, Challenge, Challenger>;

fn make_poseidon_test_config() -> TestConfig {
    let perm = Perm16::new_from_rng_128(&mut davinci_stark::config::DeterministicRng(42));
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let fri_params = p3_fri::FriParameters {
        log_blowup: 3,
        log_final_poly_len: 0,
        num_queries: 2,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 1,
        mmcs: challenge_mmcs,
    };
    let pcs = Pcs::new(Dft::default(), val_mmcs, fri_params);
    let challenger = Challenger::new(perm);
    TestConfig::new(pcs, challenger)
}

fn assert_poseidon_trace_rejected(
    trace: p3_matrix::dense::RowMajorMatrix<Goldilocks>,
    pv: Vec<Goldilocks>,
    reason: &str,
) {
    use davinci_stark::air::BallotAir;

    let air = BallotAir::new();
    let config = make_poseidon_test_config();
    let prove_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        prove(&config, &air, trace, &pv)
    }));

    match prove_result {
        Ok(proof) => {
            let verify_result = verify(&config, &air, &proof, &pv);
            assert!(
                verify_result.is_err(),
                "{reason}: verifier accepted tampered Poseidon trace"
            );
        }
        Err(_) => {}
    }
}

fn upstream_hl_poseidon2_width_8(input: [Goldilocks; WIDTH]) -> [Goldilocks; WIDTH] {
    let perm: UpstreamPoseidon2GoldilocksHL8 = Poseidon2::new(
        ExternalLayerConstants::<Goldilocks, WIDTH>::new_from_saved_array(
            p3_goldilocks::HL_GOLDILOCKS_8_EXTERNAL_ROUND_CONSTANTS,
            Goldilocks::new_array,
        ),
        Goldilocks::new_array(p3_goldilocks::HL_GOLDILOCKS_8_INTERNAL_ROUND_CONSTANTS).to_vec(),
    );

    let mut state = input;
    perm.permute_mut(&mut state);
    state
}

#[test]
fn test_poseidon2_different_inputs_different_outputs() {
    let constants = Poseidon2Constants::new();

    let mut input_a = [Goldilocks::ZERO; WIDTH];
    input_a[0] = Goldilocks::from_u64(1);

    let mut input_b = [Goldilocks::ZERO; WIDTH];
    input_b[0] = Goldilocks::from_u64(2);

    let trace_a = poseidon2_permute_traced(&input_a, &constants);
    let trace_b = poseidon2_permute_traced(&input_b, &constants);

    let out_a = trace_a.states.last().unwrap();
    let out_b = trace_b.states.last().unwrap();

    assert_ne!(
        out_a, out_b,
        "Different inputs must produce different outputs"
    );
}

#[test]
fn test_poseidon2_trace_has_correct_length() {
    let constants = Poseidon2Constants::new();
    let input = [Goldilocks::ZERO; WIDTH];
    let trace = poseidon2_permute_traced(&input, &constants);

    // TOTAL_ROUNDS + 1 states (initial + one per round)
    assert_eq!(trace.states.len(), TOTAL_ROUNDS + 1);
    assert_eq!(trace.states.len(), 31); // 8 full + 22 partial + 1 initial
}

#[test]
fn test_poseidon2_sponge_hash_consistency() {
    let constants = Poseidon2Constants::new();

    // Hash with traced and non-traced should match
    let input: Vec<Goldilocks> = (0..10).map(|i| Goldilocks::from_u64(i)).collect();

    let output1 = poseidon2_hash(&input, 4, &constants);
    let (output2, traces) = poseidon2_hash_traced(&input, 4, &constants);

    assert_eq!(output1, output2);
    // 10 elements, rate 4 → ceil(10/4) = 3 permutations
    assert_eq!(traces.len(), 3);
}

#[test]
fn test_poseidon2_sponge_collision_resistance() {
    let constants = Poseidon2Constants::new();

    let input1: Vec<Goldilocks> = (0..5).map(|i| Goldilocks::from_u64(i)).collect();
    let input2: Vec<Goldilocks> = (0..5).map(|i| Goldilocks::from_u64(i + 100)).collect();

    let out1 = poseidon2_hash(&input1, 4, &constants);
    let out2 = poseidon2_hash(&input2, 4, &constants);

    assert_ne!(out1, out2);
}

#[test]
fn test_poseidon2_round_transitions_nontrivial() {
    // Verify each round actually changes the state (no no-op rounds)
    let constants = Poseidon2Constants::new();
    let mut input = [Goldilocks::ZERO; WIDTH];
    input[0] = Goldilocks::from_u64(42);

    let trace = poseidon2_permute_traced(&input, &constants);

    for r in 0..TOTAL_ROUNDS {
        assert_ne!(
            trace.states[r],
            trace.states[r + 1],
            "Round {} produced identical state",
            r
        );
    }
}

#[test]
fn test_poseidon2_matches_upstream_horizen_variant_on_zero_input() {
    let constants = Poseidon2Constants::new();
    let input = [Goldilocks::ZERO; WIDTH];
    let local = *poseidon2_permute_traced(&input, &constants)
        .states
        .last()
        .unwrap();
    let upstream = upstream_hl_poseidon2_width_8(input);

    assert_eq!(
        local, upstream,
        "local Poseidon2 width-8 must match upstream HL variant"
    );
}

#[test]
fn test_poseidon2_matches_upstream_horizen_variant_on_zisk_vector() {
    let constants = Poseidon2Constants::new();
    let input = [
        Goldilocks::from_u64(0),
        Goldilocks::from_u64(1),
        Goldilocks::from_u64(2),
        Goldilocks::from_u64(3),
        Goldilocks::from_u64(4),
        Goldilocks::from_u64(5),
        Goldilocks::from_u64(6),
        Goldilocks::from_u64(7),
    ];

    let local = *poseidon2_permute_traced(&input, &constants)
        .states
        .last()
        .unwrap();
    let upstream = upstream_hl_poseidon2_width_8(input);

    assert_eq!(
        local, upstream,
        "local Poseidon2 width-8 must match upstream HL variant on ZisK vector"
    );
}

#[test]
fn test_poseidon_perm_id_must_be_constrained() {
    use davinci_stark::trace::generate_poseidon2_trace;

    let constants = Poseidon2Constants::new();
    let mut input = [Goldilocks::ZERO; WIDTH];
    input[0] = Goldilocks::from_u64(7);
    input[1] = Goldilocks::from_u64(11);

    let (mut trace, pv) = generate_poseidon2_trace(&[input], &constants);
    trace.values[P2_PERM_ID] += Goldilocks::ONE;
    assert_poseidon_trace_rejected(trace, pv, "tampered permutation id");
}

#[test]
fn test_poseidon_output_gap_row_must_be_constrained() {
    use davinci_stark::trace::generate_poseidon2_trace;

    let constants = Poseidon2Constants::new();
    let mut input = [Goldilocks::ZERO; WIDTH];
    input[0] = Goldilocks::from_u64(21);

    let (mut trace, pv) = generate_poseidon2_trace(&[input], &constants);
    let output_row = TOTAL_ROUNDS;
    let idx = output_row * TRACE_WIDTH + P2_STATE;
    trace.values[idx] += Goldilocks::ONE;
    assert_poseidon_trace_rejected(trace, pv, "tampered permutation output row");
}
