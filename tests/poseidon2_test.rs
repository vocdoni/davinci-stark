//! Tests for the Poseidon2 implementation.

use p3_goldilocks::Goldilocks;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::Matrix;
use davinci_stark::poseidon2::*;

#[test]
fn test_poseidon2_different_inputs_different_outputs() {
    let constants = Poseidon2Constants::from_seed(42);
    
    let mut input_a = [Goldilocks::ZERO; WIDTH];
    input_a[0] = Goldilocks::from_u64(1);
    
    let mut input_b = [Goldilocks::ZERO; WIDTH];
    input_b[0] = Goldilocks::from_u64(2);
    
    let trace_a = poseidon2_permute_traced(&input_a, &constants);
    let trace_b = poseidon2_permute_traced(&input_b, &constants);
    
    let out_a = trace_a.states.last().unwrap();
    let out_b = trace_b.states.last().unwrap();
    
    assert_ne!(out_a, out_b, "Different inputs must produce different outputs");
}

#[test]
fn test_poseidon2_trace_has_correct_length() {
    let constants = Poseidon2Constants::from_seed(42);
    let input = [Goldilocks::ZERO; WIDTH];
    let trace = poseidon2_permute_traced(&input, &constants);
    
    // TOTAL_ROUNDS + 1 states (initial + one per round)
    assert_eq!(trace.states.len(), TOTAL_ROUNDS + 1);
    assert_eq!(trace.states.len(), 31); // 8 full + 22 partial + 1 initial
}

#[test]
fn test_poseidon2_sponge_hash_consistency() {
    let constants = Poseidon2Constants::from_seed(42);
    
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
    let constants = Poseidon2Constants::from_seed(42);
    
    let input1: Vec<Goldilocks> = (0..5).map(|i| Goldilocks::from_u64(i)).collect();
    let input2: Vec<Goldilocks> = (0..5).map(|i| Goldilocks::from_u64(i + 100)).collect();
    
    let out1 = poseidon2_hash(&input1, 4, &constants);
    let out2 = poseidon2_hash(&input2, 4, &constants);
    
    assert_ne!(out1, out2);
}

#[test]
fn test_poseidon2_round_transitions_nontrivial() {
    // Verify each round actually changes the state (no no-op rounds)
    let constants = Poseidon2Constants::from_seed(42);
    let mut input = [Goldilocks::ZERO; WIDTH];
    input[0] = Goldilocks::from_u64(42);
    
    let trace = poseidon2_permute_traced(&input, &constants);
    
    for r in 0..TOTAL_ROUNDS {
        assert_ne!(
            trace.states[r], trace.states[r + 1],
            "Round {} produced identical state", r
        );
    }
}

#[test]
fn test_poseidon2_stark_proof() {
    use davinci_stark::air::BallotAir;
    use davinci_stark::config::make_config;
    use davinci_stark::trace::generate_poseidon2_trace;
    use p3_miden_prover::{prove, verify};

    type Val = Goldilocks;
    let constants = Poseidon2Constants::from_seed(42);

    let mut input = [Goldilocks::ZERO; WIDTH];
    input[0] = Goldilocks::from_u64(123);
    input[1] = Goldilocks::from_u64(456);

    let (trace, pv) = generate_poseidon2_trace(&[input], &constants);
    println!("Poseidon2 trace: {}x{}", trace.height(), trace.width);

    let air = BallotAir::new();
    let config = make_config();
    let var_len_pis: Vec<&[&[Val]]> = vec![];

    let proof = prove(&config, &air, &trace, &pv);
    verify(&config, &air, &proof, &pv, &var_len_pis).expect("Poseidon2 proof verification failed");
    println!("✅ Poseidon2 STARK proof verified!");
}

#[test]
fn test_poseidon2_stark_multiple_perms() {
    use davinci_stark::air::BallotAir;
    use davinci_stark::config::make_config;
    use davinci_stark::trace::generate_poseidon2_trace;
    use p3_miden_prover::{prove, verify};

    type Val = Goldilocks;
    let constants = Poseidon2Constants::from_seed(42);

    let inputs: Vec<[Goldilocks; WIDTH]> = (0..4)
        .map(|i| {
            let mut inp = [Goldilocks::ZERO; WIDTH];
            inp[0] = Goldilocks::from_u64(i * 100 + 1);
            inp[1] = Goldilocks::from_u64(i * 100 + 2);
            inp
        })
        .collect();

    let (trace, pv) = generate_poseidon2_trace(&inputs, &constants);
    println!("Multi-perm trace: {}x{}", trace.height(), trace.width);

    let air = BallotAir::new();
    let config = make_config();
    let var_len_pis: Vec<&[&[Val]]> = vec![];

    let proof = prove(&config, &air, &trace, &pv);
    verify(&config, &air, &proof, &pv, &var_len_pis).expect("Multi-perm proof verification failed");
    println!("✅ Multi-perm Poseidon2 STARK proof verified!");
}
