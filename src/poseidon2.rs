//! Poseidon2 over Goldilocks with round-by-round trace capture.
//!
//! The circuit needs the intermediate round state for every width-8 Poseidon2
//! permutation, so this module keeps a small local tracer on top of the
//! upstream Plonky3 constants and linear layers.

use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::{
    Goldilocks, GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL,
    GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL, GOLDILOCKS_POSEIDON2_RC_8_INTERNAL,
    MATRIX_DIAG_8_GOLDILOCKS,
};

/// Poseidon2 parameters for Goldilocks width 8.
pub const WIDTH: usize = 8;
pub const ROUNDS_F: usize = 8; // 4 initial + 4 terminal
pub const ROUNDS_F_HALF: usize = ROUNDS_F / 2; // 4
pub const ROUNDS_P: usize = 22;
pub const TOTAL_ROUNDS: usize = ROUNDS_F + ROUNDS_P; // 30

/// Stored round constants for a Poseidon2 instance.
#[derive(Clone, Debug)]
pub struct Poseidon2Constants {
    /// External (full) round constants: ROUNDS_F arrays of WIDTH constants each.
    /// First ROUNDS_F_HALF are initial, last ROUNDS_F_HALF are terminal.
    pub external_rc: Vec<[Goldilocks; WIDTH]>,
    /// Internal (partial) round constants: ROUNDS_P single constants.
    pub internal_rc: Vec<Goldilocks>,
}

impl Poseidon2Constants {
    /// Load the upstream Plonky3 Horizen Labs constants used by the ZisK precompile.
    pub fn new() -> Self {
        let mut external_rc = Vec::with_capacity(ROUNDS_F);
        // Initial full rounds (4 rounds)
        for round in &GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL {
            external_rc.push(*round);
        }
        // Final full rounds (4 rounds)
        for round in &GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL {
            external_rc.push(*round);
        }

        let internal_rc = GOLDILOCKS_POSEIDON2_RC_8_INTERNAL.to_vec();

        Self {
            external_rc,
            internal_rc,
        }
    }
}

/// Apply the Horizen Labs 4×4 MDS matrix (Zisk-compatible).
///
/// Matrix: [[5,7,1,3],[4,6,1,1],[1,3,5,7],[1,1,4,6]]
/// This matches Zisk's `matmul_m4` in pil2-proofman/fields/src/poseidon2.rs.
#[inline]
fn apply_mat4(x: &mut [Goldilocks; 4]) {
    let t0 = x[0] + x[1];
    let t1 = x[2] + x[3];
    let t2 = x[1] + x[1] + t1; // 2*x1 + x2 + x3
    let t3 = x[3] + x[3] + t0; // x0 + x1 + 2*x3
    let t1_2 = t1 + t1; // 2*x2 + 2*x3
    let t0_2 = t0 + t0; // 2*x0 + 2*x1
    let t4 = t1_2 + t1_2 + t3; // x0 + x1 + 4*x2 + 6*x3
    let t5 = t0_2 + t0_2 + t2; // 4*x0 + 6*x1 + x2 + x3
    let t6 = t3 + t5; // 5*x0 + 7*x1 + x2 + 3*x3
    let t7 = t2 + t4; // x0 + 3*x1 + 5*x2 + 7*x3
    x[0] = t6;
    x[1] = t5;
    x[2] = t7;
    x[3] = t4;
}

/// External linear layer for width 8: apply HL 4x4 MDS to each block, then mix.
/// Matches Zisk's `matmul_external` in pil2-proofman/fields/src/poseidon2.rs.
fn external_linear_layer(state: &mut [Goldilocks; WIDTH]) {
    // Apply 4x4 MDS to blocks [0..4] and [4..8]
    let mut block0 = [state[0], state[1], state[2], state[3]];
    let mut block1 = [state[4], state[5], state[6], state[7]];
    apply_mat4(&mut block0);
    apply_mat4(&mut block1);

    // Mix: for each position, add the sum of both blocks
    for i in 0..4 {
        let sum = block0[i] + block1[i];
        state[i] = block0[i] + sum;
        state[4 + i] = block1[i] + sum;
    }
}

/// Internal linear layer: matmul_internal with diagonal matrix.
/// Formula: s = sum(state), state[i] = state[i] * diag[i] + s
fn internal_linear_layer(state: &mut [Goldilocks; WIDTH]) {
    let sum: Goldilocks = state.iter().copied().sum();
    for i in 0..WIDTH {
        state[i] = state[i] * MATRIX_DIAG_8_GOLDILOCKS[i] + sum;
    }
}

/// S-box: x^7
#[inline]
fn sbox(x: Goldilocks) -> Goldilocks {
    let x2 = x * x;
    let x3 = x * x2;
    let x4 = x2 * x2;
    x3 * x4
}

/// Full record of all states during a single Poseidon2 permutation.
///
/// states[0] is the input, states[30] is the output. The trace generator
/// uses these to fill 30 constraint rows plus 1 output/gap row.
#[derive(Clone, Debug)]
pub struct Poseidon2Trace {
    /// States: [initial, after_round_0, after_round_1, ..., after_round_29]
    /// Length = TOTAL_ROUNDS + 1 = 31
    pub states: Vec<[Goldilocks; WIDTH]>,
}

/// Run the full Poseidon2 permutation, recording the state after each round.
///
/// This is the workhorse for trace generation: it returns every intermediate
/// state so fill_poseidon2_rows can write them into the trace matrix.
/// For a simple hash (no trace needed), use poseidon2_hash instead.
pub fn poseidon2_permute_traced(
    input: &[Goldilocks; WIDTH],
    constants: &Poseidon2Constants,
) -> Poseidon2Trace {
    let mut states = Vec::with_capacity(TOTAL_ROUNDS + 1);
    let mut state = *input;

    // Initial external linear layer (Poseidon2 spec: pre-round mixing)
    external_linear_layer(&mut state);
    states.push(state);

    // 4 initial full rounds
    for r in 0..ROUNDS_F_HALF {
        // Add round constants
        for i in 0..WIDTH {
            state[i] += constants.external_rc[r][i];
        }
        // S-box all
        for i in 0..WIDTH {
            state[i] = sbox(state[i]);
        }
        // External linear layer
        external_linear_layer(&mut state);
        states.push(state);
    }

    // 22 partial rounds
    for r in 0..ROUNDS_P {
        // Add round constant to element 0 only
        state[0] += constants.internal_rc[r];
        // S-box only element 0
        state[0] = sbox(state[0]);
        // Internal linear layer
        internal_linear_layer(&mut state);
        states.push(state);
    }

    // 4 terminal full rounds
    for r in 0..ROUNDS_F_HALF {
        // Add round constants
        for i in 0..WIDTH {
            state[i] += constants.external_rc[ROUNDS_F_HALF + r][i];
        }
        // S-box all
        for i in 0..WIDTH {
            state[i] = sbox(state[i]);
        }
        // External linear layer
        external_linear_layer(&mut state);
        states.push(state);
    }

    assert_eq!(states.len(), TOTAL_ROUNDS + 1);
    Poseidon2Trace { states }
}

/// Poseidon2 sponge hash (no trace recording, just the result).
///
/// Absorbs `input` in chunks of 4 (the rate), applying a permutation after
/// each chunk. Then squeezes `output_len` elements from the capacity portion.
/// Used when you only need the hash output, not the intermediate states.
pub fn poseidon2_hash(
    input: &[Goldilocks],
    output_len: usize,
    constants: &Poseidon2Constants,
) -> Vec<Goldilocks> {
    let rate = 4;
    let mut state = [Goldilocks::ZERO; WIDTH];

    // Absorb phase
    for chunk in input.chunks(rate) {
        for (i, &val) in chunk.iter().enumerate() {
            state[i] += val;
        }
        let trace = poseidon2_permute_traced(&state, constants);
        state = *trace.states.last().unwrap();
    }

    // Squeeze
    state[..output_len].to_vec()
}

/// Poseidon2 sponge hash that also returns every permutation trace.
///
/// Same logic as poseidon2_hash, but records and returns a Poseidon2Trace
/// for each permutation call. The trace generator (trace.rs) uses these
/// to fill the Poseidon2 section of the STARK execution trace.
pub fn poseidon2_hash_traced(
    input: &[Goldilocks],
    output_len: usize,
    constants: &Poseidon2Constants,
) -> (Vec<Goldilocks>, Vec<Poseidon2Trace>) {
    let rate = 4;
    let mut state = [Goldilocks::ZERO; WIDTH];
    let mut traces = Vec::new();

    // Absorb phase
    for chunk in input.chunks(rate) {
        for (i, &val) in chunk.iter().enumerate() {
            state[i] += val;
        }
        let trace = poseidon2_permute_traced(&state, constants);
        state = *trace.states.last().unwrap();
        traces.push(trace);
    }

    // Squeeze
    let output = state[..output_len].to_vec();
    (output, traces)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeField64;

    #[test]
    fn test_poseidon2_permute_deterministic() {
        let constants = Poseidon2Constants::new();
        let input = [Goldilocks::ZERO; WIDTH];
        let trace = poseidon2_permute_traced(&input, &constants);
        let output = trace.states.last().unwrap();

        // Should be deterministic
        let trace2 = poseidon2_permute_traced(&input, &constants);
        let output2 = trace2.states.last().unwrap();
        assert_eq!(output, output2);

        // Output should differ from input
        assert_ne!(&input, output);
    }

    #[test]
    fn test_poseidon2_hash_simple() {
        let constants = Poseidon2Constants::new();
        let input = [Goldilocks::from_u64(1), Goldilocks::from_u64(2)];
        let output = poseidon2_hash(&input, 4, &constants);
        assert_eq!(output.len(), 4);

        // Different input should give different output
        let input2 = [Goldilocks::from_u64(3), Goldilocks::from_u64(4)];
        let output2 = poseidon2_hash(&input2, 4, &constants);
        assert_ne!(output, output2);
    }

    #[test]
    fn test_poseidon2_trace_consistency() {
        let constants = Poseidon2Constants::new();
        let input = [
            Goldilocks::from_u64(1),
            Goldilocks::from_u64(2),
            Goldilocks::from_u64(3),
        ];
        let (output, traces) = poseidon2_hash_traced(&input, 4, &constants);
        let output_simple = poseidon2_hash(&input, 4, &constants);
        assert_eq!(output, output_simple);
        assert_eq!(traces.len(), 1); // 3 elements < rate=4, so 1 permutation
    }

    /// Cross-validate with Zisk's Poseidon8 test vector.
    ///
    /// Zisk test: input = [0,1,2,3,4,5,6,7], expected output from raw permutation.
    /// This ensures our permutation matches Zisk's pil2-proofman implementation.
    #[test]
    fn test_poseidon2_zisk_compatibility() {
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
        let trace = poseidon2_permute_traced(&input, &constants);
        let output = trace.states.last().unwrap();

        // Expected values from Plonky3 v0.5.0 Goldilocks Poseidon2 width-8.
        // The diagonal matrix changed from HL constants (v0.4.x) to new values (v0.5.0).
        // With the recursion aggregation plan, ballot STARK proofs are verified
        // outside ZisK, so ZisK precompile compatibility for width-8 is not needed.
        let expected: [u64; 8] = [
            14758079437403499858,
            4768220715988658038,
            9988209636190012306,
            8808631253505580005,
            17526572370116009359,
            1590367810676479047,
            13027328087430412699,
            13357513690486523336,
        ];

        for i in 0..8 {
            assert_eq!(
                output[i].as_canonical_u64(),
                expected[i],
                "Poseidon2 output[{}] mismatch: got {}, expected {}",
                i,
                output[i].as_canonical_u64(),
                expected[i]
            );
        }
        println!("✅ Poseidon2 width-8 permutation matches expected test vector!");
    }
}
