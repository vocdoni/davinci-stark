//! Poseidon2 hash function over Goldilocks, with full trace recording.
//!
//! This module is used in two ways:
//!   1. By the trace generator (trace.rs) to compute hashes AND record every
//!      intermediate state for embedding in the STARK execution trace.
//!   2. By standalone callers (tests, wasm) who just want the hash output.
//!
//! Parameters (Zisk-compatible, Horizen Labs variant):
//!   - Width: 8 state elements
//!   - S-box: x^7 (degree 7, STARK-friendly)
//!   - Full rounds: 8 (4 initial + 4 terminal)
//!   - Partial rounds: 22 (S-box on element 0 only)
//!   - Total: 30 rounds per permutation
//!   - Sponge rate: 4, capacity: 4
//!   - 4×4 MDS: Horizen Labs matrix [[5,7,1,3],[4,6,1,1],[1,3,5,7],[1,1,4,6]]
//!   - Round constants: hardcoded from Zisk (pil2-proofman Poseidon8)
//!
//! These parameters match the Zisk zkVM's Poseidon2 precompile, enabling
//! cross-system hash compatibility for proof aggregation.

use p3_goldilocks::Goldilocks;
use p3_field::{PrimeCharacteristicRing, PrimeField64};

/// Poseidon2 parameters for Goldilocks width 8.
pub const WIDTH: usize = 8;
pub const SBOX_DEGREE: u64 = 7;
pub const ROUNDS_F: usize = 8; // 4 initial + 4 terminal
pub const ROUNDS_F_HALF: usize = ROUNDS_F / 2; // 4
pub const ROUNDS_P: usize = 22;
pub const TOTAL_ROUNDS: usize = ROUNDS_F + ROUNDS_P; // 30

/// Internal diagonal matrix for width 8 (from Zisk pil2-proofman Poseidon8).
pub const MATRIX_DIAG_8: [u64; 8] = [
    0xa98811a1fed4e3a5,
    0x1cc48b54f377e2a0,
    0xe40cd4f6c5609a26,
    0x11de79ebca97a4a3,
    0x9177c73d8b7e929c,
    0x2a6fe8085797e791,
    0x3de6e93329f8d5ad,
    0x3f7af9125da962fe,
];

/// Hardcoded round constants from Zisk (pil2-proofman Poseidon8).
///
/// Layout: [4 full rounds × 8 constants] [22 partial round constants] [4 full rounds × 8 constants]
/// Total: 32 + 22 + 32 = 86 constants.
const RC_8: [u64; 86] = [
    // Initial full rounds (4 × 8 = 32)
    0xdd5743e7f2a5a5d9, 0xcb3a864e58ada44b, 0xffa2449ed32f8cdc, 0x42025f65d6bd13ee,
    0x7889175e25506323, 0x34b98bb03d24b737, 0xbdcc535ecc4faa2a, 0x5b20ad869fc0d033,
    0xf1dda5b9259dfcb4, 0x27515210be112d59, 0x4227d1718c766c3f, 0x26d333161a5bd794,
    0x49b938957bf4b026, 0x4a56b5938b213669, 0x1120426b48c8353d, 0x6b323c3f10a56cad,
    0xce57d6245ddca6b2, 0xb1fc8d402bba1eb1, 0xb5c5096ca959bd04, 0x6db55cd306d31f7f,
    0xc49d293a81cb9641, 0x1ce55a4fe979719f, 0xa92e60a9d178a4d1, 0x002cc64973bcfd8c,
    0xcea721cce82fb11b, 0xe5b55eb8098ece81, 0x4e30525c6f1ddd66, 0x43c6702827070987,
    0xaca68430a7b5762a, 0x3674238634df9c93, 0x88cee1c825e33433, 0xde99ae8d74b57176,
    // Partial rounds (22)
    0x488897d85ff51f56, 0x1140737ccb162218, 0xa7eeb9215866ed35, 0x9bd2976fee49fcc9,
    0xc0c8f0de580a3fcc, 0x4fb2dae6ee8fc793, 0x343a89f35f37395b, 0x223b525a77ca72c8,
    0x56ccb62574aaa918, 0xc4d507d8027af9ed, 0xa080673cf0b7e95c, 0xf0184884eb70dcf8,
    0x044f10b0cb3d5c69, 0xe9e3f7993938f186, 0x1b761c80e772f459, 0x606cec607a1b5fac,
    0x14a0c2e1d45f03cd, 0x4eace8855398574f, 0xf905ca7103eff3e6, 0xf8c8f8d20862c059,
    0xb524fe8bdd678e5a, 0xfbb7865901a1ec41,
    // Terminal full rounds (4 × 8 = 32)
    0x014ef1197d341346, 0x9725e20825d07394, 0xfdb25aef2c5bae3b, 0xbe5402dc598c971e,
    0x93a5711f04cdca3d, 0xc45a9a5b2f8fb97b, 0xfe8946a924933545, 0x2af997a27369091c,
    0xaa62c88e0b294011, 0x058eb9d810ce9f74, 0xb3cb23eced349ae4, 0xa3648177a77b4a84,
    0x43153d905992d95d, 0xf4e2a97cda44aa4b, 0x5baa2702b908682f, 0x082923bdf4f750d1,
    0x98ae09a325893803, 0xf8a6475077968838, 0xceb0735bf00b2c5f, 0x0a1a5d953888e072,
    0x2fcb190489f94475, 0xb5be06270dec69fc, 0x739cb934b09acf8b, 0x537750b75ec7f25b,
    0xe9dd318bae1f3961, 0xf7462137299efe1a, 0xb1f6b8eee9adb940, 0xbdebcc8a809dfe6b,
    0x40fc1f791b178113, 0x3ac1c3362d014864, 0x9a016184bdb8aeba, 0x95f2394459fbc25e,
];

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
    /// Load the hardcoded Zisk-compatible round constants.
    pub fn new() -> Self {
        let g = |v: u64| Goldilocks::from_u64(v);

        // Initial full rounds: RC_8[0..32] as 4 × 8
        let mut external_rc = Vec::with_capacity(ROUNDS_F);
        for r in 0..ROUNDS_F_HALF {
            let base = r * WIDTH;
            let mut rc = [Goldilocks::ZERO; WIDTH];
            for j in 0..WIDTH {
                rc[j] = g(RC_8[base + j]);
            }
            external_rc.push(rc);
        }

        // Partial rounds: RC_8[32..54] as 22 singles
        let partial_base = ROUNDS_F_HALF * WIDTH;
        let mut internal_rc = Vec::with_capacity(ROUNDS_P);
        for r in 0..ROUNDS_P {
            internal_rc.push(g(RC_8[partial_base + r]));
        }

        // Terminal full rounds: RC_8[54..86] as 4 × 8
        let terminal_base = partial_base + ROUNDS_P;
        for r in 0..ROUNDS_F_HALF {
            let base = terminal_base + r * WIDTH;
            let mut rc = [Goldilocks::ZERO; WIDTH];
            for j in 0..WIDTH {
                rc[j] = g(RC_8[base + j]);
            }
            external_rc.push(rc);
        }

        Self {
            external_rc,
            internal_rc,
        }
    }

    /// Backward compatibility alias (ignores the seed, uses hardcoded constants).
    pub fn from_seed(_seed: u64) -> Self {
        Self::new()
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
    let t2 = x[1] + x[1] + t1;     // 2*x1 + x2 + x3
    let t3 = x[3] + x[3] + t0;     // x0 + x1 + 2*x3
    let t1_2 = t1 + t1;             // 2*x2 + 2*x3
    let t0_2 = t0 + t0;             // 2*x0 + 2*x1
    let t4 = t1_2 + t1_2 + t3;     // x0 + x1 + 4*x2 + 6*x3
    let t5 = t0_2 + t0_2 + t2;     // 4*x0 + 6*x1 + x2 + x3
    let t6 = t3 + t5;               // 5*x0 + 7*x1 + x2 + 3*x3
    let t7 = t2 + t4;               // x0 + 3*x1 + 5*x2 + 7*x3
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
        state[i] = state[i] * Goldilocks::from_u64(MATRIX_DIAG_8[i] % Goldilocks::ORDER_U64) + sum;
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

    #[test]
    fn test_poseidon2_permute_deterministic() {
        let constants = Poseidon2Constants::from_seed(42);
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
        let constants = Poseidon2Constants::from_seed(42);
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

        // Expected values from Zisk's test_poseidon2_8 in pil2-proofman
        let expected: [u64; 8] = [
            14266028122062624699,
            5353147180106052723,
            15203350112844181434,
            17630919042639565165,
            16601551015858213987,
            10184091939013874068,
            16774100645754596496,
            12047415603622314780,
        ];

        for i in 0..8 {
            assert_eq!(
                output[i].as_canonical_u64(),
                expected[i],
                "Poseidon2 output[{}] mismatch: got {}, expected {} (Zisk)",
                i,
                output[i].as_canonical_u64(),
                expected[i]
            );
        }
        println!("✅ Poseidon2 permutation matches Zisk test vector!");
    }
}
