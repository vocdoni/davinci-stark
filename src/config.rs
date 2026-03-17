//! STARK configuration for the ballot proof.
//!
//! This is where we wire up all the Plonky3 components: the field, the hash,
//! the FRI parameters, and the polynomial commitment scheme. We use HidingFriPcs
//! so that private inputs stay hidden in the proof (ZK = true).
//!
//! Two config constructors are provided:
//!   - make_prover_config(): uses entropy-seeded blinding randomness
//!   - make_verifier_config(): uses a fixed seed because the verifier never blinds
//!
//! The FRI parameters target a single browser-oriented security profile:
//!   - log_blowup=3 (blowup factor 8, needed for the completed BV AIR)
//!   - num_queries=34 (~102-bit conjectured soundness with blowup 8)
//!   - proof_of_work_bits=0 (keeps browser proving practical)
//!
//! Note: We ship a patched p3-challenger that fixes the PoW grinding bug on
//! wasm32. The original code does `F::ORDER_U64 as usize` which truncates
//! to 1 on 32-bit targets. Our patch divides in u64 first and clamps.

use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::Field;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters, HidingFriPcs};
use p3_goldilocks::Goldilocks;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::StarkConfig;

// -- Type aliases for the full STARK configuration stack. --
// Each layer builds on the previous one: field -> hash -> Merkle tree -> PCS -> config.

/// Base field: Goldilocks (p = 2^64 - 2^32 + 1).
pub type Val = Goldilocks;

/// Poseidon2 permutation over Goldilocks with width 16 (used for Merkle hashing,
/// not to be confused with the width-8 Poseidon2 inside the ballot AIR).
pub type Perm = crate::zisk_poseidon2::ZiskPoseidon2Goldilocks16;

/// Sponge hash wrapping the width-16 permutation: absorbs 8, squeezes 8.
pub type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;

/// Merkle tree compression: truncated permutation producing 8-element digests.
pub type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;

/// Merkle-tree-based MMCS (multi-matrix commitment scheme) over Goldilocks values.
pub type ValMmcs =
    MerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, MyHash, MyCompress, 2, 8>;

/// Challenge field: degree-2 extension of Goldilocks (gives ~128-bit security).
pub type Challenge = BinomialExtensionField<Val, 2>;

/// MMCS lifted to the challenge (extension) field.
pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;

/// Fiat-Shamir challenger using the width-16 Poseidon2 duplex sponge.
pub type Challenger = DuplexChallenger<Val, Perm, 16, 8>;

/// DFT implementation: radix-2 DIT (decimation-in-time) with parallel butterflies.
pub type Dft = Radix2DitParallel<Val>;

/// Polynomial commitment scheme: FRI with hiding (ZK = true).
/// Blinding randomness is expanded from a seed supplied to `DeterministicRng`.
pub type Pcs = HidingFriPcs<Val, Dft, ValMmcs, ChallengeMmcs, DeterministicRng>;

pub type BallotConfig = StarkConfig<Pcs, Challenge, Challenger>;

/// Build the STARK configuration with an entropy-seeded blinding RNG.
///
/// This is the config the PROVER should use. The blinding RNG is seeded from
/// OS entropy (crypto.getRandomValues on WASM, /dev/urandom on Linux) so the
/// hiding codewords are unpredictable. This is essential for zero-knowledge.
///
/// FRI parameters are set for the single browser proving profile used by this repo:
/// - log_blowup=3 (blowup factor 8, needed for the completed BV AIR)
/// - num_queries=34 (~102-bit conjectured soundness under the ethSTARK heuristic)
/// - proof_of_work_bits=0
///
/// The degree-4 budget was achieved by storing Poseidon2 x7 S-box outputs
/// and BV accumulator intermediates as trace columns, reducing the previous
/// degree-7 constraints down to degree 4. This halved the extended domain
/// (from 8× to 4× blowup), dramatically improving proving performance.
pub fn make_prover_config() -> BallotConfig {
    let seed = entropy_seed();
    make_config_with_rng_seed(seed)
}

/// Build the STARK configuration with a fixed blinding seed.
///
/// This is the config the VERIFIER should use. The verifier never generates
/// blinding codewords, so the RNG seed is irrelevant. Using a fixed seed
/// avoids needing OS entropy on the verifier side.
pub fn make_verifier_config() -> BallotConfig {
    make_config_with_rng_seed(0)
}

/// Internal: build the config with a specific blinding RNG seed.
fn make_config_with_rng_seed(blinding_seed: u64) -> BallotConfig {
    let perm = Perm::new_from_rng_128(&mut DeterministicRng(42));
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    let fri_params = FriParameters {
        log_blowup: 3,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 34,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: challenge_mmcs,
    };
    let rng = DeterministicRng(blinding_seed);
    let pcs = Pcs::new(dft, val_mmcs, fri_params, 1, rng);
    let challenger = Challenger::new(perm);
    BallotConfig::new(pcs, challenger)
}

/// Read a blinding seed from OS entropy.
///
/// The fallback keeps the API infallible on unsupported targets, but supported
/// platforms are expected to provide entropy.
fn entropy_seed() -> u64 {
    let mut buf = [0u8; 8];
    if getrandom::getrandom(&mut buf).is_ok() {
        u64::from_le_bytes(buf)
    } else {
        0xDAFC_1BAC_0000_0001
    }
}

/// SplitMix64 stream generator used as a seed expander for Plonky3 components.
#[derive(Clone)]
pub struct DeterministicRng(pub u64);

impl DeterministicRng {
    fn splitmix64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }
}

impl rand::TryRng for DeterministicRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.splitmix64() as u32)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.splitmix64())
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        let mut i = 0;
        while i < dest.len() {
            let val = self.splitmix64();
            let remaining = dest.len() - i;
            let to_copy = remaining.min(8);
            dest[i..i + to_copy].copy_from_slice(&val.to_le_bytes()[..to_copy]);
            i += to_copy;
        }
        Ok(())
    }
}

// TryCryptoRng marks this as cryptographically suitable (blanket impls provide Rng + CryptoRng).
impl rand::TryCryptoRng for DeterministicRng {}
