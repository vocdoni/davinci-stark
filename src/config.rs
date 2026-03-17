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
//! We use width-8 Goldilocks Poseidon2 for all STARK infrastructure hashing.
//! This matches the Plonky3-recursion library's Goldilocks configuration,
//! enabling native recursive proof aggregation.

use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::Field;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters, HidingFriPcs};
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks, default_goldilocks_poseidon2_8};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::StarkConfig;

// -- Type aliases for the full STARK configuration stack. --

/// Base field: Goldilocks (p = 2^64 - 2^32 + 1).
pub type Val = Goldilocks;

/// Poseidon2 permutation over Goldilocks with width 8.
/// Matches the Plonky3-recursion GoldilocksD2Width8 configuration.
pub type Perm = Poseidon2Goldilocks<8>;

/// Width and rate constants for the width-8 Poseidon2 sponge.
pub const PERM_WIDTH: usize = 8;
pub const PERM_RATE: usize = 4;
pub const DIGEST_ELEMS: usize = 4;

/// Sponge hash wrapping the width-8 permutation: absorbs 4, squeezes 4.
pub type MyHash = PaddingFreeSponge<Perm, PERM_WIDTH, PERM_RATE, DIGEST_ELEMS>;

/// Merkle tree compression: truncated permutation producing 4-element digests.
pub type MyCompress = TruncatedPermutation<Perm, 2, DIGEST_ELEMS, PERM_WIDTH>;

/// Merkle-tree-based MMCS (multi-matrix commitment scheme) over Goldilocks values.
pub type ValMmcs = MerkleTreeMmcs<
    <Val as Field>::Packing,
    <Val as Field>::Packing,
    MyHash,
    MyCompress,
    2,
    DIGEST_ELEMS,
>;

/// Challenge field: degree-2 extension of Goldilocks (gives ~128-bit security).
pub type Challenge = BinomialExtensionField<Val, 2>;

/// MMCS lifted to the challenge (extension) field.
pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;

/// Fiat-Shamir challenger using the width-8 Poseidon2 duplex sponge.
pub type Challenger = DuplexChallenger<Val, Perm, PERM_WIDTH, PERM_RATE>;

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
pub fn make_prover_config() -> BallotConfig {
    let seed = entropy_seed();
    make_config_with_rng_seed(seed)
}

/// Build the STARK configuration with a fixed blinding seed.
///
/// This is the config the VERIFIER should use. The verifier never generates
/// blinding codewords, so the RNG seed is irrelevant.
pub fn make_verifier_config() -> BallotConfig {
    make_config_with_rng_seed(0)
}

/// Internal: build the config with a specific blinding RNG seed.
fn make_config_with_rng_seed(blinding_seed: u64) -> BallotConfig {
    let perm = default_goldilocks_poseidon2_8();
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
