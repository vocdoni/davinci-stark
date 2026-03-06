//! STARK configuration for the ballot proof.
//!
//! This is where we wire up all the Plonky3 components: the field, the hash,
//! the FRI parameters, and the polynomial commitment scheme. We use HidingFriPcs
//! so that private inputs stay hidden in the proof (ZK = true).
//!
//! Two config constructors are provided:
//!   - make_prover_config(): uses entropy-seeded blinding RNG (for real ZK)
//!   - make_verifier_config(): uses a dummy RNG (verifier never blinds)
//!
//! The FRI parameters target ~100-bit security:
//!   - log_blowup=3 (blowup factor 8, minimum for degree-7 constraints)
//!   - num_queries=28 (28 x 3 = 84 bits from query soundness)
//!   - proof_of_work_bits=16 (adds 16 bits, reaching 100 total)
//!
//! Note: We ship a patched p3-challenger that fixes the PoW grinding bug on
//! wasm32. The original code does `F::ORDER_U64 as usize` which truncates
//! to 1 on 32-bit targets. Our patch divides in u64 first and clamps.

use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::Field;
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_miden_fri::{HidingFriPcs, FriParameters};
use p3_miden_prover::StarkConfig;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};

// -- Type aliases for the full STARK configuration stack. --
// Each layer builds on the previous one: field -> hash -> Merkle tree -> PCS -> config.

/// Base field: Goldilocks (p = 2^64 - 2^32 + 1).
pub type Val = Goldilocks;

/// Poseidon2 permutation over Goldilocks with width 16 (used for Merkle hashing,
/// not to be confused with the width-8 Poseidon2 inside the ballot AIR).
pub type Perm = Poseidon2Goldilocks<16>;

/// Sponge hash wrapping the width-16 permutation: absorbs 8, squeezes 8.
pub type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;

/// Merkle tree compression: truncated permutation producing 8-element digests.
pub type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;

/// Merkle-tree-based MMCS (multi-matrix commitment scheme) over Goldilocks values.
pub type ValMmcs =
    MerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, MyHash, MyCompress, 8>;

/// Challenge field: degree-2 extension of Goldilocks (gives ~128-bit security).
pub type Challenge = BinomialExtensionField<Val, 2>;

/// MMCS lifted to the challenge (extension) field.
pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;

/// Fiat-Shamir challenger using the width-16 Poseidon2 duplex sponge.
pub type Challenger = DuplexChallenger<Val, Perm, 16, 8>;

/// DFT implementation: radix-2 DIT (decimation-in-time) with parallel butterflies.
pub type Dft = Radix2DitParallel<Val>;

/// Polynomial commitment scheme: FRI with hiding (ZK = true).
/// The DeterministicRng provides blinding randomness -- fine for PoC, but a real
/// deployment should swap this for OsRng or another CSPRNG.
pub type Pcs = HidingFriPcs<Val, Dft, ValMmcs, ChallengeMmcs, DeterministicRng>;

/// Wrapper that makes BallotConfig safe to pass across thread boundaries.
///
/// HidingFriPcs stores a RefCell<R> internally for the blinding RNG. RefCell
/// is not Sync, but Plonky3's prove/verify functions require `SC: Sync`.
/// Since we never actually use parallel proving (especially in WASM), the
/// Sync bound is purely a trait requirement, not a real concurrency concern.
#[repr(transparent)]
pub struct SyncBallotConfig(pub BallotConfig);

// SAFETY: We only prove single-threaded. The RefCell inside HidingFriPcs is never
// accessed from multiple threads. This holds in WASM (inherently single-threaded)
// and in our native builds (parallel feature is off by default).
unsafe impl Sync for SyncBallotConfig {}
unsafe impl Send for SyncBallotConfig {}

impl p3_miden_prover::StarkGenericConfig for SyncBallotConfig {
    type Pcs = Pcs;
    type Challenge = Challenge;
    type Challenger = Challenger;

    fn pcs(&self) -> &Self::Pcs { self.0.pcs() }
    fn initialise_challenger(&self) -> Self::Challenger { self.0.initialise_challenger() }
}

/// The inner STARK config type before we wrap it for Sync.
pub type BallotConfig = StarkConfig<Pcs, Challenge, Challenger>;

/// Build the STARK configuration with an entropy-seeded blinding RNG.
///
/// This is the config the PROVER should use. The blinding RNG is seeded from
/// OS entropy (crypto.getRandomValues on WASM, /dev/urandom on Linux) so the
/// hiding codewords are unpredictable. This is essential for zero-knowledge.
///
/// FRI parameters are set for ~100-bit security:
/// - log_blowup=3 (blowup factor 8, needed for degree-7 constraints)
/// - num_queries=28 (84 bits from query soundness)
/// - proof_of_work_bits=16 (adds 16 bits → 100 total, ~65K hash trials)
pub fn make_prover_config() -> SyncBallotConfig {
    let seed = entropy_seed();
    make_config_with_rng_seed(seed)
}

/// Build the STARK configuration with a dummy blinding RNG.
///
/// This is the config the VERIFIER should use. The verifier never generates
/// blinding codewords, so the RNG seed is irrelevant. Using a fixed seed
/// avoids needing OS entropy on the verifier side.
pub fn make_verifier_config() -> SyncBallotConfig {
    make_config_with_rng_seed(0)
}

/// Backward-compatible alias: uses entropy-seeded RNG (prover config).
pub fn make_config() -> SyncBallotConfig {
    make_prover_config()
}

/// Internal: build the config with a specific blinding RNG seed.
fn make_config_with_rng_seed(blinding_seed: u64) -> SyncBallotConfig {
    let perm = Perm::new_from_rng_128(&mut DeterministicRng(42));
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    let fri_params = FriParameters {
        log_blowup: 3,
        log_final_poly_len: 0,
        num_queries: 28,
        proof_of_work_bits: 16,
        mmcs: challenge_mmcs,
        log_folding_factor: 1,
    };
    let rng = DeterministicRng(blinding_seed);
    let pcs = Pcs::new(dft, val_mmcs, fri_params, 1, rng);
    let challenger = Challenger::new(perm);
    SyncBallotConfig(BallotConfig::new(pcs, challenger))
}

/// Get a random u64 seed from OS entropy. Falls back to a fixed value if
/// entropy is unavailable (should not happen on any supported platform).
fn entropy_seed() -> u64 {
    let mut buf = [0u8; 8];
    if getrandom::getrandom(&mut buf).is_ok() {
        u64::from_le_bytes(buf)
    } else {
        // Fallback: time-based or fixed. Should never happen in practice.
        0xDAFC_1BAC_0000_0001
    }
}

/// A simple splitmix64-based RNG for deterministic constant generation.
///
/// Used in two places:
/// 1. Generating Poseidon2 round constants (seed 42)
/// 2. Producing blinding randomness in HidingFriPcs (seed 123)
///
/// This is fine for a PoC because reproducibility matters more than entropy.
/// In production, replace the blinding RNG with a real CSPRNG.
pub struct DeterministicRng(pub u64);

impl rand::RngCore for DeterministicRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        // splitmix64: simple, fast, deterministic
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut i = 0;
        while i < dest.len() {
            let val = self.next_u64();
            let remaining = dest.len() - i;
            let to_copy = remaining.min(8);
            dest[i..i + to_copy].copy_from_slice(&val.to_le_bytes()[..to_copy]);
            i += to_copy;
        }
    }
}

// Mark as CryptoRng to satisfy trait bounds. The actual entropy is not
// cryptographic -- see the note above about replacing this in production.
impl rand::CryptoRng for DeterministicRng {}
