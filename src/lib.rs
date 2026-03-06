//! davinci-stark: zkSTARK ballot proof for the DAVINCI e-voting protocol.
//!
//! This crate builds an Algebraic Intermediate Representation (AIR) over the
//! Goldilocks field using Plonky3, proving that an ElGamal-encrypted ballot
//! was constructed honestly. The circuit handles 8 vote fields, a Poseidon2
//! k-derivation chain, vote ID computation, and an inputs hash.
//!
//! Everything compiles to WASM for in-browser proving.

pub mod air;
pub mod columns;
pub mod config;
pub mod ecgfp5_ops;
pub mod elgamal;
pub mod gfp5;
pub mod poseidon2;
pub mod trace;

#[cfg(target_arch = "wasm32")]
pub mod wasm;

use p3_goldilocks::Goldilocks;
use p3_miden_prover::{prove, verify, Proof};
use ecgfp5::curve::Point;
use ecgfp5::scalar::Scalar;

use air::BallotAir;
use config::{SyncBallotConfig, make_config};
use trace::{generate_ballot_trace, generate_full_ballot_trace, BallotInputs, BallotOutputs};

/// A complete ballot proof: the STARK proof object plus the public values
/// that were committed to during proving. Both are needed for verification.
pub struct BallotProof {
    pub proof: Proof<SyncBallotConfig>,
    pub public_values: Vec<Goldilocks>,
}

/// Prove a single-field ElGamal encryption (legacy API, mostly for tests).
///
/// This is the backward-compatible entry point that proves one (C1, C2) pair.
/// For the full 8-field ballot proof, use `prove_full_ballot` instead.
pub fn prove_ballot(k: &Scalar, field_val: &Scalar, pk: &Point) -> BallotProof {
    let config = make_config();
    let air = BallotAir::new();
    let (trace, pv) = generate_ballot_trace(k, field_val, pk);
    let proof = prove(&config, &air, &trace, &pv);
    BallotProof {
        proof,
        public_values: pv,
    }
}

/// Prove a full 8-field ballot: ElGamal encryption of each field, k-derivation
/// chain, vote ID computation, and inputs hash.
///
/// Returns the proof and the computed outputs (C1/C2 points, vote_id, etc.)
/// so the caller can use them for further processing or display.
pub fn prove_full_ballot(inputs: &BallotInputs) -> (BallotProof, BallotOutputs) {
    let config = make_config();
    let air = BallotAir::new();
    let (trace, pv, outputs) = generate_full_ballot_trace(inputs);
    let proof = prove(&config, &air, &trace, &pv);
    (
        BallotProof {
            proof,
            public_values: pv,
        },
        outputs,
    )
}

/// Verify a ballot proof against its public values.
///
/// Reconstructs the STARK config (deterministic, same as the prover), then
/// runs the Plonky3 verifier. Returns Ok(()) if the proof is valid.
pub fn verify_ballot(ballot_proof: &BallotProof) -> Result<(), impl core::fmt::Debug> {
    let config = make_config();
    let air = BallotAir::new();
    let var_len_pis: Vec<&[&[Goldilocks]]> = vec![];
    verify(
        &config,
        &air,
        &ballot_proof.proof,
        &ballot_proof.public_values,
        &var_len_pis,
    )
}
