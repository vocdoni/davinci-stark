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

use air::BallotAir;
use config::{BallotConfig, make_prover_config, make_verifier_config};
use p3_goldilocks::Goldilocks;
use poseidon2::{Poseidon2Constants, poseidon2_hash};
use p3_uni_stark::{Proof, prove, verify};
use trace::{BallotInputs, BallotOutputs, generate_full_ballot_trace};

/// A complete ballot proof: the STARK proof object plus the public values
/// that were committed to during proving. Both are needed for verification.
pub struct BallotProof {
    pub proof: Proof<BallotConfig>,
    pub public_values: Vec<Goldilocks>,
}

/// Prove a full 8-field ballot: ElGamal encryption of each field, k-derivation
/// chain, vote ID computation, and inputs hash.
///
/// Returns the proof and the computed outputs (C1/C2 points, vote_id, etc.)
/// so the caller can use them for further processing or display.
pub fn prove_full_ballot(inputs: &BallotInputs) -> (BallotProof, BallotOutputs) {
    let config = make_prover_config();
    let air = BallotAir::new();
    let (trace, pv, outputs) = generate_full_ballot_trace(inputs);
    let proof = prove(&config, &air, trace, &pv);
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
pub fn verify_ballot(ballot_proof: &BallotProof) -> Result<(), String> {
    let config = make_verifier_config();
    let air = BallotAir::new();
    verify(
        &config,
        &air,
        &ballot_proof.proof,
        &ballot_proof.public_values,
    )
    .map_err(|err| format!("{err:?}"))?;

    let pv = &ballot_proof.public_values;
    if pv.len() != air::PV_COUNT {
        return Err(format!(
            "invalid public-value length: expected {}, got {}",
            air::PV_COUNT,
            pv.len()
        ));
    }

    let preimage = &pv[air::PV_INPUTS_PREIMAGE..air::PV_INPUTS_PREIMAGE + air::PV_INPUTS_PREIMAGE_COUNT];
    let expected_hash = poseidon2_hash(preimage, 4, &Poseidon2Constants::new());
    if expected_hash.as_slice() != &pv[air::PV_INPUTS_HASH..air::PV_INPUTS_HASH + 4] {
        return Err("inputs_hash does not match the public preimage".to_string());
    }
    if preimage[28..32] != pv[air::PV_ADDRESS..air::PV_ADDRESS + 4] {
        return Err("address does not match the public preimage".to_string());
    }
    if preimage[32] != pv[air::PV_VOTE_ID] {
        return Err("vote_id does not match the public preimage".to_string());
    }
    Ok(())
}
