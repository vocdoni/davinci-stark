//! WASM bindings for the ballot proof.
//!
//! These are the functions exposed to JavaScript via wasm-bindgen. The browser
//! calls them through a Web Worker so proving does not block the main thread.
//!
//! Data format convention: all multi-element values are passed as byte arrays
//! with u64 little-endian encoding. For example, a 4-element Goldilocks array
//! is 32 bytes (4 x 8 bytes). EC points are encoded as 5 GF(p) limbs = 40 bytes.
//!
//! The proof wire format is: [4 bytes proof_len LE][proof_bytes][public_values_bytes]
//! where proof_bytes is the postcard-serialized STARK proof and public_values_bytes
//! is the raw u64-LE encoding of the public value vector.

use ecgfp5::curve::Point;
use ecgfp5::scalar::Scalar;
use js_sys::Date;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use wasm_bindgen::prelude::*;

use crate::air::NUM_FIELDS;
use crate::trace::BallotInputs;

const WASM_BUILD_COMMIT: &str = env!("WASM_BUILD_COMMIT");

/// Set up the panic hook so Rust panics show readable messages in the
/// browser console instead of just "unreachable executed". This runs
/// automatically when the WASM module is instantiated.
#[wasm_bindgen(start)]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

/// Derive a public key from arbitrary secret bytes.
///
/// Takes any byte slice, reduces it modulo the ecgfp5 group order to get
/// a secret scalar, then computes sk * G to get the public key point.
/// Returns 40 bytes: the encoded point as 5 x u64 LE limbs.
#[wasm_bindgen]
pub fn generate_keypair(sk_bytes: &[u8]) -> Vec<u8> {
    let (_, pk) = crate::elgamal::keygen(sk_bytes);
    let enc = pk.encode();
    let mut out = vec![0u8; 40];
    for i in 0..5 {
        out[i * 8..(i + 1) * 8].copy_from_slice(&enc.0[i].to_u64().to_le_bytes());
    }
    out
}

#[wasm_bindgen]
pub fn wasm_build_commit() -> String {
    WASM_BUILD_COMMIT.to_string()
}

#[wasm_bindgen]
pub struct ProveFullResult {
    proof_data: Vec<u8>,
    decode_ms: f64,
    trace_ms: f64,
    prove_ms: f64,
    serialize_ms: f64,
}

#[wasm_bindgen]
impl ProveFullResult {
    #[wasm_bindgen(getter, js_name = proofData)]
    pub fn proof_data(&self) -> Vec<u8> {
        self.proof_data.clone()
    }

    #[wasm_bindgen(getter, js_name = decodeMs)]
    pub fn decode_ms(&self) -> f64 {
        self.decode_ms
    }

    #[wasm_bindgen(getter, js_name = traceMs)]
    pub fn trace_ms(&self) -> f64 {
        self.trace_ms
    }

    #[wasm_bindgen(getter, js_name = proveMs)]
    pub fn prove_ms(&self) -> f64 {
        self.prove_ms
    }

    #[wasm_bindgen(getter, js_name = serializeMs)]
    pub fn serialize_ms(&self) -> f64 {
        self.serialize_ms
    }
}

/// Generate a full 8-field ballot proof (the main entry point for voting).
///
/// All byte arrays use u64 little-endian encoding. Returns the serialized
/// proof in the wire format described in the module doc.
///
/// Arguments:
///   k_bytes      - encryption randomness (arbitrary length, reduced mod order)
///   fields       - 8 vote field values as 64 bytes (8 x u64 LE)
///   pk_bytes     - encryption public key as 40 bytes (5 x u64 LE)
///   process_id   - voting process identifier as 32 bytes (4 x u64 LE)
///   address      - voter address as 32 bytes (4 x u64 LE)
///   weight       - voter weight as 8 bytes (u64 LE)
///   ballot_mode  - packed ballot configuration as 32 bytes (4 x u64 LE)
#[wasm_bindgen]
pub fn prove_full(
    k_bytes: &[u8],
    fields: &[u8],
    pk_bytes: &[u8],
    process_id: &[u8],
    address: &[u8],
    weight: &[u8],
    ballot_mode: &[u8],
) -> Result<Vec<u8>, JsValue> {
    Ok(prove_full_detailed(
        k_bytes,
        fields,
        pk_bytes,
        process_id,
        address,
        weight,
        ballot_mode,
    )?
    .proof_data)
}

#[wasm_bindgen]
pub fn prove_full_detailed(
    k_bytes: &[u8],
    fields: &[u8],
    pk_bytes: &[u8],
    process_id: &[u8],
    address: &[u8],
    weight: &[u8],
    ballot_mode: &[u8],
) -> Result<ProveFullResult, JsValue> {
    let decode_start = now_ms();
    let k = Scalar::decode_reduce(k_bytes);
    let pk = decode_pk(pk_bytes).map_err(|e| JsValue::from_str(&e))?;

    // Decode field values (8 x u64 LE)
    if fields.len() != NUM_FIELDS * 8 {
        return Err(JsValue::from_str(&format!(
            "fields must be {} bytes (8 x u64), got {}",
            NUM_FIELDS * 8,
            fields.len()
        )));
    }
    let mut field_scalars = [Scalar([0, 0, 0, 0, 0]); NUM_FIELDS];
    for i in 0..NUM_FIELDS {
        let val = u64::from_le_bytes([
            fields[i * 8],
            fields[i * 8 + 1],
            fields[i * 8 + 2],
            fields[i * 8 + 3],
            fields[i * 8 + 4],
            fields[i * 8 + 5],
            fields[i * 8 + 6],
            fields[i * 8 + 7],
        ]);
        field_scalars[i] = Scalar([val, 0, 0, 0, 0]);
    }

    // Decode process_id and address (4 x u64 LE each)
    let pid = decode_4u64(process_id, "process_id")?;
    let addr = decode_4u64(address, "address")?;

    // Decode weight (u64 LE, 8 bytes)
    if weight.len() != 8 {
        return Err(JsValue::from_str(&format!(
            "weight must be 8 bytes (u64), got {}",
            weight.len()
        )));
    }
    let w = u64::from_le_bytes([
        weight[0], weight[1], weight[2], weight[3], weight[4], weight[5], weight[6], weight[7],
    ]);

    // Decode packed ballot mode (4 x u64 LE = 32 bytes)
    let bm = decode_4u64(ballot_mode, "ballot_mode")?;

    let inputs = BallotInputs {
        k,
        fields: field_scalars,
        pk,
        process_id: pid,
        address: addr,
        weight: Goldilocks::from_u64(w % Goldilocks::ORDER_U64),
        packed_ballot_mode: bm,
    };
    let decode_ms = now_ms() - decode_start;

    let trace_start = now_ms();
    let (trace, public_values, _outputs) = crate::trace::generate_full_ballot_trace(&inputs);
    let trace_ms = now_ms() - trace_start;

    let prove_start = now_ms();
    let config = crate::config::make_prover_config();
    let air = crate::air::BallotAir::new();
    let proof = p3_uni_stark::prove(&config, &air, trace, &public_values);
    let prove_ms = now_ms() - prove_start;

    let ballot_proof = crate::BallotProof {
        proof,
        public_values,
    };
    // Serialize proof + public values
    let serialize_start = now_ms();
    let proof_bytes = postcard::to_allocvec(&ballot_proof.proof)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))?;

    let mut pv_bytes = vec![0u8; ballot_proof.public_values.len() * 8];
    for (i, v) in ballot_proof.public_values.iter().enumerate() {
        let raw: u64 = Goldilocks::as_canonical_u64(v);
        pv_bytes[i * 8..(i + 1) * 8].copy_from_slice(&raw.to_le_bytes());
    }

    // Format: [4 bytes proof_len][proof_bytes][pv_bytes]
    let proof_len = proof_bytes.len() as u32;
    let mut out = Vec::with_capacity(4 + proof_bytes.len() + pv_bytes.len());
    out.extend_from_slice(&proof_len.to_le_bytes());
    out.extend_from_slice(&proof_bytes);
    out.extend_from_slice(&pv_bytes);
    let serialize_ms = now_ms() - serialize_start;
    Ok(ProveFullResult {
        proof_data: out,
        decode_ms,
        trace_ms,
        prove_ms,
        serialize_ms,
    })
}

fn now_ms() -> f64 {
    Date::now()
}

/// Verify a ballot proof from its wire-format byte representation.
///
/// Deserializes the proof and public values, reconstructs the STARK config,
/// and runs the Plonky3 verifier. Returns true if valid, false if the proof
/// is well-formed but fails verification. Returns an error if the data is
/// malformed (too short, bad encoding, etc.).
#[wasm_bindgen]
pub fn verify(proof_data: &[u8]) -> Result<bool, JsValue> {
    if proof_data.len() < 4 {
        return Err(JsValue::from_str("Proof data too short"));
    }

    let proof_len =
        u32::from_le_bytes([proof_data[0], proof_data[1], proof_data[2], proof_data[3]]) as usize;

    if proof_data.len() < 4 + proof_len {
        return Err(JsValue::from_str("Invalid proof data length"));
    }

    let proof_bytes = &proof_data[4..4 + proof_len];
    let pv_bytes = &proof_data[4 + proof_len..];
    let expected_pv_bytes = crate::air::PV_COUNT * 8;
    if pv_bytes.len() != expected_pv_bytes {
        return Err(JsValue::from_str(&format!(
            "Invalid public value length: expected {} bytes, got {}",
            expected_pv_bytes,
            pv_bytes.len()
        )));
    }
    if pv_bytes.len() % 8 != 0 {
        return Err(JsValue::from_str(
            "Invalid public value encoding: trailing bytes present",
        ));
    }

    let proof: p3_uni_stark::Proof<crate::config::BallotConfig> = postcard::from_bytes(proof_bytes)
        .map_err(|e| JsValue::from_str(&format!("Deserialization error: {}", e)))?;

    let pv_count = pv_bytes.len() / 8;
    let mut pv = Vec::with_capacity(pv_count);
    for i in 0..pv_count {
        let raw = u64::from_le_bytes([
            pv_bytes[i * 8],
            pv_bytes[i * 8 + 1],
            pv_bytes[i * 8 + 2],
            pv_bytes[i * 8 + 3],
            pv_bytes[i * 8 + 4],
            pv_bytes[i * 8 + 5],
            pv_bytes[i * 8 + 6],
            pv_bytes[i * 8 + 7],
        ]);
        pv.push(Goldilocks::from_u64(raw));
    }

    let ballot_proof = crate::BallotProof {
        proof,
        public_values: pv,
    };

    match crate::verify_ballot(&ballot_proof) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Decode a 40-byte encoded ecgfp5 public key into a Point.
/// Returns an error if the encoding does not correspond to a valid curve point.
fn decode_pk(pk_bytes: &[u8]) -> Result<Point, String> {
    if pk_bytes.len() != 40 {
        return Err(format!("PK must be 40 bytes, got {}", pk_bytes.len()));
    }
    use ecgfp5::field::{GFp, GFp5};
    let mut limbs = [0u64; 5];
    for i in 0..5 {
        limbs[i] = u64::from_le_bytes([
            pk_bytes[i * 8],
            pk_bytes[i * 8 + 1],
            pk_bytes[i * 8 + 2],
            pk_bytes[i * 8 + 3],
            pk_bytes[i * 8 + 4],
            pk_bytes[i * 8 + 5],
            pk_bytes[i * 8 + 6],
            pk_bytes[i * 8 + 7],
        ]);
    }
    let w = GFp5([
        GFp::from_u64_reduce(limbs[0]),
        GFp::from_u64_reduce(limbs[1]),
        GFp::from_u64_reduce(limbs[2]),
        GFp::from_u64_reduce(limbs[3]),
        GFp::from_u64_reduce(limbs[4]),
    ]);
    let (point, ok) = Point::decode(w);
    if ok == 0 {
        return Err("Invalid point encoding".to_string());
    }
    Ok(point)
}

/// Decode 32 bytes into 4 Goldilocks elements (each reduced mod p).
/// Used for process_id, address, and ballot_mode fields.
fn decode_4u64(bytes: &[u8], name: &str) -> Result<[Goldilocks; 4], JsValue> {
    if bytes.len() != 32 {
        return Err(JsValue::from_str(&format!(
            "{} must be 32 bytes (4 x u64), got {}",
            name,
            bytes.len()
        )));
    }
    let mut result = [Goldilocks::ZERO; 4];
    for i in 0..4 {
        let val = u64::from_le_bytes([
            bytes[i * 8],
            bytes[i * 8 + 1],
            bytes[i * 8 + 2],
            bytes[i * 8 + 3],
            bytes[i * 8 + 4],
            bytes[i * 8 + 5],
            bytes[i * 8 + 6],
            bytes[i * 8 + 7],
        ]);
        result[i] = Goldilocks::from_u64(val % Goldilocks::ORDER_U64);
    }
    Ok(result)
}
