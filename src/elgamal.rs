//! ElGamal encryption helpers using the ecgfp5 curve.
//!
//! In the DAVINCI protocol, each vote field is encrypted with ElGamal:
//!   C1 = k * G
//!   C2 = field_val * G + k * PK
//! where k is random, G is the generator, and PK is the public key.
//!
//! These helpers handle key generation and input preparation. The actual
//! scalar multiplications happen inside the STARK trace, not here.

use ecgfp5::curve::Point;
use ecgfp5::scalar::Scalar;

/// Derive a keypair from arbitrary bytes.
///
/// The bytes are reduced modulo the group order to get the secret key scalar,
/// then the public key is sk * G. Returns (secret_key, public_key).
pub fn keygen(sk_bytes: &[u8]) -> (Scalar, Point) {
    let sk = Scalar::decode_reduce(sk_bytes);
    let pk = Point::mulgen(sk);
    (sk, pk)
}
