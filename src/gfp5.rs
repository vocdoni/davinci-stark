//! GF(p^5) arithmetic constraint helpers.
//!
//! GF(p^5) = GF(p)[x] / (x^5 - 3) where p is the Goldilocks prime.
//! Each element is a tuple (a0, a1, a2, a3, a4) representing a0 + a1*x + ... + a4*x^4.
//!
//! The ecgfp5 curve lives over this extension field, so every EC operation
//! (doubling, addition) boils down to a bunch of GF(p^5) multiplications.
//! We need to constrain these multiplications inside the STARK.
//!
//! The key insight: a GF(p^5) multiplication c = a * b expands to 5 equations
//! of degree 2 in the limbs. So each GF(p^5) product becomes 5 constraints
//! at degree 2, which is very cheap for the STARK.
//!
//! Multiplication formula (schoolbook with reduction mod x^5 - 3):
//!   c0 = a0*b0 + 3*(a1*b4 + a2*b3 + a3*b2 + a4*b1)
//!   c1 = a0*b1 + a1*b0 + 3*(a2*b4 + a3*b3 + a4*b2)
//!   c2 = a0*b2 + a1*b1 + a2*b0 + 3*(a3*b4 + a4*b3)
//!   c3 = a0*b3 + a1*b2 + a2*b1 + a3*b0 + 3*a4*b4
//!   c4 = a0*b4 + a1*b3 + a2*b2 + a3*b1 + a4*b0

use p3_field::{Algebra, PrimeCharacteristicRing};

/// Constrain that c = a * b in GF(p^5).
///
/// Returns 5 expressions (one per limb) that should each evaluate to zero
/// when the multiplication relationship holds. The caller gates these
/// with the appropriate section flag and feeds them to builder.assert_zero.
pub fn gfp5_mul_constraints<F: PrimeCharacteristicRing, E: Algebra<F> + Clone>(
    a: [E; 5],
    b: [E; 5],
    c: [E; 5],
) -> [E; 5] {
    let three = E::from_u16(3);

    [
        // c0 = a0*b0 + 3*(a1*b4 + a2*b3 + a3*b2 + a4*b1)
        c[0].clone()
            - (a[0].clone() * b[0].clone()
                + three.clone()
                    * (a[1].clone() * b[4].clone()
                        + a[2].clone() * b[3].clone()
                        + a[3].clone() * b[2].clone()
                        + a[4].clone() * b[1].clone())),
        // c1 = a0*b1 + a1*b0 + 3*(a2*b4 + a3*b3 + a4*b2)
        c[1].clone()
            - (a[0].clone() * b[1].clone()
                + a[1].clone() * b[0].clone()
                + three.clone()
                    * (a[2].clone() * b[4].clone()
                        + a[3].clone() * b[3].clone()
                        + a[4].clone() * b[2].clone())),
        // c2 = a0*b2 + a1*b1 + a2*b0 + 3*(a3*b4 + a4*b3)
        c[2].clone()
            - (a[0].clone() * b[2].clone()
                + a[1].clone() * b[1].clone()
                + a[2].clone() * b[0].clone()
                + three.clone() * (a[3].clone() * b[4].clone() + a[4].clone() * b[3].clone())),
        // c3 = a0*b3 + a1*b2 + a2*b1 + a3*b0 + 3*a4*b4
        c[3].clone()
            - (a[0].clone() * b[3].clone()
                + a[1].clone() * b[2].clone()
                + a[2].clone() * b[1].clone()
                + a[3].clone() * b[0].clone()
                + three * a[4].clone() * b[4].clone()),
        // c4 = a0*b4 + a1*b3 + a2*b2 + a3*b1 + a4*b0
        c[4].clone()
            - (a[0].clone() * b[4].clone()
                + a[1].clone() * b[3].clone()
                + a[2].clone() * b[2].clone()
                + a[3].clone() * b[1].clone()
                + a[4].clone() * b[0].clone()),
    ]
}

/// Constrain that c = a^2 in GF(p^5). Just calls mul with both inputs set to a.
pub fn gfp5_square_constraints<F: PrimeCharacteristicRing, E: Algebra<F> + Clone>(
    a: [E; 5],
    c: [E; 5],
) -> [E; 5] {
    gfp5_mul_constraints::<F, E>(a.clone(), a, c)
}

/// Constrain that c = a + b in GF(p^5). Limb-wise addition.
pub fn gfp5_add_constraints<F: PrimeCharacteristicRing, E: Algebra<F> + Clone>(
    a: [E; 5],
    b: [E; 5],
    c: [E; 5],
) -> [E; 5] {
    [
        c[0].clone() - (a[0].clone() + b[0].clone()),
        c[1].clone() - (a[1].clone() + b[1].clone()),
        c[2].clone() - (a[2].clone() + b[2].clone()),
        c[3].clone() - (a[3].clone() + b[3].clone()),
        c[4].clone() - (a[4].clone() + b[4].clone()),
    ]
}

/// Constrain that c = a - b in GF(p^5). Limb-wise subtraction.
pub fn gfp5_sub_constraints<F: PrimeCharacteristicRing, E: Algebra<F> + Clone>(
    a: [E; 5],
    b: [E; 5],
    c: [E; 5],
) -> [E; 5] {
    [
        c[0].clone() - (a[0].clone() - b[0].clone()),
        c[1].clone() - (a[1].clone() - b[1].clone()),
        c[2].clone() - (a[2].clone() - b[2].clone()),
        c[3].clone() - (a[3].clone() - b[3].clone()),
        c[4].clone() - (a[4].clone() - b[4].clone()),
    ]
}

/// Compute k * a in GF(p^5) where k is a small integer constant.
/// No constraints here -- this is a pure symbolic expression builder.
pub fn gfp5_scale<F: PrimeCharacteristicRing, E: Algebra<F> + Clone>(k: u64, a: [E; 5]) -> [E; 5] {
    let kf = E::from_u64(k);
    [
        kf.clone() * a[0].clone(),
        kf.clone() * a[1].clone(),
        kf.clone() * a[2].clone(),
        kf.clone() * a[3].clone(),
        kf * a[4].clone(),
    ]
}

/// Compute a + b in GF(p^5) as a symbolic expression. No constraints.
pub fn gfp5_add<F: PrimeCharacteristicRing, E: Algebra<F> + Clone>(a: [E; 5], b: [E; 5]) -> [E; 5] {
    [
        a[0].clone() + b[0].clone(),
        a[1].clone() + b[1].clone(),
        a[2].clone() + b[2].clone(),
        a[3].clone() + b[3].clone(),
        a[4].clone() + b[4].clone(),
    ]
}

/// Compute a - b in GF(p^5) as a symbolic expression. No constraints.
pub fn gfp5_sub<F: PrimeCharacteristicRing, E: Algebra<F> + Clone>(a: [E; 5], b: [E; 5]) -> [E; 5] {
    [
        a[0].clone() - b[0].clone(),
        a[1].clone() - b[1].clone(),
        a[2].clone() - b[2].clone(),
        a[3].clone() - b[3].clone(),
        a[4].clone() - b[4].clone(),
    ]
}
