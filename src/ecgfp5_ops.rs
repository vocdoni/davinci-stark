//! EC point operation trace generation for the ecgfp5 curve.
//!
//! This module computes all the intermediate values needed for EC point
//! doubling and addition, filling the trace columns so the STARK prover
//! can later verify them through the AIR constraints in air.rs.
//!
//! The ecgfp5 curve uses Jacobi quartic coordinates (X:Z:U:T) and a
//! parameter B1 = 263. The doubling formula uses 9 GF(p^5) products and
//! the addition formula uses 10. We store every intermediate product as
//! a trace column so that each constraint stays at degree 2.

use crate::columns::*;
use ecgfp5::curve::Point;
use ecgfp5::field::GFp5;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;

/// Write a single GF(p^5) element into the trace row at `offset`.
fn write_gfp5(row: &mut [Goldilocks], offset: usize, v: &GFp5) {
    for i in 0..5 {
        row[offset + i] = Goldilocks::from_u64(v.0[i].to_u64());
    }
}

/// Write a full ecgfp5 point (X, Z, U, T) starting at `x_offset`.
fn write_point(row: &mut [Goldilocks], x_offset: usize, p: &Point) {
    write_gfp5(row, x_offset, &p.X);
    write_gfp5(row, x_offset + 5, &p.Z);
    write_gfp5(row, x_offset + 10, &p.U);
    write_gfp5(row, x_offset + 15, &p.T);
}

/// Compute the point doubling intermediates and write them into the trace row.
///
/// This follows the Jacobi quartic doubling formula from the ecgfp5 paper:
///   t1 = Z*T,  t2 = t1*T,  X1 = t2^2,  Z1 = t1*U,  t3 = U^2,
///   xz_t3 = (X+Z)*t3,  W1 = t2 - 2*xz_t3,
///   t4 = Z1^2,  W1sq = W1^2,  wz_sq = (W1+Z1)^2
///
/// Then the doubled point is derived from these intermediates.
/// Returns the doubled point.
pub fn fill_doubling(row: &mut [Goldilocks], acc: &Point) -> Point {
    let (x, z, u, t) = (&acc.X, &acc.Z, &acc.U, &acc.T);

    let t1 = *z * *t;
    write_gfp5(row, DBL_T1, &t1);

    let t2 = t1 * *t;
    write_gfp5(row, DBL_T2, &t2);

    let x1 = t2 * t2; // t2^2
    write_gfp5(row, DBL_X1, &x1);

    let z1 = t1 * *u;
    write_gfp5(row, DBL_Z1, &z1);

    let t3 = *u * *u; // U^2
    write_gfp5(row, DBL_T3, &t3);

    let xz_t3 = (*x + *z) * t3;
    write_gfp5(row, DBL_XZ_T3, &xz_t3);

    // W1 = t2 - 2*(X+Z)*t3
    let w1 = t2 - xz_t3.double();

    let t4 = z1 * z1; // Z1^2
    write_gfp5(row, DBL_T4, &t4);

    let w1sq = w1 * w1;
    write_gfp5(row, DBL_W1SQ, &w1sq);

    let wz_sq = (w1 + z1) * (w1 + z1); // (W1+Z1)^2
    write_gfp5(row, DBL_WZ_SQ, &wz_sq);

    // Derive the doubled point coordinates from the intermediates.
    let x_out = t4.mul_small_k1(4 * Point::B1);
    let z_out = w1sq;
    let u_out = wz_sq - t4 - z_out;
    let t_out = x1.double() - t4.mul_small(4) - z_out;

    let doubled = Point {
        X: x_out,
        Z: z_out,
        U: u_out,
        T: t_out,
    };
    write_point(row, DBL_X, &doubled);
    doubled
}

/// Compute the point addition intermediates and write them into the trace row.
///
/// This follows the Jacobi quartic addition formula from the ecgfp5 paper.
/// The 10 intermediate products are stored so the AIR can verify each at
/// degree 2. Returns the sum p1 + p2.
pub fn fill_addition(row: &mut [Goldilocks], p1: &Point, p2: &Point) -> Point {
    let (x1, z1, u1, t1_p) = (&p1.X, &p1.Z, &p1.U, &p1.T);
    let (x2, z2, u2, t2_p) = (&p2.X, &p2.Z, &p2.U, &p2.T);

    // Cross-products of coordinates.
    let at1 = *x1 * *x2;
    write_gfp5(row, ADD_AT1, &at1);

    let at2 = *z1 * *z2;
    write_gfp5(row, ADD_AT2, &at2);

    let at3 = *u1 * *u2;
    write_gfp5(row, ADD_AT3, &at3);

    let at4 = *t1_p * *t2_p;
    write_gfp5(row, ADD_AT4, &at4);

    // Karatsuba-style products for t5 and t6.
    let at5_raw = (*x1 + *z1) * (*x2 + *z2);
    write_gfp5(row, ADD_AT5_RAW, &at5_raw);

    let at6_raw = (*u1 + *t1_p) * (*u2 + *t2_p);
    write_gfp5(row, ADD_AT6_RAW, &at6_raw);

    let t5 = at5_raw - at1 - at2;
    let t6 = at6_raw - at3 - at4;
    let t7 = at1 + at2.mul_small_k1(Point::B1);

    let at8 = at4 * t7;
    write_gfp5(row, ADD_AT8, &at8);

    let t9_factor = t5.mul_small_k1(2 * Point::B1) + t7.double();
    let at9 = at3 * t9_factor;
    write_gfp5(row, ADD_AT9, &at9);

    let at10 = (at4 + at3.double()) * (t5 + t7);
    write_gfp5(row, ADD_AT10, &at10);

    let u_pre = t6 * (at2.mul_small_k1(Point::B1) - at1);
    write_gfp5(row, ADD_U_PRE, &u_pre);

    // Derive the added point from the intermediates.
    let x_out = (at10 - at8).mul_small_k1(Point::B1);
    let z_out = at8 - at9;
    let u_out = u_pre;
    let t_out = at8 + at9;

    let added = Point {
        X: x_out,
        Z: z_out,
        U: u_out,
        T: t_out,
    };
    write_point(row, ADD_X, &added);
    added
}

/// Fill a complete scalar-multiplication row: write all inputs, compute
/// doubling and addition, return (doubled, added) points.
///
/// The caller decides which result (doubled or added) becomes the next
/// row's accumulator based on the scalar bit.
pub fn fill_scalar_mul_row(
    row: &mut [Goldilocks],
    acc: &Point,
    base: &Point,
    bit: u64,
    phase: u64,
) -> (Point, Point) {
    write_point(row, ACC_X, acc);
    write_point(row, BASE_X, base);
    row[BIT] = Goldilocks::from_u64(bit);
    row[PHASE] = Goldilocks::from_u64(phase);

    let doubled = fill_doubling(row, acc);
    let added = fill_addition(row, &doubled, base);
    (doubled, added)
}
