use plonky2_field::field_types::Field;
use serde::{Deserialize, Serialize};

use crate::curve::curve_types::{AffinePoint, Curve};
use crate::field::ed25519_base::Ed25519Base;
use crate::field::ed25519_scalar::Ed25519Scalar;

#[derive(Debug, Copy, Clone, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Ed25519;

impl Curve for Ed25519 {
    type BaseField = Ed25519Base;
    type ScalarField = Ed25519Scalar;

    const A: Ed25519Base = Ed25519Base::ONE;
    const B: Ed25519Base = Ed25519Base([
        0x75eb4dca135978a3,
        0x00700a4d4141d8ab,
        0x8cc740797779e898,
        0x52036cee2b6ffe73,
    ]);
    const GENERATOR_AFFINE: AffinePoint<Self> = AffinePoint {
        x: ED25519_GENERATOR_X,
        y: ED25519_GENERATOR_Y,
        zero: false,
    };
}

/// 15112221349535400772501151409588531511454012693041857206046113283949847762202
const ED25519_GENERATOR_X: Ed25519Base = Ed25519Base([
    0xc9562d608f25d51a,
    0x692cc7609525a7b2,
    0xc0a4e231fdd6dc5c,
    0x216936d3cd6e53fe,
]);

/// 46316835694926478169428394003475163141307993866256225615783033603165251855960
const ED25519_GENERATOR_Y: Ed25519Base = Ed25519Base([
    0x6666666666666658,
    0x6666666666666666,
    0x6666666666666666,
    0x6666666666666666,
]);

#[cfg(test)]
mod tests {
    use num::BigUint;
    use plonky2_field::field_types::Field;
    use plonky2_field::field_types::PrimeField;

    use crate::curve::curve_types::{AffinePoint, Curve, ProjectivePoint};
    use crate::curve::ed25519::Ed25519;
    use crate::field::ed25519_base::Ed25519Base;
    use crate::field::ed25519_scalar::Ed25519Scalar;

    #[test]
    fn test_generator() {
        let g = Ed25519::GENERATOR_AFFINE;
        assert!(g.is_valid());

        let neg_g = AffinePoint::<Ed25519> {
            x: g.x,
            y: -g.y,
            zero: g.zero,
        };
        assert!(neg_g.is_valid());
    }

    #[test]
    fn test_naive_multiplication() {
        let g = Ed25519::GENERATOR_PROJECTIVE;
        let ten = Ed25519Scalar::from_canonical_u64(10);
        let product = mul_naive(ten, g);
        let sum = g + g + g + g + g + g + g + g + g + g;
        assert_eq!(product, sum);
    }

    #[test]
    fn test_g1_multiplication() {
        let lhs = Ed25519Scalar::from_biguint(BigUint::from_slice(&[
            1111, 2222, 3333, 4444, 5555, 6666, 7777, 8888,
        ]));
        assert_eq!(
            Ed25519::convert(lhs) * Ed25519::GENERATOR_PROJECTIVE,
            mul_naive(lhs, Ed25519::GENERATOR_PROJECTIVE)
        );
    }

    /// A simple, somewhat inefficient implementation of multiplication which is used as a reference
    /// for correctness.
    fn mul_naive(
        lhs: Ed25519Scalar,
        rhs: ProjectivePoint<Ed25519>,
    ) -> ProjectivePoint<Ed25519> {
        let mut g = rhs;
        let mut sum = ProjectivePoint::ZERO;
        for limb in lhs.to_canonical_biguint().to_u64_digits().iter() {
            for j in 0..64 {
                if (limb >> j & 1u64) != 0u64 {
                    sum = sum + g;
                }
                g = g.double();
            }
        }
        sum
    }
}