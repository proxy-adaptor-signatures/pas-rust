//! Minimal arithmetic facade for secp256k1 using k256.
//!
//! Goals:
//! - Provide small helpers equivalent to previously used Ristretto helpers.
//! - Keep usage localized so we can progressively migrate existing code.
//! - Avoid bringing heavy Bitcoin-specific wiring at this layer.
//!
//! This module intentionally exposes only the primitives we need now.

use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::elliptic_curve::Field;
use k256::{AffinePoint, ProjectivePoint, Scalar};
use rand_core::RngCore;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct SecpPoint(pub ProjectivePoint);

pub type SecpScalar = Scalar;

// --- Arithmetic Trait Implementations ---

impl SecpPoint {
    pub const IDENTITY: Self = SecpPoint(ProjectivePoint::IDENTITY);
}

impl std::ops::Add for SecpPoint {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        SecpPoint(self.0 + rhs.0)
    }
}

impl std::ops::Sub<SecpPoint> for SecpPoint {
    type Output = Self;
    fn sub(self, rhs: SecpPoint) -> Self::Output {
        SecpPoint(self.0 - rhs.0)
    }
}

impl std::ops::Mul<SecpScalar> for SecpPoint {
    type Output = Self;
    fn mul(self, rhs: SecpScalar) -> Self::Output {
        SecpPoint(self.0 * rhs)
    }
}

// --- Serde Implementations ---

impl Serialize for SecpPoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.to_affine().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SecpPoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        AffinePoint::deserialize(deserializer).map(|p| SecpPoint(ProjectivePoint::from(p)))
    }
}

// --- Helper Functions ---

pub fn secp_generator() -> SecpPoint {
    SecpPoint(ProjectivePoint::GENERATOR)
}

pub fn secp_mul_base(s: &SecpScalar) -> SecpPoint {
    SecpPoint(ProjectivePoint::GENERATOR * s)
}

pub fn secp_random_scalar<R: RngCore>(rng: &mut R) -> SecpScalar {
    Scalar::random(rng)
}

pub fn secp_compress(p: &SecpPoint) -> Vec<u8> {
    p.0.to_affine().to_encoded_point(true).to_bytes().to_vec()
}

pub fn secp_decompress(bytes: &[u8]) -> Option<SecpPoint> {
    AffinePoint::from_encoded_point(&k256::EncodedPoint::from_bytes(bytes).ok()?)
        .map(|p| SecpPoint(ProjectivePoint::from(p)))
        .into()
}

/// Compatibility shim for existing code that multiplies a dalek basepoint table by a scalar.
pub mod constants {
    use super::*;
    #[derive(Copy, Clone, Debug)]
    pub struct RistrettoBasepointTable;
    pub const RISTRETTO_BASEPOINT_TABLE: RistrettoBasepointTable = RistrettoBasepointTable;

    impl<'a> core::ops::Mul<&'a SecpScalar> for RistrettoBasepointTable {
        type Output = SecpPoint;
        fn mul(self, rhs: &'a SecpScalar) -> SecpPoint {
            super::secp_mul_base(rhs)
        }
    }

    impl<'a, 'b> core::ops::Mul<&'a SecpScalar> for &'b RistrettoBasepointTable {
        type Output = SecpPoint;
        fn mul(self, rhs: &'a SecpScalar) -> SecpPoint {
            super::secp_mul_base(rhs)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn generator_mul_roundtrip_compress_decompress() {
        let mut rng = OsRng;
        let k = secp_random_scalar(&mut rng);
        let p = secp_mul_base(&k);
        let bytes = secp_compress(&p);
        assert_eq!(bytes.len(), 33, "compressed SEC1 length");
        let q = secp_decompress(&bytes).expect("valid point");
        assert_eq!(AffinePoint::from(p.0), AffinePoint::from(q.0));
    }
}
