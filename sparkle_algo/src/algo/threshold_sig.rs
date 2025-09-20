//! Generic threshold signature operations parameterized by curve type.
//!
//! This module provides a unified interface for threshold signatures that works
//! with both Ristretto and secp256k1 curves through trait abstractions.

use crate::exn;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::convert::TryInto;
use xuanmi_base_support::*;

/// Trait for elliptic curve operations needed by threshold signatures
pub trait ThresholdCurve:
    Serialize + DeserializeOwned + Clone + Copy + PartialEq + std::fmt::Debug + 'static
{
    type Scalar: Clone
        + Copy
        + PartialEq
        + std::fmt::Debug
        + From<u64>
        + std::ops::Add<Output = Self::Scalar>
        + std::ops::Sub<Output = Self::Scalar>
        + std::ops::Mul<Output = Self::Scalar>
        + Serialize
        + for<'de> Deserialize<'de>;
    type Point: Clone
        + Copy
        + PartialEq
        + std::fmt::Debug
        + std::ops::Add<Output = Self::Point>
        + std::ops::Sub<Output = Self::Point>
        + std::ops::Mul<Self::Scalar, Output = Self::Point>
        + Serialize
        + for<'de> Deserialize<'de>;

    fn random_scalar<R: rand_core::CryptoRngCore>(rng: &mut R) -> Self::Scalar;
    fn scalar_zero() -> Self::Scalar;
    fn scalar_one() -> Self::Scalar;
    fn scalar_invert(s: &Self::Scalar) -> Option<Self::Scalar>;
    fn point_identity() -> Self::Point;
    fn generator() -> Self::Point;
    fn mul_base(s: &Self::Scalar) -> Self::Point;
    fn point_compress(p: &Self::Point) -> Vec<u8>;
    fn scalar_from_bytes_reduced(bytes: [u8; 32]) -> Self::Scalar;
    fn scalar_to_bytes(s: &Self::Scalar) -> [u8; 32];
    fn scalar_from_hash(hasher: Sha512) -> Self::Scalar;

    // Hex serialization methods for JSON
    fn scalar_to_hex(s: &Self::Scalar) -> String;
    fn point_to_hex(p: &Self::Point) -> String;
    fn scalar_from_hex(hex: &str) -> Outcome<Self::Scalar>;
    fn point_from_hex(hex: &str) -> Outcome<Self::Point>;

    /// Curve-specific challenge computation used by Schnorr signatures.
    fn schnorr_challenge(
        msg: &[u8],
        group_public: &Self::Point,
        group_nonce: &Self::Point,
    ) -> Outcome<Self::Scalar>;
}

/// Generic threshold signature operations
pub struct ThresholdSig<C: ThresholdCurve> {
    _phantom: std::marker::PhantomData<C>,
}

impl<C: ThresholdCurve> ThresholdSig<C> {
    pub fn generate_dkg_challenge(
        index: &u16,
        context: &str,
        public: &C::Point,
        commitment: &C::Point,
    ) -> Outcome<C::Scalar> {
        let mut hasher = Sha256::new();
        hasher.update(C::point_compress(commitment));
        hasher.update(C::point_compress(public));
        hasher.update(index.to_string());
        hasher.update(context);
        let result = hasher.finalize();

        let a: [u8; 32] = result.as_slice().try_into().catch(
            exn::HashException,
            "Failed to generate challenge for KeyGen",
        )?;

        Ok(C::scalar_from_bytes_reduced(a))
    }

    pub fn generate_hash_commitment(
        msg: &[u8],
        signers: &Vec<u16>,
        group_nonce: &C::Point,
    ) -> Outcome<C::Scalar> {
        let mut hasher = Sha256::new();
        let string_result = String::from_utf16_lossy(signers);
        hasher.update(msg);
        hasher.update(string_result);
        hasher.update(C::point_compress(group_nonce));
        let result = hasher.finalize();

        let a: [u8; 32] = result.as_slice().try_into().catch(
            exn::HashException,
            "Failed to generate hash for commitments",
        )?;

        Ok(C::scalar_from_bytes_reduced(a))
    }

    pub fn generate_hash_commitment_adaptor(
        msg: &[u8],
        signers: &Vec<u16>,
        group_nonce: &C::Point,
        statement: &C::Point,
    ) -> Outcome<C::Scalar> {
        let mut hasher = Sha256::new();
        let string_result = String::from_utf16_lossy(signers);
        hasher.update(msg);
        hasher.update(string_result);
        hasher.update(C::point_compress(group_nonce));
        hasher.update(C::point_compress(statement));
        let result = hasher.finalize();
        let a: [u8; 32] = result.as_slice().try_into().catch(
            exn::HashException,
            "Failed to generate hash for commitments",
        )?;
        Ok(C::scalar_from_bytes_reduced(a))
    }

    pub fn generate_hash_signing(
        msg: &[u8],
        group_public: &C::Point,
        group_nonce: &C::Point,
    ) -> Outcome<C::Scalar> {
        C::schnorr_challenge(msg, group_public, group_nonce)
    }

    pub fn get_lagrange_coeff(
        x_coord: u16,
        signer_index: u16,
        all_signer_indices: &[u16],
    ) -> Outcome<C::Scalar> {
        let mut num = C::scalar_one();
        let mut den = C::scalar_one();

        for j in all_signer_indices {
            if *j == signer_index {
                continue;
            }

            let j_scalar = C::Scalar::from(*j as u64);
            let coord_scalar = C::Scalar::from(x_coord as u64);
            let signer_scalar = C::Scalar::from(signer_index as u64);

            num = num * (j_scalar - coord_scalar);
            den = den * (j_scalar - signer_scalar);
        }

        if den == C::scalar_zero() {
            throw!(
                name = exn::ConfigException,
                ctx = "Duplicate key shares provided"
            );
        }

        let inv =
            C::scalar_invert(&den).if_none(exn::ConfigException, "Cannot invert denominator")?;
        Ok(num * inv)
    }

    pub fn validate_signature(
        r: &C::Point,
        z: &C::Scalar,
        hash: &[u8],
        pubkey: &C::Point,
    ) -> Outcome<()> {
        let challenge = Self::generate_hash_signing(hash, pubkey, r)?;
        if *r != (C::mul_base(z) + (*pubkey * (C::scalar_zero() - challenge))) {
            throw!(name = exn::SignatureException, ctx = "Signature is invalid");
        }
        Ok(())
    }

    pub fn verify_presignature(
        r_prime: &C::Point,
        z: &C::Scalar,
        hash: &[u8],
        group_public: &C::Point,
        statement: &C::Point,
    ) -> Outcome<()> {
        let challenge = Self::generate_hash_signing(hash, group_public, r_prime)?;
        if (C::mul_base(z) + *statement) != (*r_prime + (*group_public * challenge)) {
            throw!(
                name = exn::SignatureException,
                ctx = "Invalid pre-signature"
            );
        }
        Ok(())
    }
}
