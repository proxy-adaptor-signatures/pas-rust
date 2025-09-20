//! Concrete curve implementations for the threshold signature trait.
use super::threshold_sig::ThresholdCurve;
use crate::exn;
use curve25519_dalek::traits::Identity;
use k256::elliptic_curve::Group;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sha3::Sha3_256;
use xuanmi_base_support::{
    throw, Exception, Outcome, TraitStdOptionToOutcome, TraitStdResultToOutcome,
};

/// Ristretto curve implementation
#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize)]
pub struct RistrettoCurve;

impl ThresholdCurve for RistrettoCurve {
    type Scalar = curve25519_dalek::scalar::Scalar;
    type Point = curve25519_dalek::ristretto::RistrettoPoint;

    fn random_scalar<R: rand_core::CryptoRngCore>(rng: &mut R) -> Self::Scalar {
        curve25519_dalek::scalar::Scalar::random(rng)
    }

    fn scalar_zero() -> Self::Scalar {
        curve25519_dalek::scalar::Scalar::ZERO
    }

    fn scalar_one() -> Self::Scalar {
        curve25519_dalek::scalar::Scalar::ONE
    }

    fn scalar_invert(s: &Self::Scalar) -> Option<Self::Scalar> {
        if *s == Self::scalar_zero() {
            None
        } else {
            Some(s.invert())
        }
    }

    fn point_identity() -> Self::Point {
        curve25519_dalek::ristretto::RistrettoPoint::identity()
    }

    fn generator() -> Self::Point {
        curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT
    }

    fn mul_base(s: &Self::Scalar) -> Self::Point {
        curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE * s
    }

    fn point_compress(p: &Self::Point) -> Vec<u8> {
        p.compress().to_bytes().to_vec()
    }

    fn scalar_from_bytes_reduced(bytes: [u8; 32]) -> Self::Scalar {
        curve25519_dalek::scalar::Scalar::from_bytes_mod_order(bytes)
    }

    fn scalar_to_bytes(s: &Self::Scalar) -> [u8; 32] {
        s.to_bytes()
    }

    fn scalar_from_hash(hasher: sha2::Sha512) -> Self::Scalar {
        let digest = hasher.finalize();
        let mut wide = [0u8; 64];
        wide.copy_from_slice(&digest);
        curve25519_dalek::scalar::Scalar::from_bytes_mod_order_wide(&wide)
    }

    fn scalar_to_hex(s: &Self::Scalar) -> String {
        ristretto_serde::scalar_to_hex(s)
    }

    fn point_to_hex(p: &Self::Point) -> String {
        ristretto_serde::point_to_hex(p)
    }

    fn scalar_from_hex(hex: &str) -> xuanmi_base_support::Outcome<Self::Scalar> {
        ristretto_serde::scalar_from_hex(hex)
    }

    fn point_from_hex(hex: &str) -> xuanmi_base_support::Outcome<Self::Point> {
        ristretto_serde::point_from_hex(hex)
    }

    fn schnorr_challenge(
        msg: &[u8],
        group_public: &Self::Point,
        group_nonce: &Self::Point,
    ) -> Outcome<Self::Scalar> {
        let mut hasher = Sha3_256::new();
        hasher.update(group_public.compress().to_bytes());
        hasher.update(msg);
        hasher.update(group_nonce.compress().to_bytes());
        let result = hasher.finalize();
        let digest: [u8; 32] = result
            .as_slice()
            .try_into()
            .catch(exn::HashException, "Failed to generate hash for signing")?;
        Ok(Self::scalar_from_bytes_reduced(digest))
    }
}

/// secp256k1 curve implementation
#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize)]
pub struct Secp256k1Curve;

impl ThresholdCurve for Secp256k1Curve {
    type Scalar = crate::SecpScalar;
    type Point = crate::SecpPoint;

    fn random_scalar<R: rand_core::RngCore>(rng: &mut R) -> Self::Scalar {
        crate::secp_random_scalar(rng)
    }

    fn scalar_zero() -> Self::Scalar {
        crate::SecpScalar::ZERO
    }

    fn scalar_one() -> Self::Scalar {
        crate::SecpScalar::ONE
    }

    fn scalar_invert(s: &Self::Scalar) -> Option<Self::Scalar> {
        if *s == Self::scalar_zero() {
            None
        } else {
            Some(s.invert().unwrap())
        }
    }

    fn point_identity() -> Self::Point {
        crate::SecpPoint::IDENTITY
    }

    fn generator() -> Self::Point {
        crate::secp_generator()
    }

    fn mul_base(s: &Self::Scalar) -> Self::Point {
        crate::secp_mul_base(s)
    }

    fn point_compress(p: &Self::Point) -> Vec<u8> {
        crate::secp_compress(p)
    }

    fn scalar_from_bytes_reduced(bytes: [u8; 32]) -> Self::Scalar {
        use k256::elliptic_curve::ff::PrimeField;
        crate::SecpScalar::from_repr(bytes.into()).unwrap_or(Self::scalar_zero())
    }

    fn scalar_to_bytes(s: &Self::Scalar) -> [u8; 32] {
        s.to_bytes().into()
    }

    fn scalar_from_hash(hasher: sha2::Sha512) -> Self::Scalar {
        let digest = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&digest[..32]);
        Self::scalar_from_bytes_reduced(bytes)
    }

    fn scalar_to_hex(s: &Self::Scalar) -> String {
        secp256k1_serde::scalar_to_hex(s)
    }

    fn point_to_hex(p: &Self::Point) -> String {
        secp256k1_serde::point_to_hex(p)
    }

    fn scalar_from_hex(hex: &str) -> xuanmi_base_support::Outcome<Self::Scalar> {
        secp256k1_serde::scalar_from_hex(hex)
    }

    fn point_from_hex(hex: &str) -> xuanmi_base_support::Outcome<Self::Point> {
        secp256k1_serde::point_from_hex(hex)
    }

    fn schnorr_challenge(
        msg: &[u8],
        group_public: &Self::Point,
        group_nonce: &Self::Point,
    ) -> Outcome<Self::Scalar> {
        use crate::exn;
        use k256::elliptic_curve::sec1::ToEncodedPoint;

        if group_nonce.0.is_identity().into() {
            throw!(
                name = exn::SignatureException,
                ctx = "Group nonce is identity"
            );
        }
        if group_public.0.is_identity().into() {
            throw!(
                name = exn::SignatureException,
                ctx = "Group public key is identity"
            );
        }

        let r_encoded = group_nonce.0.to_affine().to_encoded_point(false);
        let p_encoded = group_public.0.to_affine().to_encoded_point(false);
        let rx = r_encoded
            .x()
            .if_none(exn::SignatureException, "Missing x-coordinate for nonce")?;
        let px = p_encoded.x().if_none(
            exn::SignatureException,
            "Missing x-coordinate for public key",
        )?;

        let mut tag_hasher = Sha256::new();
        tag_hasher.update(b"BIP0340/challenge");
        let tag = tag_hasher.finalize();

        let mut hasher = Sha256::new();
        hasher.update(&tag);
        hasher.update(&tag);
        hasher.update(rx.as_slice());
        hasher.update(px.as_slice());
        hasher.update(msg);
        let digest = hasher.finalize();

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&digest);
        Ok(Self::scalar_from_bytes_reduced(bytes))
    }
}

// Type aliases for convenience
pub type RistrettoThresholdSig = super::threshold_sig::ThresholdSig<RistrettoCurve>;
pub type Secp256k1ThresholdSig = super::threshold_sig::ThresholdSig<Secp256k1Curve>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecpPoint;
    use k256::{elliptic_curve::sec1::ToEncodedPoint, ProjectivePoint, Scalar};
    use rand_core::OsRng;

    fn ensure_even_point(point: ProjectivePoint) -> ProjectivePoint {
        let mut p = point;
        let encoded = p.to_affine().to_encoded_point(true);
        if encoded.as_bytes()[0] == 0x03 {
            p = -p;
        }
        p
    }

    #[test]
    fn ristretto_curve_works() {
        let mut rng = OsRng;
        let s = RistrettoCurve::random_scalar(&mut rng);
        let p = RistrettoCurve::mul_base(&s);
        assert_ne!(p, RistrettoCurve::point_identity());

        let compressed = RistrettoCurve::point_compress(&p);
        assert_eq!(compressed.len(), 32);
    }

    #[test]
    fn secp256k1_curve_works() {
        let mut rng = OsRng;
        let s = Secp256k1Curve::random_scalar(&mut rng);
        let p = Secp256k1Curve::mul_base(&s);
        assert_ne!(p, Secp256k1Curve::point_identity());

        let compressed = Secp256k1Curve::point_compress(&p);
        assert_eq!(compressed.len(), 33); // SEC1 compressed format
    }

    #[test]
    fn secp256k1_bip340_challenge_matches_manual() {
        let msg = [0xAAu8; 32];
        let sk = Scalar::from(12345u64);
        let k = Scalar::from(67890u64);

        let group_point = ensure_even_point(ProjectivePoint::GENERATOR * sk);
        let nonce_point = ensure_even_point(ProjectivePoint::GENERATOR * k);

        let challenge = Secp256k1Curve::schnorr_challenge(
            &msg,
            &SecpPoint(group_point),
            &SecpPoint(nonce_point),
        )
        .unwrap();

        let r_x = nonce_point
            .to_affine()
            .to_encoded_point(false)
            .x()
            .unwrap()
            .to_vec();
        let p_x = group_point
            .to_affine()
            .to_encoded_point(false)
            .x()
            .unwrap()
            .to_vec();

        let mut tag = Sha256::new();
        tag.update(b"BIP0340/challenge");
        let tag = tag.finalize();

        let mut hasher = Sha256::new();
        hasher.update(&tag);
        hasher.update(&tag);
        hasher.update(&r_x);
        hasher.update(&p_x);
        hasher.update(&msg);
        let digest = hasher.finalize();

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&digest);
        let expected = Secp256k1Curve::scalar_from_bytes_reduced(bytes);

        assert_eq!(challenge, expected);
    }
}

// Module for Ristretto hex serialization helpers
mod ristretto_serde {
    use super::*;
    use curve25519_dalek::{
        ristretto::{CompressedRistretto, RistrettoPoint},
        scalar::Scalar,
    };
    use xuanmi_base_support::Exception;

    const BYTES_HEX: &'static str = "bytes_hex:";
    const SCALAR_HEX: &'static str = "scalar_hex:";
    const POINT_HEX: &'static str = "point_hex:";

    pub fn bytes_from_hex(hex: &str) -> xuanmi_base_support::Outcome<Vec<u8>> {
        const ERR_BYTES: &'static str = "Hex string of bytes should begin with \"bytes_hex\"";
        if hex.len() < BYTES_HEX.len() {
            throw!(name = exn::PrefixException, ctx = ERR_BYTES);
        }
        if &hex[..BYTES_HEX.len()] != BYTES_HEX {
            throw!(name = exn::PrefixException, ctx = ERR_BYTES);
        }
        hex::decode(&hex[BYTES_HEX.len()..]).catch(exn::HexToException, "")
    }

    pub fn bytes_to_hex(bytes: &[u8]) -> String {
        let mut hex_str = String::from(BYTES_HEX);
        hex_str.push_str(hex::encode(bytes).as_str());
        hex_str
    }

    pub fn scalar_from_hex(hex: &str) -> xuanmi_base_support::Outcome<Scalar> {
        const ERR_SCALAR: &'static str = "Hex string of bytes should begin with \"bytes_hex\"";
        if hex.len() < SCALAR_HEX.len() {
            throw!(name = exn::PrefixException, ctx = ERR_SCALAR);
        }
        if &hex[..SCALAR_HEX.len()] != SCALAR_HEX {
            throw!(name = exn::PrefixException, ctx = ERR_SCALAR);
        }
        let bytes = bytes_from_hex(&hex[SCALAR_HEX.len()..])?;
        let bytes: [u8; 32] = bytes.try_into().unwrap();
        Ok(Scalar::from_bytes_mod_order(bytes))
    }

    pub fn scalar_to_hex(scalar: &Scalar) -> String {
        let mut hex_str = String::from(SCALAR_HEX);
        hex_str.push_str(&bytes_to_hex(&scalar.to_bytes()));
        hex_str
    }

    pub fn point_from_hex(hex: &str) -> xuanmi_base_support::Outcome<RistrettoPoint> {
        const ERR_POINT: &'static str = "Hex string of bytes should begin with \"bytes_hex\"";
        if hex.len() < POINT_HEX.len() {
            throw!(name = exn::PrefixException, ctx = ERR_POINT);
        }
        if &hex[..POINT_HEX.len()] != POINT_HEX {
            throw!(name = exn::PrefixException, ctx = ERR_POINT);
        }
        CompressedRistretto::from_slice(&bytes_from_hex(&hex[POINT_HEX.len()..])?)
            .catch(exn::HexToException, "")?
            .decompress()
            .if_none(exn::HexToException, "")
    }

    pub fn point_to_hex(point: &RistrettoPoint) -> String {
        let mut hex_str = String::from(POINT_HEX);
        hex_str.push_str(&bytes_to_hex(&point.compress().to_bytes()));
        hex_str
    }
}

// Module for secp256k1 hex serialization helpers
mod secp256k1_serde {
    use crate::{secp_compress, secp_decompress, SecpPoint, SecpScalar};
    use k256::elliptic_curve::ff::PrimeField; // for Scalar::from_repr
    use k256::Scalar;
    use xuanmi_base_support::*;

    const BYTES_HEX: &'static str = "bytes_hex:";
    const SCALAR_HEX: &'static str = "scalar_hex:";
    const POINT_HEX: &'static str = "point_hex:";

    pub fn bytes_from_hex(hex: &str) -> Outcome<Vec<u8>> {
        const ERR: &'static str = "Hex string of bytes should begin with \"bytes_hex\"";
        if hex.len() < BYTES_HEX.len() {
            throw!(name = crate::exn::PrefixException, ctx = ERR);
        }
        if &hex[..BYTES_HEX.len()] != BYTES_HEX {
            throw!(name = crate::exn::PrefixException, ctx = ERR);
        }
        hex::decode(&hex[BYTES_HEX.len()..]).catch(crate::exn::HexToException, "")
    }

    pub fn bytes_to_hex(bytes: &[u8]) -> String {
        let mut hex_str = String::from(BYTES_HEX);
        hex_str.push_str(hex::encode(bytes).as_str());
        hex_str
    }

    pub fn scalar_from_hex(hex: &str) -> Outcome<SecpScalar> {
        const ERR: &'static str = "Hex string of scalar should begin with \"scalar_hex\"";
        if hex.len() < SCALAR_HEX.len() {
            throw!(name = crate::exn::PrefixException, ctx = ERR);
        }
        if &hex[..SCALAR_HEX.len()] != SCALAR_HEX {
            throw!(name = crate::exn::PrefixException, ctx = ERR);
        }
        let bytes = bytes_from_hex(&hex[SCALAR_HEX.len()..])?;
        let arr: [u8; 32] = bytes.try_into().unwrap();
        let ct = Scalar::from_repr(arr.into());
        if ct.is_some().into() {
            Ok(ct.unwrap())
        } else {
            throw!(
                name = crate::exn::HexToException,
                ctx = "Invalid scalar encoding"
            )
        }
    }

    pub fn scalar_to_hex(scalar: &SecpScalar) -> String {
        let mut hex_str = String::from(SCALAR_HEX);
        hex_str.push_str(&bytes_to_hex(&scalar.to_bytes()));
        hex_str
    }

    pub fn point_from_hex(hex: &str) -> Outcome<SecpPoint> {
        const ERR: &'static str = "Hex string of point should begin with \"point_hex\"";
        if hex.len() < POINT_HEX.len() {
            throw!(name = crate::exn::PrefixException, ctx = ERR);
        }
        if &hex[..POINT_HEX.len()] != POINT_HEX {
            throw!(name = crate::exn::PrefixException, ctx = ERR);
        }
        let bytes = bytes_from_hex(&hex[POINT_HEX.len()..])?;
        secp_decompress(&bytes).if_none(crate::exn::HexToException, "")
    }

    pub fn point_to_hex(point: &SecpPoint) -> String {
        let mut hex_str = String::from(POINT_HEX);
        hex_str.push_str(&bytes_to_hex(&secp_compress(point)));
        hex_str
    }
}
