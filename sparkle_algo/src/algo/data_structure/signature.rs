use crate::{
    PreSignature, RistrettoCurve, Secp256k1Curve, SecpPoint, SecpScalar, Signature, ThresholdCurve,
};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use serde::{Deserialize, Serialize};
use xuanmi_base_support::*;

use super::{bytes_from_hex, bytes_to_hex};

impl Signature<RistrettoCurve> {
    pub fn new(r: &RistrettoPoint, z: Scalar, hash: &[u8]) -> Signature<RistrettoCurve> {
        Signature {
            r: *r,
            z,
            hash: hash.to_vec(),
        }
    }

    pub fn from_json(json: &str) -> Outcome<Signature<RistrettoCurve>> {
        let ss: SignatureSerde = json_to_obj(json)?;
        let so = Signature {
            r: RistrettoCurve::point_from_hex(&ss.r)?,
            z: RistrettoCurve::scalar_from_hex(&ss.z)?,
            hash: bytes_from_hex(&ss.hash)?,
        };
        Ok(so)
    }

    pub fn to_json(&self) -> Outcome<String> {
        let ss = SignatureSerde {
            r: RistrettoCurve::point_to_hex(&self.r),
            z: RistrettoCurve::scalar_to_hex(&self.z),
            hash: bytes_to_hex(&self.hash),
        };
        obj_to_json(&ss)
    }

    pub fn to_json_pretty(&self) -> Outcome<String> {
        let ss = SignatureSerde {
            r: RistrettoCurve::point_to_hex(&self.r),
            z: RistrettoCurve::scalar_to_hex(&self.z),
            hash: bytes_to_hex(&self.hash),
        };
        obj_to_json_pretty(&ss)
    }
}

impl PreSignature<RistrettoCurve> {
    pub fn new(r: &RistrettoPoint, z: Scalar, hash: &[u8]) -> PreSignature<RistrettoCurve> {
        PreSignature {
            R_prime: *r,
            z,
            hash: hash.to_vec(),
        }
    }

    pub fn from_json(json: &str) -> Outcome<PreSignature<RistrettoCurve>> {
        let ss: PreSignatureSerde = json_to_obj(json)?;
        let so = PreSignature {
            R_prime: RistrettoCurve::point_from_hex(&ss.R_prime)?,
            z: RistrettoCurve::scalar_from_hex(&ss.z)?,
            hash: bytes_from_hex(&ss.hash)?,
        };
        Ok(so)
    }

    pub fn to_json(&self) -> Outcome<String> {
        let ss = PreSignatureSerde {
            R_prime: RistrettoCurve::point_to_hex(&self.R_prime),
            z: RistrettoCurve::scalar_to_hex(&self.z),
            hash: bytes_to_hex(&self.hash),
        };
        obj_to_json(&ss)
    }

    pub fn to_json_pretty(&self) -> Outcome<String> {
        let ss = PreSignatureSerde {
            R_prime: RistrettoCurve::point_to_hex(&self.R_prime),
            z: RistrettoCurve::scalar_to_hex(&self.z),
            hash: bytes_to_hex(&self.hash),
        };
        obj_to_json_pretty(&ss)
    }
}

impl Signature<Secp256k1Curve> {
    pub fn new(r: &SecpPoint, z: SecpScalar, hash: &[u8]) -> Signature<Secp256k1Curve> {
        Signature {
            r: *r,
            z,
            hash: hash.to_vec(),
        }
    }

    pub fn from_json(json: &str) -> Outcome<Signature<Secp256k1Curve>> {
        let ss: SignatureSerde = json_to_obj(json)?;
        Ok(Signature {
            r: Secp256k1Curve::point_from_hex(&ss.r)?,
            z: Secp256k1Curve::scalar_from_hex(&ss.z)?,
            hash: bytes_from_hex(&ss.hash)?,
        })
    }

    pub fn to_json(&self) -> Outcome<String> {
        let ss = SignatureSerde {
            r: Secp256k1Curve::point_to_hex(&self.r),
            z: Secp256k1Curve::scalar_to_hex(&self.z),
            hash: bytes_to_hex(&self.hash),
        };
        obj_to_json(&ss)
    }

    pub fn to_json_pretty(&self) -> Outcome<String> {
        let ss = SignatureSerde {
            r: Secp256k1Curve::point_to_hex(&self.r),
            z: Secp256k1Curve::scalar_to_hex(&self.z),
            hash: bytes_to_hex(&self.hash),
        };
        obj_to_json_pretty(&ss)
    }
}

impl PreSignature<Secp256k1Curve> {
    pub fn new(r: &SecpPoint, z: SecpScalar, hash: &[u8]) -> PreSignature<Secp256k1Curve> {
        PreSignature {
            R_prime: *r,
            z,
            hash: hash.to_vec(),
        }
    }

    pub fn from_json(json: &str) -> Outcome<PreSignature<Secp256k1Curve>> {
        let ss: PreSignatureSerde = json_to_obj(json)?;
        Ok(PreSignature {
            R_prime: Secp256k1Curve::point_from_hex(&ss.R_prime)?,
            z: Secp256k1Curve::scalar_from_hex(&ss.z)?,
            hash: bytes_from_hex(&ss.hash)?,
        })
    }

    pub fn to_json(&self) -> Outcome<String> {
        let ss = PreSignatureSerde {
            R_prime: Secp256k1Curve::point_to_hex(&self.R_prime),
            z: Secp256k1Curve::scalar_to_hex(&self.z),
            hash: bytes_to_hex(&self.hash),
        };
        obj_to_json(&ss)
    }

    pub fn to_json_pretty(&self) -> Outcome<String> {
        let ss = PreSignatureSerde {
            R_prime: Secp256k1Curve::point_to_hex(&self.R_prime),
            z: Secp256k1Curve::scalar_to_hex(&self.z),
            hash: bytes_to_hex(&self.hash),
        };
        obj_to_json_pretty(&ss)
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct SignatureSerde {
    r: String,    // RistrettoPoint-hex:blahblah
    z: String,    // Scalar-hex:blahblah
    hash: String, // bytes-hex:blahblah
}

#[derive(Clone, Serialize, Deserialize)]
struct PreSignatureSerde {
    R_prime: String, // RistrettoPoint-hex:blahblah
    z: String,       // Scalar-hex:blahblah
    hash: String,    // bytes-hex:blahblah
}
