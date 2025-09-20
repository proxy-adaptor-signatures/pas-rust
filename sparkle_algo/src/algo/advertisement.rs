use serde::{Deserialize, Serialize};
use xuanmi_base_support::*;

use crate::algo::pve_paillier::{PaillierPk, PaillierSk};
use crate::algo::threshold_sig::{ThresholdCurve, ThresholdSig};
use crate::exn;

pub const DST: &str = "proxy-exchange/adgen:v1/secp256k1/sha256";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Advt<C: ThresholdCurve> {
    pub pk: PaillierPk,
    pub t: C::Point,
    pub s: C::Scalar,
}

pub struct AdgenOutput<C: ThresholdCurve> {
    pub sk: PaillierSk,
    pub advt: Advt<C>,
}

pub fn ad_gen<C: ThresholdCurve, R: rand_core::CryptoRngCore>(
    stmt: &C::Point,
    witness: &C::Scalar,
    sk: &PaillierSk,
    rng: &mut R,
) -> Outcome<AdgenOutput<C>> {
    // Paillier keypair
    let pk = sk.encryption_key();

    // Schnorr-style PoK bound to pk and stmt
    let k = C::random_scalar(rng);
    let t = C::mul_base(&k);

    // Challenge c = H(DST || enc(pk) || enc(stmt) || enc(t))
    let mut bytes = Vec::new();
    bytes.extend_from_slice(DST.as_bytes());
    bytes.extend_from_slice(&bincode::serialize(&pk).catch(exn::BincodeException, "")?);
    bytes.extend_from_slice(&C::point_compress(stmt));
    bytes.extend_from_slice(&C::point_compress(&t));
    let c = ThresholdSig::<C>::generate_hash_signing(&bytes, stmt, &t)?; // reuse hash machinery

    let s = k + (c * *witness);

    Ok(AdgenOutput {
        sk: sk.clone(),
        advt: Advt {
            pk: pk.clone(),
            t,
            s,
        },
    })
}

pub fn ad_verify<C: ThresholdCurve>(stmt: &C::Point, ad: &Advt<C>) -> Outcome<bool> {
    // Recompute challenge
    let mut bytes = Vec::new();
    bytes.extend_from_slice(DST.as_bytes());
    bytes.extend_from_slice(&bincode::serialize(&ad.pk).catch(exn::BincodeException, "")?);
    bytes.extend_from_slice(&C::point_compress(stmt));
    bytes.extend_from_slice(&C::point_compress(&ad.t));
    let c = ThresholdSig::<C>::generate_hash_signing(&bytes, stmt, &ad.t)?;

    // Check G*s == t + c*stmt
    Ok(C::mul_base(&ad.s) == (ad.t + (*stmt * c)))
}
