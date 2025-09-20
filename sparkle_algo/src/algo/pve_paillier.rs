//! Paillier-based Publicly Verifiable Encryption (PVE) facade.
//!
//! This module provides thin, compile-ready types that we will flesh out
//! using `paillier-zk` + `fast-paillier`. For now it exposes the public API
//! needed by higher levels without forcing curve-specific code elsewhere.
//! The goal is to support the MPFE CWE-style public verifiability (seller-time
//! optimized decryption) while we migrate curves to secp256k1. Advertisement
//! generation (AdGen) lives in the Proxy Exchange layer, not here.

use rand_core::OsRng;
use rug::Integer;
use serde::{Deserialize, Serialize};
use xuanmi_base_support::*;

// ZK proof module (Πlog* / Rlog*)
use generic_ec::{curves::Secp256k1 as ESecp, Point as EcPoint};
pub use paillier_zk::group_element_vs_paillier_encryption_in_range as pzk;
use paillier_zk::IntegerExt as _; // to_scalar()

use fast_paillier::Ciphertext as PaillierCt;
pub use fast_paillier::{DecryptionKey as PaillierSk, EncryptionKey as PaillierPk};

// no extra internal imports needed here

pub const SHARED_STATE: &'static str = "proxy_exchange_pve_zk";

pub fn load_pzk_aux() -> xuanmi_base_support::Outcome<pzk::Aux> {
    let s = include_str!("../../assets/pzk_aux.json");
    serde_json::from_str(s).catch(crate::exn::JsonToObjectException, "aux json")
}

pub fn load_security_params() -> xuanmi_base_support::Outcome<pzk::SecurityParams> {
    let s = include_str!("../../assets/security_params.json");
    serde_json::from_str(s).catch(crate::exn::JsonToObjectException, "security params json")
}

/// Ciphertext container for PVE.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PveCiphertext {
    pub ciphertext: PaillierCt,
    /// Serialized ZK commitment, optional since only used between proxies
    pub zk_commitment: Option<Vec<u8>>,
    /// Serialized ZK proof
    pub zk_proof: Option<Vec<u8>>,
    /// Original plaintext length in bytes (for unambiguous decoding).
    pub pt_len: u32,
}

/// Encrypt bytes under the advertisement's public key (no proof).
pub fn pve_encrypt(_pk: &PaillierPk, _plaintext: &[u8]) -> Outcome<PveCiphertext> {
    let m = Integer::from_digits(_plaintext, rug::integer::Order::MsfBe);
    let (ct, _nonce) = _pk
        .encrypt_with_random(&mut OsRng, &m)
        .catch(crate::exn::EncryptionException, "paillier encrypt")?;

    Ok(PveCiphertext {
        ciphertext: ct,
        zk_commitment: None,
        zk_proof: None,
        pt_len: _plaintext.len() as u32,
    })
}

/// Encrypt and produce a Πlog* non-interactive proof for secp256k1.
/// - shared_state: domain separation string
pub fn pve_encrypt_link_secp(
    aux: &pzk::Aux,
    security: &pzk::SecurityParams,
    pk: &PaillierPk,
    witness_bytes: &[u8], // big-endian
) -> Outcome<PveCiphertext> {
    // plaintext and encryption
    let x_int = Integer::from_digits(witness_bytes, rug::integer::Order::MsfBe);
    let (ct, nonce) = pk
        .encrypt_with_random(&mut OsRng, &x_int)
        .catch(crate::exn::EncryptionException, "paillier encrypt")?;

    // X = G^x on secp256k1
    let X: EcPoint<ESecp> = EcPoint::<ESecp>::generator() * x_int.to_scalar();

    // Build proof
    let data = pzk::Data {
        key0: pk,
        c: &ct,
        x: &X,
        b: &EcPoint::<ESecp>::generator().into(),
    };
    let (commitment, proof) = pzk::non_interactive::prove::<ESecp, sha2::Sha256>(
        &SHARED_STATE,
        aux,
        data,
        pzk::PrivateData {
            x: &x_int,
            nonce: &nonce,
        },
        security,
        &mut OsRng,
    )
    .catch(crate::exn::EncryptionException, "paillier-zk prove")?;

    Ok(PveCiphertext {
        ciphertext: ct,
        zk_commitment: Some(
            bincode::serialize(&commitment)
                .catch(crate::exn::BincodeException, "serialize zk commitment")?,
        ),
        zk_proof: Some(
            bincode::serialize(&proof).catch(crate::exn::BincodeException, "serialize zk proof")?,
        ),
        pt_len: witness_bytes.len() as u32,
    })
}

/// Verify a Πlog* proof for secp256k1 that links ciphertext to the group element X (compressed).
pub fn pve_verify_link_secp(
    aux: &pzk::Aux,
    security: &pzk::SecurityParams,
    pk: &PaillierPk,
    ct: &PveCiphertext,
    x_compressed: &[u8],
) -> Outcome<()> {
    // Deserialize inputs
    let ct_inner = &ct.ciphertext;
    let commitment: pzk::Commitment<ESecp> =
        bincode::deserialize(&ct.zk_commitment.clone().expect("ZK commitment is required"))
            .catch(crate::exn::BincodeException, "zk commitment")?;
    let proof: pzk::Proof =
        bincode::deserialize(&ct.zk_proof.clone().expect("ZK proof is required"))
            .catch(crate::exn::BincodeException, "zk proof")?;

    // Rebuild X from bytes
    let X = EcPoint::<ESecp>::from_bytes(x_compressed)
        .map_err(|_| exception!(name = crate::exn::EncryptionException, ctx = "bad X bytes"))?;

    // Verify
    let data = pzk::Data {
        key0: pk,
        c: &ct_inner,
        x: &X,
        b: &EcPoint::<ESecp>::generator().into(),
    };
    pzk::non_interactive::verify::<ESecp, sha2::Sha256>(
        &SHARED_STATE,
        aux,
        data,
        &commitment,
        security,
        &proof,
    )
    .catch(crate::exn::EncryptionException, "paillier-zk verify")?;
    Ok(())
}

/// Decrypt and return the raw Paillier plaintext as a big integer (no truncation).
pub fn pve_decrypt_integer(sk: &PaillierSk, ct: &PveCiphertext) -> Outcome<Integer> {
    let m = sk
        .decrypt(&ct.ciphertext)
        .catch(crate::exn::EncryptionException, "paillier decrypt")?;
    Ok(m)
}

/// Backward-compatible decrypt that returns big-endian bytes without padding/truncation.
pub fn pve_decrypt(sk: &PaillierSk, ct: &PveCiphertext) -> Outcome<Vec<u8>> {
    let m = pve_decrypt_integer(sk, ct)?;
    Ok(m.to_digits(rug::integer::Order::MsfBe))
}

/// secp256k1 group order as Integer
pub fn secp_order_integer() -> Integer {
    // n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    Integer::from_str_radix(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        16,
    )
    .unwrap()
}

/// Reduce an integer modulo secp256k1 order and return a fixed 32-byte big-endian array.
pub fn integer_mod_secp_to_32be(x: &Integer) -> [u8; 32] {
    let q = secp_order_integer();
    let r = x.clone() % q;
    let mut bytes = r.to_digits(rug::integer::Order::MsfBe);
    if bytes.len() < 32 {
        let mut padded = vec![0u8; 32 - bytes.len()];
        padded.extend_from_slice(&bytes);
        bytes = padded;
    } else if bytes.len() > 32 {
        bytes = bytes[bytes.len() - 32..].to_vec();
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    arr
}

/// Combine Paillier ciphertexts using library homomorphic ops (handles negatives).
/// Computes Enc(Σ exp_i * pt_i) where `exp_i` are signed integers.
pub fn pve_combine(
    pk: &PaillierPk,
    pairs: &[(PveCiphertext, Integer)],
    pt_len_hint: u32,
) -> Outcome<PveCiphertext> {
    // Start from Enc(0)
    let (mut acc, _) = pk
        .encrypt_with_random(&mut OsRng, &Integer::from(0))
        .catch(crate::exn::EncryptionException, "encrypt zero")?;

    for (ct_box, exp) in pairs.iter() {
        let neg = exp < &Integer::from(0);
        let abs_exp = if neg {
            Integer::from(-exp)
        } else {
            Integer::from(exp.clone())
        };
        let mut term = pk
            .omul(&abs_exp, &ct_box.ciphertext)
            .catch(crate::exn::EncryptionException, "omul in combine")?;
        if neg {
            term = pk
                .oneg(&term)
                .catch(crate::exn::EncryptionException, "oneg in combine")?;
        }
        acc = pk
            .oadd(&acc, &term)
            .catch(crate::exn::EncryptionException, "oadd in combine")?;
    }
    Ok(PveCiphertext {
        ciphertext: acc,
        zk_commitment: None,
        zk_proof: None,
        pt_len: pt_len_hint,
    })
}

#[cfg(test)]
mod tests {}
