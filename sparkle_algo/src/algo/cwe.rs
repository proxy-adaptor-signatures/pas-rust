// sparkle_algo/src/algo/cwe.rs

use serde::{Deserialize, Serialize};
use sha2::Digest;
use xuanmi_base_support::*;

use crate::algo::party_i::Signature;
use crate::algo::threshold_sig::ThresholdCurve;

/// A CWE ciphertext, which is an ElGamal-like ciphertext over curve C.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CweCiphertext<C: ThresholdCurve> {
    pub c1: C::Point,
    pub c2: Vec<u8>, // Encrypted message
}

fn generate_symmetric_key<C: ThresholdCurve>(point: &C::Point) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(C::point_compress(point));
    hasher.finalize().into()
}

/// CWE.Encrypt
pub fn cwe_encrypt<C: ThresholdCurve>(
    group_public_key: &C::Point,
    msg_to_sign: &[u8],
    aggregated_nonce: &C::Point,
    plaintext: &[u8],
) -> Outcome<CweCiphertext<C>> {
    use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit, Nonce};
    use rand_core::OsRng;
    use sha2::Sha512;

    // h = H(group_public_key || msg_to_sign || aggregated_nonce)
    let mut hasher = Sha512::new();
    hasher.update(C::point_compress(group_public_key));
    hasher.update(msg_to_sign);
    hasher.update(C::point_compress(aggregated_nonce));
    let h = C::scalar_from_hash(hasher);

    // ek = h * group_public_key + aggregated_nonce
    let ek = (*group_public_key) * h + *aggregated_nonce;

    // Random ephemeral y and c1 = y*G
    let mut rng = OsRng;
    let y = C::random_scalar(&mut rng);
    let c1 = C::mul_base(&y);

    // shared_secret = y * ek (compute as ek * y due to trait bounds)
    let shared_secret = ek * y;
    let key = generate_symmetric_key::<C>(&shared_secret);

    let cipher = ChaCha20Poly1305::new(&key.into());
    let nonce = Nonce::from_slice(&[0u8; 12]);

    let mut buffer = Vec::with_capacity(plaintext.len() + 16);
    buffer.extend_from_slice(plaintext);

    cipher
        .encrypt_in_place(nonce, b"", &mut buffer)
        .map_err(|_| Exception::new())?;
    Ok(CweCiphertext { c1, c2: buffer })
}

/// CWE.Decrypt
pub fn cwe_decrypt<C: ThresholdCurve>(
    signature: &Signature<C>,
    ciphertext: &CweCiphertext<C>,
) -> Outcome<Vec<u8>> {
    use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit, Nonce};

    let dk = signature.z;
    let c1 = &ciphertext.c1;

    let shared_secret = (*c1) * dk;
    let key = generate_symmetric_key::<C>(&shared_secret);

    let cipher = ChaCha20Poly1305::new(&key.into());
    let nonce = Nonce::from_slice(&[0u8; 12]);

    let mut buffer = ciphertext.c2.clone();

    cipher
        .decrypt_in_place(nonce, b"", &mut buffer)
        .map_err(|_| Exception::new())?;

    Ok(buffer)
}
