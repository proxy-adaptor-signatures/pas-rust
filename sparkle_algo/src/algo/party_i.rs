//! Generic, curve-agnostic implementation of party operations for threshold signatures.

use crate::{
    integer_mod_secp_to_32be, pve_decrypt_integer, PaillierSk, PveCiphertext, ThresholdCurve,
    ThresholdSig,
};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use std::iter::zip;
use xuanmi_base_support::*;
use zeroize::Zeroize;

use crate::exn;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SharesCommitment<C: ThresholdCurve> {
    pub commitment: Vec<C::Point>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(deserialize = "C: ThresholdCurve"))]
pub struct KeyGenProposedCommitment<C: ThresholdCurve> {
    pub index: u16,
    pub shares_commitment: SharesCommitment<C>,
    pub zkp: KeyGenZKP<C>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(deserialize = "C: ThresholdCurve"))]
pub struct KeyGenCommitment<C: ThresholdCurve> {
    pub index: u16,
    pub shares_commitment: SharesCommitment<C>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Share<C: ThresholdCurve> {
    generator_index: u16,
    pub receiver_index: u16,
    value: C::Scalar,
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct PartyKey<C: ThresholdCurve> {
    pub index: u16,
    pub u_i: C::Scalar,
    pub g_u_i: C::Point,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenZKP<C: ThresholdCurve> {
    pub g_k_i: C::Point,
    pub sigma_i: C::Scalar,
}

#[derive(Copy, Clone)]
pub struct Nonce<C: ThresholdCurve> {
    pub secret: C::Scalar,
    pub public: C::Point,
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct SigningKey<C: ThresholdCurve> {
    pub index: u16,
    pub x_i: C::Scalar,
    pub g_x_i: C::Point,
    pub group_public: C::Point,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SigningCommitment<C: ThresholdCurve> {
    pub index: u16,
    pub com: C::Scalar,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SigningDecommitment<C: ThresholdCurve> {
    pub index: u16,
    pub g_r_i: C::Point,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SigningResponse<C: ThresholdCurve> {
    pub index: u16,
    pub response: C::Scalar,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signature<C: ThresholdCurve> {
    pub r: C::Point,
    pub z: C::Scalar,
    pub hash: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreSignature<C: ThresholdCurve> {
    pub R_prime: C::Point,
    pub z: C::Scalar,
    pub hash: Vec<u8>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(bound(deserialize = "C: ThresholdCurve"))]
pub struct ProxyOutput<C: ThresholdCurve> {
    pub pre_signature: PreSignature<C>,
    pub blinding_share_enc: PveCiphertext,
    pub R: C::Point,
}

pub struct BlindedWitness<C: ThresholdCurve>(pub C::Scalar);

pub type AdaptorSignature<C> = Signature<C>;

impl<C: ThresholdCurve> Zeroize for KeyGenProposedCommitment<C> {
    fn zeroize(&mut self) {
        // Not zeroizing index
        self.shares_commitment.zeroize();
        self.zkp.zeroize();
    }
}

impl<C: ThresholdCurve> Zeroize for KeyGenZKP<C> {
    fn zeroize(&mut self) {
        // Points and scalars do not implement Zeroize in k256
    }
}

impl<C: ThresholdCurve> Zeroize for SharesCommitment<C> {
    fn zeroize(&mut self) {
        // Points do not implement Zeroize in k256
    }
}

impl<C: ThresholdCurve> Zeroize for Share<C> {
    fn zeroize(&mut self) {
        // Not zeroizing indices
        // Scalars do not implement Zeroize in k256
    }
}

impl<C: ThresholdCurve> KeyGenProposedCommitment<C> {
    pub fn is_valid_zkp(&self, challenge: C::Scalar) -> Outcome<()> {
        if self.zkp.g_k_i
            != (C::mul_base(&self.zkp.sigma_i)
                + (self.get_commitment_to_secret() * (C::scalar_zero() - challenge)))
        {
            throw!(
                name = exn::SignatureException,
                ctx = "Proof of knowledge to the key share is invalid"
            );
        }
        Ok(())
    }

    pub fn get_commitment_to_secret(&self) -> C::Point {
        self.shares_commitment.commitment[0]
    }
}

impl<C: ThresholdCurve> Share<C> {
    pub fn new_from(generator_index: u16, receiver_index: u16, value: C::Scalar) -> Self {
        Self {
            generator_index,
            receiver_index,
            value,
        }
    }

    pub fn get_value(&self) -> C::Scalar {
        self.value
    }

    fn verify_share(&self, com: &SharesCommitment<C>) -> Outcome<()> {
        let f_result = C::mul_base(&self.value);
        let term = C::Scalar::from(self.receiver_index as u64);
        let mut result = C::point_identity();

        for (index, comm_i) in com.commitment.iter().rev().enumerate() {
            result = result + *comm_i;
            if index != com.commitment.len() - 1 {
                result = result * term;
            }
        }

        if f_result != result {
            throw!(
                name = exn::CommitmentException,
                ctx = "Commitment to the key share is invalid"
            );
        }
        Ok(())
    }
}

impl<C: ThresholdCurve> PartyKey<C> {
    pub fn new<R: CryptoRngCore>(index: u16, rng: &mut R) -> Self {
        let u_i = C::random_scalar(rng);
        let g_u_i = C::mul_base(&u_i);
        Self { index, u_i, g_u_i }
    }

    pub fn generate_shares<R: CryptoRngCore>(
        &self,
        numshares: u16,
        threshold: u16,
        rng: &mut R,
    ) -> Outcome<(SharesCommitment<C>, Vec<Share<C>>)> {
        if threshold < 1 || numshares < 1 || threshold > numshares {
            throw!(
                name = exn::ConfigException,
                ctx = "Invalid threshold/share configuration"
            );
        }

        let numcoeffs = threshold;
        let coefficients: Vec<C::Scalar> = (0..numcoeffs).map(|_| C::random_scalar(rng)).collect();

        let commitment = coefficients.iter().fold(vec![self.g_u_i], |mut acc, c| {
            acc.push(C::mul_base(c));
            acc
        });

        let shares = (1..=numshares)
            .map(|index| {
                let scalar_index = C::Scalar::from(index as u64);
                let mut value = C::scalar_zero();
                for i in (0..numcoeffs).rev() {
                    value = value + coefficients[i as usize];
                    value = value * scalar_index;
                }
                value = value + self.u_i;
                Share {
                    generator_index: self.index,
                    receiver_index: index,
                    value,
                }
            })
            .collect();

        Ok((SharesCommitment { commitment }, shares))
    }

    pub fn keygen_generate_zkp<R: CryptoRngCore>(
        &self,
        context: &str,
        rng: &mut R,
    ) -> Outcome<KeyGenZKP<C>> {
        let k_i = C::random_scalar(rng);
        let g_k_i = C::mul_base(&k_i);
        let challenge =
            ThresholdSig::<C>::generate_dkg_challenge(&self.index, context, &self.g_u_i, &g_k_i)?;
        let sigma_i = k_i + (self.u_i * challenge);
        Ok(KeyGenZKP { g_k_i, sigma_i })
    }

    pub fn keygen_receive_commitments_and_validate_peers(
        peer_commitments: Vec<KeyGenProposedCommitment<C>>,
        context: &str,
    ) -> Outcome<(Vec<u16>, Vec<KeyGenCommitment<C>>)> {
        let mut invalid_peer_ids = Vec::new();
        let mut valid_peer_commitments = Vec::with_capacity(peer_commitments.len());

        for commitment in peer_commitments {
            let challenge = ThresholdSig::<C>::generate_dkg_challenge(
                &commitment.index,
                context,
                &commitment.get_commitment_to_secret(),
                &commitment.zkp.g_k_i,
            )?;

            if !commitment.is_valid_zkp(challenge).is_ok() {
                invalid_peer_ids.push(commitment.index);
            } else {
                valid_peer_commitments.push(KeyGenCommitment {
                    index: commitment.index,
                    shares_commitment: commitment.shares_commitment,
                });
            }
        }
        Ok((invalid_peer_ids, valid_peer_commitments))
    }

    pub fn keygen_verify_share_construct_signingkey(
        party_shares: Vec<Share<C>>,
        shares_com_vec: Vec<KeyGenCommitment<C>>,
        index: u16,
    ) -> Outcome<SigningKey<C>> {
        for share in &party_shares {
            let commitment = shares_com_vec
                .iter()
                .find(|comm| comm.index == share.generator_index)
                .if_none(
                    exn::CommitmentException,
                    "Share has no corresponding commitment",
                )?;
            share.verify_share(&commitment.shares_commitment)?;
        }

        let x_i = party_shares
            .iter()
            .fold(C::scalar_zero(), |acc, x| acc + x.value);
        let g_x_i = C::mul_base(&x_i);

        let group_public = shares_com_vec
            .iter()
            .map(|c| c.shares_commitment.commitment[0])
            .fold(C::point_identity(), |acc, x| acc + x);

        Ok(SigningKey {
            index,
            x_i,
            g_x_i,
            group_public,
        })
    }
}

impl<C: ThresholdCurve> SigningKey<C> {
    pub fn sign_sample_nonce_and_commit<R: CryptoRngCore>(
        &self,
        rng: &mut R,
        msg: &[u8],
        signers: &Vec<u16>,
    ) -> Outcome<(Nonce<C>, C::Scalar, C::Point)> {
        let nonce = Nonce::new(rng)?;
        let com = ThresholdSig::<C>::generate_hash_commitment(msg, signers, &nonce.public)?;
        Ok((nonce, com, nonce.public))
    }

    pub fn sign_decommit_and_respond(
        &self,
        msg: &[u8],
        signers: &Vec<u16>,
        com_vec: &Vec<C::Scalar>,
        decom_vec: &Vec<C::Point>,
        nonce: &Nonce<C>,
    ) -> Outcome<SigningResponse<C>> {
        for (com_i, decom_i) in zip(com_vec, decom_vec) {
            let com = ThresholdSig::<C>::generate_hash_commitment(msg, signers, decom_i)?;
            if com != *com_i {
                throw!(
                    name = exn::CommitmentException,
                    ctx = "Commitment to local nonce is invalid"
                );
            }
        }
        let group_nonce: C::Point = decom_vec
            .iter()
            .copied()
            .fold(C::point_identity(), |acc, p| acc + p);
        let c = ThresholdSig::<C>::generate_hash_signing(msg, &self.group_public, &group_nonce)?;
        let lambda_i = ThresholdSig::<C>::get_lagrange_coeff(0, self.index, signers)?;
        let response = nonce.secret + (c * lambda_i * self.x_i);
        Ok(SigningResponse {
            index: self.index,
            response,
        })
    }
}

impl<C: ThresholdCurve> Nonce<C> {
    pub fn new<R: CryptoRngCore>(rng: &mut R) -> Outcome<Nonce<C>> {
        let secret = C::random_scalar(rng);
        let public = C::mul_base(&secret);
        if public == C::point_identity() {
            throw!(
                name = exn::CommitmentException,
                ctx = "Invalid nonce commitment"
            );
        }
        Ok(Nonce { secret, public })
    }
}

pub fn get_ith_pubkey<C: ThresholdCurve>(
    index: u16,
    commitments: &Vec<KeyGenCommitment<C>>,
) -> C::Point {
    let mut ith_pubkey = C::point_identity();
    let term = C::Scalar::from(index as u64);

    for commitment in commitments {
        let mut result = C::point_identity();
        let t = commitment.shares_commitment.commitment.len() as u16;
        for (inner_index, comm_i) in commitment
            .shares_commitment
            .commitment
            .iter()
            .rev()
            .enumerate()
        {
            result = result + *comm_i;
            if (inner_index as u16) != t - 1 {
                result = result * term;
            }
        }
        ith_pubkey = ith_pubkey + result;
    }
    ith_pubkey
}

impl<C: ThresholdCurve> Signature<C> {
    /// validate performs a plain Schnorr validation operation; this is identical
    /// to performing validation of a Schnorr signature that has been signed by a
    /// single party.
    pub fn validate(&self, pubkey: C::Point) -> Outcome<()> {
        let challenge = ThresholdSig::<C>::generate_hash_signing(&self.hash, &pubkey, &self.r)?;
        if self.r != (C::mul_base(&self.z) - (pubkey * challenge)) {
            throw!(
                name = exn::SignatureException,
                ctx = &format!("Aggregated signature is invalid")
            );
        }
        Ok(())
    }

    pub fn extract(&self, pre_signature: &PreSignature<C>) -> Outcome<C::Scalar> {
        Ok(self.z - pre_signature.z)
    }
}

impl<C: ThresholdCurve> PreSignature<C> {
    pub fn adapt(&self, witness: C::Scalar) -> Outcome<AdaptorSignature<C>> {
        let z_prime = self.z + witness;
        Ok(Signature {
            r: self.R_prime,
            z: z_prime,
            hash: self.hash.clone(),
        })
    }

    pub fn pvrfy(&self, group_public: C::Point, statement: C::Point) -> Outcome<()> {
        let challenge =
            ThresholdSig::<C>::generate_hash_signing(&self.hash, &group_public, &self.R_prime)?;
        if (C::mul_base(&self.z) + statement) != (self.R_prime + (group_public * challenge)) {
            throw!(
                name = exn::SignatureException,
                ctx = &format!("Invalid pre-signature")
            );
        }
        Ok(())
    }
}

impl<C: ThresholdCurve> ProxyOutput<C> {
    pub fn adapt(
        &self,
        decryption_key: &PaillierSk,
        witness: C::Scalar,
    ) -> Outcome<AdaptorSignature<C>> {
        // Decrypt to Integer and reduce mod curve order
        let m = pve_decrypt_integer(decryption_key, &self.blinding_share_enc)?;
        let arr = integer_mod_secp_to_32be(&m);
        let r = C::scalar_from_bytes_reduced(arr);
        self.pre_signature.adapt(witness + r)
    }

    // Extracts a *blinded* witness, instead of the original witness.
    pub fn extract(&self, sig: &AdaptorSignature<C>) -> Outcome<BlindedWitness<C>> {
        sig.extract(&self.pre_signature).map(BlindedWitness)
    }
}

impl<C: ThresholdCurve> BlindedWitness<C> {
    pub fn unblind(&self, shares: &Vec<Share<C>>, _full_signers: &Vec<u16>) -> Outcome<C::Scalar> {
        use crate::algo::threshold_ops::{reconstruct_secret, validate_shares};

        // Validate shares before reconstruction
        validate_shares(shares, 2)?; // Need at least 2 shares for meaningful reconstruction

        // Reconstruct the blinding factor r from the provided shares
        let r = reconstruct_secret(shares, 0)?;

        // Return the unblinded witness: blinded_witness - r = (witness + r) - r = witness
        Ok(self.0 - r)
    }
}
