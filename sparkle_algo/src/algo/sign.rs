#![allow(non_snake_case)]

use luban_core::MpcClientMessenger;
use rand_core::OsRng;
use std::collections::HashMap;
use xuanmi_base_support::*;

use super::cwe::{cwe_encrypt, CweCiphertext};
use super::data_structure::KeyStore;
use super::party_i::{get_ith_pubkey, PreSignature, Signature, SigningKey, SigningResponse};
use super::pve_paillier::{
    pve_combine, pve_encrypt_link_secp, pve_verify_link_secp, pzk, PaillierPk, PveCiphertext,
};
use crate::algo::advertisement::Advt;
use crate::algo::party_i::Nonce;
use crate::algo::threshold_sig::{ThresholdCurve, ThresholdSig};
use crate::{exn, ProxyOutput};
use rug::integer::Order;
use rug::Integer;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(bound(deserialize = "C: ThresholdCurve"))]
pub struct BlindingShareEnc<C: ThresholdCurve> {
    pub gr_i: C::Point,
    pub ct: PveCiphertext,
    pub binding: Vec<u8>,
    pub cwe: CweCiphertext<C>,
}

fn combine_paillier_for_blinding<C: ThresholdCurve>(
    seller_pk: &PaillierPk,
    signers: &Vec<u16>,
    enc_vec: &Vec<BlindingShareEnc<C>>,
) -> Outcome<PveCiphertext> {
    let mut pairs: Vec<(PveCiphertext, Integer)> = Vec::with_capacity(enc_vec.len());
    for (i, signer_id) in signers.iter().enumerate() {
        let lambda_i = ThresholdSig::<C>::get_lagrange_coeff(0, *signer_id, signers)?;
        let exp = Integer::from_digits(&C::scalar_to_bytes(&lambda_i), Order::MsfBe);
        pairs.push((enc_vec[i].ct.clone(), exp));
    }
    // 32-byte scalar length hint
    pve_combine(seller_pk, &pairs, 32)
}

fn verify_enc_batch<C: ThresholdCurve>(
    aux: &pzk::Aux,
    security: &pzk::SecurityParams,
    seller_pk: &PaillierPk,
    enc_vec: &Vec<BlindingShareEnc<C>>,
) -> Outcome<()> {
    for enc in enc_vec.iter() {
        let ge_bytes = C::point_compress(&enc.gr_i);
        pve_verify_link_secp(aux, security, seller_pk, &enc.ct, &ge_bytes)?;
        if enc.cwe.c2.is_empty() {
            throw!(
                name = exn::EncryptionException,
                ctx = "empty CWE ciphertext"
            );
        }
    }
    Ok(())
}

pub fn algo_sign<C: ThresholdCurve>(
    server: &str,
    tr_uuid: &str,
    tcn_config: &[u16; 3],
    msg_hashed: &[u8],
    keystore: &KeyStore<C>,
) -> Outcome<Signature<C>> {
    if msg_hashed.len() > 64 {
        let mut msg =
            String::from("The sign algorithm assumes its input message has been hashed.\n");
        msg += &format!(
            "However, the algorithm received a message with length = {}, indicating the message is probably un-hashed.\n",
            msg_hashed.len()
        );
        msg += "Did the caller forget to hash the message?";
        throw!(
            name = exn::ConfigException,
            ctx = &("Message=\"".to_owned() + &msg + "\" is invalid")
        );
    }

    let (threshold, parties, share_count) = (tcn_config[0], tcn_config[1], tcn_config[2]);
    let signing_key: SigningKey<C> = keystore.signing_key;
    let valid_com_vec = keystore.valid_com_vec.clone();
    let party_id = keystore.party_num_int;
    println!(
        "Start sign with threshold={}, parties={}, share_count={}",
        threshold, parties, share_count,
    );
    let cond = threshold + 1 <= parties && parties <= share_count;
    if !cond {
        throw!(
            name = exn::ConfigException,
            ctx = &format!(
                "t/c/n config should satisfy t<c<=n.\n\tHowever, {}/{}/{} was provided",
                threshold, parties, share_count
            )
        );
    }

    // #region signup for signing
    let messenger =
        MpcClientMessenger::signup(server, "sign", tr_uuid, threshold, parties, share_count)
            .catch(
                exn::SignUpException,
                &format!(
                    "Cannot sign up for signing with server={}, tr_uuid={}.",
                    server, tr_uuid
                ),
            )?;
    let party_num_int = messenger.my_id();
    println!(
        "MPC Server {} designated this party with\n\tparty_id={}, tr_uuid={}",
        server,
        party_num_int,
        messenger.uuid()
    );
    let mut round: u16 = 1;
    let mut rng = OsRng;
    // #endregion

    // #region round 1: collect signer IDs
    messenger.send_broadcast(party_num_int, round, &obj_to_json(&party_id)?)?;
    let round1_ans_vec = messenger.recv_broadcasts(party_num_int, parties, round);
    let mut signers_vec: Vec<u16> = round1_ans_vec
        .iter()
        .map(|text| json_to_obj(text))
        .collect::<Result<Vec<u16>, _>>()?;
    if signers_vec.contains(&party_id) {
        throw!(
            name = exn::ConfigException,
            ctx = &(format!("Duplicate keystore in signing"))
        );
    }
    if valid_com_vec
        .iter()
        .find(|comm| comm.index == party_id)
        .is_none()
    {
        throw!(
            name = exn::ConfigException,
            ctx = &(format!("Keystore not in the list of valid parties from KeyGen"))
        );
    }
    signers_vec.insert(party_num_int as usize - 1, party_id);
    println!("Finished sign round {round}");
    round += 1;
    // #endregion

    // #region round 2: broadcast signing commitment to the nonce
    let (nonce, com, decom) =
        match signing_key.sign_sample_nonce_and_commit(&mut rng, msg_hashed, &signers_vec) {
            Ok(_ok) => _ok,
            Err(_) => throw!(
                name = exn::CommitmentException,
                ctx = &format!("Failed to generate commitments to the local nonce")
            ),
        };
    messenger.send_broadcast(party_num_int, round, &obj_to_json(&com)?)?;
    let round2_ans_vec = messenger.recv_broadcasts(party_num_int, parties, round);
    let mut signing_com_vec: Vec<C::Scalar> = round2_ans_vec
        .iter()
        .map(|text| json_to_obj(text))
        .collect::<Result<Vec<C::Scalar>, _>>()?;
    signing_com_vec.insert(party_num_int as usize - 1, com.clone());
    println!("Finished sign round {round}");
    round += 1;
    // #endregion

    // #region round 3: broadcast signing decommitment
    messenger.send_broadcast(party_num_int, round, &obj_to_json(&decom)?)?;
    let round3_ans_vec = messenger.recv_broadcasts(party_num_int, parties, round);
    let mut signing_decom_vec: Vec<C::Point> = round3_ans_vec
        .iter()
        .map(|text| json_to_obj(text))
        .collect::<Result<Vec<C::Point>, _>>()?;
    signing_decom_vec.insert(party_num_int as usize - 1, decom.clone());
    println!("Finished sign round {round}");
    round += 1;
    // #endregion

    // #region round 4: broadcast signing response
    let response_i: SigningResponse<C> = match signing_key.sign_decommit_and_respond(
        msg_hashed,
        &signers_vec,
        &signing_com_vec,
        &signing_decom_vec,
        &nonce,
    ) {
        Ok(_ok) => _ok,
        Err(err) => throw!(
            name = exn::SignatureException,
            ctx = &(format!("Failed to sign with secret share, particularly \"{}\"", err))
        ),
    };

    messenger.send_broadcast(party_num_int, round, &obj_to_json(&response_i)?)?;
    let round4_ans_vec = messenger.recv_broadcasts(party_num_int, parties, round);
    let mut response_vec: Vec<SigningResponse<C>> = round4_ans_vec
        .iter()
        .map(|text| json_to_obj(text))
        .collect::<Result<Vec<SigningResponse<C>>, _>>()?;
    response_vec.insert(party_num_int as usize - 1, response_i);
    println!("Finished sign round {round}");
    // #endregion

    // #region: combine signature shares and verify
    let mut signer_pubkeys: HashMap<u16, C::Point> = HashMap::with_capacity(parties as usize);
    for counter in 0..parties as usize {
        let ith_pubkey = get_ith_pubkey::<C>(signers_vec[counter], &valid_com_vec);
        let _ = signer_pubkeys.insert(signers_vec[counter], ith_pubkey);
    }
    let r: C::Point = signing_decom_vec
        .iter()
        .copied()
        .fold(C::point_identity(), |acc, p| acc + p);
    let z: C::Scalar = response_vec
        .iter()
        .fold(C::scalar_zero(), |acc, s| acc + s.response);
    let group_sig = Signature::<C> {
        r,
        z,
        hash: msg_hashed.to_vec(),
    };
    if !ThresholdSig::<C>::validate_signature(
        &group_sig.r,
        &group_sig.z,
        &group_sig.hash,
        &signing_key.group_public,
    )
    .is_ok()
    {
        throw!(
            name = exn::SignatureException,
            ctx = &(format!("Invalid aggregated signature"))
        );
    }
    // #endregion

    println!("Finished sign");
    Ok(group_sig)
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(bound(deserialize = "C: ThresholdCurve"))]
pub struct PartialProxyOutput<C: ThresholdCurve> {
    pub pre_signature: PreSignature<C>,
    pub R: C::Point,
    pub signers: Vec<u16>,
    pub encs: Vec<BlindingShareEnc<C>>,
    pub compute_time: u64,
}

pub struct ProxGenConfig<'a, C: ThresholdCurve> {
    pub server: &'a str,
    pub tr_uuid: &'a str,
    pub tcn_config: &'a [u16; 3],
    pub msg_hashed: &'a [u8],
    pub statement: &'a C::Point,
    pub keystore: &'a KeyStore<C>,
    pub blind_keystore: &'a KeyStore<C>,
    pub advt: &'a Advt<C>,
    pub security_params: &'a pzk::SecurityParams,
    pub aux: &'a pzk::Aux,
    pub bench_logs: bool,
}

pub fn algo_prox_gen<C: ThresholdCurve>(
    ProxGenConfig {
        server,
        tr_uuid,
        tcn_config,
        msg_hashed,
        statement,
        keystore,
        blind_keystore,
        advt,
        security_params,
        aux,
        bench_logs,
    }: ProxGenConfig<C>,
) -> Outcome<PartialProxyOutput<C>> {
    if msg_hashed.len() > 64 {
        let mut msg =
            String::from("The sign algorithm assumes its input message has been hashed.\n");
        msg += &format!(
            "However, the algorithm received a message with length = {}, indicating the message is probably un-hashed.\n",
            msg_hashed.len()
        );
        msg += "Did the caller forget to hash the message?";
        throw!(
            name = exn::ConfigException,
            ctx = &("Message=\"".to_owned() + &msg + "\" is invalid")
        );
    }

    let mut total_compute_ns: u128 = 0;

    // Assume AdVerify is run separately
    let seller_pk = &advt.pk;
    let (threshold, parties, share_count) = (tcn_config[0], tcn_config[1], tcn_config[2]);
    let signing_key: SigningKey<C> = keystore.signing_key;
    let valid_com_vec = keystore.valid_com_vec.clone();
    let party_id = keystore.party_num_int;

    // blinding-factor pieces
    let r_i: C::Scalar = blind_keystore.signing_key.x_i;
    let gr_i: C::Point = blind_keystore.signing_key.g_x_i; // g^{r_i}
    let R: C::Point = blind_keystore.signing_key.group_public; // group R

    println!(
        "Start psign with threshold={}, parties={}, share_count={}",
        threshold, parties, share_count,
    );
    let cond = threshold + 1 <= parties && parties <= share_count;
    if !cond {
        throw!(
            name = exn::ConfigException,
            ctx = &format!(
                "t/c/n config should satisfy t<c<=n.\n\tHowever, {}/{}/{} was provided",
                threshold, parties, share_count
            )
        );
    }

    // #region signup for signing
    let messenger =
        MpcClientMessenger::signup(server, "sign", tr_uuid, threshold, parties, share_count)
            .catch(
                exn::SignUpException,
                &format!(
                    "Cannot sign up for pre-signing with server={}, tr_uuid={}.",
                    server, tr_uuid
                ),
            )?;
    let party_num_int = messenger.my_id();
    println!(
        "MPC Server {} designated this party with\n\tparty_id={}, tr_uuid={}",
        server,
        party_num_int,
        messenger.uuid()
    );
    let mut round: u16 = 1;
    let mut rng = OsRng;
    // #endregion

    // #region round 1: collect signer IDs
    messenger.send_broadcast(party_num_int, round, &obj_to_json(&party_id)?)?;
    let round1_ans_vec = messenger.recv_broadcasts(party_num_int, parties, round);
    let mut signers_vec: Vec<u16> = round1_ans_vec
        .iter()
        .map(|text| json_to_obj(text))
        .collect::<Result<Vec<u16>, _>>()?;
    if signers_vec.contains(&party_id) {
        throw!(
            name = exn::ConfigException,
            ctx = &(format!("Duplicate keystore in signing"))
        );
    }
    if valid_com_vec
        .iter()
        .find(|comm| comm.index == party_id)
        .is_none()
    {
        throw!(
            name = exn::ConfigException,
            ctx = &(format!("Keystore not in the list of valid parties from KeyGen"))
        );
    }
    signers_vec.insert(party_num_int as usize - 1, party_id);
    println!("Finished psign round {round}");
    round += 1;
    // #endregion

    // #region round 2: adaptor commitment including blinded statement
    let statement_blinded = *statement + R; // g^{wit} * g^{r} = g^{wit+r}
    let t0 = std::time::Instant::now();
    let nonce = Nonce::<C>::new(&mut rng)?;
    let com = ThresholdSig::<C>::generate_hash_commitment_adaptor(
        msg_hashed,
        &signers_vec,
        &nonce.public,
        &statement_blinded,
    )?;
    total_compute_ns += t0.elapsed().as_nanos();
    if bench_logs {
        println!(
            "[bench] proxgen.compute.commitment_ns={}",
            total_compute_ns as u64
        );
    }
    messenger.send_broadcast(party_num_int, round, &obj_to_json(&com)?)?;
    let round2_ans_vec = messenger.recv_broadcasts(party_num_int, parties, round);
    let mut signing_com_vec: Vec<C::Scalar> = round2_ans_vec
        .iter()
        .map(|text| json_to_obj(text))
        .collect::<Result<Vec<C::Scalar>, _>>()?;
    signing_com_vec.insert(party_num_int as usize - 1, com.clone());
    println!("Finished psign round {round}");
    round += 1;
    // #endregion

    // #region round 3: broadcast decommitment (nonce point)
    messenger.send_broadcast(party_num_int, round, &obj_to_json(&nonce.public)?)?;
    let round3_ans_vec = messenger.recv_broadcasts(party_num_int, parties, round);
    let mut signing_decom_vec: Vec<C::Point> = round3_ans_vec
        .iter()
        .map(|text| json_to_obj(text))
        .collect::<Result<Vec<C::Point>, _>>()?;
    signing_decom_vec.insert(party_num_int as usize - 1, nonce.public);
    println!("Finished psign round {round}");
    round += 1;
    // #endregion

    // #region round 4: broadcast Paillier encryption of r_i with ZK linkage to g^{r_i} + CWE
    let t1 = std::time::Instant::now();
    let ct = pve_encrypt_link_secp(aux, security_params, seller_pk, &C::scalar_to_bytes(&r_i))?;

    let enc_payload = BlindingShareEnc::<C> {
        gr_i,
        ct,
        binding: msg_hashed.to_vec(),
        cwe: cwe_encrypt::<C>(
            &signing_key.group_public,
            msg_hashed,
            &(*statement + R),
            &C::scalar_to_bytes(&r_i),
        )?,
    };
    total_compute_ns += t1.elapsed().as_nanos();
    if bench_logs {
        println!(
            "[bench] proxgen.compute.pve_cwe_ns={}",
            t1.elapsed().as_nanos() as u64
        );
    }
    messenger.send_broadcast(party_num_int, round, &obj_to_json(&enc_payload)?)?;
    let round4_ans_vec = messenger.recv_broadcasts(party_num_int, parties, round);
    let mut enc_vec: Vec<BlindingShareEnc<C>> = round4_ans_vec
        .iter()
        .map(|text| json_to_obj(text))
        .collect::<Result<Vec<BlindingShareEnc<C>>, _>>()?;
    enc_vec.insert(party_num_int as usize - 1, enc_payload);

    println!("Finished psign round {round}");
    round += 1;
    // #endregion

    // #region round 5: broadcast signing response under adaptor
    let t2 = std::time::Instant::now();
    for (com_i, decom_i) in signing_com_vec.iter().zip(signing_decom_vec.iter()) {
        let recomputed = ThresholdSig::<C>::generate_hash_commitment_adaptor(
            msg_hashed,
            &signers_vec,
            decom_i,
            &statement_blinded,
        )?;
        if &recomputed != com_i {
            throw!(
                name = exn::CommitmentException,
                ctx = "Commitment to local nonce is invalid"
            );
        }
    }
    if bench_logs {
        println!(
            "[bench] proxgen.compute.verify_commitments_ns={}",
            t2.elapsed().as_nanos() as u64
        );
    }
    let group_nonce: C::Point = signing_decom_vec
        .iter()
        .copied()
        .fold(C::point_identity(), |acc, p| acc + p);
    let r_prime = group_nonce + statement_blinded;
    let t3 = std::time::Instant::now();
    let c =
        ThresholdSig::<C>::generate_hash_signing(msg_hashed, &signing_key.group_public, &r_prime)?;
    let lambda_i = ThresholdSig::<C>::get_lagrange_coeff(0, signing_key.index, &signers_vec)?;
    let response_i = SigningResponse::<C> {
        index: signing_key.index,
        response: nonce.secret + (c * lambda_i * signing_key.x_i),
    };
    total_compute_ns += t2.elapsed().as_nanos() + t3.elapsed().as_nanos();
    if bench_logs {
        println!(
            "[bench] proxgen.compute.response_ns={}",
            t3.elapsed().as_nanos() as u64
        );
    }

    messenger.send_broadcast(party_num_int, round, &obj_to_json(&response_i)?)?;
    let round5_ans_vec = messenger.recv_broadcasts(party_num_int, parties, round);
    let mut response_vec: Vec<SigningResponse<C>> = round5_ans_vec
        .iter()
        .map(|text| json_to_obj(text))
        .collect::<Result<Vec<SigningResponse<C>>, _>>()?;
    response_vec.insert(party_num_int as usize - 1, response_i);
    println!("Finished psign round {round}");
    // #endregion

    // #region: aggregate pre-signature and verify
    let t4 = std::time::Instant::now();
    let z_agg: C::Scalar = response_vec
        .iter()
        .fold(C::scalar_zero(), |acc, s| acc + s.response);
    let pre_sig = PreSignature::<C> {
        R_prime: r_prime,
        z: z_agg,
        hash: msg_hashed.to_vec(),
    };
    total_compute_ns += t4.elapsed().as_nanos();
    if bench_logs {
        println!(
            "[bench] proxgen.compute.aggregate_ns={}",
            t4.elapsed().as_nanos() as u64
        );
    }
    // #endregion

    if bench_logs {
        println!(
            "[bench] proxgen.compute.total_ns={}",
            total_compute_ns as u64
        );
    }
    println!("Finished psign");
    Ok(PartialProxyOutput::<C> {
        pre_signature: pre_sig,
        signers: signers_vec,
        encs: enc_vec,
        R,
        compute_time: total_compute_ns as u64,
    })
}

pub fn algo_combine<C: ThresholdCurve>(
    advt: &Advt<C>,
    aux: &pzk::Aux,
    security_params: &pzk::SecurityParams,
    partial_proxy_out: &PartialProxyOutput<C>,
) -> Outcome<ProxyOutput<C>> {
    let seller_pk = &advt.pk;
    let PartialProxyOutput {
        pre_signature,
        R,
        signers,
        encs,
        compute_time: _,
    } = partial_proxy_out;
    verify_enc_batch::<C>(aux, security_params, seller_pk, &encs)?;
    // Compute combined Paillier ciphertext c = prod c_i^{lambda_i}
    let combined_ct = combine_paillier_for_blinding::<C>(seller_pk, &signers, &encs)?;
    Ok(ProxyOutput::<C> {
        pre_signature: pre_signature.clone(),
        blinding_share_enc: combined_ct,
        R: *R,
    })
}
