use std::{collections::HashMap, path::Path, str::FromStr, thread, time::Duration};

use bitcoin::{
    absolute,
    blockdata::{
        opcodes::all::{OP_CHECKSIG, OP_CHECKSIGVERIFY},
        script::Builder,
    },
    consensus::encode::{deserialize_hex, serialize_hex},
    hashes::{sha256d, Hash},
    secp256k1::{schnorr, Keypair, Message, Secp256k1, XOnlyPublicKey},
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{LeafVersion, TapLeafHash, TaprootBuilder},
    transaction::Version,
    Address, Amount, BlockHash, Network, NetworkKind, OutPoint, PrivateKey, Sequence, Transaction,
    TxIn, TxOut, Txid, Witness,
};
use k256::elliptic_curve::{group::Group, sec1::ToEncodedPoint};
use rand_core::OsRng;
use reqwest::blocking::Client as HttpClient;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{self, json, Value};
use sparkle_algo::{
    ad_gen, algo_combine, algo_prox_gen, exn, load_pzk_aux, load_security_params, KeyStore,
    PartialProxyOutput, ProxGenConfig, Secp256k1Curve, SecpPoint, Signature as SparkleSignature,
    ThresholdCurve,
};
use xuanmi_base_support::*;

use crate::{load_keystore, load_seller_sk, T_P_N_CONFIG};

/// Configuration for running the end-to-end adaptor-signature demo.
pub struct DemoConfig {
    pub server: String,
    pub tr_uuid: String,
    pub rpc_url: String,
    pub rpc_user: Option<String>,
    pub rpc_pass: Option<String>,
    pub signer_ids: Vec<u16>,
    pub broadcast: bool,
    pub funding_txhash: String,
    pub funding_blockhash: String,
    pub funding_vout: u32,
}

/// Artefacts captured during the demo for inspection or further testing.
pub struct DemoArtifacts {
    pub taproot_address: Address,
    pub funding_txid: Txid,
    pub spend_tx: Transaction,
    pub spend_txid: Txid,
    pub seller_address: Address,
    pub witness_hex: String,
}

#[derive(Serialize, Deserialize)]
struct FundingInfo {
    txid: Txid,
    vout: u32,
    value_sat: u64,
}

const FUNDING_INFO_PATH: &str = "funding_info.json";
const SELLER_WALLET_PATH: &str = "seller_wallet.json";

#[derive(Serialize, Deserialize)]
struct SellerWalletRecord {
    wif: String,
}

/// Execute the full adaptor signature flow and return artefacts for inspection.
pub fn run_demo(cfg: DemoConfig) -> Outcome<DemoArtifacts> {
    let secp = Secp256k1::new();
    let mut rng = OsRng;

    if cfg.signer_ids.len() < T_P_N_CONFIG[0] as usize {
        throw!(
            name = exn::ConfigException,
            ctx = &format!(
                "insufficient signers provided: got {}, need {}",
                cfg.signer_ids.len(),
                T_P_N_CONFIG[0]
            )
        );
    }

    let auth = match (&cfg.rpc_user, &cfg.rpc_pass) {
        (Some(user), Some(pass)) => Some((user.clone(), pass.clone())),
        (None, None) => None,
        _ => {
            throw!(
                name = exn::ConfigException,
                ctx = "rpc-user and rpc-pass must be provided together"
            )
        }
    };

    let rpc = BitcoinRpcClient::new(&cfg.rpc_url, auth)
        .catch(exn::ConfigException, "failed to construct RPC client")?;

    // Load keystores for signing and blinding shares.
    let mut signing_keystores: HashMap<u16, KeyStore<Secp256k1Curve>> = HashMap::new();
    let mut blinding_keystores: HashMap<u16, KeyStore<Secp256k1Curve>> = HashMap::new();
    for party_id in &cfg.signer_ids {
        let signing = load_keystore(*party_id, false)?;
        let blinding = load_keystore(*party_id, true)?;
        signing_keystores.insert(*party_id, signing);
        blinding_keystores.insert(*party_id, blinding);
    }

    let proxy_group_key = signing_keystores
        .values()
        .next()
        .if_none(exn::ConfigException, "missing signing keystore")?
        .signing_key
        .group_public;
    let (proxy_xonly, _) = secp_point_to_xonly(&proxy_group_key)?;

    // Seller keypair and derived payment address.
    let (seller_keypair, seller_address) = load_or_create_seller_wallet(&secp)?;
    let (seller_xonly, _) = seller_keypair.x_only_public_key();

    // Taproot script requiring the proxy signature first, then the seller signature.
    let tap_script = Builder::new()
        .push_x_only_key(&proxy_xonly)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_x_only_key(&seller_xonly)
        .push_opcode(OP_CHECKSIG)
        .into_script();

    let builder = TaprootBuilder::new();
    let builder = builder.add_leaf(0, tap_script.clone()).map_err(|e| {
        exception!(
            name = exn::ConfigException,
            ctx = &format!("failed to add tapscript leaf: {:?}", e)
        )
    })?;
    let spend_info = builder.finalize(&secp, proxy_xonly).map_err(|e| {
        exception!(
            name = exn::ConfigException,
            ctx = &format!("failed to finalize taproot builder: {:?}", e)
        )
    })?;
    let taproot_address = Address::p2tr_tweaked(spend_info.output_key(), Network::Testnet);

    println!("Taproot funding address: {}", taproot_address);
    println!("Seller receive address: {}", seller_address);

    let funding_txid = Txid::from_raw_hash(
        sha256d::Hash::from_str(&cfg.funding_txhash)
            .catch(exn::ConfigException, "invalid funding txhash")?,
    );
    let blockhash = BlockHash::from_str(&cfg.funding_blockhash)
        .catch(exn::ConfigException, "invalid funding blockhash")?;
    // Fetch tx and verify provided vout matches our taproot address; get its value
    let funding_tx = rpc
        .get_raw_transaction(&funding_txid, Some(&blockhash))
        .catch(
            exn::SignatureException,
            "failed to query funding transaction",
        )?;
    if cfg.funding_vout as usize >= funding_tx.output.len() {
        throw!(
            name = exn::SignatureException,
            ctx = "funding vout out of range for transaction outputs"
        );
    }
    let prev = &funding_tx.output[cfg.funding_vout as usize];
    if prev.script_pubkey != taproot_address.script_pubkey() {
        throw!(
            name = exn::SignatureException,
            ctx = "specified funding output does not pay to derived taproot address"
        );
    }
    let funding_vout = cfg.funding_vout;
    let funding_value = prev.value.to_sat();

    save_funding_info(&FundingInfo {
        txid: funding_txid,
        vout: funding_vout,
        value_sat: funding_value,
    })?;

    let taproot_prevout = TxOut {
        value: Amount::from_sat(funding_value),
        script_pubkey: taproot_address.script_pubkey(),
    };

    const FEE_SATS: u64 = 500;
    let spend_value = taproot_prevout
        .value
        .checked_sub(Amount::from_sat(FEE_SATS))
        .if_none(exn::ConfigException, "funding output too small for fee")?;

    let txin = TxIn {
        previous_output: OutPoint::new(funding_txid, funding_vout),
        script_sig: bitcoin::ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    };
    let seller_output = TxOut {
        value: spend_value,
        script_pubkey: seller_address.script_pubkey(),
    };

    let mut spend_tx = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![txin],
        output: vec![seller_output.clone()],
    };

    // Compute the Taproot script-path sighash.
    let leaf_hash = TapLeafHash::from_script(&tap_script, LeafVersion::TapScript);
    let mut cache = SighashCache::new(&mut spend_tx);
    let sighash = cache
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[taproot_prevout.clone()]),
            leaf_hash,
            TapSighashType::Default,
        )
        .catch(exn::SignatureException, "failed to compute taproot sighash")?;
    let msg_bytes = sighash.as_raw_hash().to_byte_array();

    // Prepare adaptor signature flow.
    let witness_scalar = Secp256k1Curve::random_scalar(&mut rng);
    let statement_point = Secp256k1Curve::mul_base(&witness_scalar);
    let aux = load_pzk_aux()?;
    let sec_params = load_security_params()?;
    let paillier_sk = load_seller_sk()?;
    let advt =
        ad_gen::<Secp256k1Curve, _>(&statement_point, &witness_scalar, &paillier_sk, &mut rng)?
            .advt;

    let partial = run_prox_gen(
        &cfg,
        &signing_keystores,
        &blinding_keystores,
        &advt,
        &aux,
        &sec_params,
        &msg_bytes,
        statement_point,
    )?;

    let proxy_output = algo_combine(&advt, &aux, &sec_params, &partial)
        .catch(exn::SignatureException, "failed to combine proxy outputs")?;
    let sparkle_signature = proxy_output
        .adapt(&paillier_sk, witness_scalar)
        .catch(exn::SignatureException, "proxy adaptation failed")?;
    let proxy_sig = sparkle_signature_to_schnorr(&sparkle_signature)?;

    let seller_msg = Message::from_digest_slice(&msg_bytes)
        .catch(exn::SignatureException, "taproot sighash malformed")?;
    let seller_sig = secp.sign_schnorr_no_aux_rand(&seller_msg, &seller_keypair);

    // Verify both signatures locally before constructing the witness/broadcasting.
    // This catches any digest, key, or conversion mismatches early with a clear error.
    if let Err(_) = secp.verify_schnorr(&proxy_sig, &seller_msg, &proxy_xonly) {
        throw!(
            name = exn::SignatureException,
            ctx = "proxy Schnorr signature failed local verification"
        );
    }
    if let Err(_) = secp.verify_schnorr(&seller_sig, &seller_msg, &seller_xonly) {
        throw!(
            name = exn::SignatureException,
            ctx = "seller Schnorr signature failed local verification"
        );
    }
    println!("Local verification OK: proxy and seller signatures verify.");

    let control_block = spend_info
        .control_block(&(tap_script.clone(), LeafVersion::TapScript))
        .if_none(
            exn::SignatureException,
            "missing control block for tapscript",
        )?;
    let mut witness = Witness::new();
    witness.push(seller_sig.as_ref());
    witness.push(proxy_sig.as_ref());
    witness.push(tap_script.as_bytes());
    witness.push(&control_block.serialize());
    spend_tx.input[0].witness = witness;

    let spend_txid = spend_tx.compute_txid();
    println!("transaction hex: {}", serialize_hex(&spend_tx));
    if cfg.broadcast {
        rpc.send_raw_transaction(&spend_tx).catch(
            exn::SignatureException,
            "failed to broadcast spend transaction",
        )?;
    }

    let witness_hex = serialize_hex(&spend_tx.input[0].witness);

    Ok(DemoArtifacts {
        taproot_address,
        funding_txid,
        spend_tx,
        spend_txid,
        seller_address,
        witness_hex,
    })
}

fn run_prox_gen(
    cfg: &DemoConfig,
    signing_keystores: &HashMap<u16, KeyStore<Secp256k1Curve>>,
    blinding_keystores: &HashMap<u16, KeyStore<Secp256k1Curve>>,
    advt: &sparkle_algo::Advt<Secp256k1Curve>,
    aux: &sparkle_algo::pzk::Aux,
    sec_params: &sparkle_algo::pzk::SecurityParams,
    msg_bytes: &[u8],
    statement_point: SecpPoint,
) -> Outcome<PartialProxyOutput<Secp256k1Curve>> {
    let mut handles = Vec::with_capacity(cfg.signer_ids.len());
    for (idx, party_id) in cfg.signer_ids.iter().enumerate() {
        let server = cfg.server.clone();
        let tr_uuid = cfg.tr_uuid.clone();
        let msg_vec = msg_bytes.to_vec();
        let ks = signing_keystores
            .get(party_id)
            .if_none(exn::ConfigException, "missing signing keystore for party")?
            .clone();
        let bks = blinding_keystores
            .get(party_id)
            .if_none(exn::ConfigException, "missing blinding keystore for party")?
            .clone();
        let advt_clone = advt.clone();
        let aux_clone = aux.clone();
        let sec_clone = sec_params.clone();
        handles.push(thread::spawn(
            move || -> Result<PartialProxyOutput<Secp256k1Curve>, String> {
                thread::sleep(Duration::from_millis(50 * idx as u64));
                let cfg = ProxGenConfig {
                    server: &server,
                    tr_uuid: &tr_uuid,
                    tcn_config: &T_P_N_CONFIG,
                    msg_hashed: &msg_vec,
                    statement: &statement_point,
                    keystore: &ks,
                    blind_keystore: &bks,
                    advt: &advt_clone,
                    security_params: &sec_clone,
                    aux: &aux_clone,
                    bench_logs: false,
                };
                algo_prox_gen(cfg).map_err(|e| format!("{}", e))
            },
        ));
    }

    let mut partial_opt: Option<PartialProxyOutput<Secp256k1Curve>> = None;
    for handle in handles {
        let res = handle.join().map_err(|_| {
            exception!(
                name = exn::SignatureException,
                ctx = "prox-gen thread panicked"
            )
        })?;
        let partial = res.map_err(|e| {
            exception!(
                name = exn::SignatureException,
                ctx = &format!("prox-gen error: {}", e)
            )
        })?;
        if partial_opt.is_none() {
            partial_opt = Some(partial);
        }
    }

    partial_opt.if_none(exn::SignatureException, "prox-gen did not produce output")
}

fn save_funding_info(info: &FundingInfo) -> Outcome<()> {
    let json = serde_json::to_string_pretty(info).catch(exn::ObjectToJsonException, "")?;
    write_str_to_file(FUNDING_INFO_PATH, &json)?;
    Ok(())
}

pub(crate) fn load_or_create_seller_wallet(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
) -> Outcome<(Keypair, Address)> {
    if Path::new(SELLER_WALLET_PATH).exists() {
        let json = read_str_from_file(SELLER_WALLET_PATH)?;
        let record: SellerWalletRecord =
            serde_json::from_str(&json).catch(exn::JsonToObjectException, "seller wallet")?;
        let private = PrivateKey::from_wif(&record.wif)
            .catch(exn::ConfigException, "invalid seller wallet WIF")?;
        if private.network != NetworkKind::Test {
            throw!(
                name = exn::ConfigException,
                ctx = "seller key must be a testnet key"
            );
        }
        let secret_key = private.inner;
        let keypair = Keypair::from_secret_key(secp, &secret_key);
        let pubkey = bitcoin::secp256k1::PublicKey::from_keypair(&keypair);
        let address = Address::p2wpkh(&bitcoin::CompressedPublicKey(pubkey), Network::Testnet);
        Ok((keypair, address))
    } else {
        // Generate once and save for consistency across runs.
        let keypair = bitcoin::secp256k1::Keypair::new(secp, &mut OsRng);
        let secret = keypair.secret_key();
        let private = PrivateKey::new(secret, Network::Testnet);
        let record = SellerWalletRecord {
            wif: private.to_wif(),
        };
        let json = serde_json::to_string_pretty(&record).catch(exn::ObjectToJsonException, "")?;
        write_str_to_file(SELLER_WALLET_PATH, &json)?;
        let pubkey = bitcoin::secp256k1::PublicKey::from_keypair(&keypair);
        let address = Address::p2wpkh(&bitcoin::CompressedPublicKey(pubkey), Network::Testnet);
        Ok((keypair, address))
    }
}

// fn fund_taproot_output(
//     rpc: &BitcoinRpcClient,
//     taproot_address: &Address,
//     amount_sat: u64,
// ) -> Outcome<(Txid, u32, u64)> {
//     let utxos = rpc
//         .list_unspent(1, true)
//         .catch(exn::SignatureException, "listunspent failed")?;
//     let required = amount_sat + FUNDING_FEE_SATS;
//     let utxo = utxos
//         .into_iter()
//         .find(|u| u.spendable && u.amount_sat >= required)
//         .if_none(
//             exn::SignatureException,
//             "wallet has no UTXO large enough to fund taproot output",
//         )?;

//     let input_value = utxo.amount_sat;
//     let mut outputs = Vec::new();
//     outputs.push(TxOut {
//         value: Amount::from_sat(amount_sat),
//         script_pubkey: taproot_address.script_pubkey(),
//     });

//     let change_value = input_value - required;
//     if change_value >= MIN_CHANGE_SATS {
//         let change_addr = rpc
//             .get_new_address()
//             .catch(exn::SignatureException, "failed to obtain change address")?;
//         outputs.push(TxOut {
//             value: Amount::from_sat(change_value),
//             script_pubkey: change_addr.script_pubkey(),
//         });
//     }

//     let funding_input = TxIn {
//         previous_output: OutPoint::new(utxo.txid, utxo.vout),
//         script_sig: bitcoin::ScriptBuf::new(),
//         sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
//         witness: Witness::new(),
//     };

//     let funding_tx = Transaction {
//         version: Version::TWO,
//         lock_time: absolute::LockTime::ZERO,
//         input: vec![funding_input],
//         output: outputs,
//     };

//     let sign_result = rpc
//         .sign_raw_transaction_with_wallet(&funding_tx)
//         .catch(
//             exn::SignatureException,
//             "signrawtransactionwithwallet failed for funding transaction",
//         )?;
//     if !sign_result.complete {
//         throw!(
//             name = exn::SignatureException,
//             ctx = "wallet could not fully sign funding transaction"
//         );
//     }

//     let signed_tx: Transaction = deserialize_hex(&sign_result.hex)
//         .catch(exn::SignatureException, "failed to deserialize signed funding transaction")?;

//     let txid = rpc
//         .send_raw_transaction(&signed_tx)
//         .catch(exn::SignatureException, "failed to broadcast funding transaction")?;

//     Ok((txid, 0, amount_sat))
// }

pub(crate) fn secp_point_to_xonly(point: &SecpPoint) -> Outcome<(XOnlyPublicKey, bool)> {
    if point.0.is_identity().into() {
        throw!(name = exn::SignatureException, ctx = "point at infinity");
    }
    let encoded = point.0.to_affine().to_encoded_point(true);
    let (pk, parity) = bitcoin::secp256k1::PublicKey::from_slice(encoded.as_bytes())
        .and_then(|pk| Ok(pk.x_only_public_key()))
        .catch(exn::SignatureException, "invalid secp point encoding")?;
    let parity_bool = matches!(parity, bitcoin::secp256k1::Parity::Odd);
    Ok((pk, parity_bool))
}

pub(crate) fn sparkle_signature_to_schnorr(
    signature: &SparkleSignature<Secp256k1Curve>,
) -> Outcome<schnorr::Signature> {
    if signature.r.0.is_identity().into() {
        throw!(
            name = exn::SignatureException,
            ctx = "signature nonce is identity"
        );
    }
    let compressed = signature.r.0.to_affine().to_encoded_point(true);
    let uncompressed = signature.r.0.to_affine().to_encoded_point(false);
    let x_bytes = uncompressed
        .x()
        .if_none(exn::SignatureException, "missing x-coordinate")?;
    let y_odd = compressed.as_bytes()[0] == 0x03;
    let mut s_scalar = signature.z;
    if y_odd {
        s_scalar = Secp256k1Curve::scalar_zero() - s_scalar;
    }
    let s_bytes = Secp256k1Curve::scalar_to_bytes(&s_scalar);
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(x_bytes);
    sig_bytes[32..].copy_from_slice(&s_bytes);
    schnorr::Signature::from_slice(&sig_bytes)
        .catch(exn::SignatureException, "invalid schnorr signature bytes")
}

// Derive the taproot funding address (tweaked key spend) and the seller's P2WPKH
// address using any party's keystore (the group public key is identical).
pub(crate) fn derive_taproot_funding_address(party_id: u16) -> Outcome<(Address, Address)> {
    let secp = Secp256k1::new();
    let keystore = crate::load_keystore(party_id, false)?;
    let group_pub = keystore.signing_key.group_public;
    let (proxy_xonly, _) = secp_point_to_xonly(&group_pub)?;
    let (seller_kp, seller_addr) = load_or_create_seller_wallet(&secp)?;
    let (seller_xonly, _) = seller_kp.x_only_public_key();

    let tap_script = Builder::new()
        .push_x_only_key(&proxy_xonly)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_x_only_key(&seller_xonly)
        .push_opcode(OP_CHECKSIG)
        .into_script();
    let builder = TaprootBuilder::new();
    let builder = builder.add_leaf(0, tap_script).map_err(|e| {
        exception!(
            name = exn::ConfigException,
            ctx = &format!("failed to add leaf: {:?}", e)
        )
    })?;
    let spend_info = builder.finalize(&secp, proxy_xonly).map_err(|e| {
        exception!(
            name = exn::ConfigException,
            ctx = &format!("finalize failed: {:?}", e)
        )
    })?;
    let taproot_addr = Address::p2tr_tweaked(spend_info.output_key(), Network::Testnet);
    Ok((taproot_addr, seller_addr))
}

#[derive(Clone)]
struct BitcoinRpcClient {
    http: HttpClient,
    url: String,
    auth: Option<(String, String)>,
}

impl BitcoinRpcClient {
    fn new(url: &str, auth: Option<(String, String)>) -> Result<Self, reqwest::Error> {
        let http = HttpClient::builder().build()?;
        Ok(Self {
            http,
            url: url.to_owned(),
            auth,
        })
    }

    fn call_raw(&self, method: &str, params: Vec<Value>) -> Outcome<Value> {
        #[derive(Serialize)]
        struct RpcRequest<'a> {
            jsonrpc: &'static str,
            id: u64,
            method: &'a str,
            params: Vec<Value>,
        }

        #[derive(Deserialize)]
        struct RpcError {
            code: i64,
            message: String,
            #[serde(default)]
            data: Option<Value>,
        }

        #[derive(Deserialize)]
        struct RpcResponse {
            result: Option<Value>,
            error: Option<RpcError>,
        }

        let request = RpcRequest {
            jsonrpc: "1.0",
            id: 1,
            method,
            params,
        };

        let mut req_builder = self.http.post(&self.url).json(&request);
        if let Some((ref user, ref pass)) = self.auth {
            req_builder = req_builder.basic_auth(user, Some(pass));
        }

        let response = req_builder.send().catch(
            exn::SignatureException,
            &format!("rpc call {} failed to send", method),
        )?;

        if !response.status().is_success() {
            throw!(
                name = exn::SignatureException,
                ctx = &format!(
                    "rpc call {} failed with HTTP status {}",
                    method,
                    response.status()
                )
            );
        }

        let rpc_response: RpcResponse = response.json().catch(
            exn::SignatureException,
            &format!("rpc call {} returned invalid json", method),
        )?;

        if let Some(err) = rpc_response.error {
            let ctx = match err.data {
                Some(data) => format!(
                    "rpc {} error {}: {} ({})",
                    method, err.code, err.message, data
                ),
                None => format!("rpc {} error {}: {}", method, err.code, err.message),
            };
            throw!(name = exn::SignatureException, ctx = &ctx);
        }

        Ok(rpc_response.result.unwrap_or(Value::Null))
    }

    fn call<T>(&self, method: &str, params: Vec<Value>) -> Outcome<T>
    where
        T: DeserializeOwned,
    {
        let value = self.call_raw(method, params)?;
        serde_json::from_value(value).catch(
            exn::SignatureException,
            &format!("failed to decode {} result", method),
        )
    }

    fn send_raw_transaction(&self, tx: &Transaction) -> Outcome<Txid> {
        let hex = serialize_hex(tx);
        let txid_str: String = self.call("sendrawtransaction", vec![json!(hex)])?;
        Txid::from_str(&txid_str).catch(exn::SignatureException, "invalid txid returned")
    }

    fn get_raw_transaction(
        &self,
        txid: &Txid,
        blockhash: Option<&BlockHash>,
    ) -> Outcome<Transaction> {
        let mut params = vec![json!(txid.to_string()), json!(false)];
        if let Some(blockhash) = blockhash {
            params.push(json!(blockhash.to_string()));
        }
        let hex: String = self.call("getrawtransaction", params)?;
        deserialize_hex(&hex).catch(exn::SignatureException, "failed to decode raw transaction")
    }
}
