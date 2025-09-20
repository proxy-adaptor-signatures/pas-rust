use bitcoin::consensus::encode::serialize_hex;
use clap::{Parser, Subcommand};
use fast_paillier;
use log::info;
use rand_core::OsRng;
use sparkle_algo::{
    ad_gen, ad_verify, algo_combine, algo_keygen, algo_prox_gen, bytes_from_hex, bytes_to_hex, exn,
    load_pzk_aux, load_security_params, secp_decompress, Advt, BlindedWitness, KeyStore,
    PaillierSk, PartialProxyOutput, ProxGenConfig, ProxyOutput, Secp256k1Curve, Share, Signature,
    ThresholdCurve,
};
use std::thread;
use std::time::Instant;
use xuanmi_base_support::*;

mod demo;
use demo::{run_demo, DemoConfig};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

const NUM_THRESHOLD: u16 = 2;
const NUM_SIGNERS: u16 = 3;
// Threshold, participants, total share count
pub(crate) const T_P_N_CONFIG: [u16; 3] = [NUM_THRESHOLD, NUM_SIGNERS, NUM_SIGNERS];

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate a statement-witness pair
    Rgen,
    /// Generate a key for a party
    Keygen {
        /// Server address
        #[clap(long, default_value = "http://127.0.0.1:8000")]
        server: String,
        /// Transaction UUID
        #[clap(long, default_value = "2")]
        tr_uuid: String,
        /// Threshold and number of parties (t, n)
        #[clap(long, number_of_values = 2, default_values = &["2", "3"])]
        tn_config: Vec<u16>,
        /// Party ID
        #[clap(long)]
        party_id: u16,
        /// Generate blinding factor shares instead of signing shares
        #[clap(long, action = clap::ArgAction::SetTrue, default_value = "false")]
        blinding_shares: bool,
        /// Generate Paillier key pair for seller
        #[clap(long, action = clap::ArgAction::SetTrue, default_value = "false")]
        paillier: bool,
    },
    /// Sign a message
    Sign {
        /// Server address
        #[clap(long, default_value = "http://127.0.0.1:8000")]
        server: String,
        /// Transaction UUID
        #[clap(long, default_value = "2")]
        tr_uuid: String,
        /// Message to sign (hex-encoded)
        #[clap(long)]
        message: String,
        /// Party ID
        #[clap(long)]
        party_id: u16,
    },
    /// Pre-sign a message
    ProxGen {
        /// Server address
        #[clap(long, default_value = "http://127.0.0.1:8000")]
        server: String,
        /// Transaction UUID
        #[clap(long, default_value = "2")]
        tr_uuid: String,
        /// Message to sign (hex-encoded)
        #[clap(long)]
        message: String,
        /// Statement (hex-encoded)
        #[clap(long)]
        statement: String,
        /// Party ID
        #[clap(long)]
        party_id: u16,
    },
    /// Run the full adaptor signature demo and broadcast the payout
    Demo {
        /// MPC coordinator address
        #[clap(long, default_value = "http://127.0.0.1:8000")]
        server: String,
        /// Transaction UUID used with the MPC server
        #[clap(long, default_value = "2")]
        tr_uuid: String,
        /// Bitcoin Core RPC endpoint (testnet)
        #[clap(long, default_value = "http://127.0.0.1:18332")]
        rpc_url: String,
        /// Bitcoin Core RPC username
        #[clap(long)]
        rpc_user: Option<String>,
        /// Bitcoin Core RPC password
        #[clap(long)]
        rpc_pass: Option<String>,
        /// Comma-separated signer party IDs (e.g. "1,2")
        #[clap(long, default_value = "1,2,3")]
        signers: String,
        /// Broadcast the final transaction via RPC when set
        #[clap(long, action = clap::ArgAction::SetTrue, default_value = "false")]
        broadcast: bool,
        /// Taproot funding txhash (hex)
        #[clap(long)]
        funding_txhash: String,
        /// Block hash containing the funding tx (hex)
        #[clap(long)]
        funding_blockhash: String,
        /// Output index of the taproot funding output
        #[clap(long)]
        funding_vout: u32,
    },
    /// Display funding addresses for the aggregated proxy key
    ShowAddr {
        /// Party ID whose keystore should be used (any valid proxy)
        #[clap(long, default_value = "1")]
        party_id: u16,
    },
    /// Generate an advertisement
    AdGen {
        /// Statement (hex-encoded)
        #[clap(long)]
        statement: String,
        /// Witness (hex-encoded)
        #[clap(long)]
        witness: String,
    },
    /// Combine partial signatures
    Combine,
    /// Adapt a pre-signature
    Adapt {
        /// Witness (hex-encoded)
        #[clap(long)]
        witness: String,
    },
    /// Extract the witness from a signature
    Extract,
    /// Unblind a witness
    Unblind,
    /// Benchmark protocol functions (outputs CSV)
    Bench {
        /// Server address
        #[clap(long, default_value = "http://127.0.0.1:8000")]
        server: String,
        /// Number of parties n
        #[clap(long, default_value = "3")]
        n: u16,
        /// Threshold t
        #[clap(long, default_value = "2")]
        t: u16,
        /// Iterations for local ops (adapt/extract/unblind)
        #[clap(long, default_value = "64")]
        iters: u32,
        /// Hex-encoded message (already hashed preferred)
        #[clap(
            long,
            default_value = "bytes_hex:4d6573736167653a2050524f58595f45584348414e47455f44454d4f"
        )]
        message: String,
        /// Output CSV path
        #[clap(long, default_value = "bench.csv")]
        out: String,
    },
}

pub(crate) fn load_keystore(party_id: u16, blinding: bool) -> Outcome<KeyStore<Secp256k1Curve>> {
    let kfpath = if blinding {
        format!("keystore_blind_{}.json", party_id)
    } else {
        format!("keystore_{}.json", party_id)
    };
    let keystore_json = read_str_from_file(&kfpath)?;
    KeyStore::from_json(&keystore_json)
}

fn save_keystore(keystore: &KeyStore<Secp256k1Curve>, blinding: bool) -> Outcome<usize> {
    let kfpath = if blinding {
        format!("keystore_blind_{}.json", keystore.party_num_int)
    } else {
        format!("keystore_{}.json", keystore.party_num_int)
    };
    let keystore_json = keystore.to_json_pretty()?;
    write_str_to_file(&kfpath, &keystore_json)
}

fn save_paillier_keystore(sk: &fast_paillier::DecryptionKey) -> Outcome<usize> {
    let path = "paillier_keystore.json";
    let json = serde_json::to_string_pretty(sk).catch(exn::ObjectToJsonException, "")?;
    write_str_to_file(path, &json)
}

fn load_paillier_keystore() -> Outcome<fast_paillier::DecryptionKey> {
    let path = "paillier_keystore.json";
    let json = read_str_from_file(path)?;
    serde_json::from_str(&json).catch(exn::JsonToObjectException, "")
}

fn load_advertisement() -> Outcome<Advt<Secp256k1Curve>> {
    let path = "advertisement.json";
    let json = read_str_from_file(path)?;
    serde_json::from_str(&json).catch(exn::JsonToObjectException, "")
}

fn load_seller_sk() -> Outcome<PaillierSk> {
    let path = "paillier_keystore.json";
    let json = read_str_from_file(path)?;
    serde_json::from_str(&json).catch(exn::JsonToObjectException, "")
}

fn load_partial_proxy_output() -> Outcome<sparkle_algo::PartialProxyOutput<Secp256k1Curve>> {
    let path = "partial_proxy_output.json";
    let json = read_str_from_file(path)?;
    serde_json::from_str(&json).catch(exn::JsonToObjectException, "")
}

fn save_partial_proxy_output(
    output: &sparkle_algo::PartialProxyOutput<Secp256k1Curve>,
) -> Outcome<usize> {
    let path = "partial_proxy_output.json";
    let json = serde_json::to_string_pretty(output).catch(exn::ObjectToJsonException, "")?;
    write_str_to_file(path, &json)
}

fn save_proxy_output(output: &ProxyOutput<Secp256k1Curve>) -> Outcome<usize> {
    let path = "proxy_output.json";
    let json = serde_json::to_string_pretty(output).catch(exn::ObjectToJsonException, "")?;
    write_str_to_file(path, &json)
}

fn load_proxy_output() -> Outcome<ProxyOutput<Secp256k1Curve>> {
    let path = "proxy_output.json";
    let json = read_str_from_file(path)?;
    serde_json::from_str(&json).catch(exn::JsonToObjectException, "")
}

fn load_blinded_witness() -> Outcome<BlindedWitness<Secp256k1Curve>> {
    let hex = read_str_from_file("blinded_witness.json")?;
    let bytes = bytes_from_hex(&hex)?;
    let scalar = Secp256k1Curve::scalar_from_bytes_reduced(
        bytes.try_into().unwrap(), // Infallible
    );
    Ok(BlindedWitness(scalar))
}

fn load_signature() -> Outcome<Signature<Secp256k1Curve>> {
    let sfpath = "adapted_signature.json";
    let signature_json = read_str_from_file(sfpath)?;
    Signature::<Secp256k1Curve>::from_json(&signature_json)
}

fn save_signature(signature: &Signature<Secp256k1Curve>) -> Outcome<usize> {
    let sfpath = "adapted_signature.json";
    let signature_json = signature.to_json_pretty()?;
    write_str_to_file(sfpath, &signature_json)
}

fn request_code(server: &str, action: &str) -> Outcome<String> {
    let url = format!("{}/reqcode/{}", server, action);
    let rc: Result<String, String> = http_post(&url, &"").catch(exn::SignUpException, &url)?;
    match rc {
        Ok(code) => Ok(code),
        Err(e) => throw!(
            name = exn::SignUpException,
            ctx = &format!("reqcode error: {}", e)
        ),
    }
}

fn mean_ns<F, T>(iters: u32, mut f: F) -> Outcome<u64>
where
    F: FnMut() -> Outcome<T>,
{
    let mut total: u128 = 0;
    for _ in 0..iters {
        let start = Instant::now();
        let _ = f()?;
        total += start.elapsed().as_nanos();
    }
    Ok((total / (iters as u128)) as u64)
}

fn main() -> Outcome<()> {
    let _ = env_logger::builder().format_timestamp_millis().try_init();
    let cli = Cli::parse();

    match &cli.command {
        Commands::Rgen => {
            let witness = Secp256k1Curve::random_scalar(&mut OsRng);
            let statement = Secp256k1Curve::mul_base(&witness);
            println!(
                "Witness: {}",
                bytes_to_hex(&Secp256k1Curve::scalar_to_bytes(&witness))
            );
            println!("Statement: {}", Secp256k1Curve::point_to_hex(&statement));
        }
        Commands::Keygen {
            server,
            tr_uuid,
            tn_config,
            party_id,
            blinding_shares,
            paillier,
        } => {
            if *paillier {
                let sk = &fast_paillier::DecryptionKey::generate(&mut OsRng).unwrap();
                save_paillier_keystore(&sk)?;
            } else {
                let tn_config_arr: [u16; 2] = tn_config.clone().try_into().unwrap();
                let keystore = algo_keygen(
                    server,
                    tr_uuid,
                    &tn_config_arr,
                    if *blinding_shares {
                        "sparkle_blinding_test"
                    } else {
                        "sparkle_test"
                    },
                )?;
                save_keystore(&keystore, *blinding_shares)?;
                println!(
                    "Keystore for party {} saved to built/{}",
                    party_id,
                    if *blinding_shares {
                        format!("keystore_blind_{}.json", party_id)
                    } else {
                        format!("keystore_{}.json", party_id)
                    }
                );
            }
        }
        Commands::Sign {
            server,
            tr_uuid,
            message,
            party_id,
        } => {
            let keystore = load_keystore(*party_id, false)?;
            let msg_hashed = bytes_from_hex(message)?;
            let signature =
                sparkle_algo::algo_sign(server, tr_uuid, &T_P_N_CONFIG, &msg_hashed, &keystore)?;
            let signature_json = signature.to_json_pretty()?;
            println!("{}", &signature_json);
        }
        Commands::ProxGen {
            server,
            tr_uuid,
            message,
            statement,
            party_id,
        } => {
            let keystore = load_keystore(*party_id, false)?;
            let blind_keystore = load_keystore(*party_id, true)?;
            let paillier_sk = load_paillier_keystore()?;
            let msg_hashed = bytes_from_hex(message)?;
            let statement_bytes = bytes_from_hex(statement)?;
            let statement_point = secp_decompress(&statement_bytes)
                .if_none(exn::DecompressionException, "statement point")?;

            let aux = load_pzk_aux()?;
            let security_params = load_security_params()?;

            // A dummy witness is created here for advertisement generation.
            // In a real scenario, the witness would not be known by the party creating the pre-signature.
            let mut rng = OsRng;
            let dummy_witness = Secp256k1Curve::random_scalar(&mut OsRng);
            let adgen_output = ad_gen::<Secp256k1Curve, _>(
                &statement_point,
                &dummy_witness,
                &paillier_sk,
                &mut rng,
            )?;
            let advt = adgen_output.advt;

            let prox_gen_config = ProxGenConfig {
                server,
                tr_uuid,
                tcn_config: &T_P_N_CONFIG,
                msg_hashed: &msg_hashed,
                statement: &statement_point,
                keystore: &keystore,
                blind_keystore: &blind_keystore,
                advt: &advt,
                security_params: &security_params,
                aux: &aux,
                bench_logs: false,
            };
            let partial_proxy_output = algo_prox_gen(prox_gen_config)?;
            save_partial_proxy_output(&partial_proxy_output)?;
            println!("Partial proxy output saved to built/partial_proxy_output.json");
        }
        Commands::Demo {
            server,
            tr_uuid,
            rpc_url,
            rpc_user,
            rpc_pass,
            signers,
            broadcast,
            funding_txhash,
            funding_blockhash,
            funding_vout,
        } => {
            let mut signer_ids = Vec::new();
            for token in signers.split(',') {
                let trimmed = token.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let id = trimmed
                    .parse::<u16>()
                    .catch(exn::ConfigException, "invalid signer id")?;
                signer_ids.push(id);
            }
            if signer_ids.is_empty() {
                throw!(name = exn::ConfigException, ctx = "no signer ids provided");
            }

            let demo_cfg = DemoConfig {
                server: server.clone(),
                tr_uuid: tr_uuid.clone(),
                rpc_url: rpc_url.clone(),
                rpc_user: rpc_user.clone(),
                rpc_pass: rpc_pass.clone(),
                signer_ids,
                broadcast: *broadcast,
                funding_txhash: funding_txhash.clone(),
                funding_blockhash: funding_blockhash.clone(),
                funding_vout: *funding_vout,
            };

            let artifacts = run_demo(demo_cfg)?;
            println!("Taproot address: {}", artifacts.taproot_address);
            println!("Funding txid: {}", artifacts.funding_txid);
            println!("Spend txid: {}", artifacts.spend_txid);
            println!("Seller address: {}", artifacts.seller_address);
            println!("Witness stack (hex): {}", artifacts.witness_hex);
            println!(
                "Spend transaction (hex): {}",
                serialize_hex(&artifacts.spend_tx)
            );
        }
        Commands::ShowAddr { party_id } => {
            let (taproot_addr, seller_addr) = demo::derive_taproot_funding_address(*party_id)?;
            println!("Taproot funding address: {}", taproot_addr);
            println!("Seller receive address: {}", seller_addr);
        }
        Commands::AdGen { statement, witness } => {
            let paillier_sk = load_paillier_keystore()?;
            let statement_bytes = bytes_from_hex(statement)?;
            let statement_point = secp_decompress(&statement_bytes)
                .if_none(exn::DecompressionException, "statement point")?;
            let witness_bytes = bytes_from_hex(witness)?;
            let witness_scalar =
                Secp256k1Curve::scalar_from_bytes_reduced(witness_bytes.try_into().unwrap());
            let adgen_output = ad_gen::<Secp256k1Curve, _>(
                &statement_point,
                &witness_scalar,
                &paillier_sk,
                &mut OsRng,
            )?;
            let advt_json = serde_json::to_string_pretty(&adgen_output.advt)
                .catch(exn::ObjectToJsonException, "")?;
            write_str_to_file("advertisement.json", &advt_json)?;
            let sk_json = serde_json::to_string_pretty(&adgen_output.sk)
                .catch(exn::ObjectToJsonException, "")?;
            write_str_to_file("seller_sk.json", &sk_json)?;
            println!("Advertisement saved to built/advertisement.json");
        }
        Commands::Combine => {
            let partial_proxy_output = load_partial_proxy_output()?;
            let advt = load_advertisement()?;
            let aux = load_pzk_aux()?;
            let security_params = load_security_params()?;
            let proxy_output = algo_combine(&advt, &aux, &security_params, &partial_proxy_output)?;
            save_proxy_output(&proxy_output)?;
            println!("Proxy output saved to built/proxy_output.json");
        }
        Commands::Adapt { witness } => {
            let proxy_output = load_proxy_output()?;
            let seller_sk = load_seller_sk()?;
            let witness_bytes = bytes_from_hex(witness)?;
            let witness_scalar =
                Secp256k1Curve::scalar_from_bytes_reduced(witness_bytes.try_into().unwrap());
            let signature = proxy_output.adapt(&seller_sk, witness_scalar)?;
            save_signature(&signature)?;
            println!("Adapted signature saved to built/adapted_signature.json");
        }
        Commands::Extract => {
            let proxy_output = load_proxy_output()?;
            let signature = load_signature()?;
            let witness = proxy_output.extract(&signature)?;
            let witness_bytes = Secp256k1Curve::scalar_to_bytes(&witness.0);
            write_str_to_file("blinded_witness.json", &bytes_to_hex(&witness_bytes))?;
            println!("Blinded witness saved to built/blinded_witness.json");
        }
        Commands::Unblind => {
            let blinded_witness = load_blinded_witness()?;
            let partial_proxy_output = load_partial_proxy_output()?;
            let signers = partial_proxy_output.signers;

            let mut shares = Vec::new();
            // We only need t+1 shares. Let's take the first t+1 signers.
            let threshold = T_P_N_CONFIG[0];
            for party_id in signers.iter().take((threshold as usize) + 1) {
                let blind_keystore = load_keystore(*party_id, true)?;
                let r_i = blind_keystore.signing_key.x_i;
                shares.push(Share::new_from(0, *party_id, r_i));
            }

            let witness = blinded_witness.unblind(&shares, &signers)?;
            println!(
                "Unblinded witness: {}",
                Secp256k1Curve::scalar_to_hex(&witness)
            );
        }
        Commands::Bench {
            server,
            n,
            t,
            iters,
            message,
            out,
        } => {
            println!(
                "[bench] Starting benchmark (t={}, n={}, iters={})",
                t, n, iters
            );
            info!(
                "[bench] Starting benchmark (t={}, n={}, iters={})",
                t, n, iters
            );
            // Inputs
            let tpn: [u16; 3] = [*t, *t + 1, *n];
            let msg_hashed = bytes_from_hex(message)?;

            // Statement & Witness generated internally (Rgen-like)
            let w = Secp256k1Curve::random_scalar(&mut OsRng);
            let stmt = Secp256k1Curve::mul_base(&w);
            let wit = w;
            info!("[bench] Statement: {}", Secp256k1Curve::point_to_hex(&stmt));
            info!("[bench] Witness: {}", Secp256k1Curve::scalar_to_hex(&wit));

            // PVE params
            let aux = load_pzk_aux()?;
            let sec = load_security_params()?;
            let paillier_sk = load_paillier_keystore()?;

            // In-memory key generation for signing keys and blinding keys
            // Generate signing keys (t-of-n)
            info!("[bench] KeyGen(signing) starting (t={}, n={})", t, n);
            let keygen_uuid_sign = request_code(server, "keygen")?;
            let tn_sign: [u16; 2] = [*t, *n];
            let mut kg_handles = Vec::new();
            for party_id in 1..=*n {
                let server_s = server.clone();
                let uuid_s = keygen_uuid_sign.clone();
                let tn = tn_sign;
                let delay_ms = 50u64 * (party_id as u64 - 1);
                kg_handles.push(thread::spawn(
                    move || -> Result<KeyStore<Secp256k1Curve>, String> {
                        std::thread::sleep(std::time::Duration::from_millis(delay_ms));
                        algo_keygen::<Secp256k1Curve>(&server_s, &uuid_s, &tn, "sparkle_test")
                            .map_err(|e| format!("{}", e))
                    },
                ));
            }
            let mut ks_map: std::collections::HashMap<u16, KeyStore<Secp256k1Curve>> =
                std::collections::HashMap::with_capacity(*n as usize);
            for j in kg_handles {
                let ks_res = j.join().map_err(|_| {
                    exception!(
                        name = exn::SignatureException,
                        ctx = "keygen(signing) thread panicked"
                    )
                })?;
                let ks = ks_res.map_err(|e| {
                    exception!(name = exn::SignatureException, ctx = &format!("{}", e))
                })?;
                ks_map.insert(ks.party_num_int, ks);
            }
            info!("[bench] KeyGen(signing) done");

            // Generate blinding keys (t-of-n)
            info!("[bench] KeyGen(blinding) starting (t={}, n={})", t, n);
            let keygen_uuid_blind = request_code(server, "keygen")?;
            let mut bk_handles = Vec::new();
            for party_id in 1..=*n {
                let server_s = server.clone();
                let uuid_s = keygen_uuid_blind.clone();
                let tn = tn_sign;
                let delay_ms = 50u64 * (party_id as u64 - 1);
                bk_handles.push(thread::spawn(
                    move || -> Result<KeyStore<Secp256k1Curve>, String> {
                        std::thread::sleep(std::time::Duration::from_millis(delay_ms));
                        algo_keygen::<Secp256k1Curve>(
                            &server_s,
                            &uuid_s,
                            &tn,
                            "sparkle_blinding_test",
                        )
                        .map_err(|e| format!("{}", e))
                    },
                ));
            }
            let mut bks_map: std::collections::HashMap<u16, KeyStore<Secp256k1Curve>> =
                std::collections::HashMap::with_capacity(*n as usize);
            for j in bk_handles {
                let ks_res = j.join().map_err(|_| {
                    exception!(
                        name = exn::SignatureException,
                        ctx = "keygen(blinding) thread panicked"
                    )
                })?;
                let ks = ks_res.map_err(|e| {
                    exception!(name = exn::SignatureException, ctx = &format!("{}", e))
                })?;
                bks_map.insert(ks.party_num_int, ks);
            }
            info!("[bench] KeyGen(blinding) done");

            // AdGen (mean)
            info!("[bench] AdGen(mean over {}) starting", iters);
            let adgen_ns = mean_ns(*iters, || {
                ad_gen::<Secp256k1Curve, _>(&stmt, &wit, &paillier_sk, &mut OsRng)
            })?;
            info!("[bench] AdGen(mean) done: {} ns", adgen_ns);
            // Produce one output for subsequent steps
            let ad_out = ad_gen::<Secp256k1Curve, _>(&stmt, &wit, &paillier_sk, &mut OsRng)?;
            let advt = ad_out.advt;
            let sk = ad_out.sk;

            // AdVerify (mean)
            info!("[bench] AdVerify(mean over {}) starting", iters);
            let adverify_ns = mean_ns(*iters, || ad_verify::<Secp256k1Curve>(&stmt, &advt))?;
            info!("[bench] AdVerify(mean) done: {} ns", adverify_ns);

            // Prepare UUID for sign session
            let sign_uuid = request_code(server, "sign")?;

            // Load keystores
            let mut handles = Vec::new();
            info!("[bench] ProxGen starting (spawning {} parties)", t);
            let start = Instant::now();
            for party_id in 1..=*t + 1 {
                let ks = ks_map
                    .get(&party_id)
                    .expect("missing signing keystore")
                    .clone();
                let bks = bks_map
                    .get(&party_id)
                    .expect("missing blinding keystore")
                    .clone();
                let server_s = server.clone();
                let uuid_s = sign_uuid.clone();
                let advt_c = advt.clone();
                let aux_c = aux.clone();
                let sec_c = sec.clone();
                let stmt_c = stmt;
                let msg_c = msg_hashed.clone();
                let tpn_c = tpn;
                let delay_ms = 50u64 * (party_id as u64 - 1); // stagger start
                handles.push(thread::spawn(
                    move || -> Result<PartialProxyOutput<Secp256k1Curve>, String> {
                        std::thread::sleep(std::time::Duration::from_millis(delay_ms));
                        let cfg = ProxGenConfig {
                            server: &server_s,
                            tr_uuid: &uuid_s,
                            tcn_config: &tpn_c,
                            msg_hashed: &msg_c,
                            statement: &stmt_c,
                            keystore: &ks,
                            blind_keystore: &bks,
                            advt: &advt_c,
                            security_params: &sec_c,
                            aux: &aux_c,
                            bench_logs: true,
                        };
                        algo_prox_gen(cfg).map_err(|e| format!("{}", e))
                    },
                ));
            }
            let mut partial_opt: Option<PartialProxyOutput<Secp256k1Curve>> = None;
            for h in handles {
                let r = match h.join() {
                    Ok(res) => match res {
                        Ok(v) => v,
                        Err(e) => {
                            throw!(
                                name = exn::SignatureException,
                                ctx = &format!("prox-gen thread error: {}", e)
                            );
                        }
                    },
                    Err(_) => {
                        throw!(
                            name = exn::SignatureException,
                            ctx = "prox-gen thread panicked"
                        );
                    }
                };
                if partial_opt.is_none() {
                    partial_opt = Some(r);
                }
            }
            let proxgen_ns = start.elapsed().as_nanos() as u64;
            info!("[bench] ProxGen done: {} ns", proxgen_ns);
            let partial = partial_opt.expect("prox-gen produced no output");
            // Record compute-only time from partial output (accumulated inside algo_prox_gen)
            let proxgen_compute_only_ns = partial.compute_time;

            let group_public = ks_map
                .get(&1u16)
                .expect("missing signing keystore 1")
                .signing_key
                .group_public;
            partial
                .pre_signature
                .pvrfy(group_public, stmt + partial.R)
                .catch(exn::SignatureException, "PreVerify failed")?;

            // Combine (mean)
            info!("[bench] Combine(mean over {}) starting", iters);
            let combine_ns = mean_ns(*iters, || algo_combine(&advt, &aux, &sec, &partial))?;
            info!("[bench] Combine(mean) done: {} ns", combine_ns);
            let proxy_out = algo_combine(&advt, &aux, &sec, &partial)?;

            // Adapt (average)
            info!("[bench] Adapt(mean over {}) starting", iters);
            let adapt_mean = mean_ns(*iters, || proxy_out.adapt(&sk, wit))?;
            info!("[bench] Adapt(mean) done: {} ns", adapt_mean);
            // Use one signature for subsequent steps
            let sig = proxy_out.adapt(&sk, wit)?;

            // ProxExt (extract)
            info!("[bench] ProxExt(mean over {}) starting", iters);
            let extract_mean = mean_ns(*iters, || proxy_out.extract(&sig))?;
            info!("[bench] ProxExt(mean) done: {} ns", extract_mean);
            let blinded = proxy_out.extract(&sig)?;

            // ReqExt (unblind)
            info!("[bench] ReqExt(mean over {}) starting", iters);
            let mut shares = Vec::new();
            for party_id in partial.signers.iter().take((*t as usize) + 1) {
                let bks = bks_map.get(party_id).expect("missing blinding keystore");
                shares.push(Share::new_from(0, *party_id, bks.signing_key.x_i));
            }
            let unblind_mean = mean_ns(*iters, || blinded.unblind(&shares, &partial.signers))?;
            info!("[bench] ReqExt(mean) done: {} ns", unblind_mean);
            // Sanity check: unblinded witness must equal the original witness
            let unblinded = blinded.unblind(&shares, &partial.signers)?;
            if unblinded != wit {
                throw!(
                    name = exn::SignatureException,
                    ctx = &format!("Witness extraction verification failed: unblinded != original, expected={}, actual={}", Secp256k1Curve::scalar_to_hex(&wit), Secp256k1Curve::scalar_to_hex(&unblinded))
                );
            }
            info!("[bench] Witness extraction verified");

            // Write CSV
            let header = "function,t,n,iters,mean_ns\n";
            let mut csv = String::new();
            csv.push_str(header);
            csv.push_str(&format!("AdGen,{},{},{},{}\n", t, n, iters, adgen_ns));
            csv.push_str(&format!("AdVerify,{},{},{},{}\n", t, n, iters, adverify_ns));
            csv.push_str(&format!("ProxGen,{},{},{},{}\n", t, n, 1, proxgen_ns));
            csv.push_str(&format!(
                "ProxGen-Compute,{},{},{},{}\n",
                t, n, 1, proxgen_compute_only_ns
            ));
            csv.push_str(&format!("Combine,{},{},{},{}\n", t, n, iters, combine_ns));
            csv.push_str(&format!("Adapt,{},{},{},{}\n", t, n, iters, adapt_mean));
            csv.push_str(&format!("ProxExt,{},{},{},{}\n", t, n, iters, extract_mean));
            csv.push_str(&format!("ReqExt,{},{},{},{}\n", t, n, iters, unblind_mean));
            write_str_to_file(out, &csv)?;
            println!("Wrote benchmarks to {}", out);
        }
    }

    Ok(())
}
