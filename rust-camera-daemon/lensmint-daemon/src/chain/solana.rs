// Solana mint: Anchor ix + CU fees + HTTP confirm; RPCs from config/.

use super::rpc::{self, host};
use super::{BoxError, MintLifecycle, MintRequest, MintResult};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use solana_sdk::compute_budget::ComputeBudgetInstruction;
use solana_sdk::hash::Hash;
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signer};
use solana_sdk::transaction::Transaction;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::{Duration, Instant};

const SYSTEM_PROGRAM_ID: Pubkey = pubkey!("11111111111111111111111111111111");
const COMPUTE_UNIT_LIMIT: u32 = 500_000;
const COMPUTE_UNIT_PRICE: u64 = 10_000; // microlamports
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(60);
const CONFIRM_POLL: Duration = Duration::from_millis(1500);

/// Load keypair from `<data_dir>/solana_wallet.key` (JSON bytes or base58).
pub fn load_gas_wallet() -> Result<Keypair, BoxError> {
    let path = wallet_path()?;
    if !path.exists() {
        return Err(format!(
            "Solana gas wallet not found at {} — place a JSON byte-array or base58 key there (chmod 400)",
            path.display()
        )
        .into());
    }
    let raw = fs::read_to_string(&path)?;
    let keypair = parse_keypair(raw.trim())?;
    println!("[Solana] Gas wallet loaded: {}", keypair.pubkey());
    Ok(keypair)
}

fn wallet_path() -> Result<PathBuf, BoxError> {
    let proj = directories::ProjectDirs::from("", "", "lensmint")
        .ok_or("Could not resolve lensmint data dir")?;
    Ok(proj.data_dir().join("solana_wallet.key"))
}

fn parse_keypair(raw: &str) -> Result<Keypair, BoxError> {
    if raw.starts_with('[') {
        let bytes: Vec<u8> = serde_json::from_str(raw)?;
        Keypair::try_from(bytes.as_slice())
            .map_err(|e| format!("invalid Solana JSON keypair: {e}").into())
    } else {
        Ok(Keypair::from_base58_string(raw))
    }
}

fn encode_borsh_string(value: &str) -> Vec<u8> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(4 + bytes.len());
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
    out
}

fn encode_mint_args(
    uuid: &str,
    sha256: &[u8; 32],
    phash: &str,
    device_pubkey: &[u8; 32],
) -> Vec<u8> {
    let mut out = encode_borsh_string(uuid);
    out.extend_from_slice(sha256);
    out.extend_from_slice(&encode_borsh_string(phash));
    out.extend_from_slice(device_pubkey);
    out
}

fn anchor_discriminator(name: &str) -> [u8; 8] {
    let hash = Sha256::digest(format!("global:{name}").as_bytes());
    let mut out = [0u8; 8];
    out.copy_from_slice(&hash[..8]);
    out
}

fn parse_bytes32(hex_str: &str) -> Result<[u8; 32], BoxError> {
    let clean = hex_str.trim().trim_start_matches("0x");
    let bytes = hex::decode(clean).map_err(|e| format!("invalid hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()).into());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn http_client() -> Result<reqwest::Client, BoxError> {
    // Optional HTTPS_PROXY for restricted networks (not an RPC URL config).
    let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(30));
    let proxy = std::env::var("HTTPS_PROXY")
        .or_else(|_| std::env::var("https_proxy"))
        .or_else(|_| std::env::var("http_proxy"))
        .ok()
        .filter(|s| !s.trim().is_empty());
    if let Some(url) = proxy {
        builder = builder.proxy(reqwest::Proxy::all(url)?);
    }
    Ok(builder.build()?)
}

pub async fn mint(
    cluster: &str,
    req: &MintRequest,
    mut on_lifecycle: impl FnMut(MintLifecycle, Option<&str>),
) -> Result<MintResult, BoxError> {
    let contracts = crate::config::load_contracts();
    let cfg = contracts
        .solana(cluster)
        .ok_or_else(|| format!("no Solana program configured for cluster '{cluster}'"))?;
    let program_id = Pubkey::from_str(&cfg.program_id)
        .map_err(|e| format!("invalid program_id: {e}"))?;
    let mpl_core = Pubkey::from_str(&cfg.mpl_core).map_err(|e| format!("invalid mpl_core: {e}"))?;

    let relayer = load_gas_wallet()?;
    let pool = rpc::solana_pool(cluster)?;
    let client = http_client()?;

    let device_bytes = parse_bytes32(&req.device_id)?;
    let sha256_bytes = parse_bytes32(&req.sha256)?;

    let (device_record, _) =
        Pubkey::find_program_address(&[b"device", &device_bytes], &program_id);
    let (camera_record, _) =
        Pubkey::find_program_address(&[b"camera", &sha256_bytes], &program_id);

    // Fresh asset keypair — mpl-core CreateV1 requires the asset address as a signer.
    let asset = Keypair::new();

    let mut ix_data = Vec::new();
    ix_data.extend_from_slice(&anchor_discriminator("mint_from_hardware"));
    ix_data.extend_from_slice(&encode_mint_args(
        &req.uuid,
        &sha256_bytes,
        &req.phash,
        &device_bytes,
    ));

    let mint_ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(device_record, false),
            AccountMeta::new(camera_record, false),
            AccountMeta::new(asset.pubkey(), true),
            AccountMeta::new(relayer.pubkey(), true),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            AccountMeta::new_readonly(mpl_core, false),
        ],
        data: ix_data,
    };

    let cu_limit = ComputeBudgetInstruction::set_compute_unit_limit(COMPUTE_UNIT_LIMIT);
    let cu_price = ComputeBudgetInstruction::set_compute_unit_price(COMPUTE_UNIT_PRICE);

    println!("[Solana] Minting on cluster={cluster} program={}", cfg.program_id);
    println!("  - device PDA: {device_record}");
    println!("  - camera PDA: {camera_record}");
    println!("  - asset:      {}", asset.pubkey());

    let result = pool
        .with_failover(|url| {
            let client = client.clone();
            let relayer_bytes = relayer.to_bytes();
            let asset_bytes = asset.to_bytes();
            let instructions = vec![cu_limit.clone(), cu_price.clone(), mint_ix.clone()];
            async move {
                let relayer = Keypair::try_from(&relayer_bytes[..])
                    .map_err(|e| -> BoxError { format!("relayer keypair: {e}").into() })?;
                let asset = Keypair::try_from(&asset_bytes[..])
                    .map_err(|e| -> BoxError { format!("asset keypair: {e}").into() })?;

                let blockhash = get_latest_blockhash(&client, &url).await?;
                let tx = Transaction::new_signed_with_payer(
                    &instructions,
                    Some(&relayer.pubkey()),
                    &[&relayer, &asset],
                    blockhash,
                );
                let sig = send_transaction(&client, &url, &tx).await?;
                println!("[Solana] BROADCASTED tx={sig} via {}", host(&url));
                poll_confirm(&client, &url, &sig).await?;
                println!("[Solana] CONFIRMED tx={sig}");
                Ok(sig)
            }
        })
        .await;

    match result {
        Ok(sig) => {
            on_lifecycle(MintLifecycle::Broadcasted, Some(&sig));
            on_lifecycle(MintLifecycle::Mined, Some(&sig));
            Ok(MintResult {
                tx_hash: sig,
                block_number: None,
            })
        }
        Err(e) => {
            on_lifecycle(MintLifecycle::Failed, None);
            Err(e)
        }
    }
}

// JSON-RPC over HTTP (no websocket).

#[derive(Debug, Deserialize)]
struct RpcEnvelope<T> {
    result: Option<T>,
    error: Option<RpcErrorBody>,
}

#[derive(Debug, Deserialize)]
struct RpcErrorBody {
    message: String,
}

#[derive(Debug, Deserialize)]
struct BlockhashResult {
    value: BlockhashValue,
}

#[derive(Debug, Deserialize)]
struct BlockhashValue {
    blockhash: String,
}

#[derive(Debug, Deserialize)]
struct SignatureStatusesResult {
    value: Vec<Option<SignatureStatus>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignatureStatus {
    confirmation_status: Option<String>,
    err: Option<serde_json::Value>,
}

async fn rpc_call<T: for<'de> Deserialize<'de>>(
    client: &reqwest::Client,
    url: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<T, BoxError> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    let resp = client.post(url).json(&body).send().await?.error_for_status()?;
    let envelope: RpcEnvelope<T> = resp.json().await?;
    if let Some(err) = envelope.error {
        return Err(format!("RPC {method} error: {}", err.message).into());
    }
    envelope
        .result
        .ok_or_else(|| format!("RPC {method}: missing result").into())
}

async fn get_latest_blockhash(client: &reqwest::Client, url: &str) -> Result<Hash, BoxError> {
    let result: BlockhashResult = rpc_call(
        client,
        url,
        "getLatestBlockhash",
        serde_json::json!([{ "commitment": "confirmed" }]),
    )
    .await?;
    Hash::from_str(&result.value.blockhash)
        .map_err(|e| format!("invalid blockhash: {e}").into())
}

async fn send_transaction(
    client: &reqwest::Client,
    url: &str,
    tx: &Transaction,
) -> Result<String, BoxError> {
    let bytes = bincode::serialize(tx).map_err(|e| format!("tx serialize: {e}"))?;
    let encoded = B64.encode(bytes);
    let sig: String = rpc_call(
        client,
        url,
        "sendTransaction",
        serde_json::json!([
            encoded,
            {
                "encoding": "base64",
                "skipPreflight": false,
                "preflightCommitment": "confirmed"
            }
        ]),
    )
    .await?;
    Ok(sig)
}

async fn poll_confirm(
    client: &reqwest::Client,
    url: &str,
    signature: &str,
) -> Result<(), BoxError> {
    let start = Instant::now();
    while start.elapsed() < CONFIRM_TIMEOUT {
        let result: SignatureStatusesResult = rpc_call(
            client,
            url,
            "getSignatureStatuses",
            serde_json::json!([[signature], { "searchTransactionHistory": true }]),
        )
        .await?;

        if let Some(Some(status)) = result.value.first() {
            if let Some(err) = &status.err {
                return Err(format!("Transaction failed on-chain: {err}").into());
            }
            match status.confirmation_status.as_deref() {
                Some("confirmed") | Some("finalized") => return Ok(()),
                _ => {}
            }
        }
        tokio::time::sleep(CONFIRM_POLL).await;
    }
    Err(format!(
        "Transaction not confirmed within {}s",
        CONFIRM_TIMEOUT.as_secs()
    )
    .into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn borsh_string_has_le_length_prefix() {
        let enc = encode_borsh_string("ab");
        assert_eq!(&enc[..4], &[2, 0, 0, 0]);
        assert_eq!(&enc[4..], b"ab");
    }

    #[test]
    fn anchor_discriminator_is_stable() {
        // sha256("global:mint_from_hardware")[:8] — must match Anchor / the TS adapter.
        let d = anchor_discriminator("mint_from_hardware");
        let expected = {
            let h = Sha256::digest(b"global:mint_from_hardware");
            let mut a = [0u8; 8];
            a.copy_from_slice(&h[..8]);
            a
        };
        assert_eq!(d, expected);
    }

    #[test]
    fn parse_keypair_json_roundtrip() {
        let kp = Keypair::new();
        let json = serde_json::to_string(&kp.to_bytes().to_vec()).unwrap();
        let parsed = parse_keypair(&json).unwrap();
        assert_eq!(kp.pubkey(), parsed.pubkey());
    }
}
