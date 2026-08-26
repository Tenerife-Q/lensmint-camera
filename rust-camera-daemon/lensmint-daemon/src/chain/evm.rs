//! EVM mint via alloy: pinned nonce, bounded gas bump, chainlist RPC pool.

use super::rpc::{self, RpcPool};
use super::{BoxError, MintLifecycle, MintRequest, MintResult};
use alloy::primitives::{Address, B256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::BlockNumberOrTag;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use alloy::sol_types::private::FixedBytes;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::{Duration, Instant};

// Bounded RBF: bump every BUMP_INTERVAL, stop at MAX_BUMPS or fee cap.
const BUMP_INTERVAL: Duration = Duration::from_secs(24);
const MAX_BUMPS: u32 = 5;
const FINAL_WAIT: Duration = Duration::from_secs(60);
const RECEIPT_POLL: Duration = Duration::from_secs(3);
const BUMP_NUM: u128 = 115; // +15% per bump (>10% min for replacement)
const BUMP_DEN: u128 = 100;
const MAX_GAS_FEE_CAP_GWEI: u128 = 500;
const DEFAULT_MAX_FEE_GWEI: u128 = 2;
const DEFAULT_PRIORITY_GWEI: u128 = 2; // slightly above 1.5 so we stay in integers

sol! {
    #[sol(rpc)]
    contract LensMint {
        function mintFromHardware(
            address to,
            string uuid,
            bytes32 sha256Hash,
            string phash,
            string deviceId
        ) external returns (uint256);
    }
}

/// Load hex private key from `<data_dir>/evm_wallet.key`.
pub fn load_gas_wallet() -> Result<PrivateKeySigner, BoxError> {
    let path = wallet_path()?;
    if !path.exists() {
        return Err(format!(
            "EVM gas wallet not found at {} — place a hex private key there (chmod 400)",
            path.display()
        )
        .into());
    }
    let raw = fs::read_to_string(&path)?;
    let key = raw.trim();
    let signer: PrivateKeySigner = key.parse()?;
    println!("[EVM] Gas wallet loaded: {}", signer.address());
    Ok(signer)
}

fn wallet_path() -> Result<PathBuf, BoxError> {
    let proj = directories::ProjectDirs::from("", "", "lensmint")
        .ok_or("Could not resolve lensmint data dir")?;
    Ok(proj.data_dir().join("evm_wallet.key"))
}

fn gwei(n: u128) -> u128 {
    n * 1_000_000_000
}

fn is_deterministic_revert(err: &dyn std::error::Error) -> bool {
    let msg = format!("{err:#}").to_lowercase();
    msg.contains("execution reverted")
        || msg.contains("reverted")
        || msg.contains("unauthorized device")
        || msg.contains("duplicate asset hash")
}

fn parse_address(s: &str) -> Result<Address, BoxError> {
    Address::from_str(s.trim()).map_err(|e| format!("invalid address '{s}': {e}").into())
}

fn parse_bytes32(hex_str: &str) -> Result<FixedBytes<32>, BoxError> {
    let clean = hex_str.trim().trim_start_matches("0x");
    let bytes = hex::decode(clean).map_err(|e| format!("invalid sha256 hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("sha256 must be 32 bytes, got {}", bytes.len()).into());
    }
    Ok(FixedBytes::<32>::from_slice(&bytes))
}

fn build_provider(
    rpc_url: &str,
    signer: PrivateKeySigner,
) -> Result<impl Provider + Clone, BoxError> {
    let url = reqwest::Url::parse(rpc_url)?;
    Ok(ProviderBuilder::new().wallet(signer).connect_http(url))
}

pub async fn mint(
    chain_id: u64,
    req: &MintRequest,
    mut on_lifecycle: impl FnMut(MintLifecycle, Option<&str>),
) -> Result<MintResult, BoxError> {
    let contracts = crate::config::load_contracts();
    let chain_cfg = contracts
        .evm(chain_id)
        .ok_or_else(|| format!("no EVM contract configured for chainId {chain_id}"))?;
    let contract_addr = parse_address(&chain_cfg.lensmint)?;

    let signer = load_gas_wallet()?;
    let from = signer.address();
    let pool = rpc::evm_pool(chain_id).await?;
    if pool.is_empty() {
        return Err("EVM RPC pool is empty".into());
    }

    let recipient = match req.target_address.as_deref() {
        Some(a) if !a.is_empty() && a != "0x0000000000000000000000000000000000000000" => {
            parse_address(a)?
        }
        _ => from,
    };
    let sha256 = parse_bytes32(&req.sha256)?;
    let device_id = req.device_id.trim().to_lowercase();

    // Fee estimate + pinned nonce — rotate RPC on transient failure.
    let (mut max_fee, mut max_prio, nonce) = pool
        .with_failover(|url| {
            let signer = signer.clone();
            async move {
                let provider = build_provider(&url, signer)?;
                let fees = provider.estimate_eip1559_fees().await.map_err(into_box)?;
                let mut max_fee = fees.max_fee_per_gas.saturating_mul(BUMP_NUM) / BUMP_DEN;
                let mut max_prio =
                    fees.max_priority_fee_per_gas.saturating_mul(BUMP_NUM) / BUMP_DEN;
                if max_fee == 0 {
                    max_fee = gwei(DEFAULT_MAX_FEE_GWEI);
                }
                if max_prio == 0 {
                    max_prio = gwei(DEFAULT_PRIORITY_GWEI);
                }
                let nonce = provider
                    .get_transaction_count(from)
                    .block_id(BlockNumberOrTag::Pending.into())
                    .await
                    .map_err(into_box)?;
                Ok((max_fee, max_prio, nonce))
            }
        })
        .await?;

    println!("[EVM] Sending mint on pinned nonce {nonce} (chainId={chain_id})");
    println!("  - contract:  {}", chain_cfg.lensmint);
    println!("  - recipient: {recipient}");
    println!("  - deviceId:  {device_id}");
    if let Some(proof) = &req.proof {
        println!(
            "  - proof:     receipt_sha256={} file={} distance={}",
            proof.receipt_sha256, proof.receipt_file, proof.distance
        );
    } else {
        return Err("EVM mint requires proof attachment from mint gate".into());
    }

    let fee_cap = gwei(MAX_GAS_FEE_CAP_GWEI);
    let mut sent_hashes: Vec<B256> = Vec::new();
    let mut bumps: u32 = 0;

    loop {
        let mut cap_reached = false;
        if max_fee >= fee_cap {
            max_fee = fee_cap;
            cap_reached = true;
        }
        if max_prio > max_fee {
            max_prio = max_fee;
        }

        let lifecycle = if bumps == 0 {
            MintLifecycle::Broadcasted
        } else {
            MintLifecycle::Bumping
        };

        let send_result = send_mint(
            &pool,
            &signer,
            contract_addr,
            recipient,
            &req.uuid,
            sha256,
            &req.phash,
            &device_id,
            nonce,
            max_fee,
            max_prio,
        )
        .await;

        match send_result {
            Ok(tx_hash) => {
                sent_hashes.push(tx_hash);
                let hash_hex = format!("{tx_hash:#x}");
                println!(
                    "[EVM] {} nonce={nonce} tx={hash_hex} maxFee={}gwei (bump {bumps}/{MAX_BUMPS})",
                    lifecycle.as_str(),
                    max_fee / 1_000_000_000
                );
                on_lifecycle(lifecycle, Some(&hash_hex));

                if let Some(receipt) =
                    wait_for_receipt_any(&pool, &signer, &sent_hashes, BUMP_INTERVAL).await
                {
                    return finish_mined(receipt, &mut on_lifecycle);
                }
            }
            Err(e) => {
                // Replacement may fail because a prior tx already mined — check first.
                if !sent_hashes.is_empty() {
                    if let Some(receipt) = wait_for_receipt_any(
                        &pool,
                        &signer,
                        &sent_hashes,
                        Duration::from_secs(6),
                    )
                    .await
                    {
                        return finish_mined(receipt, &mut on_lifecycle);
                    }
                }
                if is_deterministic_revert(&*e) {
                    on_lifecycle(MintLifecycle::Failed, None);
                    return Err(format!("Mint rejected on-chain: {e}").into());
                }
                // Transient after first broadcast: keep bumping / waiting.
                if sent_hashes.is_empty() {
                    on_lifecycle(MintLifecycle::Failed, None);
                    return Err(e);
                }
                eprintln!("[EVM] send error after broadcast (will continue wait/bump): {e}");
            }
        }

        if cap_reached || bumps >= MAX_BUMPS {
            println!(
                "[EVM] Gas cap / max bumps reached, final wait {}s on nonce {nonce}",
                FINAL_WAIT.as_secs()
            );
            if let Some(receipt) =
                wait_for_receipt_any(&pool, &signer, &sent_hashes, FINAL_WAIT).await
            {
                return finish_mined(receipt, &mut on_lifecycle);
            }
            on_lifecycle(MintLifecycle::Failed, None);
            return Err(format!(
                "EVM tx stuck: reached gas cap {} gwei without inclusion (nonce {nonce})",
                MAX_GAS_FEE_CAP_GWEI
            )
            .into());
        }

        max_fee = max_fee.saturating_mul(BUMP_NUM) / BUMP_DEN;
        max_prio = max_prio.saturating_mul(BUMP_NUM) / BUMP_DEN;
        bumps += 1;
    }
}

async fn send_mint(
    pool: &RpcPool,
    signer: &PrivateKeySigner,
    contract_addr: Address,
    recipient: Address,
    uuid: &str,
    sha256: FixedBytes<32>,
    phash: &str,
    device_id: &str,
    nonce: u64,
    max_fee: u128,
    max_prio: u128,
) -> Result<B256, BoxError> {
    let uuid = uuid.to_string();
    let phash = phash.to_string();
    let device_id = device_id.to_string();
    let signer = signer.clone();

    pool.with_failover(|url| {
        let signer = signer.clone();
        let uuid = uuid.clone();
        let phash = phash.clone();
        let device_id = device_id.clone();
        async move {
            let provider = build_provider(&url, signer)?;
            let contract = LensMint::new(contract_addr, provider);
            let pending = contract
                .mintFromHardware(recipient, uuid, sha256, phash, device_id)
                .nonce(nonce)
                .max_fee_per_gas(max_fee)
                .max_priority_fee_per_gas(max_prio)
                .send()
                .await
                .map_err(into_box)?;
            Ok(*pending.tx_hash())
        }
    })
    .await
}

struct MinedReceipt {
    hash: B256,
    block_number: Option<u64>,
    status: bool,
}

async fn wait_for_receipt_any(
    pool: &RpcPool,
    signer: &PrivateKeySigner,
    hashes: &[B256],
    timeout: Duration,
) -> Option<MinedReceipt> {
    if hashes.is_empty() {
        return None;
    }
    let start = Instant::now();
    while start.elapsed() < timeout {
        for &hash in hashes {
            let signer = signer.clone();
            let looked = pool
                .with_failover(|url| {
                    let signer = signer.clone();
                    async move {
                        let provider = build_provider(&url, signer)?;
                        let receipt = provider
                            .get_transaction_receipt(hash)
                            .await
                            .map_err(into_box)?;
                        Ok(receipt)
                    }
                })
                .await;

            if let Ok(Some(r)) = looked {
                let status = r.status();
                let block_number = r.block_number;
                return Some(MinedReceipt {
                    hash: r.transaction_hash,
                    block_number,
                    status,
                });
            }
        }
        tokio::time::sleep(RECEIPT_POLL).await;
    }
    None
}

fn finish_mined(
    receipt: MinedReceipt,
    on_lifecycle: &mut impl FnMut(MintLifecycle, Option<&str>),
) -> Result<MintResult, BoxError> {
    let hash_hex = format!("{:#x}", receipt.hash);
    if !receipt.status {
        on_lifecycle(MintLifecycle::Failed, Some(&hash_hex));
        return Err("Transaction reverted on-chain!".into());
    }
    println!(
        "[EVM] MINED block={:?} tx={hash_hex}",
        receipt.block_number
    );
    on_lifecycle(MintLifecycle::Mined, Some(&hash_hex));
    Ok(MintResult {
        tx_hash: hash_hex,
        block_number: receipt.block_number,
    })
}

fn into_box<E: std::error::Error + Send + Sync + 'static>(e: E) -> BoxError {
    Box::new(e)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bytes32_with_and_without_prefix() {
        let a = parse_bytes32(
            "eb33cd52b68482b3f70c1f31e77582cb53c5b55d7e942f8cd44d297c844361c1",
        )
        .unwrap();
        let b = parse_bytes32(
            "0xeb33cd52b68482b3f70c1f31e77582cb53c5b55d7e942f8cd44d297c844361c1",
        )
        .unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn detects_deterministic_reverts() {
        let err = std::io::Error::new(
            std::io::ErrorKind::Other,
            "execution reverted: Unauthorized device",
        );
        assert!(is_deterministic_revert(&err));
        let ok = std::io::Error::new(std::io::ErrorKind::Other, "request timeout");
        assert!(!is_deterministic_revert(&ok));
    }
}
