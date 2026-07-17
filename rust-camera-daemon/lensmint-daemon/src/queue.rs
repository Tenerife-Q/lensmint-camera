//! Single-concurrency mint queue with sha256 idempotency.

use crate::chain::{self, MintLifecycle, MintRequest, MintResult};
use crate::cmd::ChainTarget;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub enum MintOutcome {
    InFlight,
    Completed { tx_hash: String },
    Failed {
        #[allow(dead_code)]
        reason: String,
    },
}

#[derive(Clone, Default)]
pub struct MintQueue {
    lock: Arc<Mutex<()>>,
    outcomes: Arc<Mutex<HashMap<String, MintOutcome>>>,
}

impl MintQueue {
    pub fn new() -> Self {
        Self::default()
    }

    fn job_key(target: &ChainTarget, sha256: &str) -> String {
        let chain = match target {
            ChainTarget::EVM => "evm",
            ChainTarget::Solana => "solana",
        };
        format!("{chain}-{}", sha256.trim().trim_start_matches("0x").to_lowercase())
    }

    pub async fn peek(&self, target: &ChainTarget, sha256: &str) -> Option<MintOutcome> {
        let key = Self::job_key(target, sha256);
        self.outcomes.lock().await.get(&key).cloned()
    }

    pub async fn mint<F>(
        &self,
        target: ChainTarget,
        evm_chain_id: u64,
        solana_cluster: String,
        req: MintRequest,
        mut on_lifecycle: F,
    ) -> Result<MintResult, String>
    where
        F: FnMut(MintLifecycle, Option<&str>),
    {
        let key = Self::job_key(&target, &req.sha256);

        {
            let mut map = self.outcomes.lock().await;
            if let Some(MintOutcome::Completed { tx_hash }) = map.get(&key) {
                println!("[Queue] Duplicate mint for {key}, returning prior tx={tx_hash}");
                on_lifecycle(MintLifecycle::Mined, Some(tx_hash));
                return Ok(MintResult {
                    tx_hash: tx_hash.clone(),
                    block_number: None,
                });
            }
            if matches!(map.get(&key), Some(MintOutcome::InFlight)) {
                return Err("Mint already in flight for this capture".into());
            }
            map.insert(key.clone(), MintOutcome::InFlight);
        }

        let _guard = self.lock.lock().await;

        let result = match target {
            ChainTarget::EVM => {
                chain::evm::mint(evm_chain_id, &req, &mut on_lifecycle)
                    .await
                    .map_err(|e| e.to_string())
            }
            ChainTarget::Solana => {
                chain::solana::mint(&solana_cluster, &req, &mut on_lifecycle)
                    .await
                    .map_err(|e| e.to_string())
            }
        };

        let mut map = self.outcomes.lock().await;
        match &result {
            Ok(r) => {
                map.insert(
                    key,
                    MintOutcome::Completed {
                        tx_hash: r.tx_hash.clone(),
                    },
                );
            }
            Err(reason) => {
                map.insert(
                    key,
                    MintOutcome::Failed {
                        reason: reason.clone(),
                    },
                );
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_key_normalizes_hex_prefix() {
        let a = MintQueue::job_key(&ChainTarget::EVM, "0xAbCd");
        let b = MintQueue::job_key(&ChainTarget::EVM, "abcd");
        assert_eq!(a, b);
        assert_eq!(a, "evm-abcd");
    }
}
