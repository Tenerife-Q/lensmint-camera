// Per-chain mint adapters and shared RPC failover.

pub mod evm;
pub mod rpc;
pub mod solana;

use std::error::Error;

pub type BoxError = Box<dyn Error + Send + Sync>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MintLifecycle {
    Broadcasted,
    Bumping,
    Mined,
    Failed,
}

impl MintLifecycle {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Broadcasted => "BROADCASTED",
            Self::Bumping => "BUMPING",
            Self::Mined => "MINED",
            Self::Failed => "FAILED",
        }
    }
}

#[derive(Debug, Clone)]
pub struct MintProofAttach {
    pub receipt_sha256: String,
    pub distance: u32,
    pub phash1: String,
    pub receipt_file: String,
    pub journal_file: String,
}

#[derive(Debug, Clone)]
pub struct MintRequest {
    pub uuid: String,
    pub sha256: String,
    pub phash: String,
    pub device_id: String,
    /// NFT recipient; `None` / zero address mints to the gas wallet.
    pub target_address: Option<String>,
    pub proof: Option<MintProofAttach>,
}

#[derive(Debug, Clone)]
pub struct MintResult {
    pub tx_hash: String,
    pub block_number: Option<u64>,
}
