use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ChainTarget {
    EVM,
    Solana,
}

fn default_evm_chain_id() -> u64 {
    11155111 // Sepolia
}

fn default_solana_cluster() -> String {
    "devnet".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CameraSettings {
    pub active_chain: ChainTarget,
    #[serde(default = "default_evm_chain_id")]
    pub evm_chain_id: u64,
    #[serde(default = "default_solana_cluster")]
    pub solana_cluster: String,
}

impl Default for CameraSettings {
    fn default() -> Self {
        Self {
            active_chain: ChainTarget::EVM,
            evm_chain_id: default_evm_chain_id(),
            solana_cluster: default_solana_cluster(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum DaemonCmd {
    CapturePhoto(Uuid),
    SetFocus(i32),
    DeletePhoto(Uuid),
    StartVideo(Uuid),
    StopVideo,
    Mint(Uuid, ChainTarget),
    UpdateSettings(CameraSettings),
}

#[derive(Debug, Clone)]
pub enum AppEvent {
    MintProgress(Uuid, String),
    MintSuccess(Uuid, ChainTarget, String),
    MintFailed(Uuid, ChainTarget, String),
}
