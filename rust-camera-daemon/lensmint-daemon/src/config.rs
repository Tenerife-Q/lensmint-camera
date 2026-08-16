// Central config: contract addresses and Solana RPC lists live under `config/`.
// Lookup order: `$LENSMINT_CONFIG_DIR` → `<exe>/config/` → `./config/` → embedded.

use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

const EMBEDDED_CONTRACTS: &str = include_str!("../config/contracts.json");
const EMBEDDED_SOLANA_RPCS: &str = include_str!("../config/solana_rpcs.json");

#[derive(Debug, Clone, Deserialize)]
pub struct EvmChainConfig {
    pub name: String,
    pub lensmint: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SolanaClusterConfig {
    pub program_id: String,
    pub mpl_core: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ContractsConfig {
    #[serde(default)]
    pub evm: HashMap<String, EvmChainConfig>,
    #[serde(default)]
    pub solana: HashMap<String, SolanaClusterConfig>,
}

impl ContractsConfig {
    pub fn evm(&self, chain_id: u64) -> Option<&EvmChainConfig> {
        self.evm.get(&chain_id.to_string())
    }

    pub fn solana(&self, cluster: &str) -> Option<&SolanaClusterConfig> {
        self.solana.get(cluster)
    }
}

pub type SolanaRpcConfig = HashMap<String, Vec<String>>;

fn config_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(d) = std::env::var("LENSMINT_CONFIG_DIR") {
        if !d.trim().is_empty() {
            dirs.push(PathBuf::from(d));
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            dirs.push(parent.join("config"));
        }
    }
    dirs.push(PathBuf::from("config"));
    dirs
}

fn read_config(file_name: &str, embedded: &str) -> String {
    for dir in config_dirs() {
        let path = dir.join(file_name);
        if let Ok(contents) = std::fs::read_to_string(&path) {
            println!("[Config] Loaded {} from {}", file_name, path.display());
            return contents;
        }
    }
    println!("[Config] {} not found on disk, using embedded default", file_name);
    embedded.to_string()
}

pub fn load_contracts() -> ContractsConfig {
    let raw = read_config("contracts.json", EMBEDDED_CONTRACTS);
    serde_json::from_str(&raw).expect("Invalid contracts.json")
}

pub fn load_solana_rpcs() -> SolanaRpcConfig {
    let raw = read_config("solana_rpcs.json", EMBEDDED_SOLANA_RPCS);
    serde_json::from_str(&raw).expect("Invalid solana_rpcs.json")
}
