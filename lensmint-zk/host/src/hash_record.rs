use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HashRecord {
    pub uuid: String,
    pub sha256: String,
    pub phash: String,
    pub alg: String,
    pub message: String,
    pub signature: String,
    pub device_pubkey: String,
    pub created_at: u64,
}

impl HashRecord {
    pub fn load_path(path: &std::path::Path) -> anyhow::Result<Self> {
        let bytes = std::fs::read(path)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn save_path(&self, path: &std::path::Path) -> anyhow::Result<()> {
        let json = serde_json::to_vec_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }
}
