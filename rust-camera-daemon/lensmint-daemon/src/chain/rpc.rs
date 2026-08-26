// EVM / Solana RPC pools with round-robin failover.
// EVM URLs come from https://chainlist.org/rpcs.json at runtime; Solana from config/.

use serde::Deserialize;
use std::error::Error;
use std::future::Future;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

type BoxError = Box<dyn Error + Send + Sync>;

const CHAINLIST_URL: &str = "https://chainlist.org/rpcs.json";
const CACHE_TTL: Duration = Duration::from_secs(6 * 3600);

#[derive(Debug, Deserialize)]
struct ChainlistEntry {
    #[serde(rename = "chainId")]
    chain_id: Option<u64>,
    #[serde(default)]
    rpc: Vec<RpcEntry>,
}

#[derive(Debug, Deserialize)]
struct RpcEntry {
    url: String,
    #[serde(default)]
    tracking: Option<String>,
}

pub struct RpcPool {
    endpoints: Vec<String>,
    cursor: AtomicUsize,
}

impl RpcPool {
    pub fn new(endpoints: Vec<String>) -> Self {
        Self {
            endpoints,
            cursor: AtomicUsize::new(0),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
    }

    pub fn len(&self) -> usize {
        self.endpoints.len()
    }

    pub fn current(&self) -> &str {
        let i = self.cursor.load(Ordering::Relaxed) % self.endpoints.len();
        &self.endpoints[i]
    }

    pub fn rotate(&self) {
        self.cursor.fetch_add(1, Ordering::Relaxed);
    }

    /// Try each endpoint once; rotate on error.
    pub async fn with_failover<F, Fut, T>(&self, mut f: F) -> Result<T, BoxError>
    where
        F: FnMut(String) -> Fut,
        Fut: Future<Output = Result<T, BoxError>>,
    {
        if self.endpoints.is_empty() {
            return Err("RPC pool is empty".into());
        }
        let mut last_err: Option<BoxError> = None;
        for _ in 0..self.endpoints.len() {
            let url = self.current().to_string();
            match f(url.clone()).await {
                Ok(v) => return Ok(v),
                Err(e) => {
                    eprintln!("[RPC] endpoint failed: {} -> {}", host(&url), e);
                    self.rotate();
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| "all RPC endpoints failed".into()))
    }
}

pub async fn evm_pool(chain_id: u64) -> Result<RpcPool, BoxError> {
    let urls = fetch_evm_rpcs(chain_id).await?;
    println!(
        "[RPC] chainId {} -> {} usable EVM endpoints",
        chain_id,
        urls.len()
    );
    Ok(RpcPool::new(urls))
}

pub fn solana_pool(cluster: &str) -> Result<RpcPool, BoxError> {
    let cfg = crate::config::load_solana_rpcs();
    let urls = cfg
        .get(cluster)
        .cloned()
        .ok_or_else(|| format!("no Solana RPCs configured for cluster '{}'", cluster))?;
    if urls.is_empty() {
        return Err(format!("Solana cluster '{}' has an empty RPC list", cluster).into());
    }
    println!("[RPC] Solana '{}' -> {} endpoints", cluster, urls.len());
    Ok(RpcPool::new(urls))
}

async fn fetch_evm_rpcs(chain_id: u64) -> Result<Vec<String>, BoxError> {
    let raw = fetch_chainlist_cached().await?;
    let entries: Vec<ChainlistEntry> = serde_json::from_str(&raw)?;

    let entry = entries
        .into_iter()
        .find(|e| e.chain_id == Some(chain_id))
        .ok_or_else(|| format!("chainId {} not found in chainlist", chain_id))?;

    // HTTP(S) only; drop ws/wss and unresolved `${API_KEY}` templates.
    let mut usable: Vec<(bool, String)> = entry
        .rpc
        .into_iter()
        .filter(|r| {
            let u = r.url.trim();
            (u.starts_with("http://") || u.starts_with("https://")) && !u.contains("${")
        })
        .map(|r| (r.tracking.as_deref() == Some("none"), r.url))
        .collect();

    usable.sort_by(|a, b| b.0.cmp(&a.0));

    let urls: Vec<String> = usable.into_iter().map(|(_, u)| u).collect();
    if urls.is_empty() {
        return Err(format!("no usable HTTP RPC for chainId {}", chain_id).into());
    }
    Ok(urls)
}

fn cache_path() -> PathBuf {
    let base = directories::ProjectDirs::from("", "", "lensmint")
        .map(|d| d.data_dir().join("cache"))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("chainlist_rpcs.json")
}

async fn fetch_chainlist_cached() -> Result<String, BoxError> {
    let cache = cache_path();

    if let Ok(meta) = std::fs::metadata(&cache) {
        if let Ok(modified) = meta.modified() {
            let fresh = modified.elapsed().map(|e| e < CACHE_TTL).unwrap_or(false);
            if fresh {
                if let Ok(s) = std::fs::read_to_string(&cache) {
                    println!("[RPC] Using cached chainlist ({} bytes)", s.len());
                    return Ok(s);
                }
            }
        }
    }

    println!("[RPC] Fetching {}", CHAINLIST_URL);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

    match client.get(CHAINLIST_URL).send().await {
        Ok(resp) => {
            let text = resp.error_for_status()?.text().await?;
            if let Some(parent) = cache.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(&cache, &text);
            Ok(text)
        }
        Err(e) => {
            if let Ok(s) = std::fs::read_to_string(&cache) {
                eprintln!("[RPC] chainlist fetch failed ({}), using stale cache", e);
                return Ok(s);
            }
            Err(Box::new(e))
        }
    }
}

pub fn host(url: &str) -> String {
    match reqwest::Url::parse(url) {
        Ok(u) => u.host_str().unwrap_or(url).to_string(),
        Err(_) => url.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn failover_rotates_to_next_healthy_endpoint() {
        let pool = RpcPool::new(vec![
            "http://bad-1.invalid".to_string(),
            "http://bad-2.invalid".to_string(),
            "http://good.example".to_string(),
        ]);

        let calls = AtomicUsize::new(0);
        let got = pool
            .with_failover(|url| {
                calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    if url.contains("good") {
                        Ok(url)
                    } else {
                        Err::<String, BoxError>("simulated node down".into())
                    }
                }
            })
            .await
            .expect("should succeed on the healthy endpoint");

        assert_eq!(got, "http://good.example");
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn failover_gives_up_after_one_pass() {
        let pool = RpcPool::new(vec!["http://a.invalid".into(), "http://b.invalid".into()]);
        let calls = AtomicUsize::new(0);
        let res = pool
            .with_failover(|_url| {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Err::<(), BoxError>("down".into()) }
            })
            .await;
        assert!(res.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    #[ignore]
    async fn fetches_live_sepolia_rpcs() {
        let urls = fetch_evm_rpcs(11155111)
            .await
            .expect("should fetch Sepolia RPCs");
        assert!(!urls.is_empty());
        assert!(urls.iter().all(|u| u.starts_with("http")));
        assert!(urls.iter().all(|u| !u.contains("${")));
    }
}
