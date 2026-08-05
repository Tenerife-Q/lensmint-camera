use crate::hash_record::HashRecord;
use crate::phash::sha256_hex;
use crate::recompress_pick::pick_recompress;
use lensmint_zk_core::{verify_authenticity, GuestInput, GuestJournal};
use methods::{AUTHENTICITY_ELF, AUTHENTICITY_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, Receipt};
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct ProveRequest {
    pub record: HashRecord,
    pub jpeg_bytes: Vec<u8>,
    // Preferred JPEG quality; host may scan nearby values for a demo pick.
    pub recompress_quality: u8,
    pub out_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct BenchStats {
    pub prove_wall_ms: u128,
    pub receipt_bytes: u64,
    pub receipt_path: PathBuf,
    pub distance: u32,
    pub phash0_hex: String,
    pub phash1_hex: String,
    pub sha256_original: String,
    pub sha256_recompressed: String,
    pub recompress_quality: u8,
    pub journal: GuestJournal,
}

pub fn build_guest_input(
    record: &HashRecord,
    jpeg_bytes: &[u8],
    recompress_quality: u8,
) -> anyhow::Result<(GuestInput, String, u32, String, u8)> {
    let pick = pick_recompress(jpeg_bytes, &record.phash, Some(recompress_quality))?;
    let input = GuestInput {
        message: record.message.clone(),
        signature_hex: record.signature.clone(),
        device_pubkey_hex: record.device_pubkey.clone(),
        phash1_hex: pick.phash1_hex.clone(),
    };
    let journal = verify_authenticity(&input)?;
    Ok((
        input,
        pick.phash1_hex,
        journal.distance,
        pick.sha256_recompressed,
        pick.quality,
    ))
}

pub fn prove_and_save(req: &ProveRequest) -> anyhow::Result<BenchStats> {
    std::fs::create_dir_all(&req.out_dir)?;
    let sha256_original = if req.record.sha256.is_empty() {
        sha256_hex(&req.jpeg_bytes)
    } else {
        req.record.sha256.clone()
    };

    let (input, phash1_hex, _distance, sha256_recompressed, quality) =
        build_guest_input(&req.record, &req.jpeg_bytes, req.recompress_quality)?;

    let env = ExecutorEnv::builder().write(&input)?.build()?;
    let prover = default_prover();

    // Groth16 for Sepolia; RISC0_DEV_MODE keeps the fast fake path.
    let use_dev = matches!(
        std::env::var("RISC0_DEV_MODE").ok().as_deref(),
        Some(v) if v != "0" && !v.is_empty()
    );
    let started = Instant::now();
    let prove_info = if use_dev {
        prover.prove(env, AUTHENTICITY_ELF)?
    } else {
        prover.prove_with_opts(env, AUTHENTICITY_ELF, &ProverOpts::groth16())?
    };
    let prove_wall_ms = started.elapsed().as_millis();

    let receipt = prove_info.receipt;
    receipt.verify(AUTHENTICITY_ID)?;
    // Guest journal is Solidity abi.encode bytes.
    let journal = GuestJournal::from_abi(receipt.journal.as_ref())
        .map_err(|e| anyhow::anyhow!("decode ABI journal: {e}"))?;

    let receipt_path = req.out_dir.join(format!("{}.receipt.bin", req.record.uuid));
    save_receipt(&receipt_path, &receipt)?;
    let receipt_bytes = std::fs::metadata(&receipt_path)?.len();

    let journal_path = req.out_dir.join(format!("{}.journal.json", req.record.uuid));
    std::fs::write(&journal_path, serde_json::to_vec_pretty(&journal)?)?;
    let journal_abi_path = req.out_dir.join(format!("{}.journal.abi", req.record.uuid));
    std::fs::write(
        &journal_abi_path,
        journal
            .abi_encode()
            .map_err(|e| anyhow::anyhow!("encode ABI journal: {e}"))?,
    )?;

    Ok(BenchStats {
        prove_wall_ms,
        receipt_bytes,
        receipt_path,
        distance: journal.distance,
        phash0_hex: journal.phash0_hex.clone(),
        phash1_hex,
        sha256_original,
        sha256_recompressed,
        recompress_quality: quality,
        journal,
    })
}

pub fn save_receipt(path: &Path, receipt: &Receipt) -> anyhow::Result<()> {
    let bytes = bincode::serialize(receipt)?;
    std::fs::write(path, bytes)?;
    Ok(())
}

pub fn load_receipt(path: &Path) -> anyhow::Result<Receipt> {
    let bytes = std::fs::read(path)?;
    Ok(bincode::deserialize(&bytes)?)
}

// On-chain seal: 4-byte verifier selector then Groth16 seal bytes.
pub fn groth16_seal(receipt: &Receipt) -> anyhow::Result<Vec<u8>> {
    let groth16 = receipt
        .inner
        .groth16()
        .map_err(|e| anyhow::anyhow!("receipt is not Groth16 (need non-dev prove with groth16): {e}"))?;
    let selector = &groth16.verifier_parameters.as_bytes()[..4];
    let mut out = Vec::with_capacity(4 + groth16.seal.len());
    out.extend_from_slice(selector);
    out.extend_from_slice(&groth16.seal);
    Ok(out)
}

pub fn authenticity_image_id_hex() -> String {
    let mut bytes = [0u8; 32];
    for (i, word) in AUTHENTICITY_ID.iter().enumerate() {
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::make_signed_fixture;
    use crate::phash::{gradient_phash_hex, recompress_jpeg};
    use lensmint_zk_core::{hamming_distance, GuestError};

    #[test]
    fn preflight_rejects_bad_signature() {
        let (mut record, jpeg) = make_signed_fixture().unwrap();
        record.signature = "00".repeat(64);
        let err = build_guest_input(&record, &jpeg, 40).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("signature") || msg.contains("BadSignature") || msg.contains("ed25519"),
            "unexpected err: {msg}"
        );
    }

    #[test]
    fn preflight_rejects_distance_over_threshold() {
        let (record, jpeg) = make_signed_fixture().unwrap();
        let recompressed = recompress_jpeg(&jpeg, 40).unwrap();
        let mut phash1 = hex::decode(gradient_phash_hex(&recompressed).unwrap()).unwrap();
        for b in &mut phash1 {
            *b = !*b;
        }
        let input = GuestInput {
            message: record.message.clone(),
            signature_hex: record.signature.clone(),
            device_pubkey_hex: record.device_pubkey.clone(),
            phash1_hex: hex::encode(&phash1),
        };
        let err = verify_authenticity(&input).unwrap_err();
        assert!(matches!(err, GuestError::DistanceTooLarge { .. }));
        let phash0 = hex::decode(record.phash).unwrap();
        assert!(hamming_distance(&phash0, &phash1).unwrap() > 5);
    }

    #[test]
    fn prove_dev_mode_writes_receipt() {
        std::env::set_var("RISC0_DEV_MODE", "1");
        let (record, jpeg) = make_signed_fixture().unwrap();
        let out = tempfile::tempdir().unwrap();
        let stats = prove_and_save(&ProveRequest {
            record: record.clone(),
            jpeg_bytes: jpeg,
            recompress_quality: 50,
            out_dir: out.path().to_path_buf(),
        })
        .expect("dev-mode prove");
        assert!(stats.receipt_path.exists());
        assert!(stats.receipt_bytes > 0);
        assert!(stats.distance <= 5);
        assert_ne!(stats.sha256_original, stats.sha256_recompressed);
        assert_eq!(stats.sha256_original, record.sha256);
        let receipt = load_receipt(&stats.receipt_path).unwrap();
        receipt.verify(AUTHENTICITY_ID).unwrap();
    }
}
