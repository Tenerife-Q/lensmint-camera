// Mint gate: receipt + journal must match HashRecord.

use crate::hash_record::HashRecord;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JournalFile {
    pub device_pubkey_hex: String,
    pub phash0_hex: String,
    pub phash1_hex: String,
    pub distance: u32,
    pub threshold: u32,
    pub sha256_hex: String,
    pub alg: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MintProofMeta {
    pub uuid: String,
    pub receipt_file: String,
    pub receipt_sha256: String,
    pub journal_file: String,
    pub sha256: String,
    pub phash0: String,
    pub phash1: String,
    pub distance: u32,
    pub device_pubkey: String,
    pub alg: String,
}

#[derive(Debug, Clone)]
pub struct ProofMaterials {
    pub record: HashRecord,
    pub journal: JournalFile,
    pub receipt_sha256: String,
    pub meta: MintProofMeta,
}

fn norm_hex(s: &str) -> String {
    s.trim().trim_start_matches("0x").to_lowercase()
}

pub fn receipt_path(photos_dir: &Path, uuid: &uuid::Uuid) -> PathBuf {
    photos_dir.join(format!("{uuid}.receipt.bin"))
}

pub fn journal_path(photos_dir: &Path, uuid: &uuid::Uuid) -> PathBuf {
    photos_dir.join(format!("{uuid}.journal.json"))
}

pub fn mint_proof_path(photos_dir: &Path, uuid: &uuid::Uuid) -> PathBuf {
    photos_dir.join(format!("{uuid}.mint-proof.json"))
}

pub fn require_proof_for_mint(
    photos_dir: &Path,
    uuid: &uuid::Uuid,
) -> Result<ProofMaterials, String> {
    let record = HashRecord::load(photos_dir, uuid).map_err(|e| {
        format!("mint blocked: missing hash record for {uuid}: {e}")
    })?;
    record.verify_signature().map_err(|e| {
        format!("mint blocked: hash record signature invalid for {uuid}: {e}")
    })?;

    let journal_path = journal_path(photos_dir, uuid);
    if !journal_path.exists() {
        return Err(format!("mint blocked: missing journal for {uuid}"));
    }
    let journal_bytes = std::fs::read(&journal_path).map_err(|e| {
        format!("mint blocked: cannot read journal for {uuid}: {e}")
    })?;
    let journal: JournalFile = serde_json::from_slice(&journal_bytes).map_err(|e| {
        format!("mint blocked: invalid journal for {uuid}: {e}")
    })?;

    let receipt_path = receipt_path(photos_dir, uuid);
    if !receipt_path.exists() {
        return Err(format!("mint blocked: missing receipt for {uuid}"));
    }
    let receipt_bytes = std::fs::read(&receipt_path).map_err(|e| {
        format!("mint blocked: cannot read receipt for {uuid}: {e}")
    })?;
    if receipt_bytes.is_empty() {
        return Err(format!("mint blocked: empty receipt for {uuid}"));
    }

    if norm_hex(&journal.sha256_hex) != norm_hex(&record.sha256) {
        return Err(format!(
            "mint blocked: journal does not match hash record (sha256) for {uuid}"
        ));
    }
    if norm_hex(&journal.phash0_hex) != norm_hex(&record.phash) {
        return Err(format!(
            "mint blocked: journal does not match hash record (phash) for {uuid}"
        ));
    }
    if norm_hex(&journal.device_pubkey_hex) != norm_hex(&record.device_pubkey) {
        return Err(format!(
            "mint blocked: journal does not match hash record (pubkey) for {uuid}"
        ));
    }

    let mut hasher = Sha256::new();
    hasher.update(&receipt_bytes);
    let receipt_sha256 = hex::encode(hasher.finalize());

    let meta = MintProofMeta {
        uuid: record.uuid.clone(),
        receipt_file: format!("{}.receipt.bin", record.uuid),
        receipt_sha256: receipt_sha256.clone(),
        journal_file: format!("{}.journal.json", record.uuid),
        sha256: norm_hex(&journal.sha256_hex),
        phash0: norm_hex(&journal.phash0_hex),
        phash1: norm_hex(&journal.phash1_hex),
        distance: journal.distance,
        device_pubkey: norm_hex(&journal.device_pubkey_hex),
        alg: journal.alg.clone(),
    };

    Ok(ProofMaterials {
        record,
        journal,
        receipt_sha256,
        meta,
    })
}

pub fn save_mint_proof(
    photos_dir: &Path,
    uuid: &uuid::Uuid,
    meta: &MintProofMeta,
) -> Result<PathBuf, String> {
    let path = mint_proof_path(photos_dir, uuid);
    let json = serde_json::to_vec_pretty(meta).map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| format!("failed to write mint-proof: {e}"))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::LocalKeystore;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn test_keystore() -> LocalKeystore {
        let mut csprng = OsRng;
        LocalKeystore {
            signing_key: SigningKey::generate(&mut csprng),
        }
    }

    fn tiny_jpeg() -> Vec<u8> {
        let img = image::RgbaImage::from_pixel(8, 8, image::Rgba([10, 20, 30, 255]));
        let mut cursor = std::io::Cursor::new(Vec::new());
        img.write_to(&mut cursor, image::ImageFormat::Jpeg)
            .expect("encode jpeg");
        cursor.into_inner()
    }

    fn setup_capture(dir: &Path, keystore: &LocalKeystore) -> (uuid::Uuid, HashRecord) {
        let uuid = uuid::Uuid::new_v4();
        let record = HashRecord::create_from_jpeg_bytes(uuid, &tiny_jpeg(), keystore).unwrap();
        record.save(dir).unwrap();
        (uuid, record)
    }

    fn write_matching_journal(dir: &Path, record: &HashRecord) {
        let journal = JournalFile {
            device_pubkey_hex: record.device_pubkey.clone(),
            phash0_hex: record.phash.clone(),
            phash1_hex: record.phash.clone(),
            distance: 0,
            threshold: 5,
            sha256_hex: record.sha256.clone(),
            alg: record.alg.clone(),
        };
        let uuid = uuid::Uuid::parse_str(&record.uuid).unwrap();
        std::fs::write(
            journal_path(dir, &uuid),
            serde_json::to_vec_pretty(&journal).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn missing_receipt_blocks_mint() {
        let keystore = test_keystore();
        let uuid = uuid::Uuid::new_v4();
        let dir = std::env::temp_dir().join(format!("lensmint-gate-miss-{uuid}"));
        std::fs::create_dir_all(&dir).unwrap();
        let (uuid, record) = setup_capture(&dir, &keystore);
        write_matching_journal(&dir, &record);

        let err = require_proof_for_mint(&dir, &uuid).expect_err("must block");
        assert!(err.contains("missing receipt"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_receipt_blocks_mint() {
        let keystore = test_keystore();
        let uuid = uuid::Uuid::new_v4();
        let dir = std::env::temp_dir().join(format!("lensmint-gate-empty-{uuid}"));
        std::fs::create_dir_all(&dir).unwrap();
        let (uuid, record) = setup_capture(&dir, &keystore);
        write_matching_journal(&dir, &record);
        std::fs::write(receipt_path(&dir, &uuid), b"").unwrap();

        let err = require_proof_for_mint(&dir, &uuid).expect_err("must block");
        assert!(err.contains("empty receipt"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mismatched_journal_blocks_mint() {
        let keystore = test_keystore();
        let uuid = uuid::Uuid::new_v4();
        let dir = std::env::temp_dir().join(format!("lensmint-gate-mismatch-{uuid}"));
        std::fs::create_dir_all(&dir).unwrap();
        let (uuid, record) = setup_capture(&dir, &keystore);
        write_matching_journal(&dir, &record);
        std::fs::write(receipt_path(&dir, &uuid), b"fake-receipt-bytes").unwrap();

        let mut journal: JournalFile = serde_json::from_slice(
            &std::fs::read(journal_path(&dir, &uuid)).unwrap(),
        )
        .unwrap();
        journal.sha256_hex = "11".repeat(32);
        std::fs::write(
            journal_path(&dir, &uuid),
            serde_json::to_vec_pretty(&journal).unwrap(),
        )
        .unwrap();

        let err = require_proof_for_mint(&dir, &uuid).expect_err("must block");
        assert!(err.contains("sha256"), "{err}");
        let _ = record.uuid;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn matching_materials_pass_and_write_meta() {
        let keystore = test_keystore();
        let uuid = uuid::Uuid::new_v4();
        let dir = std::env::temp_dir().join(format!("lensmint-gate-ok-{uuid}"));
        std::fs::create_dir_all(&dir).unwrap();
        let (uuid, record) = setup_capture(&dir, &keystore);
        write_matching_journal(&dir, &record);
        std::fs::write(receipt_path(&dir, &uuid), b"fake-receipt-bytes").unwrap();

        let materials = require_proof_for_mint(&dir, &uuid).expect("must pass");
        assert_eq!(norm_hex(&materials.journal.sha256_hex), norm_hex(&record.sha256));
        assert!(!materials.receipt_sha256.is_empty());

        let path = save_mint_proof(&dir, &uuid, &materials.meta).unwrap();
        assert!(path.exists());
        let loaded: MintProofMeta = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(loaded.uuid, record.uuid);
        assert_eq!(loaded.receipt_sha256, materials.receipt_sha256);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_hash_record_blocks_mint() {
        let uuid = uuid::Uuid::new_v4();
        let dir = std::env::temp_dir().join(format!("lensmint-gate-nohash-{uuid}"));
        std::fs::create_dir_all(&dir).unwrap();
        let err = require_proof_for_mint(&dir, &uuid).expect_err("must block");
        assert!(err.contains("missing hash record"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
#[path = "proof_gate_gap_tests.rs"]
mod proof_gate_gap_tests;
