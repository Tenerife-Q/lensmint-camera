// Capture-time signed hash record (Phase-2).
// message = "{uuid}|{sha256}|{phash}" (UTF-8, Ed25519)
// alg = "sha256+gradient-phash-v1"
// sidecar: {uuid}.hash.json next to the photo

use crate::keystore::LocalKeystore;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const HASH_ALG: &str = "sha256+gradient-phash-v1";

pub fn canonical_message(uuid: &str, sha256_hex: &str, phash_hex: &str) -> String {
    format!("{uuid}|{sha256_hex}|{phash_hex}")
}

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
    pub fn path_for(photos_dir: &Path, uuid: &uuid::Uuid) -> PathBuf {
        photos_dir.join(format!("{uuid}.hash.json"))
    }

    pub fn create_from_jpeg_bytes(
        uuid: uuid::Uuid,
        jpeg_bytes: &[u8],
        keystore: &LocalKeystore,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let (sha256, phash) = compute_hashes_from_jpeg(jpeg_bytes)?;
        let uuid_str = uuid.to_string();
        let message = canonical_message(&uuid_str, &sha256, &phash);
        let signature = keystore.sign_payload_hex(message.as_bytes());
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Ok(Self {
            uuid: uuid_str,
            sha256,
            phash,
            alg: HASH_ALG.to_string(),
            message,
            signature,
            device_pubkey: keystore.public_key_hex(),
            created_at,
        })
    }

    pub fn create_from_jpeg_path(
        uuid: uuid::Uuid,
        jpeg_path: &Path,
        keystore: &LocalKeystore,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let jpeg_bytes = std::fs::read(jpeg_path).map_err(|e| {
            format!("missing or unreadable JPEG at {}: {e}", jpeg_path.display())
        })?;
        if jpeg_bytes.is_empty() {
            return Err("JPEG file is empty".into());
        }
        Self::create_from_jpeg_bytes(uuid, &jpeg_bytes, keystore)
    }

    pub fn save(&self, photos_dir: &Path) -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
        let uuid = uuid::Uuid::parse_str(&self.uuid)?;
        let path = Self::path_for(photos_dir, &uuid);
        let json = serde_json::to_vec_pretty(self)?;
        std::fs::write(&path, json)?;
        Ok(path)
    }

    pub fn load(
        photos_dir: &Path,
        uuid: &uuid::Uuid,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let path = Self::path_for(photos_dir, uuid);
        let bytes = std::fs::read(&path).map_err(|e| {
            format!("missing hash record at {}: {e}", path.display())
        })?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn verify_signature(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let pk_bytes = hex::decode(self.device_pubkey.trim().trim_start_matches("0x"))
            .map_err(|e| format!("invalid device_pubkey hex: {e}"))?;
        if pk_bytes.len() != 32 {
            return Err(format!("device_pubkey must be 32 bytes, got {}", pk_bytes.len()).into());
        }
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&pk_bytes);
        let verifying_key = VerifyingKey::from_bytes(&pk_arr)
            .map_err(|e| format!("invalid device_pubkey: {e}"))?;

        let sig_bytes = hex::decode(self.signature.trim().trim_start_matches("0x"))
            .map_err(|e| format!("invalid signature hex: {e}"))?;
        if sig_bytes.len() != 64 {
            return Err(format!("signature must be 64 bytes, got {}", sig_bytes.len()).into());
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let signature = Signature::from_bytes(&sig_arr);

        verifying_key
            .verify(self.message.as_bytes(), &signature)
            .map_err(|e| format!("signature verification failed: {e}").into())
    }
}

pub fn compute_hashes_from_jpeg(
    jpeg_bytes: &[u8],
) -> Result<(String, String), Box<dyn std::error::Error + Send + Sync>> {
    if jpeg_bytes.is_empty() {
        return Err("empty JPEG bytes".into());
    }

    let mut sha256_hasher = Sha256::new();
    sha256_hasher.update(jpeg_bytes);
    let sha256_hex = hex::encode(sha256_hasher.finalize());

    let img = image::load_from_memory(jpeg_bytes)
        .map_err(|e| format!("corrupt or unsupported JPEG: {e}"))?;
    let p_hasher = image_hasher::HasherConfig::new()
        .hash_alg(image_hasher::HashAlg::Gradient)
        .to_hasher();
    let phash = p_hasher.hash_image(&img);
    let phash_hex = hex::encode(phash.as_bytes());

    Ok((sha256_hex, phash_hex))
}

#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    fn sha256_stable_for_same_bytes() {
        let bytes = tiny_jpeg();
        let (a, _) = compute_hashes_from_jpeg(&bytes).expect("hash a");
        let (b, _) = compute_hashes_from_jpeg(&bytes).expect("hash b");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn signature_verifies_on_fresh_record() {
        let keystore = test_keystore();
        let uuid = uuid::Uuid::new_v4();
        let record = HashRecord::create_from_jpeg_bytes(uuid, &tiny_jpeg(), &keystore)
            .expect("create record");
        assert_eq!(record.alg, HASH_ALG);
        assert_eq!(
            record.message,
            canonical_message(&record.uuid, &record.sha256, &record.phash)
        );
        record.verify_signature().expect("valid signature must verify");
    }

    #[test]
    fn tampered_message_fails_verify() {
        let keystore = test_keystore();
        let uuid = uuid::Uuid::new_v4();
        let mut record = HashRecord::create_from_jpeg_bytes(uuid, &tiny_jpeg(), &keystore)
            .expect("create record");
        record.message.push_str("|tampered");
        assert!(record.verify_signature().is_err());
    }

    #[test]
    fn corrupt_jpeg_returns_err() {
        let err = compute_hashes_from_jpeg(b"not-a-jpeg").expect_err("must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("corrupt") || msg.contains("unsupported") || msg.contains("JPEG"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn roundtrip_save_load() {
        let keystore = test_keystore();
        let uuid = uuid::Uuid::new_v4();
        let dir = std::env::temp_dir().join(format!("lensmint-hash-test-{uuid}"));
        std::fs::create_dir_all(&dir).unwrap();
        let record = HashRecord::create_from_jpeg_bytes(uuid, &tiny_jpeg(), &keystore).unwrap();
        record.save(&dir).unwrap();
        let loaded = HashRecord::load(&dir, &uuid).unwrap();
        assert_eq!(record, loaded);
        loaded.verify_signature().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn create_from_path_and_missing_file_err() {
        let keystore = test_keystore();
        let uuid = uuid::Uuid::new_v4();
        let dir = std::env::temp_dir().join(format!("lensmint-hash-path-{uuid}"));
        std::fs::create_dir_all(&dir).unwrap();
        let jpeg_path = dir.join(format!("{uuid}.jpg"));
        std::fs::write(&jpeg_path, tiny_jpeg()).unwrap();

        let record = HashRecord::create_from_jpeg_path(uuid, &jpeg_path, &keystore).unwrap();
        record.verify_signature().unwrap();

        let missing = dir.join("nope.jpg");
        assert!(HashRecord::create_from_jpeg_path(uuid, &missing, &keystore).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
