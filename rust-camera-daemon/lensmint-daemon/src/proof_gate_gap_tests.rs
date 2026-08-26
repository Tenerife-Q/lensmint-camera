use super::*;
use crate::keystore::LocalKeystore;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::path::{Path, PathBuf};

struct CaptureFixture {
    dir: PathBuf,
    uuid: uuid::Uuid,
    record: HashRecord,
}

impl CaptureFixture {
    fn new() -> Self {
        let dir =
            std::env::temp_dir().join(format!("lensmint-proof-gate-gaps-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("create fixture directory");

        let keystore = LocalKeystore {
            signing_key: SigningKey::generate(&mut OsRng),
        };
        let uuid = uuid::Uuid::new_v4();
        let jpeg = tiny_jpeg();
        let record =
            HashRecord::create_from_jpeg_bytes(uuid, &jpeg, &keystore).expect("create record");
        record.save(&dir).expect("save record");
        std::fs::write(receipt_path(&dir, &uuid), b"non-empty-receipt").expect("write receipt");

        Self { dir, uuid, record }
    }

    fn write_journal(&self, journal: &JournalFile) {
        std::fs::write(
            journal_path(&self.dir, &self.uuid),
            serde_json::to_vec_pretty(journal).expect("serialize journal"),
        )
        .expect("write journal");
    }

    fn matching_journal(&self) -> JournalFile {
        JournalFile {
            device_pubkey_hex: self.record.device_pubkey.clone(),
            phash0_hex: self.record.phash.clone(),
            phash1_hex: self.record.phash.clone(),
            distance: 0,
            threshold: 5,
            sha256_hex: self.record.sha256.clone(),
            alg: self.record.alg.clone(),
        }
    }
}

impl Drop for CaptureFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn tiny_jpeg() -> Vec<u8> {
    let img = image::RgbaImage::from_pixel(8, 8, image::Rgba([10, 20, 30, 255]));
    let mut cursor = std::io::Cursor::new(Vec::new());
    img.write_to(&mut cursor, image::ImageFormat::Jpeg)
        .expect("encode jpeg");
    cursor.into_inner()
}

fn write_raw_journal(dir: &Path, uuid: &uuid::Uuid, bytes: &[u8]) {
    std::fs::write(journal_path(dir, uuid), bytes).expect("write raw journal");
}

#[test]
fn missing_journal_blocks_mint() {
    let fixture = CaptureFixture::new();

    let err = require_proof_for_mint(&fixture.dir, &fixture.uuid)
        .expect_err("missing journal must block");

    assert!(err.contains("missing journal"), "{err}");
}

#[test]
fn mismatched_phash_blocks_mint() {
    let fixture = CaptureFixture::new();
    let mut journal = fixture.matching_journal();
    journal.phash0_hex = "ff".repeat(8);
    if journal.phash0_hex == fixture.record.phash {
        journal.phash0_hex = "00".repeat(8);
    }
    fixture.write_journal(&journal);

    let err = require_proof_for_mint(&fixture.dir, &fixture.uuid)
        .expect_err("mismatched phash must block");

    assert!(err.contains("phash"), "{err}");
}

#[test]
fn mismatched_device_pubkey_blocks_mint() {
    let fixture = CaptureFixture::new();
    let mut journal = fixture.matching_journal();
    journal.device_pubkey_hex = "00".repeat(32);
    fixture.write_journal(&journal);

    let err = require_proof_for_mint(&fixture.dir, &fixture.uuid)
        .expect_err("mismatched pubkey must block");

    assert!(err.contains("pubkey"), "{err}");
}

#[test]
fn invalid_journal_json_blocks_mint() {
    let fixture = CaptureFixture::new();
    write_raw_journal(&fixture.dir, &fixture.uuid, b"{not-json");

    let err = require_proof_for_mint(&fixture.dir, &fixture.uuid)
        .expect_err("invalid journal must block");

    assert!(err.contains("invalid journal"), "{err}");
}

#[test]
fn invalid_hash_record_signature_blocks_mint() {
    let fixture = CaptureFixture::new();
    let mut record = fixture.record.clone();
    record.signature = "00".repeat(64);
    record.save(&fixture.dir).expect("overwrite record");
    fixture.write_journal(&fixture.matching_journal());

    let err = require_proof_for_mint(&fixture.dir, &fixture.uuid)
        .expect_err("invalid record signature must block");

    assert!(err.contains("signature invalid"), "{err}");
}

#[test]
fn local_gate_does_not_recheck_distance_or_alg() {
    let fixture = CaptureFixture::new();
    let mut journal = fixture.matching_journal();
    journal.distance = 99;
    journal.threshold = 0;
    journal.alg = "not-the-real-alg".to_string();
    fixture.write_journal(&journal);

    require_proof_for_mint(&fixture.dir, &fixture.uuid)
        .expect("gate matches sha256, phash0, and pubkey only");
}
