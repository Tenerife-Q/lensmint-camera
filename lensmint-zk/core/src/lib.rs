// Guest statement: Ed25519 over HashRecord message + Hamming(pHash0, pHash1) <= 5.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

pub const HAMMING_THRESHOLD: u32 = 5;
pub const HASH_ALG: &str = "sha256+gradient-phash-v1";

pub fn canonical_message(uuid: &str, sha256_hex: &str, phash_hex: &str) -> String {
    format!("{uuid}|{sha256_hex}|{phash_hex}")
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuestInput {
    pub message: String,
    pub signature_hex: String,
    pub device_pubkey_hex: String,
    pub phash1_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuestJournal {
    pub device_pubkey_hex: String,
    pub phash0_hex: String,
    pub phash1_hex: String,
    pub distance: u32,
    pub threshold: u32,
    pub sha256_hex: String,
    pub alg: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GuestError {
    #[error("message must be uuid|sha256|phash")]
    BadMessageFormat,
    #[error("invalid hex: {0}")]
    BadHex(&'static str),
    #[error("expected {expected} bytes for {field}, got {got}")]
    BadLen {
        field: &'static str,
        expected: usize,
        got: usize,
    },
    #[error("invalid device pubkey")]
    BadPubkey,
    #[error("ed25519 signature verification failed")]
    BadSignature,
    #[error("hamming distance {distance} exceeds threshold {threshold}")]
    DistanceTooLarge { distance: u32, threshold: u32 },
}

fn decode_fixed<const N: usize>(
    hex_str: &str,
    field: &'static str,
) -> Result<[u8; N], GuestError> {
    let bytes = hex::decode(hex_str.trim().trim_start_matches("0x"))
        .map_err(|_| GuestError::BadHex(field))?;
    if bytes.len() != N {
        return Err(GuestError::BadLen {
            field,
            expected: N,
            got: bytes.len(),
        });
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn hamming_distance(a: &[u8], b: &[u8]) -> Result<u32, GuestError> {
    if a.len() != b.len() {
        return Err(GuestError::BadLen {
            field: "phash",
            expected: a.len(),
            got: b.len(),
        });
    }
    Ok(a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x ^ y).count_ones())
        .sum())
}

pub fn parse_message(message: &str) -> Result<(&str, &str, &str), GuestError> {
    let mut parts = message.split('|');
    let uuid = parts.next().filter(|s| !s.is_empty());
    let sha = parts.next().filter(|s| !s.is_empty());
    let phash = parts.next().filter(|s| !s.is_empty());
    if parts.next().is_some() {
        return Err(GuestError::BadMessageFormat);
    }
    match (uuid, sha, phash) {
        (Some(u), Some(s), Some(p)) => Ok((u, s, p)),
        _ => Err(GuestError::BadMessageFormat),
    }
}

pub fn verify_authenticity(input: &GuestInput) -> Result<GuestJournal, GuestError> {
    let (_uuid, sha256_hex, phash0_hex) = parse_message(&input.message)?;
    let phash0 = decode_fixed::<8>(phash0_hex, "phash0")?;
    let phash1 = decode_fixed::<8>(&input.phash1_hex, "phash1")?;
    let pk = decode_fixed::<32>(&input.device_pubkey_hex, "device_pubkey")?;
    let sig = decode_fixed::<64>(&input.signature_hex, "signature")?;

    let verifying_key = VerifyingKey::from_bytes(&pk).map_err(|_| GuestError::BadPubkey)?;
    let signature = Signature::from_bytes(&sig);
    verifying_key
        .verify(input.message.as_bytes(), &signature)
        .map_err(|_| GuestError::BadSignature)?;

    let distance = hamming_distance(&phash0, &phash1)?;
    if distance > HAMMING_THRESHOLD {
        return Err(GuestError::DistanceTooLarge {
            distance,
            threshold: HAMMING_THRESHOLD,
        });
    }

    Ok(GuestJournal {
        device_pubkey_hex: hex::encode(pk),
        phash0_hex: hex::encode(phash0),
        phash1_hex: hex::encode(phash1),
        distance,
        threshold: HAMMING_THRESHOLD,
        sha256_hex: sha256_hex.to_string(),
        alg: HASH_ALG.to_string(),
    })
}

// On-chain journal: Solidity abi.encode of seven static words (224 bytes).
// Order: sha256, phash0, phash1, devicePubkey, distance, threshold, alg.
// phash* and alg are left-aligned in bytes32; uint32 values are right-aligned.

pub const JOURNAL_ABI_LEN: usize = 32 * 7;

fn word_from_bytes(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let n = data.len().min(32);
    out[..n].copy_from_slice(&data[..n]);
    out
}

fn word_from_u32(v: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[28..32].copy_from_slice(&v.to_be_bytes());
    out
}

fn u32_from_word(word: &[u8; 32]) -> u32 {
    u32::from_be_bytes([word[28], word[29], word[30], word[31]])
}

pub fn alg_word() -> [u8; 32] {
    word_from_bytes(HASH_ALG.as_bytes())
}

impl GuestJournal {
    pub fn abi_encode(&self) -> Result<Vec<u8>, GuestError> {
        let sha = decode_fixed::<32>(&self.sha256_hex, "sha256")?;
        let phash0 = decode_fixed::<8>(&self.phash0_hex, "phash0")?;
        let phash1 = decode_fixed::<8>(&self.phash1_hex, "phash1")?;
        let pk = decode_fixed::<32>(&self.device_pubkey_hex, "device_pubkey")?;
        if self.alg != HASH_ALG {
            return Err(GuestError::BadHex("alg"));
        }
        let mut out = Vec::with_capacity(JOURNAL_ABI_LEN);
        out.extend_from_slice(&word_from_bytes(&sha));
        out.extend_from_slice(&word_from_bytes(&phash0));
        out.extend_from_slice(&word_from_bytes(&phash1));
        out.extend_from_slice(&word_from_bytes(&pk));
        out.extend_from_slice(&word_from_u32(self.distance));
        out.extend_from_slice(&word_from_u32(self.threshold));
        out.extend_from_slice(&alg_word());
        Ok(out)
    }

    pub fn from_abi(bytes: &[u8]) -> Result<Self, GuestError> {
        if bytes.len() != JOURNAL_ABI_LEN {
            return Err(GuestError::BadLen {
                field: "journal_abi",
                expected: JOURNAL_ABI_LEN,
                got: bytes.len(),
            });
        }
        let mut words = [[0u8; 32]; 7];
        for (i, word) in words.iter_mut().enumerate() {
            word.copy_from_slice(&bytes[i * 32..(i + 1) * 32]);
        }
        let mut phash0 = [0u8; 8];
        let mut phash1 = [0u8; 8];
        phash0.copy_from_slice(&words[1][..8]);
        phash1.copy_from_slice(&words[2][..8]);
        if words[1][8..] != [0u8; 24] || words[2][8..] != [0u8; 24] {
            return Err(GuestError::BadHex("phash_padding"));
        }
        let alg = {
            let end = words[6]
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(words[6].len());
            std::str::from_utf8(&words[6][..end]).map_err(|_| GuestError::BadHex("alg"))?
        };
        if alg != HASH_ALG {
            return Err(GuestError::BadHex("alg"));
        }
        Ok(Self {
            sha256_hex: hex::encode(words[0]),
            phash0_hex: hex::encode(phash0),
            phash1_hex: hex::encode(phash1),
            device_pubkey_hex: hex::encode(words[3]),
            distance: u32_from_word(&words[4]),
            threshold: u32_from_word(&words[5]),
            alg: alg.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn keypair() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn sign_msg(sk: &SigningKey, message: &str) -> GuestInput {
        let sig = sk.sign(message.as_bytes());
        let (_, _, phash_hex) = parse_message(message).unwrap();
        GuestInput {
            message: message.to_string(),
            signature_hex: hex::encode(sig.to_bytes()),
            device_pubkey_hex: hex::encode(sk.verifying_key().to_bytes()),
            phash1_hex: phash_hex.to_string(),
        }
    }

    #[test]
    fn hamming_identical_is_zero() {
        let a = [0u8; 8];
        assert_eq!(hamming_distance(&a, &a).unwrap(), 0);
    }

    #[test]
    fn hamming_one_bit() {
        let a = [0u8; 8];
        let mut b = a;
        b[0] = 0b0000_0001;
        assert_eq!(hamming_distance(&a, &b).unwrap(), 1);
    }

    #[test]
    fn valid_sig_and_close_phash_passes() {
        let sk = keypair();
        let sha = "e8e12e6a5f63658efb1766cdec4bd3f56400baf7200f2936710a8027a043676c";
        let phash0 = "0d1a34489032468c";
        let msg = canonical_message(
            "751da06f-5c24-41a5-ac57-4733f202940b",
            sha,
            phash0,
        );
        let input = sign_msg(&sk, &msg);
        let journal = verify_authenticity(&input).expect("should pass");
        assert_eq!(journal.distance, 0);
        assert_eq!(journal.threshold, HAMMING_THRESHOLD);
        assert_eq!(journal.alg, HASH_ALG);
        assert_eq!(journal.sha256_hex, sha);
        assert_eq!(journal.phash0_hex, phash0);
        assert_eq!(journal.phash1_hex, phash0);
        assert_eq!(
            journal.device_pubkey_hex,
            hex::encode(sk.verifying_key().to_bytes())
        );
    }

    #[test]
    fn distance_within_threshold_passes() {
        let sk = keypair();
        let msg = canonical_message("u", &"ab".repeat(32), "0000000000000000");
        let mut input = sign_msg(&sk, &msg);
        input.phash1_hex = hex::encode([0b0001_1111u8, 0, 0, 0, 0, 0, 0, 0]);
        let journal = verify_authenticity(&input).expect("distance 5 should pass");
        assert_eq!(journal.distance, 5);
    }

    #[test]
    fn distance_over_threshold_fails() {
        let sk = keypair();
        let msg = canonical_message("u", &"cd".repeat(32), "0000000000000000");
        let mut input = sign_msg(&sk, &msg);
        input.phash1_hex = hex::encode([0b0011_1111u8, 0, 0, 0, 0, 0, 0, 0]);
        let err = verify_authenticity(&input).expect_err("distance 6 must fail");
        assert!(matches!(
            err,
            GuestError::DistanceTooLarge {
                distance: 6,
                threshold: 5
            }
        ));
    }

    #[test]
    fn tampered_message_fails() {
        let sk = keypair();
        let msg = canonical_message("u", &"ef".repeat(32), "0d1a34489032468c");
        let mut input = sign_msg(&sk, &msg);
        input.message.push('x');
        assert!(verify_authenticity(&input).is_err());
    }

    #[test]
    fn wrong_signature_fails() {
        let sk = keypair();
        let other = keypair();
        let msg = canonical_message("u", &"11".repeat(32), "0d1a34489032468c");
        let mut input = sign_msg(&sk, &msg);
        input.signature_hex = hex::encode(other.sign(msg.as_bytes()).to_bytes());
        assert_eq!(
            verify_authenticity(&input).unwrap_err(),
            GuestError::BadSignature
        );
    }

    #[test]
    fn bad_message_format_fails() {
        let sk = keypair();
        let mut input = sign_msg(
            &sk,
            &canonical_message("u", &"22".repeat(32), "0d1a34489032468c"),
        );
        input.message = "not-a-valid-message".into();
        input.signature_hex = hex::encode(sk.sign(input.message.as_bytes()).to_bytes());
        assert_eq!(
            verify_authenticity(&input).unwrap_err(),
            GuestError::BadMessageFormat
        );
    }

    #[test]
    fn journal_abi_roundtrip() {
        let sk = keypair();
        let sha = "e8e12e6a5f63658efb1766cdec4bd3f56400baf7200f2936710a8027a043676c";
        let phash0 = "0d1a34489032468c";
        let msg = canonical_message("751da06f-5c24-41a5-ac57-4733f202940b", sha, phash0);
        let journal = verify_authenticity(&sign_msg(&sk, &msg)).unwrap();
        let encoded = journal.abi_encode().unwrap();
        assert_eq!(encoded.len(), JOURNAL_ABI_LEN);
        let decoded = GuestJournal::from_abi(&encoded).unwrap();
        assert_eq!(decoded, journal);
    }
}
