use lensmint_zk_core::{GuestError, GuestJournal, HASH_ALG, JOURNAL_ABI_LEN};

const SHA256_HEX: &str = "e8e12e6a5f63658efb1766cdec4bd3f56400baf7200f2936710a8027a043676c";
const PHASH0_HEX: &str = "0d1a34489032468c";
const PHASH1_HEX: &str = "0d1a34489032468d";
const PUBKEY_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";

fn fixture_journal() -> GuestJournal {
    GuestJournal {
        device_pubkey_hex: PUBKEY_HEX.to_string(),
        phash0_hex: PHASH0_HEX.to_string(),
        phash1_hex: PHASH1_HEX.to_string(),
        distance: 1,
        threshold: 5,
        sha256_hex: SHA256_HEX.to_string(),
        alg: HASH_ALG.to_string(),
    }
}

#[test]
fn journal_matches_solidity_static_abi_layout() {
    let encoded = fixture_journal().abi_encode().expect("encode journal");

    assert_eq!(encoded.len(), JOURNAL_ABI_LEN);
    assert_eq!(&encoded[0..32], hex::decode(SHA256_HEX).unwrap());
    assert_eq!(&encoded[32..40], hex::decode(PHASH0_HEX).unwrap());
    assert_eq!(&encoded[40..64], &[0; 24]);
    assert_eq!(&encoded[64..72], hex::decode(PHASH1_HEX).unwrap());
    assert_eq!(&encoded[72..96], &[0; 24]);
    assert_eq!(&encoded[96..128], hex::decode(PUBKEY_HEX).unwrap());
    assert_eq!(&encoded[128..156], &[0; 28]);
    assert_eq!(&encoded[156..160], &1u32.to_be_bytes());
    assert_eq!(&encoded[160..188], &[0; 28]);
    assert_eq!(&encoded[188..192], &5u32.to_be_bytes());
    assert_eq!(&encoded[192..192 + HASH_ALG.len()], HASH_ALG.as_bytes());
    assert!(encoded[192 + HASH_ALG.len()..224]
        .iter()
        .all(|byte| *byte == 0));

    assert_eq!(
        GuestJournal::from_abi(&encoded).expect("decode journal"),
        fixture_journal()
    );
}

#[test]
fn decode_rejects_non_224_byte_journals() {
    for len in [JOURNAL_ABI_LEN - 1, JOURNAL_ABI_LEN + 1] {
        let err = GuestJournal::from_abi(&vec![0; len]).expect_err("bad length must fail");
        assert!(matches!(
            err,
            GuestError::BadLen {
                field: "journal_abi",
                expected: JOURNAL_ABI_LEN,
                got
            } if got == len
        ));
    }
}

#[test]
fn decode_rejects_nonzero_phash_padding() {
    let mut encoded = fixture_journal().abi_encode().expect("encode journal");
    encoded[40] = 1;

    let err = GuestJournal::from_abi(&encoded).expect_err("dirty padding must fail");

    assert_eq!(err, GuestError::BadHex("phash_padding"));
}

#[test]
fn decode_rejects_wrong_algorithm_word() {
    let mut encoded = fixture_journal().abi_encode().expect("encode journal");
    encoded[192] ^= 1;

    let err = GuestJournal::from_abi(&encoded).expect_err("wrong alg must fail");

    assert_eq!(err, GuestError::BadHex("alg"));
}

#[test]
fn encode_rejects_unknown_algorithm() {
    let mut journal = fixture_journal();
    journal.alg = "sha256+unknown-phash".to_string();

    let err = journal.abi_encode().expect_err("wrong alg must fail");

    assert_eq!(err, GuestError::BadHex("alg"));
}
