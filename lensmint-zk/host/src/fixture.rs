use crate::hash_record::HashRecord;
use crate::phash::{gradient_phash_hex, sha256_hex};
use ed25519_dalek::{Signer, SigningKey};
use image::{ImageBuffer, Rgba};
use lensmint_zk_core::{canonical_message, HASH_ALG};
use rand::rngs::OsRng;
use std::io::Cursor;

/// Build a signed HashRecord + JPEG for host demos/tests.
/// Image has smooth gradients plus mild texture so mild JPEG recompress
/// usually changes bytes (sha256) and can move Gradient pHash a little.
pub fn make_signed_fixture() -> anyhow::Result<(HashRecord, Vec<u8>)> {
    let img: ImageBuffer<Rgba<u8>, Vec<u8>> = ImageBuffer::from_fn(320, 240, |x, y| {
        let g = ((x * 3 + y * 5) % 256) as u8;
        let tex = (((x / 8) ^ (y / 8)) as u8).wrapping_mul(7);
        Rgba([
            g.wrapping_add(tex),
            g.wrapping_add(40).wrapping_add(tex / 2),
            g.wrapping_add(80),
            255,
        ])
    });
    let mut jpeg = Cursor::new(Vec::new());
    img.write_to(&mut jpeg, image::ImageFormat::Jpeg)?;
    let jpeg_bytes = jpeg.into_inner();

    let sha256 = sha256_hex(&jpeg_bytes);
    let phash = gradient_phash_hex(&jpeg_bytes)?;
    let uuid = "00000000-0000-4000-8000-000000000020".to_string();
    let message = canonical_message(&uuid, &sha256, &phash);

    let sk = SigningKey::generate(&mut OsRng);
    let signature = hex::encode(sk.sign(message.as_bytes()).to_bytes());
    let device_pubkey = hex::encode(sk.verifying_key().to_bytes());

    let record = HashRecord {
        uuid,
        sha256,
        phash,
        alg: HASH_ALG.to_string(),
        message,
        signature,
        device_pubkey,
        created_at: 0,
    };
    Ok((record, jpeg_bytes))
}
