use sha2::{Digest, Sha256};
use std::io::Cursor;

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

pub fn gradient_phash_hex(jpeg_bytes: &[u8]) -> anyhow::Result<String> {
    let img = image::load_from_memory(jpeg_bytes)
        .map_err(|e| anyhow::anyhow!("bad jpeg: {e}"))?;
    let hasher = image_hasher::HasherConfig::new()
        .hash_alg(image_hasher::HashAlg::Gradient)
        .to_hasher();
    Ok(hex::encode(hasher.hash_image(&img).as_bytes()))
}

/// Re-encode JPEG at `quality` (1..=100) to demo compression-tolerant pHash.
pub fn recompress_jpeg(jpeg_bytes: &[u8], quality: u8) -> anyhow::Result<Vec<u8>> {
    let img = image::load_from_memory(jpeg_bytes)
        .map_err(|e| anyhow::anyhow!("bad jpeg: {e}"))?;
    let rgb = img.to_rgb8();
    let mut out = Cursor::new(Vec::new());
    let mut enc = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, quality);
    enc.encode(rgb.as_raw(), rgb.width(), rgb.height(), image::ColorType::Rgb8)
        .map_err(|e| anyhow::anyhow!("jpeg encode: {e}"))?;
    Ok(out.into_inner())
}
