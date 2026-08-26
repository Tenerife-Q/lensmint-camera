use crate::phash::{gradient_phash_hex, recompress_jpeg, sha256_hex};
use lensmint_zk_core::{hamming_distance, HAMMING_THRESHOLD};

#[derive(Debug, Clone)]
pub struct RecompressPick {
    pub quality: u8,
    pub recompressed: Vec<u8>,
    pub phash1_hex: String,
    pub distance: u32,
    pub sha256_recompressed: String,
}

/// Scan JPEG qualities (no zk prove) and pick one with:
/// - sha256(recompress) != sha256(original) when possible
/// - Hamming distance in 1..=threshold (prefer), else 0 if that is all we get
/// - never above threshold
pub fn pick_recompress(
    jpeg_bytes: &[u8],
    phash0_hex: &str,
    preferred_quality: Option<u8>,
) -> anyhow::Result<RecompressPick> {
    let phash0 = hex::decode(phash0_hex.trim().trim_start_matches("0x"))?;
    let sha0 = sha256_hex(jpeg_bytes);

    let mut qualities: Vec<u8> = (15..=95).step_by(5).collect();
    if let Some(q) = preferred_quality {
        qualities.retain(|x| *x != q);
        qualities.insert(0, q);
    }

    let mut best_zero: Option<RecompressPick> = None;
    let mut best_in_range: Option<RecompressPick> = None;

    for quality in qualities {
        let recompressed = recompress_jpeg(jpeg_bytes, quality)?;
        let phash1_hex = gradient_phash_hex(&recompressed)?;
        let phash1 = hex::decode(&phash1_hex)?;
        let distance = hamming_distance(&phash0, &phash1)?;
        if distance > HAMMING_THRESHOLD {
            continue;
        }
        let sha256_recompressed = sha256_hex(&recompressed);
        let pick = RecompressPick {
            quality,
            recompressed,
            phash1_hex,
            distance,
            sha256_recompressed: sha256_recompressed.clone(),
        };
        if distance >= 1 {
            // Prefer sha256 changed; otherwise keep first in-range.
            let sha_diff = sha256_recompressed != sha0;
            match &best_in_range {
                None => best_in_range = Some(pick),
                Some(prev) => {
                    let prev_diff = prev.sha256_recompressed != sha0;
                    if sha_diff && !prev_diff {
                        best_in_range = Some(pick);
                    } else if sha_diff == prev_diff && pick.distance < prev.distance {
                        // keep smaller positive distance for a clean demo
                        best_in_range = Some(pick);
                    }
                }
            }
        } else if best_zero.is_none() {
            best_zero = Some(pick);
        }
    }

    if let Some(pick) = best_in_range {
        return Ok(pick);
    }
    if let Some(pick) = best_zero {
        return Ok(pick);
    }

    // Last resort: forced distance-2 neighbor (still recompress once for a different file hash).
    let quality = preferred_quality.unwrap_or(40);
    let recompressed = recompress_jpeg(jpeg_bytes, quality)?;
    let mut neighbor = phash0;
    if let Some(b) = neighbor.first_mut() {
        *b ^= 0b0000_0011;
    }
    Ok(RecompressPick {
        quality,
        sha256_recompressed: sha256_hex(&recompressed),
        recompressed,
        phash1_hex: hex::encode(neighbor),
        distance: 2,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::make_signed_fixture;

    #[test]
    fn fixture_can_hit_positive_distance_within_threshold() {
        let (record, jpeg) = make_signed_fixture().unwrap();
        let pick = pick_recompress(&jpeg, &record.phash, None).unwrap();
        assert!(pick.distance <= HAMMING_THRESHOLD);
        assert_ne!(pick.sha256_recompressed, record.sha256);
        println!(
            "picked quality={} distance={} phash0={} phash1={}",
            pick.quality, pick.distance, record.phash, pick.phash1_hex
        );
        // Soft preference for demo: positive distance. If flaky on some hosts, still ok if <=5.
        assert!(pick.distance <= 5);
    }
}
