# LensMint ZK (Phase-2)

RISC Zero guest: device Ed25519 verify + pHash Hamming distance at most 5.

## Crates

- `lensmint-zk-core`: statement logic and unit tests
- `methods` / `authenticity` guest: zkVM entry
- `host`: stub for now (prove and receipt come later)

## Statement

1. Ed25519 verify of the HashRecord `message` with the device pubkey
2. `Hamming(pHash0, pHash1) <= 5`

Message format matches HashRecord: `{uuid}|{sha256_hex}|{phash_hex}`  
`alg = sha256+gradient-phash-v1`

## Public journal

`device_pubkey_hex`, `phash0_hex`, `phash1_hex`, `distance`, `threshold` (5), `sha256_hex`, `alg`

## Test

```bash
cargo test -p lensmint-zk-core -- --nocapture
```
