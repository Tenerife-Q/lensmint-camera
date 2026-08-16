# LensMint ZK (Phase-2)

RISC Zero guest: device Ed25519 verify + pHash Hamming distance at most 5.
Host proves that guest, writes a receipt, and records prove time / receipt size.

## Crates

- `lensmint-zk-core`: statement logic and unit tests
- `methods` / `authenticity` guest: zkVM entry
- `host`: prove CLI + library (receipt on disk)

## Statement

1. Ed25519 verify of the HashRecord `message` with the device pubkey
2. `Hamming(pHash0, pHash1) <= 5`

Message format matches HashRecord: `{uuid}|{sha256_hex}|{phash_hex}`  
`alg = sha256+gradient-phash-v1`

## Public journal

`device_pubkey_hex`, `phash0_hex`, `phash1_hex`, `distance`, `threshold` (5), `sha256_hex`, `alg`

## Test

```bash
# Statement only (fast)
cargo test -p lensmint-zk-core -- --nocapture

# Host preflight + dev-mode prove (set inside the prove test)
cargo test -p host -- --nocapture
```

## Prove / bench (PC)

```bash
# Cheap check: sha256 change + pHash distance (no prove)
cargo run -p host --release -- probe

# Real prove numbers for feedback (can take a few minutes)
CARGO_BUILD_JOBS=1 cargo run -p host --release -- bench --out out

# Fast fake receipt for wiring checks only
RISC0_DEV_MODE=1 cargo run -p host -- bench --out out-dev
```

Successful runs write `{uuid}.receipt.bin` and `{uuid}.journal.json` under `--out`.

If real prove prints `rx len failed`, `r0vm` usually exited early (often WSL OOM). Prefer closing other apps, giving WSL more RAM (`.wslconfig`), and matching `r0vm` to the `risc0-zkvm` crate version (`rzup show`).
