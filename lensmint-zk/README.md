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

Human-readable sidecar (mint gate): `device_pubkey_hex`, `phash0_hex`, `phash1_hex`, `distance`, `threshold` (5), `sha256_hex`, `alg`

On-chain bytes (guest `commit_slice`): Solidity `abi.encode` of

`bytes32 sha256`, `bytes32 phash0`, `bytes32 phash1`, `bytes32 devicePubkey`, `uint32 distance`, `uint32 threshold`, `bytes32 alg`

`phash*` and `alg` are left-aligned in `bytes32`. Host also writes `{uuid}.journal.abi` next to `{uuid}.journal.json`.

## Test

```bash
# Statement + ABI roundtrip (fast)
cargo test -p lensmint-zk-core -- --nocapture

# Host preflight + dev-mode prove
cargo test -p host -- --nocapture
```

## Prove / bench (PC)

```bash
# Cheap check: sha256 change + pHash distance (no prove)
cargo run -p host --release -- probe

# Real Groth16 prove for chain (can take a few minutes)
CARGO_BUILD_JOBS=1 cargo run -p host --release -- bench --out out

# Fast fake receipt for wiring checks only
RISC0_DEV_MODE=1 cargo run -p host -- bench --out out-dev

# IMAGE_ID for AuthenticityVerifier deploy
cargo run -p host --release -- image-id

# Extract seal + journal.abi from a Groth16 receipt
cargo run -p host --release -- export-onchain --receipt out/<uuid>.receipt.bin --out out/onchain
```

Successful runs write `{uuid}.receipt.bin`, `{uuid}.journal.json`, and `{uuid}.journal.abi` under `--out`.

If real prove prints `rx len failed`, `r0vm` usually exited early (often WSL OOM). Prefer closing other apps, giving WSL more RAM (`.wslconfig`), and matching `r0vm` to the `risc0-zkvm` crate version (`rzup show`).
