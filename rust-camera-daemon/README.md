# lensmint-daemon (GSoC 2026)

Rust daemon for the Raspberry Pi camera. It provides an `egui` UI, V4L2 capture, capture-time HashRecord creation, a local mint gate, and in-process EVM and Solana minting.

- [GSoC 2026 system documentation](../docs/gsoc-2026/README.md)
- [ZK CLI and host guide](../lensmint-zk/README.md)

## Quick start

From the repository root, set `PI_USER` and `PI_IP` in your local `Justfile`, then run:

```bash
just run
```

Do not publish a personal `PI_IP`. The command cross-compiles `lensmint-daemon` for `aarch64-unknown-linux-gnu`, copies the binary and configuration to the Pi, and starts the daemon through `libcamerify`.

Groth16 proving runs on a separate PC or server and is not part of `just run`; follow the ZK guide above for that flow.

Crate path: `rust-camera-daemon/lensmint-daemon`.
