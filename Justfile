TARGET := "aarch64-unknown-linux-gnu"
PI_USER := "tenerife"
PI_IP := "192.168.238.101"
APP_DIR := "rust-camera-daemon/lensmint-daemon"

# 强制 Cargo 使用 AArch64 链接器
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER := "aarch64-linux-gnu-gcc"
export CC_aarch64_unknown_linux_gnu := "aarch64-linux-gnu-gcc"
export CXX_aarch64_unknown_linux_gnu := "aarch64-linux-gnu-g++"
# openssl-sys (via solana-sdk) uses these when building the vendored OpenSSL for aarch64
export AR_aarch64_unknown_linux_gnu := "aarch64-linux-gnu-ar"

build:
	# First aarch64 build may take several minutes (compiles vendored OpenSSL).
	cd {{APP_DIR}} && cargo build --target {{TARGET}} --release

deploy: build
	ssh {{PI_USER}}@{{PI_IP}} "killall -9 lensmint-daemon || true"
	scp {{APP_DIR}}/target/{{TARGET}}/release/lensmint-daemon {{PI_USER}}@{{PI_IP}}:/tmp/lensmint-daemon
	# Centralised config next to the binary (contracts + Solana RPCs)
	ssh {{PI_USER}}@{{PI_IP}} "mkdir -p /tmp/config"
	scp {{APP_DIR}}/config/contracts.json {{APP_DIR}}/config/solana_rpcs.json {{PI_USER}}@{{PI_IP}}:/tmp/config/

# Single Rust daemon on the Pi — no separate TS relayer / RELAYER_URL.
run: deploy
	ssh {{PI_USER}}@{{PI_IP}} "export XDG_RUNTIME_DIR=/run/user/1000 && export DISPLAY=:0 && export WAYLAND_DISPLAY=\$(ls /run/user/1000 | grep -m1 '^wayland-[0-9]') && libcamerify /tmp/lensmint-daemon"

dev: run
