#!/usr/bin/env bash

set -euo pipefail

PROJECT_ROOT="$(pwd)"
USER_HOME="${HOME}"
OUTPUT_BIN="./target/release/rcrypt"
RUST_SYSROOT=$(rustc --print sysroot 2>/dev/null || echo "/usr/local/rustup")

echo "Starting Secure Build Protocol (Bunker Mode)..."

cargo clean

if ! cargo test; then
    echo "Tests failed. Aborting build."
    exit 1
fi

export RUSTFLAGS="\
    -C link-arg=-Wl,-z,relro,-z,now \
    -C link-arg=-Wl,-z,noexecstack \
    -C link-arg=-Wl,-z,defs \
    -C link-arg=-fstack-protector-strong \
    -C link-arg=-D_FORTIFY_SOURCE=2 \
    --remap-path-prefix=${PROJECT_ROOT}=/src \
    --remap-path-prefix=${USER_HOME}/.cargo=/cargo \
    --remap-path-prefix=${USER_HOME}=/home/user \
    --remap-path-prefix=${RUST_SYSROOT}=/rustc/std"

cargo rustc --release -- -C link-arg=-pie -C link-arg=-fstack-protector-strong

if [ -f "$OUTPUT_BIN" ]; then
    LEAK_COUNT=$(strings "$OUTPUT_BIN" | grep -c "$PROJECT_ROOT" || true)
    if [ "$LEAK_COUNT" -ne 0 ]; then
        echo "SECURITY ALERT: Metadata leak detected!"
        exit 1
    fi
fi

echo "SUCCESS. Hardened binary is ready at $OUTPUT_BIN"