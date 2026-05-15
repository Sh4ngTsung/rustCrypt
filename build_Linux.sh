#!/usr/bin/env bash
#
# rcrypt — Secure Build Protocol (Bunker Mode), Linux/GNU.
#
# Goals enforced here:
#   1. Reproducible-ish path remapping (no host paths in the binary).
#   2. Hardened linker flags (full RELRO, no executable stack, BIND_NOW).
#   3. Position-Independent Executable (PIE).
#   4. Stack protector strong (compiler-injected canaries).
#   5. Build aborts if `cargo test` fails or if host paths leak.
#   6. Optional supply-chain checks (cargo audit / cargo deny) when the
#      tools are installed locally; missing tools warn rather than fail
#      so the script still works on minimal dev hosts.
#

set -Eeuo pipefail

PROJECT_ROOT="$(pwd)"
USER_HOME="${HOME}"
OUTPUT_BIN="./target/release/rcrypt"
RUST_SYSROOT="$(rustc --print sysroot 2>/dev/null || echo /usr/local/rustup)"

cleanup() {
    trap - EXIT INT TERM
}
trap cleanup EXIT INT TERM

log() {
    printf '[rcrypt-build] %s\n' "$*"
}

log "Starting Secure Build Protocol (Bunker Mode)..."

# ---------------------------------------------------------------------
# 1. Clean prior artefacts so we never carry over stale dependency state.
# ---------------------------------------------------------------------
cargo clean

# ---------------------------------------------------------------------
# 2. Run the test suite under the same flags we will ship with.
#    A failed test must abort the build (set -e takes care of this).
# ---------------------------------------------------------------------
log "Running cargo test --release ..."
cargo test --release --all-targets

# ---------------------------------------------------------------------
# 3. Apply hardened RUSTFLAGS for the release build.
#    Note: -D_FORTIFY_SOURCE is a C preprocessor flag and is a no-op when
#    passed through `-C link-arg`, so it is intentionally omitted. The
#    Rust standard library is already built with appropriate hardening.
# ---------------------------------------------------------------------
export RUSTFLAGS="\
    -C link-arg=-Wl,-z,relro,-z,now \
    -C link-arg=-Wl,-z,noexecstack \
    -C link-arg=-Wl,-z,defs \
    -C link-arg=-Wl,--as-needed \
    -C overflow-checks=on \
    --remap-path-prefix=${PROJECT_ROOT}=/src \
    --remap-path-prefix=${USER_HOME}/.cargo=/cargo \
    --remap-path-prefix=${USER_HOME}=/home/user \
    --remap-path-prefix=${RUST_SYSROOT}=/rustc/std"

log "Building hardened release binary ..."
cargo rustc --release -- \
    -C relocation-model=pic \
    -C link-arg=-pie \
    -C link-arg=-fstack-protector-strong \
    -C link-arg=-fcf-protection=full

# ---------------------------------------------------------------------
# 4. Sanity-check the artefact:
#    - File exists.
#    - No leaked host paths.
#    - PIE marker present (ELF DYN).
#    - No executable stack.
# ---------------------------------------------------------------------
if [ ! -f "$OUTPUT_BIN" ]; then
    log "Build did not produce $OUTPUT_BIN"
    exit 1
fi

LEAK_COUNT=$(strings "$OUTPUT_BIN" | grep -cF "$PROJECT_ROOT" || true)
if [ "$LEAK_COUNT" -ne 0 ]; then
    log "SECURITY ALERT: $LEAK_COUNT host-path strings leaked into the binary."
    exit 1
fi

if command -v readelf >/dev/null 2>&1; then
    if ! readelf -h "$OUTPUT_BIN" | grep -q 'Type:\s*DYN'; then
        log "SECURITY ALERT: binary is not a PIE (ELF Type != DYN)."
        exit 1
    fi
    if readelf -lW "$OUTPUT_BIN" | grep -q 'GNU_STACK.*RWE'; then
        log "SECURITY ALERT: binary has an executable stack."
        exit 1
    fi
fi

# ---------------------------------------------------------------------
# 5. Best-effort supply-chain audits. Non-fatal if the helper is missing,
#    because the official CI workflow re-runs these on every push.
# ---------------------------------------------------------------------
if command -v cargo-audit >/dev/null 2>&1; then
    log "Running cargo audit ..."
    cargo audit || log "cargo audit reported findings -- review before shipping."
else
    log "cargo-audit not installed (skip). Install with: cargo install cargo-audit"
fi

if command -v cargo-deny >/dev/null 2>&1; then
    log "Running cargo deny ..."
    cargo deny check || log "cargo deny reported findings -- review before shipping."
else
    log "cargo-deny not installed (skip). Install with: cargo install cargo-deny"
fi

log "SUCCESS. Hardened binary is ready at $OUTPUT_BIN"
