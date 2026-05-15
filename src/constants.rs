pub const MAGIC: &[u8; 8] = b"CRYPTSEC";
pub const FILE_VERSION_CURR: u8 = 2;
pub const KDF_ARGON2ID: u8 = 1;

pub const SALT_SIZE: usize = 16;
pub const BASE_NONCE_SIZE: usize = 8;
pub const GCM_NONCE_SIZE: usize = 12;
pub const DEFAULT_CHUNK_SZ: u32 = 1 << 20; // 1 MiB
pub const HEADER_LEN_V1: usize = 8 + 1 + 1 + 4 + 4 + 1 + 4 + SALT_SIZE + BASE_NONCE_SIZE;
pub const HEADER_LEN_V2: usize = HEADER_LEN_V1 + 8;
pub const GCM_TAG_LEN: usize = 16;

pub const MIN_CHUNK_SZ: u32 = 1 << 10;
pub const MAX_CHUNK_SZ: u32 = 64 << 20;

pub const KEY_FILE_SIZE: usize = 1 << 20;

// Hard upper bound on per-file chunk count: AES-GCM safety + u32 counter.
// NIST SP 800-38D restricts a single key to 2^32 distinct (key, nonce) pairs;
// since each file derives its own key via random salt + Argon2id, we stay
// well below the safe limit even at MAX_CHUNK_COUNT.
pub const MAX_CHUNK_COUNT: u64 = (1u64 << 32) - 1;

#[derive(Clone, Copy, Debug)]
pub struct KdfParams {
    pub time: u32,
    pub memory_kib: u32,
    pub parallel: u8,
}

// Strengthened defaults (OWASP 2023 / "second" Argon2id profile):
//   * 256 MiB memory cost,
//   * 4 iterations,
//   * 4 lanes of parallelism.
// The header records the exact KDF parameters used, so existing v1/v2
// files encrypted under weaker defaults will still decrypt correctly.
pub const DEFAULT_KDF: KdfParams = KdfParams {
    time: 4,
    memory_kib: 256 * 1024,
    parallel: 4,
};

// Lower / upper bounds used when validating headers from disk.
// Argon2 RFC 9106 requires memory >= 8 KiB and at least 1 iteration;
// we additionally cap memory at 2 GiB to bound peak RAM during decrypt.
pub const KDF_TIME_MIN: u32 = 1;
pub const KDF_TIME_MAX: u32 = 20;
pub const KDF_MEMORY_KIB_MIN: u32 = 8 * 1024; // 8 MiB
pub const KDF_MEMORY_KIB_MAX: u32 = 2 * 1024 * 1024; // 2 GiB
pub const KDF_PARALLEL_MIN: u8 = 1;
pub const KDF_PARALLEL_MAX: u8 = 16;
