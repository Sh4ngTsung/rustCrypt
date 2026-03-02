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

#[derive(Clone, Copy, Debug)] 
pub struct KdfParams {
    pub time: u32,
    pub memory_kib: u32,
    pub parallel: u8,
}

pub const DEFAULT_KDF: KdfParams = KdfParams {
    time: 3,
    memory_kib: 64 * 1024,
    parallel: 4,
};

