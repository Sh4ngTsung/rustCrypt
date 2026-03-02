use crate::constants::*;
use crate::utils::read_exact_at;
use anyhow::{anyhow, bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use std::fs::File;
use zeroize::Zeroizing;

#[derive(Debug, Clone)]
pub struct Header {
    pub kdf: KdfParams,
    pub chunk_size: u32,
    pub salt: [u8; SALT_SIZE],
    pub base_nonce: [u8; BASE_NONCE_SIZE],
    pub plaintext_len: Option<u64>,
}

pub fn clamp_kdf(p: KdfParams) -> KdfParams {
    KdfParams {
        time: p.time.clamp(1, 10),
        memory_kib: p.memory_kib.clamp(8 * 1024, 1 << 20),
        parallel: p.parallel.clamp(1, 8),
    }
}

pub fn build_header_bytes_v2(
    chunk_size: u32,
    salt: &[u8; SALT_SIZE],
    base_nonce: &[u8; BASE_NONCE_SIZE],
    p: KdfParams,
    plaintext_len: u64,
) -> Vec<u8> {
    let mut b = Vec::with_capacity(HEADER_LEN_V2);
    b.extend_from_slice(MAGIC);
    b.push(FILE_VERSION_CURR);
    b.push(KDF_ARGON2ID);
    b.extend_from_slice(&p.time.to_le_bytes());
    b.extend_from_slice(&p.memory_kib.to_le_bytes());
    b.push(p.parallel);
    b.extend_from_slice(&chunk_size.to_le_bytes());
    b.extend_from_slice(salt);
    b.extend_from_slice(base_nonce);
    b.extend_from_slice(&plaintext_len.to_le_bytes());
    b
}

pub fn read_and_parse_header(src: &mut File) -> Result<(Vec<u8>, Header)> {
    let mut first10 = [0u8; 10];
    read_exact_at(src, 0, &mut first10).context("read header prefix")?;

    if &first10[0..8] != MAGIC {
        bail!("invalid magic");
    }
    let version = first10[8];
    let kdf_id = first10[9];
    if kdf_id != KDF_ARGON2ID {
        bail!("unsupported KDF id: {}", kdf_id);
    }

    let header_len = match version {
        1 => HEADER_LEN_V1,
        2 => HEADER_LEN_V2,
        _ => bail!("unsupported file version: {}", version),
    };

    let mut hdr = vec![0u8; header_len];
    read_exact_at(src, 0, &mut hdr).context("read full header")?;

    let time = u32::from_le_bytes(hdr[10..14].try_into()?);
    let memory_kib = u32::from_le_bytes(hdr[14..18].try_into()?);
    let parallel = hdr[18];
    let chunk_size = u32::from_le_bytes(hdr[19..23].try_into()?);
    let mut salt = [0u8; SALT_SIZE];
    salt.copy_from_slice(&hdr[23..39]);
    let mut base_nonce = [0u8; BASE_NONCE_SIZE];
    base_nonce.copy_from_slice(&hdr[39..47]);

    let plaintext_len = if version == 2 {
        let mut le = [0u8; 8];
        le.copy_from_slice(&hdr[47..55]);
        Some(u64::from_le_bytes(le))
    } else {
        None
    };

    Ok((
        hdr,
        Header {
            kdf: KdfParams {
                time,
                memory_kib,
                parallel,
            },
            chunk_size,
            salt,
            base_nonce,
            plaintext_len,
        },
    ))
}

pub fn derive_key_argon2id(
    passphrase: &[u8],
    salt: &[u8],
    p: KdfParams,
) -> Result<Zeroizing<[u8; 32]>> {
    let p = clamp_kdf(p);
    let params = Params::new(p.memory_kib, p.time, p.parallel as u32, Some(32))
        .map_err(|e| anyhow!("Argon2 params: {e}"))?;
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    a2.hash_password_into(passphrase, salt, &mut *out)
        .map_err(|e| anyhow!("Argon2 hash_password_into: {e}"))?;
    Ok(out)
}

pub fn make_chunk_nonce(
    base_nonce: &[u8; BASE_NONCE_SIZE],
    counter: u32,
) -> [u8; GCM_NONCE_SIZE] {
    let mut nonce = [0u8; GCM_NONCE_SIZE];
    nonce[..BASE_NONCE_SIZE].copy_from_slice(base_nonce);
    nonce[BASE_NONCE_SIZE..].copy_from_slice(&counter.to_le_bytes());
    nonce
}

pub fn combine_key_and_pass(key: &[u8], passphrase: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut combined = Zeroizing::new(Vec::with_capacity(key.len() + 1 + passphrase.len()));
    combined.extend_from_slice(key);
    combined.push(0u8);
    combined.extend_from_slice(passphrase);
    combined
}

