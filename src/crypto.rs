use crate::constants::*;
use crate::utils::read_exact_at;
use anyhow::{Context, Result, anyhow, bail};
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
        time: p.time.clamp(KDF_TIME_MIN, KDF_TIME_MAX),
        memory_kib: p.memory_kib.clamp(KDF_MEMORY_KIB_MIN, KDF_MEMORY_KIB_MAX),
        parallel: p.parallel.clamp(KDF_PARALLEL_MIN, KDF_PARALLEL_MAX),
    }
}

pub fn validate_kdf(p: KdfParams) -> Result<()> {
    if !(KDF_TIME_MIN..=KDF_TIME_MAX).contains(&p.time) {
        bail!("KDF time parameter out of allowed range: {}", p.time);
    }
    if !(KDF_MEMORY_KIB_MIN..=KDF_MEMORY_KIB_MAX).contains(&p.memory_kib) {
        bail!(
            "KDF memory parameter out of allowed range: {} KiB",
            p.memory_kib
        );
    }
    if !(KDF_PARALLEL_MIN..=KDF_PARALLEL_MAX).contains(&p.parallel) {
        bail!(
            "KDF parallelism parameter out of allowed range: {}",
            p.parallel
        );
    }
    Ok(())
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

    let kdf = KdfParams {
        time,
        memory_kib,
        parallel,
    };
    validate_kdf(kdf).context("rejected KDF parameters from header")?;

    if !(MIN_CHUNK_SZ..=MAX_CHUNK_SZ).contains(&chunk_size) {
        bail!("unsupported chunk size in header: {}", chunk_size);
    }

    Ok((
        hdr,
        Header {
            kdf,
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

pub fn make_chunk_nonce(base_nonce: &[u8; BASE_NONCE_SIZE], counter: u32) -> [u8; GCM_NONCE_SIZE] {
    let mut nonce = [0u8; GCM_NONCE_SIZE];
    nonce[..BASE_NONCE_SIZE].copy_from_slice(base_nonce);
    nonce[BASE_NONCE_SIZE..].copy_from_slice(&counter.to_le_bytes());
    nonce
}

/// Combine a raw key file and a passphrase into a single secret that is
/// then fed to Argon2id. The encoding is `key || 0x00 || passphrase`.
///
/// Note: this format is preserved verbatim across releases so that files
/// encrypted with `--with-pass` under any previous rcrypt build continue
/// to decrypt correctly. Bumping this scheme would require a header flag
/// and an explicit version migration.
pub fn combine_key_and_pass(key: &[u8], passphrase: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut combined = Zeroizing::new(Vec::with_capacity(key.len() + 1 + passphrase.len()));
    combined.extend_from_slice(key);
    combined.push(0u8);
    combined.extend_from_slice(passphrase);
    combined
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamp_kdf_brings_extremes_into_range() {
        let too_small = KdfParams {
            time: 0,
            memory_kib: 1,
            parallel: 0,
        };
        let c = clamp_kdf(too_small);
        assert!((KDF_TIME_MIN..=KDF_TIME_MAX).contains(&c.time));
        assert!((KDF_MEMORY_KIB_MIN..=KDF_MEMORY_KIB_MAX).contains(&c.memory_kib));
        assert!((KDF_PARALLEL_MIN..=KDF_PARALLEL_MAX).contains(&c.parallel));

        let too_big = KdfParams {
            time: u32::MAX,
            memory_kib: u32::MAX,
            parallel: u8::MAX,
        };
        let c = clamp_kdf(too_big);
        assert!((KDF_TIME_MIN..=KDF_TIME_MAX).contains(&c.time));
        assert!((KDF_MEMORY_KIB_MIN..=KDF_MEMORY_KIB_MAX).contains(&c.memory_kib));
        assert!((KDF_PARALLEL_MIN..=KDF_PARALLEL_MAX).contains(&c.parallel));
    }

    #[test]
    fn validate_kdf_rejects_invalid_params() {
        let bad = KdfParams {
            time: 0,
            memory_kib: DEFAULT_KDF.memory_kib,
            parallel: DEFAULT_KDF.parallel,
        };
        assert!(validate_kdf(bad).is_err());
        assert!(validate_kdf(DEFAULT_KDF).is_ok());
    }

    #[test]
    fn make_chunk_nonce_is_deterministic_and_unique_per_counter() {
        let base = [0xAAu8; BASE_NONCE_SIZE];
        let n0 = make_chunk_nonce(&base, 0);
        let n1 = make_chunk_nonce(&base, 1);
        assert_eq!(&n0[..BASE_NONCE_SIZE], &base);
        assert_ne!(n0, n1);
        // Counter bytes are appended at the tail in little-endian.
        assert_eq!(&n1[BASE_NONCE_SIZE..], &1u32.to_le_bytes());
    }

    #[test]
    fn combine_key_and_pass_is_separator_bound() {
        let a = combine_key_and_pass(b"abc", b"def");
        let b = combine_key_and_pass(b"ab", b"cdef");
        // Both produce 7 bytes but with the NUL separator they differ.
        assert_ne!(&**a, &**b);
        assert_eq!(&**a, b"abc\0def");
        assert_eq!(&**b, b"ab\0cdef");
    }

    #[test]
    fn build_header_has_expected_layout() {
        let kdf = DEFAULT_KDF;
        let salt = [1u8; SALT_SIZE];
        let nonce = [2u8; BASE_NONCE_SIZE];
        let h = build_header_bytes_v2(DEFAULT_CHUNK_SZ, &salt, &nonce, kdf, 42);
        assert_eq!(h.len(), HEADER_LEN_V2);
        assert_eq!(&h[0..8], MAGIC);
        assert_eq!(h[8], FILE_VERSION_CURR);
        assert_eq!(h[9], KDF_ARGON2ID);
        assert_eq!(&h[23..39], &salt);
        assert_eq!(&h[39..47], &nonce);
        let pt_len = u64::from_le_bytes(h[47..55].try_into().unwrap());
        assert_eq!(pt_len, 42);
    }
}
