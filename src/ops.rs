use crate::constants::*;
use crate::crypto::*;
use crate::utils::*;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, bail, Context, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs::{self, OpenOptions};
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[cfg(unix)]
fn restrict_key_permissions(path: &Path) -> Result<()> {
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_key_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

pub fn generate_key_file(path: &Path, verbose: bool) -> Result<()> {
    if path.exists() {
        bail!("key file already exists: {}", path.display());
    }

    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("create key file: {}", path.display()))?;

    let mut buf = vec![0u8; KEY_FILE_SIZE];
    let mut rng = OsRng;
    rng.fill_bytes(&mut buf);

    {
        let mut w = BufWriter::new(&mut f);
        w.write_all(&buf)?;
        w.flush()?;
    }

    f.sync_all()?;
    drop(f);

    buf.zeroize();
    restrict_key_permissions(path)?;
    sync_parent_dir(path)?;

    if verbose {
        eprintln!(
            "Generated {}-byte key file at {}",
            KEY_FILE_SIZE,
            path.display()
        );
    }

    Ok(())
}

pub fn load_key_file(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let mut f = open_r_with_retry(path, 8, 50)
        .with_context(|| format!("open key file: {}", path.display()))?;
    let meta = f.metadata()?;
    if meta.len() != KEY_FILE_SIZE as u64 {
        bail!(
            "key file must be exactly {} bytes (got {})",
            KEY_FILE_SIZE,
            meta.len()
        );
    }

    let mut buf = Zeroizing::new(vec![0u8; KEY_FILE_SIZE]);
    f.read_exact(&mut buf)?;
    Ok(buf)
}

pub fn wipe_file(path: &Path, passes: u32) -> Result<()> {
    if passes == 0 {
        return Ok(());
    }

    let mut f = open_rw_with_retry(path, 6, 30)
        .with_context(|| format!("open for wipe: {}", path.display()))?;
    let len = f.metadata()?.len();
    if len == 0 {
        f.sync_all()?;
        return Ok(());
    }

    let buf_size: usize = 1 << 20;
    let mut buf = vec![0u8; buf_size];
    let mut rng = OsRng;

    for pass in 0..passes {
        let last = pass + 1 == passes;
        let mut written: u64 = 0;
        f.seek(SeekFrom::Start(0))?;
        while written < len {
            let chunk = ((len - written) as usize).min(buf_size);
            if last {
                for b in &mut buf[..chunk] {
                    *b = 0;
                }
            } else {
                rng.fill_bytes(&mut buf[..chunk]);
            }
            f.write_all(&buf[..chunk])?;
            written += chunk as u64;
        }
        f.flush()?;
        f.sync_all()?;
    }

    buf.zeroize();
    Ok(())
}

// --- Encrypt / Decrypt Core ---

pub fn encrypt_file(
    path: &Path,
    passphrase: &[u8],
    verbose: bool,
    wipe_passes: u32,
) -> Result<()> {
    if path
        .file_name()
        .and_then(|s| s.to_str())
        .map(|s| s.ends_with(".rcpt"))
        .unwrap_or(false)
    {
        if verbose {
            eprintln!("Skipping already-encrypted: {}", path.display());
        }
        return Ok(());
    }

    let final_path = add_suffix(path, ".rcpt");
    if final_path.exists() {
        bail!("destination already exists: {}", final_path.display());
    }
    let tmp_path = final_path.with_extension("rcpt.tmp");

    let mut src = open_r_with_retry(path, 8, 50)
        .with_context(|| format!("open for read: {}", path.display()))?;
    let meta = src.metadata()?;
    let plain_size = meta.len();

    let mut rng = OsRng;
    let mut salt = [0u8; SALT_SIZE];
    rng.fill_bytes(&mut salt);
    let mut base_nonce = [0u8; BASE_NONCE_SIZE];
    rng.fill_bytes(&mut base_nonce);

    let kdf = DEFAULT_KDF;
    let key = derive_key_argon2id(passphrase, &salt, kdf)?;
    let cipher = Aes256Gcm::new_from_slice(&*key).map_err(|_| anyhow!("invalid key length"))?;
    let header = build_header_bytes_v2(DEFAULT_CHUNK_SZ, &salt, &base_nonce, kdf, plain_size);

    let mut dst_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_path)
        .with_context(|| format!("create temp: {}", tmp_path.display()))?;

    let mut buf = vec![0u8; DEFAULT_CHUNK_SZ as usize];
    let mut counter: u32 = 0;

    let write_res: Result<()> = (|| {
        let mut dst = BufWriter::new(&mut dst_file);
        dst.write_all(&header).context("write header")?;

        loop {
            let n = src.read(&mut buf)?;
            if n == 0 {
                break;
            }
            let pt = &mut buf[..n];
            let nonce_arr = make_chunk_nonce(&base_nonce, counter);
            let nonce = Nonce::from(nonce_arr);
            let ct = cipher
                .encrypt(&nonce, Payload { msg: pt, aad: &header })
                .map_err(|_| anyhow!("gcm seal failed"))?;
            let len_le = (n as u32).to_le_bytes();
            dst.write_all(&len_le)?;
            dst.write_all(&ct)?;
            pt.zeroize();
            counter = counter
                .checked_add(1)
                .ok_or_else(|| anyhow!("nonce counter overflow"))?;
        }

        dst.flush()?;
        Ok(())
    })();

    if let Err(e) = write_res {
        let _ = dst_file.sync_all();
        drop(dst_file);
        let _ = fs::remove_file(&tmp_path);
        let _ = sync_parent_dir(&tmp_path);
        return Err(e);
    }

    dst_file.sync_all()?;
    drop(dst_file);

    fs::rename(&tmp_path, &final_path)
        .with_context(|| format!("rename temp→final: {}", final_path.display()))?;
    sync_parent_dir(&final_path)?;

    if wipe_passes > 0 {
        wipe_file(path, wipe_passes)
            .with_context(|| format!("wipe original: {}", path.display()))?;
    }
    fs::remove_file(path).with_context(|| format!("remove plaintext: {}", path.display()))?;
    sync_parent_dir(path)?;

    if verbose {
        eprintln!(
            "Encrypted {} bytes → {}",
            plain_size,
            final_path.display()
        );
    }

    Ok(())
}

pub fn verify_encrypted_file(path: &Path, passphrase: &[u8]) -> Result<()> {
    let mut src = open_r_with_retry(path, 8, 50)
        .with_context(|| format!("re-open for verify: {}", path.display()))?;
    let meta = src.metadata()?;
    let total_size = meta.len();

    let (hdr_bytes, header) =
        read_and_parse_header(&mut src).context("invalid header during verify")?;
    let header_len = hdr_bytes.len();
    if total_size < header_len as u64 {
        bail!("invalid encrypted file during verify: too small");
    }
    if !(MIN_CHUNK_SZ..=MAX_CHUNK_SZ).contains(&header.chunk_size) {
        bail!(
            "unsupported chunk size during verify: {}",
            header.chunk_size
        );
    }

    let kdf = header.kdf;
    let key = derive_key_argon2id(passphrase, &header.salt, kdf)?;
    let cipher = Aes256Gcm::new_from_slice(&*key).map_err(|_| anyhow!("invalid key length"))?;

    let mut cur = header_len as u64;
    let mut len_buf = [0u8; 4];
    let mut counter: u32 = 0;
    let mut total_plain: u64 = 0;

    let mut ct_buf = vec![0u8; header.chunk_size as usize + GCM_TAG_LEN];

    while cur < total_size {
        if total_size.saturating_sub(cur) < 4 {
            bail!(
                "truncated/corrupted during verify: missing chunk length at offset {}",
                cur
            );
        }
        read_exact_at(&mut src, cur, &mut len_buf)?;
        cur += 4;

        let pt_len = u32::from_le_bytes(len_buf) as usize;
        if pt_len == 0 || pt_len as u32 > header.chunk_size {
            bail!("invalid chunk length {} during verify", pt_len);
        }
        let ct_len = pt_len + GCM_TAG_LEN;

        if total_size.saturating_sub(cur) < ct_len as u64 {
            bail!(
                "truncated/corrupted during verify: missing ciphertext for chunk {} (need {}, have {})",
                counter,
                ct_len,
                total_size.saturating_sub(cur)
            );
        }

        if ct_buf.len() < ct_len {
            ct_buf.resize(ct_len, 0);
        }
        read_exact_at(&mut src, cur, &mut ct_buf[..ct_len])?;
        cur += ct_len as u64;

        let nonce_arr = make_chunk_nonce(&header.base_nonce, counter);
        let nonce = Nonce::from(nonce_arr);
        let mut pt = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &ct_buf[..ct_len],
                    aad: &hdr_bytes,
                },
            )
            .map_err(|_| anyhow!("failed to decrypt chunk during verify"))?;
        total_plain += pt.len() as u64;
        pt.zeroize();

        counter = counter
            .checked_add(1)
            .ok_or_else(|| anyhow!("nonce counter overflow during verify"))?;
    }

    if let Some(exp) = header.plaintext_len {
        if total_plain != exp {
            bail!(
                "decrypted length mismatch during verify (expected {}, got {})",
                exp,
                total_plain
            );
        }
    }

    Ok(())
}

pub fn encrypt_file_inplace(path: &Path, passphrase: &[u8], verbose: bool) -> Result<()> {
    if path
        .file_name()
        .and_then(|s| s.to_str())
        .map(|s| s.ends_with(".rcpt"))
        .unwrap_or(false)
    {
        if verbose {
            eprintln!(
                "Skipping already-encrypted (in-place): {}",
                path.display()
            );
        }
        return Ok(());
    }

    let final_path = add_suffix(path, ".rcpt");
    if final_path.exists() {
        bail!("destination already exists: {}", final_path.display());
    }

    let mut file = open_rw_with_retry(path, 8, 50)
        .with_context(|| format!("open for in-place encrypt: {}", path.display()))?;
    let meta = file.metadata()?;
    let plain_size = meta.len();

    let mut rng = OsRng;
    let mut salt = [0u8; SALT_SIZE];
    rng.fill_bytes(&mut salt);
    let mut base_nonce = [0u8; BASE_NONCE_SIZE];
    rng.fill_bytes(&mut base_nonce);

    let kdf = DEFAULT_KDF;
    let key = derive_key_argon2id(passphrase, &salt, kdf)?;
    let cipher = Aes256Gcm::new_from_slice(&*key).map_err(|_| anyhow!("invalid key length"))?;

    let header = build_header_bytes_v2(DEFAULT_CHUNK_SZ, &salt, &base_nonce, kdf, plain_size);
    let header_len = header.len() as u64;

    let chunk_sz_u32 = DEFAULT_CHUNK_SZ;
    let chunk_sz = chunk_sz_u32 as u64;
    if chunk_sz == 0 {
        bail!("invalid chunk size");
    }

    let num_full = plain_size / chunk_sz;
    let rem = (plain_size % chunk_sz) as usize;
    let chunk_count_u64 = if plain_size == 0 {
        0
    } else if rem == 0 {
        num_full
    } else {
        num_full + 1
    };

    if chunk_count_u64 > (u32::MAX as u64) {
        bail!("file too large: chunk counter would overflow u32");
    }

    let overhead_per_chunk: u64 = 4 + GCM_TAG_LEN as u64;
    let new_len = header_len
        .checked_add(plain_size)
        .and_then(|x| x.checked_add(chunk_count_u64.checked_mul(overhead_per_chunk)?))
        .ok_or_else(|| anyhow!("file too large (size overflow)"))?;

    file.set_len(new_len)
        .with_context(|| format!("extend file for in-place encrypt: {}", path.display()))?;

    let mut buf = vec![0u8; chunk_sz_u32 as usize];
    let mut dst_pos = new_len;

    let mut idx = chunk_count_u64;
    while idx > 0 {
        idx -= 1;
        let chunk_index = idx as u32;

        let is_full = idx < num_full;
        let pt_len_u64 = if is_full {
            chunk_sz
        } else if rem == 0 {
            chunk_sz
        } else {
            rem as u64
        };
        let pt_len = pt_len_u64 as usize;

        let src_offset = idx
            .checked_mul(chunk_sz)
            .ok_or_else(|| anyhow!("source offset overflow"))?;

        file.seek(SeekFrom::Start(src_offset))?;
        file.read_exact(&mut buf[..pt_len])?;

        dst_pos = dst_pos
            .checked_sub(pt_len_u64 + GCM_TAG_LEN as u64 + 4)
            .ok_or_else(|| anyhow!("destination offset underflow"))?;
        let len_offset = dst_pos;

        let nonce_arr = make_chunk_nonce(&base_nonce, chunk_index);
        let nonce = Nonce::from(nonce_arr);
        let pt = &mut buf[..pt_len];
        let ct = cipher
            .encrypt(&nonce, Payload { msg: pt, aad: &header })
            .map_err(|_| anyhow!("gcm seal failed"))?;

        if ct.len() != pt_len + GCM_TAG_LEN {
            bail!("gcm produced unexpected length");
        }

        file.seek(SeekFrom::Start(len_offset))?;
        let len_bytes = (pt_len as u32).to_le_bytes();
        file.write_all(&len_bytes)?;
        file.write_all(&ct)?;

        pt.zeroize();
    }

    if dst_pos != header_len {
        bail!(
            "internal error: dst_pos mismatch (expected {}, got {})",
            header_len,
            dst_pos
        );
    }

    file.seek(SeekFrom::Start(0))?;
    file.write_all(&header)?;
    file.flush()?;
    file.sync_all()?;
    drop(file);

    if let Err(e) = verify_encrypted_file(path, passphrase) {
        return Err(anyhow!(
            "verification after in-place encryption failed for {}: {e}",
            path.display()
        ));
    }

    fs::rename(path, &final_path).with_context(|| {
        format!(
            "rename in-place encrypted file to {}",
            final_path.display()
        )
    })?;
    sync_parent_dir(&final_path)?;

    if verbose {
        eprintln!(
            "Encrypted (in-place) {} bytes → {}",
            plain_size,
            final_path.display()
        );
    }

    Ok(())
}

pub fn decrypt_file(path: &Path, passphrase: &[u8], cat: bool, wipe_passes: u32) -> Result<()> {
    let name_ok = path
        .file_name()
        .and_then(|s| s.to_str())
        .map(|s| s.ends_with(".rcpt"))
        .unwrap_or(false);
    if !name_ok {
        bail!("file is not .rcpt: {}", path.display());
    }

    let mut src = open_r_with_retry(path, 8, 50)
        .with_context(|| format!("open encrypted: {}", path.display()))?;
    let meta = src.metadata()?;
    let total_size = meta.len();

    let (hdr_bytes, header) = read_and_parse_header(&mut src).context("invalid header")?;
    let header_len = hdr_bytes.len();
    if total_size < header_len as u64 {
        bail!("invalid encrypted file: too small");
    }
    if !(MIN_CHUNK_SZ..=MAX_CHUNK_SZ).contains(&header.chunk_size) {
        bail!("unsupported chunk size: {}", header.chunk_size);
    }

    let kdf = header.kdf;
    let key = derive_key_argon2id(passphrase, &header.salt, kdf)?;
    let cipher = Aes256Gcm::new_from_slice(&*key).map_err(|_| anyhow!("invalid key length"))?;

    let mut cur = header_len as u64;

    if cat {
        let mut len_buf = [0u8; 4];
        let mut counter: u32 = 0;
        let mut written_total: u64 = 0;
        let stdout = io::stdout();
        let mut lock = stdout.lock();

        while cur < total_size {
            if total_size.saturating_sub(cur) < 4 {
                bail!(
                    "truncated/corrupted: missing chunk length at offset {}",
                    cur
                );
            }
            read_exact_at(&mut src, cur, &mut len_buf)?;
            cur += 4;

            let pt_len = u32::from_le_bytes(len_buf) as usize;
            if pt_len == 0 || pt_len as u32 > header.chunk_size {
                bail!("invalid chunk length {}", pt_len);
            }
            let ct_len = pt_len + GCM_TAG_LEN;

            if total_size.saturating_sub(cur) < ct_len as u64 {
                bail!(
                    "truncated/corrupted: missing ciphertext for chunk {} (need {}, have {})",
                    counter,
                    ct_len,
                    total_size.saturating_sub(cur)
                );
            }
            let mut ct = vec![0u8; ct_len];
            read_exact_at(&mut src, cur, &mut ct)?;
            cur += ct_len as u64;

            let nonce_arr = make_chunk_nonce(&header.base_nonce, counter);
            let nonce = Nonce::from(nonce_arr);
            let mut pt = cipher
                .decrypt(
                    &nonce,
                    Payload {
                        msg: &ct,
                        aad: &hdr_bytes,
                    },
                )
                .map_err(|_| anyhow!("failed to decrypt chunk"))?;
            lock.write_all(&pt)?;
            written_total += pt.len() as u64;
            pt.zeroize();
            counter = counter
                .checked_add(1)
                .ok_or_else(|| anyhow!("nonce counter overflow"))?;
        }
        lock.flush()?;

        if let Some(exp) = header.plaintext_len {
            if written_total != exp {
                bail!(
                    "decrypted length mismatch (expected {}, got {}) — possible truncation",
                    exp,
                    written_total
                );
            }
        }
        return Ok(());
    }

    let final_plain = remove_suffix(path, ".rcpt").ok_or_else(|| anyhow!("bad name"))?;
    if final_plain.exists() {
        bail!("destination already exists: {}", final_plain.display());
    }

    let tmp_plain = {
        let fname = final_plain
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("tmp");
        let mut p = final_plain.clone();
        p.set_file_name(format!("{fname}.tmp"));
        p
    };

    let mut dst_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_plain)
        .with_context(|| format!("create temp plaintext: {}", tmp_plain.display()))?;

    let mut len_buf = [0u8; 4];
    let mut counter: u32 = 0;
    let mut written_total: u64 = 0;

    let write_res: Result<()> = (|| {
        let mut dst = BufWriter::new(&mut dst_file);

        while cur < total_size {
            if total_size.saturating_sub(cur) < 4 {
                bail!(
                    "truncated/corrupted: missing chunk length at offset {}",
                    cur
                );
            }
            read_exact_at(&mut src, cur, &mut len_buf)?;
            cur += 4;

            let pt_len = u32::from_le_bytes(len_buf) as usize;
            if pt_len == 0 || pt_len as u32 > header.chunk_size {
                bail!("invalid chunk length {}", pt_len);
            }
            let ct_len = pt_len + GCM_TAG_LEN;

            if total_size.saturating_sub(cur) < ct_len as u64 {
                bail!(
                    "truncated/corrupted: missing ciphertext for chunk {} (need {}, have {})",
                    counter,
                    ct_len,
                    total_size.saturating_sub(cur)
                );
            }
            let mut ct = vec![0u8; ct_len];
            read_exact_at(&mut src, cur, &mut ct)?;
            cur += ct_len as u64;

            let nonce_arr = make_chunk_nonce(&header.base_nonce, counter);
            let nonce = Nonce::from(nonce_arr);
            let mut pt = cipher
                .decrypt(
                    &nonce,
                    Payload {
                        msg: &ct,
                        aad: &hdr_bytes,
                    },
                )
                .map_err(|_| anyhow!("failed to decrypt chunk"))?;
            dst.write_all(&pt)?;
            written_total += pt.len() as u64;
            pt.zeroize();
            counter = counter
                .checked_add(1)
                .ok_or_else(|| anyhow!("nonce counter overflow"))?;
        }

        dst.flush()?;

        if let Some(exp) = header.plaintext_len {
            if written_total != exp {
                bail!(
                    "decrypted length mismatch (expected {}, got {}) — possible truncation",
                    exp,
                    written_total
                );
            }
        }

        Ok(())
    })();

    if let Err(e) = write_res {
        let _ = dst_file.sync_all();
        drop(dst_file);
        let _ = fs::remove_file(&tmp_plain);
        let _ = sync_parent_dir(&tmp_plain);
        return Err(e);
    }

    dst_file.sync_all()?;
    drop(dst_file);

    fs::rename(&tmp_plain, &final_plain)
        .with_context(|| format!("rename temp→final: {}", final_plain.display()))?;
    sync_parent_dir(&final_plain)?;

    if wipe_passes > 0 {
        wipe_file(path, wipe_passes)
            .with_context(|| format!("wipe encrypted: {}", path.display()))?;
    }
    fs::remove_file(path).with_context(|| format!("remove encrypted: {}", path.display()))?;
    sync_parent_dir(path)?;

    Ok(())
}

