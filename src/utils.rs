use anyhow::{Context, Result, anyhow, bail};
use rand::RngCore;
use rand::rngs::OsRng;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

/// Constant-time byte slice comparison. Returns true iff both slices have
/// the same length AND every byte is equal. The work is proportional to
/// `max(a.len(), b.len())` and never short-circuits, so timing leakage is
/// limited to slice lengths (which are not secrets here).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let n = a.len().max(b.len());
    let mut diff: usize = a.len() ^ b.len();
    for i in 0..n {
        let x = *a.get(i).unwrap_or(&0);
        let y = *b.get(i).unwrap_or(&0);
        diff |= (x ^ y) as usize;
    }
    diff == 0
}

/// Refuse to operate on any path that is not a regular file. This is the
/// primary mitigation against attacker-controlled symlinks redirecting
/// rcrypt to operate on files the caller did not intend (e.g. /etc/shadow,
/// other users' files, or block devices).
pub fn ensure_regular_file(path: &Path) -> Result<()> {
    let meta =
        fs::symlink_metadata(path).with_context(|| format!("stat (lstat) {}", path.display()))?;
    let ft = meta.file_type();
    if ft.is_symlink() {
        bail!(
            "refusing to operate on symlink: {} (would follow to an untrusted target)",
            path.display()
        );
    }
    if !ft.is_file() {
        bail!(
            "refusing to operate on non-regular file: {} ({:?})",
            path.display(),
            ft
        );
    }
    Ok(())
}

#[cfg(unix)]
pub fn warn_if_world_accessible(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = fs::metadata(path) {
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            eprintln!(
                "[WARNING] permissions on {} are {:o}: secret material is readable by group/others. \
                 Run `chmod 600 {}` before reusing this key.",
                path.display(),
                mode,
                path.display()
            );
        }
    }
}

#[cfg(not(unix))]
pub fn warn_if_world_accessible(_path: &Path) {}

pub fn open_r_with_retry(path: &Path, attempts: usize, base_ms: u64) -> Result<File> {
    let mut last: Option<anyhow::Error> = None;
    let mut rng = OsRng;
    for i in 0..attempts {
        match OpenOptions::new().read(true).open(path) {
            Ok(f) => return Ok(f),
            Err(e) => {
                last = Some(anyhow!(e));
                let shift = (i as u32).min(10);
                let mut sleep_ms = base_ms.saturating_mul(1u64 << shift);
                if sleep_ms > 2000 {
                    sleep_ms = 2000;
                }
                let jitter = (rng.next_u32() % 200) as u64;
                thread::sleep(Duration::from_millis(sleep_ms + jitter));
            }
        }
    }
    Err(anyhow!(
        "failed to open {:?}: {}",
        path,
        last.expect("retry loop must record at least one error")
    ))
}

pub fn open_rw_with_retry(path: &Path, attempts: usize, base_ms: u64) -> Result<File> {
    let mut last: Option<anyhow::Error> = None;
    let mut rng = OsRng;
    for i in 0..attempts {
        match OpenOptions::new().read(true).write(true).open(path) {
            Ok(f) => return Ok(f),
            Err(e) => {
                last = Some(anyhow!(e));
                let shift = (i as u32).min(10);
                let mut sleep_ms = base_ms.saturating_mul(1u64 << shift);
                if sleep_ms > 2000 {
                    sleep_ms = 2000;
                }
                let jitter = (rng.next_u32() % 200) as u64;
                thread::sleep(Duration::from_millis(sleep_ms + jitter));
            }
        }
    }
    Err(anyhow!(
        "failed to open R/W {:?}: {}",
        path,
        last.expect("retry loop must record at least one error")
    ))
}

pub fn read_exact_at(file: &mut File, offset: u64, buf: &mut [u8]) -> Result<()> {
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(buf)?;
    Ok(())
}

/// Operating-system metadata / index files that almost never carry useful
/// content for a user driving an encryption tool. We skip them by default
/// to avoid littering directories with `.rcpt` artefacts and to keep
/// metadata leaks small.
pub fn is_system_noise(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    matches!(
        n.as_str(),
        "desktop.ini"
            | "thumbs.db"
            | "ehthumbs.db"
            | ".ds_store"
            | ".localized"
            | ".spotlight-v100"
            | ".trashes"
            | ".fseventsd"
            | "icon\r"
    ) || n.starts_with("$recycle.bin")
        || n.starts_with("~$")
}

pub fn add_suffix(path: &Path, suffix: &str) -> PathBuf {
    let name = path.file_name().unwrap_or_else(|| OsStr::new(""));
    let mut new_name = OsString::from(name);
    new_name.push(suffix);
    let mut out = path.to_path_buf();
    out.set_file_name(new_name);
    out
}

pub fn remove_suffix(path: &Path, suffix: &str) -> Option<PathBuf> {
    let name = path.file_name()?.to_string_lossy();
    let trimmed = name.strip_suffix(suffix)?;
    let mut out = path.to_path_buf();
    out.set_file_name(trimmed);
    Some(out)
}

/// Best-effort fsync of the parent directory, used after rename/remove so a
/// crash cannot leave the directory entry in an inconsistent state. We
/// deliberately swallow errors: not all filesystems support directory
/// fsync, and failure here must not abort a successful encrypt/decrypt.
pub fn sync_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent()
        && let Ok(dirf) = OpenOptions::new().read(true).open(parent)
    {
        let _ = dirf.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_basic() {
        assert!(ct_eq(b"", b""));
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
        assert!(!ct_eq(b"abcd", b"abc"));
    }

    #[test]
    fn ct_eq_handles_long_inputs() {
        let a = vec![0x55u8; 4096];
        let b = vec![0x55u8; 4096];
        let mut c = b.clone();
        c[4000] = 0xAA;
        assert!(ct_eq(&a, &b));
        assert!(!ct_eq(&a, &c));
    }

    #[test]
    fn is_system_noise_matches_expected() {
        assert!(is_system_noise("Thumbs.db"));
        assert!(is_system_noise("thumbs.db"));
        assert!(is_system_noise(".DS_Store"));
        assert!(is_system_noise("desktop.ini"));
        assert!(is_system_noise("$RECYCLE.BIN"));
        assert!(is_system_noise("~$report.docx"));
        assert!(!is_system_noise("important.txt"));
        assert!(!is_system_noise("notes.md"));
    }

    #[test]
    fn suffix_helpers_roundtrip() {
        let p = std::path::PathBuf::from("/tmp/x/data.bin");
        let with = add_suffix(&p, ".rcpt");
        assert_eq!(with, std::path::PathBuf::from("/tmp/x/data.bin.rcpt"));
        let back = remove_suffix(&with, ".rcpt").unwrap();
        assert_eq!(back, p);
        assert!(remove_suffix(&p, ".rcpt").is_none());
    }

    #[test]
    fn ensure_regular_file_rejects_symlink() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let dir = tempfile::tempdir().unwrap();
            let target = dir.path().join("real.txt");
            std::fs::write(&target, b"data").unwrap();
            let link = dir.path().join("link.txt");
            symlink(&target, &link).unwrap();
            assert!(ensure_regular_file(&link).is_err());
            assert!(ensure_regular_file(&target).is_ok());
        }
    }
}
