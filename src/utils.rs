use anyhow::{anyhow, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let n = a.len().max(b.len());
    let mut diff = a.len() ^ b.len();
    for i in 0..n {
        let x = *a.get(i).unwrap_or(&0);
        let y = *b.get(i).unwrap_or(&0);
        diff |= (x ^ y) as usize;
    }
    diff == 0
}

pub fn open_r_with_retry(path: &Path, attempts: usize, base_ms: u64) -> Result<File> {
    let mut last: Option<anyhow::Error> = None;
    let mut rng = OsRng;
    for i in 0..attempts {
        match OpenOptions::new().read(true).open(path) {
            Ok(f) => return Ok(f),
            Err(e) => {
                last = Some(anyhow!(e));
                let mut sleep_ms = base_ms * (1u64 << i);
                if sleep_ms > 2000 {
                    sleep_ms = 2000;
                }
                let jitter = (rng.next_u32() % 200) as u64;
                thread::sleep(Duration::from_millis(sleep_ms + jitter));
            }
        }
    }
    Err(anyhow!("failed to open {:?}: {}", path, last.unwrap()))
}

pub fn open_rw_with_retry(path: &Path, attempts: usize, base_ms: u64) -> Result<File> {
    let mut last: Option<anyhow::Error> = None;
    let mut rng = OsRng;
    for i in 0..attempts {
        match OpenOptions::new().read(true).write(true).open(path) {
            Ok(f) => return Ok(f),
            Err(e) => {
                last = Some(anyhow!(e));
                let mut sleep_ms = base_ms * (1u64 << i);
                if sleep_ms > 2000 {
                    sleep_ms = 2000;
                }
                let jitter = (rng.next_u32() % 200) as u64;
                thread::sleep(Duration::from_millis(sleep_ms + jitter));
            }
        }
    }
    Err(anyhow!("failed to open R/W {:?}: {}", path, last.unwrap()))
}

pub fn read_exact_at(file: &mut File, offset: u64, buf: &mut [u8]) -> Result<()> {
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(buf)?;
    Ok(())
}

pub fn is_system_noise(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n == "desktop.ini" || n == "thumbs.db" || n == "ehthumbs.db"
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
    if let Some(trimmed) = name.strip_suffix(suffix) {
        let mut out = path.to_path_buf();
        out.set_file_name(trimmed);
        Some(out)
    } else {
        None
    }
}

pub fn sync_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        if let Ok(dirf) = OpenOptions::new().read(true).open(parent) {
            let _ = dirf.sync_all();
        }
    }
    Ok(())
}

