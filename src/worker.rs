use crate::ops::{decrypt_file, encrypt_file, encrypt_file_inplace};
use crate::utils::is_system_noise;
use anyhow::anyhow;
use crossbeam_channel::unbounded;
use glob::Pattern;
use std::path::{Path, PathBuf};
use std::thread;
use walkdir::WalkDir;
use zeroize::{Zeroize, Zeroizing};

pub fn collect_from_glob_pattern(pattern: &Path, include_system: bool) -> Vec<PathBuf> {
    let base_dir = pattern.parent().unwrap_or_else(|| Path::new("."));
    let match_pat = pattern
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("*")
        .to_string();
    let pat = Pattern::new(&match_pat).unwrap_or_else(|_| Pattern::new("*").unwrap());

    let mut files = Vec::new();
    for entry in WalkDir::new(base_dir)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if !include_system && is_system_noise(&name) {
            continue;
        }
        if pat.matches(&name) {
            files.push(entry.path().to_path_buf());
        }
    }
    files
}

pub fn path_has_glob(s: &str) -> bool {
    s.contains('*') || s.contains('?')
}

#[allow(clippy::too_many_arguments)]
pub fn start_workers(
    files: Vec<PathBuf>,
    mut passphrase: Zeroizing<Vec<u8>>,
    threads: usize,
    encrypt: bool,
    cat: bool,
    verbose: bool,
    include_system: bool,
    passes: u32,
    inplace: bool,
) {
    let (tx, rx) = unbounded::<PathBuf>();
    let (err_tx, err_rx) = unbounded::<anyhow::Error>();

    let drain = thread::spawn(move || {
        while let Ok(err) = err_rx.recv() {
            eprintln!("{err:#}");
        }
    });

    if passes > 0 {
        eprintln!("[WARNING] Secure wipe (-p) requested. Note that hardware wear-leveling on modern SSDs/NVMe drives may prevent the physical erasure of plaintext data. Use with caution on solid-state media.");
    }

    let mut joins = Vec::new();
    for _ in 0..threads.max(1) {
        let rx = rx.clone();
        let err_tx = err_tx.clone();
        let pass = passphrase.clone(); 
        
        let j = thread::spawn(move || {
            for path in rx.iter() {
                let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("");

                if !include_system && is_system_noise(fname) {
                    continue;
                }

                let res = if encrypt {
                    if fname.ends_with(".rcpt") {
                        Ok(())
                    } else if inplace {
                        encrypt_file_inplace(&path, pass.as_slice(), verbose)
                    } else {
                        encrypt_file(&path, pass.as_slice(), verbose, passes)
                    }
                } else if !fname.ends_with(".rcpt") {
                    Ok(())
                } else {
                    decrypt_file(&path, pass.as_slice(), cat, passes)
                };

                if let Err(e) = res {
                    let _ = err_tx.send(anyhow!("error processing {}: {e:#}", path.display()));
                } else if verbose {
                    eprintln!("Processed {}", path.display());
                }
            }
        });
        joins.push(j);
    }

    drop(err_tx);
    for f in files {
        let _ = tx.send(f);
    }
    drop(tx);

    for j in joins {
        let _ = j.join();
    }
    let _ = drain.join();

    passphrase.zeroize();
}