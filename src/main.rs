#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]

mod cli;
mod constants;
mod crypto;
mod hardening;
mod ops;
mod utils;
mod worker;

use crate::cli::Args;
use crate::crypto::combine_key_and_pass;
use crate::ops::{
    decrypt_file, encrypt_file, encrypt_file_inplace, generate_key_file, load_key_file,
};
use crate::utils::{ct_eq, is_system_noise};
use crate::worker::{collect_from_glob_pattern, path_has_glob, start_workers};
use anyhow::{Result, bail};
use clap::Parser;
use rpassword::read_password;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

const PASSPHRASE_MIN_LEN: usize = 8;
const MAX_THREADS: usize = 256;

fn read_passphrase_from_env(allow_env: bool) -> Option<Zeroizing<Vec<u8>>> {
    if !allow_env {
        return None;
    }
    // NOTE: We deliberately do NOT call `env::remove_var`. In Rust 2024
    // that API requires unsafe (POSIX getenv/setenv are not thread-safe);
    // since the crate enforces `#![forbid(unsafe_code)]`, we leave the
    // env entry in place. Callers that must hide secrets from child
    // processes should `unset` the variable in their shell wrapper.
    for key in ["RCRYPT_PASS", "RCrypt_PASS", "CRYPTSEC_PASS"] {
        if let Ok(val) = env::var(key) {
            return Some(Zeroizing::new(val.into_bytes()));
        }
    }
    None
}

fn get_passphrase_for_encryption(allow_env: bool) -> Result<Zeroizing<Vec<u8>>> {
    if let Some(p) = read_passphrase_from_env(allow_env) {
        if p.len() < PASSPHRASE_MIN_LEN {
            bail!(
                "passphrase from environment is too short ({} bytes; need >= {})",
                p.len(),
                PASSPHRASE_MIN_LEN
            );
        }
        return Ok(p);
    }

    eprint!("Enter encryption key: ");
    let pw1 = Zeroizing::new(read_password()?);
    eprintln!();
    eprint!("Confirm encryption key: ");
    let pw2 = Zeroizing::new(read_password()?);
    eprintln!();

    let p1 = pw1.as_bytes();
    let p2 = pw2.as_bytes();
    if !ct_eq(p1, p2) {
        bail!("keys do not match");
    }
    if p1.len() < PASSPHRASE_MIN_LEN {
        bail!(
            "passphrase too short ({} bytes; need >= {})",
            p1.len(),
            PASSPHRASE_MIN_LEN
        );
    }
    Ok(Zeroizing::new(p1.to_vec()))
}

fn get_passphrase_for_decryption(allow_env: bool) -> Result<Zeroizing<Vec<u8>>> {
    if let Some(p) = read_passphrase_from_env(allow_env) {
        return Ok(p);
    }

    eprint!("Enter decryption key: ");
    let pw = Zeroizing::new(read_password()?);
    eprintln!();
    Ok(Zeroizing::new(pw.as_bytes().to_vec()))
}

fn validate_args(args: &Args) -> Result<()> {
    if args.gen_key.is_some() {
        if args.encrypt
            || args.decrypt
            || args.cat
            || args.directory.is_some()
            || args.single_file.is_some()
            || !args.paths.is_empty()
            || args.inplace
            || args.with_pass
        {
            bail!("-g/--gen-key cannot be combined with -e/-d/--cat/-s/--with-pass or input paths");
        }
        return Ok(());
    }
    if args.encrypt && args.decrypt {
        bail!("cannot use -e and -d together");
    }
    if !args.encrypt && !args.decrypt {
        bail!("no operation specified (use -e/-d, see -h for help)");
    }
    if args.cat && !args.decrypt {
        bail!("--cat is only valid with -d/--decrypt");
    }
    if args.cat && args.passes > 0 {
        bail!("--cat does not consume the source file; -p/--passes is incompatible");
    }
    if args.inplace && !args.encrypt {
        bail!("-s/--inplace is only valid with -e/--encrypt");
    }
    if args.inplace && args.passes > 0 {
        bail!("-s/--inplace cannot be combined with -p/--passes (no extra copy to wipe)");
    }
    if args.with_pass && args.key_file.is_none() {
        bail!("--with-pass requires -k/--key-file");
    }
    if args.threads == 0 || args.threads > MAX_THREADS {
        bail!(
            "invalid -t/--threads value: {} (must be 1..={})",
            args.threads,
            MAX_THREADS
        );
    }
    Ok(())
}

fn main() -> Result<()> {
    // Best-effort process hardening: disables core dumps and tightens
    // ptrace exposure where the kernel allows. Done before we read any
    // secret material so a crash during arg parsing also stays minimal.
    let _ = hardening::apply_all();

    let args = Args::parse();
    if let Err(e) = validate_args(&args) {
        eprintln!("{e}");
        std::process::exit(2);
    }

    if let Some(ref key_out) = args.gen_key {
        generate_key_file(key_out, args.verbose)?;
        return Ok(());
    }

    let allow_env = !args.no_env_pass;

    let mut secret: Zeroizing<Vec<u8>> = if let Some(ref key_path) = args.key_file {
        let key_bytes = load_key_file(key_path)?;
        if args.with_pass {
            if args.encrypt {
                let pass = get_passphrase_for_encryption(allow_env)?;
                combine_key_and_pass(&key_bytes, &pass)
            } else {
                let pass = get_passphrase_for_decryption(allow_env)?;
                combine_key_and_pass(&key_bytes, &pass)
            }
        } else {
            key_bytes
        }
    } else if args.encrypt {
        get_passphrase_for_encryption(allow_env)?
    } else {
        get_passphrase_for_decryption(allow_env)?
    };

    let mut files: Vec<PathBuf> = Vec::new();
    if let Some(dir) = &args.directory {
        let pat = dir.join("*");
        files.extend(collect_from_glob_pattern(&pat, args.include_system));
    }
    if let Some(sf) = &args.single_file {
        match fs::metadata(sf) {
            Ok(m) if m.is_dir() => {
                let pat = sf.join("*");
                files.extend(collect_from_glob_pattern(&pat, args.include_system));
            }
            Ok(_) => files.push(sf.clone()),
            Err(e) => eprintln!("Skipping {} ({e})", sf.display()),
        }
    }
    if !args.paths.is_empty() {
        for p in &args.paths {
            if path_has_glob(p) {
                let pb = PathBuf::from(p);
                files.extend(collect_from_glob_pattern(&pb, args.include_system));
            } else {
                match fs::metadata(p) {
                    Ok(m) if m.is_dir() => {
                        let pat = Path::new(p).join("*");
                        files.extend(collect_from_glob_pattern(&pat, args.include_system));
                    }
                    Ok(_) => files.push(PathBuf::from(p)),
                    Err(_) => eprintln!("Skipping {p}"),
                }
            }
        }
    }

    files.sort();
    files.dedup();

    if files.is_empty() {
        eprintln!("No input files. Use -r/-f or paths/globs. See -h for help.");
        std::process::exit(1);
    }

    let threads = if args.cat { 1 } else { args.threads };
    if args.cat && files.len() != 1 {
        eprintln!("--cat requires exactly one .rcpt input file.");
        std::process::exit(1);
    }

    if threads <= 1 {
        let pass = secret.clone();
        if args.passes > 0 {
            eprintln!(
                "[WARNING] Secure wipe (-p) requested. Hardware wear-leveling on modern SSDs/NVMe \
                 drives may prevent the physical erasure of plaintext data. Use full-disk \
                 encryption for solid-state media."
            );
        }
        for path in files {
            let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if !args.include_system && is_system_noise(fname) {
                continue;
            }

            let res = if args.encrypt {
                if fname.ends_with(".rcpt") {
                    Ok(())
                } else if args.inplace {
                    encrypt_file_inplace(&path, pass.as_slice(), args.verbose)
                } else {
                    encrypt_file(&path, pass.as_slice(), args.verbose, args.passes)
                }
            } else if !fname.ends_with(".rcpt") && !args.cat {
                Ok(())
            } else {
                decrypt_file(&path, pass.as_slice(), args.cat, args.passes)
            };
            if let Err(e) = res {
                eprintln!("{e:#}");
            } else if args.verbose {
                eprintln!("Processed {}", path.display());
            }
        }
    } else {
        let pass_for_workers = secret.clone();
        start_workers(
            files,
            pass_for_workers,
            threads,
            args.encrypt,
            args.cat,
            args.verbose,
            args.include_system,
            args.passes,
            args.inplace,
        );
    }

    secret.zeroize();
    Ok(())
}
