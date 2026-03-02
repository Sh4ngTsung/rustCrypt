#![forbid(unsafe_code)]

mod cli;
mod constants;
mod crypto;
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
use anyhow::{bail, Result};
use clap::Parser;
use rpassword::read_password;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

fn get_passphrase_for_encryption() -> Result<Zeroizing<Vec<u8>>> {
    if let Ok(p) = env::var("RCrypt_PASS").or_else(|_| env::var("CRYPTSEC_PASS")) {
        return Ok(Zeroizing::new(p.into_bytes()));
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
    Ok(Zeroizing::new(p1.to_vec()))
}

fn get_passphrase_for_decryption() -> Result<Zeroizing<Vec<u8>>> {
    if let Ok(p) = env::var("RCrypt_PASS").or_else(|_| env::var("CRYPTSEC_PASS")) {
        return Ok(Zeroizing::new(p.into_bytes()));
    }

    eprint!("Enter decryption key: ");
    let pw = Zeroizing::new(read_password()?);
    eprintln!();
    Ok(Zeroizing::new(pw.as_bytes().to_vec()))
}

fn main() -> Result<()> {
    let args = Args::parse();

    if let Some(ref key_out) = args.gen_key {
        if args.encrypt
            || args.decrypt
            || args.cat
            || args.directory.is_some()
            || args.single_file.is_some()
            || !args.paths.is_empty()
            || args.inplace
            || args.with_pass
        {
            eprintln!("-g/--gen-key cannot be combined with -e/-d/--cat/-s/--with-pass or input paths.");
            std::process::exit(1);
        }

        generate_key_file(key_out, args.verbose)?;
        return Ok(());
    }

    if args.encrypt && args.decrypt {
        eprintln!("Cannot use -e and -d together.");
        std::process::exit(1);
    }
    if !args.encrypt && !args.decrypt {
        eprintln!("No operation specified. Use -h for help.");
        std::process::exit(1);
    }
    if args.cat && !args.decrypt {
        eprintln!("--cat is only valid with -d/--decrypt.");
        std::process::exit(1);
    }

    if args.inplace && !args.encrypt {
        eprintln!("-s/--inplace is only valid with -e/--encrypt.");
        std::process::exit(1);
    }
    if args.inplace && args.passes > 0 {
        eprintln!("-s/--inplace cannot be combined with -p/--passes (no extra copy to wipe).");
        std::process::exit(1);
    }

    if args.with_pass && args.key_file.is_none() {
        eprintln!("--with-pass requires -k/--key-file.");
        std::process::exit(1);
    }

    let mut secret: Zeroizing<Vec<u8>> = if let Some(ref key_path) = args.key_file {
        let key_bytes = load_key_file(key_path)?;
        if args.with_pass {
            if args.encrypt {
                let pass = get_passphrase_for_encryption()?;
                combine_key_and_pass(&key_bytes, &pass)
            } else {
                let pass = get_passphrase_for_decryption()?;
                combine_key_and_pass(&key_bytes, &pass)
            }
        } else {
            key_bytes
        }
    } else if args.encrypt {
        get_passphrase_for_encryption()?
    } else {
        get_passphrase_for_decryption()?
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
                    Err(_) => eprintln!("Skipping {}", p),
                }
            }
        }
    }

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
            eprintln!("[WARNING] Secure wipe (-p) requested. Note that hardware wear-leveling on modern SSDs/NVMe drives may prevent the physical erasure of plaintext data.");
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
