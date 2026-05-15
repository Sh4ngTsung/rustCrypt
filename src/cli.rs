use clap::{ArgAction, Parser};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "rcrypt",
    author = "Sh4ngTsung",
    version,
    about = "Robust per-file encryption: AES-256-GCM, Argon2id key derivation, chunked/parallel I/O, optional secure wipe.",
    long_about = None
)]
pub struct Args {
    #[arg(short = 'e', long)]
    pub encrypt: bool,

    #[arg(short = 'd', long)]
    pub decrypt: bool,

    #[arg(short = 'r', long)]
    pub directory: Option<PathBuf>,

    #[arg(short = 'f', long)]
    pub single_file: Option<PathBuf>,

    /// Number of worker threads (>=1, <=256).
    #[arg(short = 't', long, default_value_t = 3)]
    pub threads: usize,

    /// Decrypt and stream plaintext to stdout. Requires exactly one input.
    #[arg(short = 'c', long)]
    pub cat: bool,

    #[arg(short = 'v', long)]
    pub verbose: bool,

    /// Do not skip OS-generated noise files (Thumbs.db, .DS_Store, etc.).
    #[arg(long = "include-system", action = ArgAction::SetTrue)]
    pub include_system: bool,

    /// Overwrite passes when wiping originals (0 = no overwrite).
    /// Only meaningful on rotating media; flash is wear-leveled.
    #[arg(short = 'p', long = "passes", default_value_t = 0)]
    pub passes: u32,

    /// In-place encryption: file is rewritten in shrinking-window mode.
    /// Power loss during this operation can permanently corrupt the file.
    #[arg(short = 's', long = "inplace")]
    pub inplace: bool,

    /// Use a 1 MiB binary key file instead of (or together with) a passphrase.
    #[arg(short = 'k', long = "key-file")]
    pub key_file: Option<PathBuf>,

    /// Combine the binary key file with a typed passphrase (2FA mode).
    #[arg(long = "with-pass")]
    pub with_pass: bool,

    /// Generate a fresh 1 MiB key file at the given path.
    #[arg(short = 'g', long = "gen-key")]
    pub gen_key: Option<PathBuf>,

    /// Refuse to take passphrases from RCRYPT_PASS / CRYPTSEC_PASS env vars.
    /// Recommended for shared hosts where /proc/<pid>/environ is readable.
    #[arg(long = "no-env-pass", action = ArgAction::SetTrue)]
    pub no_env_pass: bool,

    /// Free-form input paths or shell globs (encrypted or plain).
    #[arg()]
    pub paths: Vec<String>,
}
