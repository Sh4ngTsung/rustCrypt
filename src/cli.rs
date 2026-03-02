use clap::{ArgAction, Parser};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "rcrypt",
    author = "Sh4ngTsung",
    version = "1.0",
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

    #[arg(short = 't', long, default_value_t = 3)]
    pub threads: usize,

    #[arg(short = 'c', long)]
    pub cat: bool,

    #[arg(short = 'v', long)]
    pub verbose: bool,

    #[arg(long = "include-system", action = ArgAction::SetTrue)]
    pub include_system: bool,

    #[arg(short = 'p', long = "passes", default_value_t = 0)]
    pub passes: u32,

    #[arg(short = 's', long = "inplace")]
    pub inplace: bool,

    #[arg(short = 'k', long = "key-file")]
    pub key_file: Option<PathBuf>,

    #[arg(long = "with-pass")]
    pub with_pass: bool,

    #[arg(short = 'g', long = "gen-key")]
    pub gen_key: Option<PathBuf>,

    #[arg()]
    pub paths: Vec<String>,
}
