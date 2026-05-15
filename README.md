# rCrypt

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Language: Rust](https://img.shields.io/badge/Language-Rust-orange)
![Unsafe: forbidden](https://img.shields.io/badge/unsafe-forbidden-success)

`rcrypt` is a hardened command-line file encryption tool written in Rust.
It is designed for environments where confidentiality and integrity of
data at rest must not be negotiable: authenticated encryption, memory-safe
execution, parallel processing, and aggressive binary hardening.

> **Status:** v1.1.0 — security-audited release. See `SECURITY.md` for
> the threat model and reporting procedure.

---

## Cryptographic Architecture

| Concern              | Choice                                                |
| -------------------- | ----------------------------------------------------- |
| Symmetric encryption | AES-256-GCM (NIST SP 800-38D)                         |
| KDF                  | Argon2id v1.3 (RFC 9106)                              |
| Default KDF cost     | t = 4, m = 256 MiB, p = 4                             |
| Salt                 | 16 random bytes per file (`OsRng`)                    |
| Nonce                | 8 random base bytes + 4 counter bytes per chunk       |
| MAC                  | GCM 16-byte tag per chunk                             |
| AAD                  | Full header bound as AAD into every chunk             |
| Key zeroization      | `zeroize` on every buffer holding plaintext/keys      |
| Unsafe code          | `#![forbid(unsafe_code)]` at crate root               |
| Core dumps           | Disabled via `/proc/self/coredump_filter` on Linux    |
| Panic policy         | `panic = "abort"` (no unwinder reads dropped frames)  |
| Overflow checks      | Enforced in release builds                            |

Every encrypted file begins with a versioned header that records the KDF
parameters actually used. Older files encrypted under weaker defaults
still decrypt correctly because the header is the source of truth.

---

## Features

- **Authenticated, chunked AEAD.** AES-256-GCM with a per-chunk nonce
  derived from `(random_base, counter)`, with the full header bound as
  AAD so even a single flipped header bit causes decryption to fail.
- **Strong KDF defaults.** Argon2id with 256 MiB / 4 iterations / 4 lanes
  — resistant to GPU/ASIC brute force at substantial cost.
- **Parallel batch processing.** `-t N` workers process files in
  parallel; a single passphrase is derived once and shared across workers
  inside `Zeroizing` containers.
- **In-place encryption (`-s`).** Encrypts massive files directly in
  place without doubling disk usage. Performs a full read-back
  authentication pass before renaming so corrupted output never wins.
- **Best-effort secure wipe (`-p N`).** Multi-pattern overwrite
  (0x00 → 0xFF → random) of original files before unlinking. Effective
  on rotating media; flash media require full-disk encryption (see
  warning below).
- **Symlink protection.** Refuses to read or write through symlinks by
  default. A malicious link cannot redirect rcrypt to victim files.
- **Keyfiles & 2FA-style mode.** 1 MiB binary keyfile (`-k`) can be used
  alone or combined with a passphrase (`--with-pass`) for two-factor
  decryption.
- **Pipeline mode (`--cat`).** Decrypts to stdout without ever writing
  plaintext to disk. Compatible with shell pipelines.
- **Process hardening.** On Linux, core dumps are disabled at startup so
  a crash cannot spill recently-touched key material to disk.

---

## Installation

```bash
git clone https://github.com/Sh4ngTsung/rustCrypt.git
cd rustCrypt
./build_Linux.sh        # Linux/macOS (bash)
build_Windows.cmd       # Windows (Developer Command Prompt)
```

The hardened binary is written to `./target/release/rcrypt`.

### Linux hardening flags

The `build_Linux.sh` script enforces:

- Full RELRO + BIND_NOW (`-Wl,-z,relro,-z,now`)
- Non-executable stack (`-Wl,-z,noexecstack`)
- Strict library binding (`-Wl,-z,defs`)
- PIE (Position-Independent Executable)
- Stack canaries (`-fstack-protector-strong`)
- CET shadow stacks (`-fcf-protection=full`)
- Path remapping so the binary contains no host paths
- Sanity check: build aborts if a host path leaks into the binary or if
  the ELF is not a PIE / has an executable stack

### Windows hardening flags

`build_Windows.cmd` enforces `/CETCOMPAT`, `/NXCOMPAT`, `/DYNAMICBASE`,
`/HIGHENTROPYVA`, `/GUARD:CF`, and strips debug data.

---

## Usage

### Basic operations

```bash
# Encrypt a single file
rcrypt -e -f secret.pdf            # writes secret.pdf.rcpt, removes the original

# Decrypt a single file
rcrypt -d -f secret.pdf.rcpt

# Encrypt a directory in parallel (8 workers)
rcrypt -e -r /path/to/confidential -t 8

# Decrypt straight to stdout without touching disk
rcrypt -d --cat -f credentials.txt.rcpt | grep '^admin'
```

### Keyfiles

```bash
# Generate a fresh 1 MiB key (file is created with 0600 perms)
rcrypt -g master.key

# Encrypt using the keyfile only
rcrypt -e -k master.key -f data.tar.gz

# Encrypt using keyfile + passphrase (2FA style)
rcrypt -e -k usb/master.key --with-pass -f secret.txt
```

### In-place encryption

```bash
rcrypt -e -s -f massive_database.sql
```

> **Warning:** in-place mode rewrites the file as it goes. A power loss
> mid-operation may permanently corrupt the file. Always keep a backup.
> rcrypt performs a full read-back authentication pass before promoting
> the result, but cannot help if the storage layer fails first.

### Secure wipe (HDD only)

```bash
rcrypt -e -f keys.txt -p 3
```

> Wipes on flash storage (SSD, NVMe, eMMC, SD cards, USB sticks) are
> **not** reliable because of wear-leveling and the FTL. Use full-disk
> encryption on solid-state media.

---

## Environment variables

`rcrypt` will read a passphrase from any of the following variables:

- `RCRYPT_PASS`  (preferred)
- `RCrypt_PASS`  (legacy alias)
- `CRYPTSEC_PASS`

```bash
RCRYPT_PASS="correct horse battery staple" rcrypt -e -f backup.zip
```

To **refuse** environment passphrases (recommended on shared hosts where
`/proc/<pid>/environ` is readable), pass `--no-env-pass`:

```bash
rcrypt --no-env-pass -e -f backup.zip
```

A passphrase from the environment must be at least 8 bytes; otherwise
rcrypt aborts rather than encrypt with a degenerate secret.

---

## CLI Reference

| Flag                 | Description                                                              |
| -------------------- | ------------------------------------------------------------------------ |
| `-e`, `--encrypt`    | Encrypt files                                                            |
| `-d`, `--decrypt`    | Decrypt files                                                            |
| `-r`, `--directory`  | Directory to process recursively                                         |
| `-f`, `--single-file`| Single file (or directory) to process                                    |
| `-t`, `--threads`    | Worker threads (default 3, max 256)                                      |
| `-c`, `--cat`        | Decrypt to stdout (requires exactly one `.rcpt` input)                   |
| `-p`, `--passes`     | Overwrite passes on the original file (0 = no overwrite, HDD only)       |
| `-s`, `--inplace`    | In-place encryption (no double space, fail-secure)                       |
| `-k`, `--key-file`   | Use a binary keyfile instead of (or with) a passphrase                   |
| `--with-pass`        | Combine keyfile with a typed passphrase                                  |
| `-g`, `--gen-key`    | Generate a fresh 1 MiB keyfile (mode 0600)                               |
| `--no-env-pass`      | Refuse to read passphrases from `RCRYPT_PASS` / `CRYPTSEC_PASS`          |
| `--include-system`   | Process OS noise files (`desktop.ini`, `Thumbs.db`, `.DS_Store`, etc.)   |
| `-v`, `--verbose`    | Verbose progress output                                                  |
| `-h`, `--help`       | Show full help                                                           |
| `-V`, `--version`    | Show version                                                             |

---

## Threat model

`rcrypt` protects data **at rest** against an attacker who has the
ciphertext but does not have the passphrase / keyfile. It explicitly
does **not** protect against:

- A compromised host that can read process memory or scrape keys before
  zeroization completes.
- A user who reuses a low-entropy passphrase across files (Argon2id only
  buys a constant slowdown).
- Wear-leveled flash media: physical erase is not possible at the file
  level. Use FDE.
- Backups, swap files, or filesystem snapshots that captured plaintext
  prior to encryption.

See `SECURITY.md` for the full threat model and the security reporting
procedure.

---

## Continuous integration

Every push and pull request runs:

- `cargo fmt --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test --release` on Linux, macOS, and Windows
- `cargo audit` for known CVEs in dependencies
- `cargo deny check` for licence + dependency policy (`deny.toml`)

---

## Support the project

If you find this tool useful, consider supporting its development:

- **Bitcoin (BTC):** `bc1q7m5pkqy6fwlmpc0k6hcvkjs954k2jyxea3tcv0`

---

## License

MIT — see `LICENSE` (or this repository's licence file).

---

## Contributing

Pull requests, security audits, and responsible vulnerability
disclosures are welcome. Please read `SECURITY.md` before reporting
anything sensitive.
