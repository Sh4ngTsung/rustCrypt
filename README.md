
#  rCrypt

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Build: Passing](https://img.shields.io/badge/build-passing-brightgreen)
![Language: Rust](https://img.shields.io/badge/Language-Rust-orange)

`rcrypt` is a robust, high-performance, command-line file encryption tool written in Rust.
Designed for security-critical environments, it provides authenticated encryption, memory-safe execution, parallel processing, and extreme hardening against forensic recovery.

---

##  Cryptographic Architecture

- **Encryption Algorithm**: AES-256-GCM (Authenticated Encryption with Associated Data)
- **Key Derivation Function (KDF)**: Argon2id (v19) ensuring strong resistance against GPU/ASIC brute-force and side-channel attacks.
- **Memory Protection**: Cryptographic materials (keys, passphrases, buffers) are wrapped in `Zeroizing` types, guaranteeing secure wipe from RAM immediately after use, mitigating Cold Boot Attacks and swap leaks.
- **Large File Support**: Processes data in constant-memory chunks (default 1 MiB), preventing OOM crashes even for multi-terabyte files.
- **Integrity Verification**: Strict validation of file structures, headers, and GCM authentication tags. Fails securely upon detecting tampering or truncation.

---

##  Features

-  **Multithreaded Execution**  
  Encrypt or decrypt entire directories concurrently using `-t` worker threads.

-  **In-Place Encryption**  
  Encrypt massive files directly on disk without requiring double free storage space (`-s`).

-  **Secure Wipe**  
  Multi-pass overwrite of original files before unlinking (`-p`), destroying residual magnetic traces. See Security Considerations regarding SSDs.

-  **Keyfiles & Multi-Factor Support**  
  Supports 1 MiB binary keyfiles (`-k`) that can be combined with a passphrase (`--with-pass`) for 2FA-like encryption.

-  **Pipeline Ready**  
  Decrypt directly to `stdout` (`--cat`) for shell piping without writing plaintext to disk.

---

##  Compilation & Hardening (Bunker Mode)

`rcrypt` is designed to be compiled statically with extreme system-level hardening:

- Stack Canaries
- Full RELRO
- PIE (Position Independent Executable)
- Path remapping to prevent host information leaks

###  Linux

```bash
chmod +x build_Linux.sh
./build_Linux.sh
```

Binary location:

```
./target/release/rcrypt
```

Enforced flags:

- `-fstack-protector-strong`
- Full RELRO

###  Windows

Run via Developer Command Prompt:

```cmd
build_Windows.cmd
```

Enforced flags:

- `/CETCOMPAT`
- `/NXCOMPAT`
- `/DYNAMICBASE`

---

#  Usage Guide

## 🔹 Basic Operations

### Encrypt a single file

```bash
rcrypt -e -f secret.pdf
```

Output: `secret.pdf.rcpt`  
Original file is removed.

### Decrypt a single file

```bash
rcrypt -d -f secret.pdf.rcpt
```

### Encrypt a directory recursively (8 threads)

```bash
rcrypt -e -r /path/to/confidential/ -t 8
```

---

## 🔹 Advanced Operations

### In-Place Encryption

```bash
rcrypt -e -s -f massive_database.sql
```

⚠️ If interrupted, the file may become permanently corrupted.

### Secure Wipe (3 passes)

```bash
rcrypt -e -f keys.txt -p 3
```

### Decrypt directly to stdout

```bash
rcrypt -d -c -f credentials.txt.rcpt | grep "admin"
```

### Generate and Use a Binary Keyfile

Generate:

```bash
rcrypt -g master.key
```

Encrypt:

```bash
rcrypt -e -k master.key -f data.tar.gz
```

Decrypt:

```bash
rcrypt -d -k master.key -f data.tar.gz.rcpt
```

### Combine Keyfile + Passphrase

```bash
rcrypt -e -k usb_drive/master.key --with-pass -f secret.txt
```

---

##  Environment Variables

`rcrypt` can read passphrases from:

- `RCrypt_PASS`
- `CRYPTSEC_PASS`

Example:

```bash
RCrypt_PASS="super_secret_password" rcrypt -e -f backup.zip
```

---

# ⚠️ Security Considerations

## SSDs and NVMe

The secure wipe feature (`-p` / `--passes`) is effective on magnetic HDDs.  
Due to Wear Leveling and Flash Translation Layer (FTL) behavior, overwrite cannot be guaranteed on SSD/NVMe drives at the OS level.

Recommendation: Use Full Disk Encryption (FDE) for SSD-backed systems.

## In-Place Encryption (`-s`)

- Destructive operation
- Power loss may permanently corrupt files
- Always maintain backups

---

#  CLI Reference

| Flag | Description |
|---|---|
| `-e`, `--encrypt` | Encrypt files |
| `-d`, `--decrypt` | Decrypt files |
| `-r`, `--directory` | Directory to process recursively |
| `-f`, `--single-file` | Single file to process |
| `-t`, `--threads` | Number of worker threads (default: 3) |
| `-c`, `--cat` | Print decrypted plaintext to stdout |
| `-p`, `--passes` | Overwrite passes when wiping files (0 = no overwrite) |
| `-s`, `--inplace` | In-place encryption (modifies file directly) |
| `-k`, `--key-file` | Use a binary key file instead of a passphrase |
| `--with-pass` | Combine key file with typed passphrase |
| `-g`, `--gen-key` | Generate a new random 1 MiB key file |
| `-v`, `--verbose` | Enable verbose output |
| `--include-system` | Include system noise files (`desktop.ini`, `Thumbs.db`) |

---

#  Design Philosophy

Security-first engineering principles:

- Fail securely
- Minimize attack surface
- Zero sensitive memory
- Harden binaries aggressively
- Avoid unnecessary dependencies

---

#  License

MIT (replace if different).

---

#  Contributing

Pull requests, audits, and responsible vulnerability disclosures are welcome.

---

#  rcrypt

Fast. Hardened. Memory-safe. Built for environments where encryption must not fail.