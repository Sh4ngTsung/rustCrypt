# Security Policy

## Reporting a Vulnerability

If you believe you have found a security issue in `rcrypt`, **please do not
file a public GitHub issue**. Instead, contact the maintainer privately:

- Open a private security advisory through the GitHub UI:
  <https://github.com/Sh4ngTsung/rustCrypt/security/advisories/new>

Please include:

- A clear description of the issue and impact.
- A minimal reproducer (sample input, command line, expected vs. observed
  behavior).
- The git commit / release version affected.

We aim to acknowledge reports within 72 hours and to ship a fix or a
mitigation within 30 days for confirmed issues. Coordinated disclosure is
appreciated.

## Supported Versions

Only the latest `main` branch and the latest released tag are supported.
Older releases will not receive patches; please upgrade.

## Threat Model

`rcrypt` is a *per-file* authenticated-encryption tool. It assumes:

- **Trusted endpoints.** The machine running `rcrypt` is not actively
  compromised. We make no guarantees against an attacker who can read
  process memory, attach a debugger, or observe RAM via DMA / cold-boot.
  We do reduce exposure by zeroizing keys, refusing to dump core, and
  using `panic = "abort"`.
- **Plaintext leaves the binary.** Once decrypted, plaintext is written
  to the filesystem (or stdout for `--cat`). Protecting it after that
  point is out of scope.
- **Storage media may be flash.** The `--passes` overwrite is only
  effective on devices that honor in-place writes (HDDs, raw partitions).
  On SSDs / NVMe, wear-leveling and the FTL make secure erase impossible
  at the file level. Use full-disk encryption.
- **Symlinks are untrusted.** `rcrypt` refuses to operate on symlinks
  by default to prevent attacker-placed links from redirecting reads /
  writes to files the caller did not intend.
- **The `.rcpt` file format is a confidentiality + integrity boundary.**
  Tampering with any byte of the header or any ciphertext chunk causes
  decryption to fail (AES-256-GCM authentication, plus the header is
  bound as AAD into every chunk).
- **Passphrases are user-chosen.** We enforce a minimum length of 8 bytes
  for encryption, but recovery from a low-entropy passphrase is the
  user's responsibility; Argon2id only buys you a constant slowdown.

## Cryptographic Choices

| Concern              | Choice                                                |
| -------------------- | ----------------------------------------------------- |
| Symmetric encryption | AES-256-GCM (NIST SP 800-38D)                         |
| KDF                  | Argon2id v1.3 / RFC 9106                              |
| Default KDF cost     | t=4, m=256 MiB, p=4                                   |
| Salt                 | 16 random bytes, per file                             |
| Nonce                | 8 random + 4 counter bytes, per chunk                 |
| MAC                  | Built into GCM (16-byte tag per chunk)                |
| AAD                  | The full header is bound as AAD into every chunk      |
| RNG                  | `OsRng` (kernel CSPRNG)                               |
| Key zeroization      | `zeroize` crate on every Vec / array holding secrets  |
| Core dumps           | Disabled at startup via `/proc/self/coredump_filter`  |
| Unsafe code          | `#![forbid(unsafe_code)]` enforced at crate root      |
