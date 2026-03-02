use assert_cmd::prelude::*;
use assert_fs::prelude::*;
use assert_fs::TempDir;
use predicates::prelude::*;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

const PW: &str = "dfKdmcDJijs93Wd23lMsd";

fn bin_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("rcrypt"))
}

fn write_file(path: &PathBuf, data: &[u8]) {
    let mut f = fs::File::create(path).unwrap();
    f.write_all(data).unwrap();
    f.flush().unwrap();
}

#[test]
fn encrypt_decrypt_roundtrip_single_file() {
    let td = TempDir::new().unwrap();
    let src = td.child("hello.txt");
    src.write_str("olá mundo\n123\n\0bin\0").unwrap();
    let src_path = src.path().to_path_buf();

    let mut cmd = bin_cmd();
    cmd.env("RCrypt_PASS", PW)
        .arg("-e")
        .arg("-f")
        .arg(&src_path)
        .arg("-v")
        .arg("-t")
        .arg("1");
    cmd.assert()
        .success()
        .stderr(predicate::str::contains("Encrypted"));

    assert!(!src_path.exists());
    let enc_path = PathBuf::from(format!("{}.rcpt", src_path.to_string_lossy()));
    assert!(enc_path.exists());

    let mut cmd = bin_cmd();
    cmd.env("RCrypt_PASS", PW)
        .arg("-d")
        .arg("-f")
        .arg(&enc_path)
        .arg("-v")
        .arg("-t")
        .arg("1");
    cmd.assert()
        .success()
        .stderr(predicate::str::contains("Processed"));

    assert!(src_path.exists());
    assert!(!enc_path.exists());
    let got = fs::read(&src_path).unwrap();
    assert_eq!(got, "olá mundo\n123\n\0bin\0".as_bytes());
}

#[test]
fn encrypt_decrypt_roundtrip_single_file_inplace() {
    let td = TempDir::new().unwrap();
    let src = td.child("hello_inplace.txt");
    src.write_str("payload-inplace-ok").unwrap();
    let src_path = src.path().to_path_buf();

    // encrypt in-place (-s)
    let mut cmd = bin_cmd();
    cmd.env("RCrypt_PASS", PW)
        .arg("-e")
        .arg("-s")
        .arg("-f")
        .arg(&src_path)
        .arg("-v")
        .arg("-t")
        .arg("1");
    cmd.assert()
        .success()
        .stderr(predicate::str::contains("Encrypted (in-place)"));

    assert!(!src_path.exists());
    let enc_path = PathBuf::from(format!("{}.rcpt", src_path.to_string_lossy()));
    assert!(enc_path.exists());

    let mut cmd = bin_cmd();
    cmd.env("RCrypt_PASS", PW)
        .arg("-d")
        .arg("-f")
        .arg(&enc_path)
        .arg("-v")
        .arg("-t")
        .arg("1");
    cmd.assert()
        .success()
        .stderr(predicate::str::contains("Processed"));

    assert!(src_path.exists());
    assert!(!enc_path.exists());
    let got = fs::read(&src_path).unwrap();
    assert_eq!(got, "payload-inplace-ok".as_bytes());
}

#[test]
fn decrypt_cat_prints_exact_bytes() {
    let td = TempDir::new().unwrap();
    let src = td.child("data.bin");
    let data: Vec<u8> = (0..=255).collect();
    src.write_binary(&data).unwrap();
    let src_path = src.path().to_path_buf();

    let mut cmd = bin_cmd();
    cmd.env("RCrypt_PASS", PW).arg("-e").arg("-f").arg(&src_path);
    cmd.assert().success();

    let enc_path = PathBuf::from(format!("{}.rcpt", src_path.to_string_lossy()));
    assert!(enc_path.exists());
    assert!(!src_path.exists());

    let mut cmd = bin_cmd();
    cmd.env("RCrypt_PASS", PW)
        .arg("-d")
        .arg("--cat")
        .arg("-f")
        .arg(&enc_path);
    cmd.assert().success().stdout(predicate::eq(data.as_slice()));
}

#[test]
fn invalid_magic_is_rejected() {
    let td = TempDir::new().unwrap();
    let bogus = td.child("fake.rcpt");
    bogus.write_str("NOT-RCrypt-Header").unwrap();

    let mut cmd = bin_cmd();
    cmd.env("RCrypt_PASS", PW).arg("-d").arg("-f").arg(bogus.path());
    cmd.assert()
        .success()
        .stderr(predicate::str::contains("invalid magic"));
}

#[test]
fn destination_exists_error_on_decrypt() {
    let td = TempDir::new().unwrap();
    let src = td.child("doc.txt");
    src.write_str("abc").unwrap();
    let src_path = src.path().to_path_buf();

    let mut cmd = bin_cmd();
    cmd.env("RCrypt_PASS", PW).arg("-e").arg("-f").arg(&src_path);
    cmd.assert().success();

    let enc_path = PathBuf::from(format!("{}.rcpt", src_path.to_string_lossy()));
    assert!(enc_path.exists());

    write_file(&src_path, b"some-content");

    let mut cmd = bin_cmd();
    cmd.env("RCrypt_PASS", PW).arg("-d").arg("-f").arg(&enc_path);
    cmd.assert()
        .success()
        .stderr(predicate::str::contains("destination already exists"));
}

#[test]
fn truncation_is_detected_or_fails() {
    let td = TempDir::new().unwrap();
    let src = td.child("big.bin");
    let data = vec![42u8; 3 * 1024 * 1024 + 123];
    src.write_binary(&data).unwrap();
    let src_path = src.path().to_path_buf();

    let mut cmd = bin_cmd();
    cmd.env("RCrypt_PASS", PW)
        .arg("-e")
        .arg("-f")
        .arg(&src_path)
        .arg("-t")
        .arg("1");
    cmd.assert().success();

    let enc_path = PathBuf::from(format!("{}.rcpt", src_path.to_string_lossy()));
    assert!(enc_path.exists());

    let meta = fs::metadata(&enc_path).unwrap();
    let new_len = meta.len().saturating_sub(1);
    {
        let f = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&enc_path)
            .unwrap();
        f.set_len(new_len).unwrap();
    }

    let mut cmd = bin_cmd();
    cmd.env("RCrypt_PASS", PW).arg("-d").arg("-f").arg(&enc_path);
    cmd.assert().success().stderr(
        predicate::str::contains("failed to decrypt chunk")
            .or(predicate::str::contains("decrypted length mismatch"))
            .or(predicate::str::contains("invalid"))
            .or(predicate::str::contains("read"))
            .or(predicate::str::contains("truncated/corrupted")),
    );
}

#[test]
fn directory_parallel_encrypt_decrypt() {
    let td = TempDir::new().unwrap();
    for i in 0..7 {
        td.child(format!("f{i}.txt"))
            .write_str(&format!("payload-{i}"))
            .unwrap();
    }

    let mut cmd = bin_cmd();
    cmd.env("RCrypt_PASS", PW)
        .arg("-e")
        .arg("-r")
        .arg(td.path())
        .arg("-t")
        .arg("4")
        .arg("-v");
    cmd.assert()
        .success()
        .stderr(predicate::str::contains("Encrypted"));

    for i in 0..7 {
        assert!(!td.child(format!("f{i}.txt")).path().exists());
        assert!(td.child(format!("f{i}.txt.rcpt")).path().exists());
    }

    let mut cmd = bin_cmd();
    cmd.env("RCrypt_PASS", PW)
        .arg("-d")
        .arg("-r")
        .arg(td.path())
        .arg("-t")
        .arg("4")
        .arg("-v");
    cmd.assert()
        .success()
        .stderr(predicate::str::contains("Processed"));

    for i in 0..7 {
        assert!(td.child(format!("f{i}.txt")).path().exists());
        assert!(!td.child(format!("f{i}.txt.rcpt")).path().exists());
    }
}

#[test]
fn binary_key_encrypt_decrypt_roundtrip() {
    let td = TempDir::new().unwrap();

    let key = td.child("key.bin");
    let key_path = key.path().to_path_buf();

    let mut cmd = bin_cmd();
    cmd.arg("-g").arg(&key_path);
    cmd.assert().success();

    let meta = fs::metadata(&key_path).unwrap();
    assert_eq!(meta.len(), 1 << 20);

    let src = td.child("secret.txt");
    src.write_str("super secret payload").unwrap();
    let src_path = src.path().to_path_buf();

    let mut cmd = bin_cmd();
    cmd.arg("-e")
        .arg("-k")
        .arg(&key_path)
        .arg("-f")
        .arg(&src_path);
    cmd.assert().success();

    let enc_path = PathBuf::from(format!("{}.rcpt", src_path.to_string_lossy()));
    assert!(enc_path.exists());
    assert!(!src_path.exists());

    let mut cmd = bin_cmd();
    cmd.arg("-d")
        .arg("-k")
        .arg(&key_path)
        .arg("-f")
        .arg(&enc_path);
    cmd.assert().success();

    assert!(src_path.exists());
    assert!(!enc_path.exists());
    let got = fs::read(&src_path).unwrap();
    assert_eq!(got, b"super secret payload");
}

#[test]
fn key_file_plus_passphrase_roundtrip() {
    let td = TempDir::new().unwrap();

    let key = td.child("key_combo.bin");
    let key_path = key.path().to_path_buf();

    let mut cmd = bin_cmd();
    cmd.arg("-g").arg(&key_path);
    cmd.assert().success();

    let src = td.child("combo.txt");
    src.write_str("key+pass combo payload").unwrap();
    let src_path = src.path().to_path_buf();

    let mut cmd = bin_cmd();
    cmd.env("RCrypt_PASS", PW)
        .arg("-e")
        .arg("-k")
        .arg(&key_path)
        .arg("--with-pass")
        .arg("-f")
        .arg(&src_path);
    cmd.assert().success();

    let enc_path = PathBuf::from(format!("{}.rcpt", src_path.to_string_lossy()));
    assert!(enc_path.exists());
    assert!(!src_path.exists());

    let mut cmd = bin_cmd();
    cmd.env("RCrypt_PASS", PW)
        .arg("-d")
        .arg("-k")
        .arg(&key_path)
        .arg("--with-pass")
        .arg("-f")
        .arg(&enc_path);
    cmd.assert().success();

    assert!(src_path.exists());
    assert!(!enc_path.exists());
    let got = fs::read(&src_path).unwrap();
    assert_eq!(got, b"key+pass combo payload");
}
