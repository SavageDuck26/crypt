//! End-to-end tests that drive the real binary.
//!
//! These are gated behind the `test-kdf` feature: with the built-in Argon2id
//! settings every single invocation would spend seconds and 512 MiB deriving a
//! key.
//!
//! Run with: `cargo test --features test-kdf`

#![cfg(feature = "test-kdf")]

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_crypt"))
}

/// A fresh, private directory for one test.
fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "crypt-it-{tag}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Run the binary against a private config path, with an optional password on
/// stdin. Returns (exit code, stdout, stderr).
fn run_in(dir: &Path, args: &[&str], password: Option<&str>) -> (i32, String, String) {
    // Beside the scratch directory, never inside it: crypt writes the config on
    // first run, and a file it creates inside a tree that is being archived would
    // end up in the archive.
    let config = dir.with_file_name(format!(
        "{}.toml",
        dir.file_name().unwrap().to_string_lossy()
    ));
    let mut command = Command::new(bin());
    command
        .args(args)
        // Relative arguments (`.`, for instance) must resolve inside the scratch
        // directory, not wherever the test harness happens to run.
        .current_dir(dir)
        .env("CRYPT_CONFIG", &config)
        .env("HOME", dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command.spawn().expect("spawn crypt");
    if let Some(password) = password {
        let mut stdin = child.stdin.take().unwrap();
        writeln!(stdin, "{password}").unwrap();
        drop(stdin);
    } else {
        drop(child.stdin.take());
    }

    let output = child.wait_with_output().unwrap();
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn only_crypt_file(dir: &Path) -> PathBuf {
    let mut found: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map(|e| e == "crypt").unwrap_or(false))
        .collect();
    assert_eq!(found.len(), 1, "expected exactly one .crypt in {dir:?}");
    found.pop().unwrap()
}

/// Names of the entries in a directory, sorted.
fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// Encrypt `input` into `out` and return the archive path.
fn encrypt(dir: &Path, input: &Path, out: &Path, password: &str) -> PathBuf {
    fs::create_dir_all(out).unwrap();
    let (code, _, stderr) = run_in(
        dir,
        &[
            "-e",
            input.to_str().unwrap(),
            "--output",
            out.to_str().unwrap(),
            "--password-stdin",
        ],
        Some(password),
    );
    assert_eq!(code, 0, "encrypt failed: {stderr}");
    only_crypt_file(out)
}

/// Decrypt `archive` into `out`.
fn decrypt(dir: &Path, archive: &Path, out: &Path, password: &str) -> (i32, String, String) {
    fs::create_dir_all(out).unwrap();
    run_in(
        dir,
        &[
            "-d",
            archive.to_str().unwrap(),
            "--output",
            out.to_str().unwrap(),
            "--password-stdin",
        ],
        Some(password),
    )
}

#[test]
fn directory_round_trip_preserves_content_mode_and_mtime() {
    let dir = scratch("roundtrip");
    let src = dir.join("src");
    let nested = src.join("sub");
    fs::create_dir_all(&nested).unwrap();
    fs::write(src.join("a.txt"), b"hello").unwrap();
    fs::write(nested.join("run.sh"), b"#!/bin/sh\necho hi\n").unwrap();
    fs::set_permissions(nested.join("run.sh"), fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(src.join("a.txt"), fs::Permissions::from_mode(0o600)).unwrap();
    filetime::set_file_mtime(
        src.join("a.txt"),
        filetime::FileTime::from_unix_time(981_173_106, 0),
    )
    .unwrap();

    let out = dir.join("out");
    let archive = encrypt(&dir, &src, &out, "correcthorse");

    let restored = dir.join("restored");
    let (code, _, stderr) = decrypt(&dir, &archive, &restored, "correcthorse");
    assert_eq!(code, 0, "decrypt failed: {stderr}");

    assert_eq!(entries(&restored), vec!["src".to_string()]);
    assert_eq!(fs::read(restored.join("src/a.txt")).unwrap(), b"hello");
    assert_eq!(
        fs::read(restored.join("src/sub/run.sh")).unwrap(),
        b"#!/bin/sh\necho hi\n"
    );

    // The executable bit survives, and the mtime is the original one.
    let mode = fs::metadata(restored.join("src/sub/run.sh"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o755, "exec bit was lost");
    let mode = fs::metadata(restored.join("src/a.txt"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);

    let meta = fs::metadata(restored.join("src/a.txt")).unwrap();
    let mtime = filetime::FileTime::from_last_modification_time(&meta);
    assert_eq!(mtime.unix_seconds(), 981_173_106, "mtime was not preserved");

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn symlinks_are_not_archived_and_do_not_leak() {
    let dir = scratch("symlink");
    let secret = dir.join("secret.txt");
    fs::write(&secret, b"TOP-SECRET-CONTENTS").unwrap();

    let src = dir.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("public.txt"), b"public").unwrap();
    std::os::unix::fs::symlink(&secret, src.join("leak.txt")).unwrap();
    std::os::unix::fs::symlink("/etc", src.join("etc")).unwrap();

    let out = dir.join("out");
    let (code, _, stderr) = {
        fs::create_dir_all(&out).unwrap();
        run_in(
            &dir,
            &[
                "-e",
                src.to_str().unwrap(),
                "--output",
                out.to_str().unwrap(),
                "--password-stdin",
            ],
            Some("correcthorse"),
        )
    };
    assert_eq!(code, 0, "encrypt failed: {stderr}");
    assert!(
        stderr.contains("symlink"),
        "the skip should be reported: {stderr}"
    );

    let restored = dir.join("restored");
    let (code, _, stderr) = decrypt(&dir, &only_crypt_file(&out), &restored, "correcthorse");
    assert_eq!(code, 0, "decrypt failed: {stderr}");

    // Neither the symlink nor anything it pointed at may appear.
    assert_eq!(
        entries(&restored.join("src")),
        vec!["public.txt".to_string()]
    );
    assert!(!restored.join("src/leak.txt").exists());
    assert!(!restored.join("src/etc").exists());

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn top_level_symlink_is_refused() {
    let dir = scratch("toplevel-symlink");
    let real = dir.join("real");
    fs::create_dir_all(&real).unwrap();
    fs::write(real.join("a.txt"), b"x").unwrap();
    let link = dir.join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();

    let out = dir.join("out");
    fs::create_dir_all(&out).unwrap();
    let (code, _, stderr) = run_in(
        &dir,
        &[
            "-e",
            link.to_str().unwrap(),
            "--output",
            out.to_str().unwrap(),
            "--password-stdin",
        ],
        Some("correcthorse"),
    );
    assert_ne!(code, 0, "a top-level symlink must be refused");
    assert!(stderr.contains("symlink"), "{stderr}");

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn wrong_password_and_tampering_leave_no_output() {
    let dir = scratch("tamper");
    let src = dir.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("a.txt"), b"hello").unwrap();
    let out = dir.join("out");
    let archive = encrypt(&dir, &src, &out, "correcthorse");
    let original = fs::read(&archive).unwrap();

    // Wrong password.
    let dest = dir.join("dest");
    let (code, _, stderr) = decrypt(&dir, &archive, &dest, "wrongpassword");
    assert_ne!(code, 0);
    assert!(stderr.contains("authentication failed"), "{stderr}");
    assert!(
        entries(&dest).is_empty(),
        "nothing may be written: {stderr}"
    );

    // Flipped byte inside the chunk stream.
    let mut flipped = original.clone();
    let last = flipped.len();
    flipped[last - 60] ^= 0x01;
    let bad = dir.join("flipped.crypt");
    fs::write(&bad, &flipped).unwrap();
    let (code, _, _) = decrypt(&dir, &bad, &dest, "correcthorse");
    assert_ne!(code, 0);
    assert!(entries(&dest).is_empty());

    // Cut on a chunk boundary: only the authenticated trailer can catch this.
    let truncated = dir.join("truncated.crypt");
    fs::write(&truncated, &original[..original.len() - 40]).unwrap();
    let (code, _, stderr) = decrypt(&dir, &truncated, &dest, "correcthorse");
    assert_ne!(code, 0);
    assert!(stderr.contains("trailer"), "{stderr}");
    assert!(entries(&dest).is_empty(), "no partial output may remain");

    // Version downgrade: the header no longer authenticates.
    let mut downgraded = original.clone();
    downgraded[4] = 4;
    downgraded[5] = 0;
    let old = dir.join("downgraded.crypt");
    fs::write(&old, &downgraded).unwrap();
    let (code, _, stderr) = decrypt(&dir, &old, &dest, "correcthorse");
    assert_ne!(code, 0);
    assert!(stderr.contains("authentication failed"), "{stderr}");
    assert!(entries(&dest).is_empty());

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn decryption_never_clobbers_existing_files() {
    let dir = scratch("clobber");
    let src = dir.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("a.txt"), b"first").unwrap();
    let out = dir.join("out");
    let archive = encrypt(&dir, &src, &out, "correcthorse");

    let dest = dir.join("dest");
    let (code, _, stderr) = decrypt(&dir, &archive, &dest, "correcthorse");
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(entries(&dest), vec!["src".to_string()]);

    let (code, _, stderr) = decrypt(&dir, &archive, &dest, "correcthorse");
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(entries(&dest), vec!["src".to_string(), "src_1".to_string()]);
    // The first copy is untouched.
    assert_eq!(fs::read(dest.join("src/a.txt")).unwrap(), b"first");

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn single_file_round_trip_uses_the_stored_name() {
    let dir = scratch("singlefile");
    let file = dir.join("notes.txt");
    fs::write(&file, b"just one file").unwrap();
    let out = dir.join("out");
    let archive = encrypt(&dir, &file, &out, "correcthorse");

    let dest = dir.join("dest");
    let (code, _, stderr) = decrypt(&dir, &archive, &dest, "correcthorse");
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(entries(&dest), vec!["notes.txt".to_string()]);
    assert_eq!(fs::read(dest.join("notes.txt")).unwrap(), b"just one file");

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn encryption_rejects_short_and_empty_passwords() {
    let dir = scratch("weakpasswords");
    let src = dir.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("a.txt"), b"hello").unwrap();
    let out = dir.join("out");
    fs::create_dir_all(&out).unwrap();

    for password in ["", "short", "1234567"] {
        let (code, _, stderr) = run_in(
            &dir,
            &[
                "-e",
                src.to_str().unwrap(),
                "--output",
                out.to_str().unwrap(),
                "--password-stdin",
            ],
            Some(password),
        );
        assert_ne!(code, 0, "password {password:?} should be refused");
        assert!(stderr.contains("password"), "{stderr}");
        assert!(entries(&out).is_empty());
    }

    // Decrypt must not apply the length rule: legacy archives may be shorter.
    let out2 = dir.join("out2");
    let archive = encrypt(&dir, &src, &out2, "correcthorse");
    let (code, _, stderr) = run_in(
        &dir,
        &[
            "-d",
            archive.to_str().unwrap(),
            "--output",
            out2.to_str().unwrap(),
            "--password-stdin",
        ],
        Some("short"),
    );
    assert_ne!(code, 0);
    assert!(
        !stderr.contains("at least"),
        "decrypt must not enforce the length rule: {stderr}"
    );

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn multiple_inputs_with_the_same_basename_stay_separate() {
    let dir = scratch("dupnames");
    let a = dir.join("a");
    let b = dir.join("b");
    fs::create_dir_all(a.join("docs")).unwrap();
    fs::create_dir_all(b.join("docs")).unwrap();
    fs::write(a.join("docs/one.txt"), b"one").unwrap();
    fs::write(b.join("docs/two.txt"), b"two").unwrap();

    let out = dir.join("out");
    fs::create_dir_all(&out).unwrap();
    let (code, _, stderr) = run_in(
        &dir,
        &[
            "-e",
            a.join("docs").to_str().unwrap(),
            b.join("docs").to_str().unwrap(),
            "--output",
            out.to_str().unwrap(),
            "--password-stdin",
        ],
        Some("correcthorse"),
    );
    assert_eq!(code, 0, "encrypt failed: {stderr}");

    let dest = dir.join("dest");
    let (code, _, stderr) = decrypt(&dir, &only_crypt_file(&out), &dest, "correcthorse");
    assert_eq!(code, 0, "{stderr}");

    // Two entries, not one merged tree.
    assert_eq!(
        entries(&dest),
        vec!["docs".to_string(), "docs_1".to_string()]
    );
    let mut files: Vec<String> = Vec::new();
    for top in ["docs", "docs_1"] {
        for entry in fs::read_dir(dest.join(top)).unwrap().filter_map(|e| e.ok()) {
            files.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    files.sort();
    assert_eq!(files, vec!["one.txt".to_string(), "two.txt".to_string()]);

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn non_utf8_filenames_survive_a_round_trip() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let dir = scratch("nonutf8");
    let src = dir.join("src");
    fs::create_dir_all(&src).unwrap();
    let odd = src.join(OsString::from_vec(b"bad\xffname".to_vec()));
    fs::write(&odd, b"payload").unwrap();

    let out = dir.join("out");
    let archive = encrypt(&dir, &src, &out, "correcthorse");
    let dest = dir.join("dest");
    let (code, _, stderr) = decrypt(&dir, &archive, &dest, "correcthorse");
    assert_eq!(code, 0, "{stderr}");

    let restored = dest
        .join("src")
        .join(OsString::from_vec(b"bad\xffname".to_vec()));
    assert!(
        restored.exists(),
        "the name lost its bytes: {:?}",
        entries(&dest)
    );
    assert_eq!(fs::read(&restored).unwrap(), b"payload");

    fs::remove_dir_all(&dir).ok();
}

/// A `.coffin` is an interrupted run, so its contents are recovered. The same
/// bytes under a `.crypt` name are still treated as a truncated archive.
#[test]
fn partial_archive_is_recovered_but_a_truncated_crypt_is_not() {
    let dir = scratch("coffin");
    let src = dir.join("src");
    fs::create_dir_all(src.join("sub")).unwrap();
    fs::write(src.join("a.txt"), b"hello").unwrap();
    fs::write(src.join("sub/b.txt"), b"world").unwrap();

    let out = dir.join("out");
    let archive = encrypt(&dir, &src, &out, "correcthorse");

    // Simulate a run that died before sealing: same bytes, no trailer.
    let bytes = fs::read(&archive).unwrap();
    let cut = &bytes[..bytes.len() - 40];
    let partial = out.join("src-1234abcd.coffin");
    fs::write(&partial, cut).unwrap();
    let truncated = out.join("truncated.crypt");
    fs::write(&truncated, cut).unwrap();

    // As a `.crypt`, the missing trailer is a hard error and nothing is written.
    let strict = dir.join("strict");
    let (code, _, stderr) = decrypt(&dir, &truncated, &strict, "correcthorse");
    assert_ne!(code, 0, "a truncated .crypt must fail");
    assert!(stderr.contains("trailer"), "{stderr}");
    assert!(entries(&strict).is_empty(), "{:?}", entries(&strict));

    // As a `.coffin`, the readable part comes back.
    let recovered = dir.join("recovered");
    let (code, _, stderr) = decrypt(&dir, &partial, &recovered, "correcthorse");
    assert_eq!(code, 0, "recovery failed: {stderr}");
    assert!(stderr.contains("partial"), "{stderr}");
    assert_eq!(fs::read(recovered.join("src/a.txt")).unwrap(), b"hello");
    assert_eq!(fs::read(recovered.join("src/sub/b.txt")).unwrap(), b"world");

    // A wrong password is still refused: recovery does not weaken authentication.
    let wrong = dir.join("wrong");
    let (code, _, _) = decrypt(&dir, &partial, &wrong, "notthepassword");
    assert_ne!(code, 0);
    assert!(entries(&wrong).is_empty());

    fs::remove_dir_all(&dir).ok();
}

/// A run that fails part way through leaves its `.coffin` behind instead of
/// deleting it, and that file decrypts to whatever was written.
#[test]
fn a_failed_run_keeps_a_recoverable_partial_archive() {
    let dir = scratch("partial-kept");
    let src = dir.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("a.txt"), b"hello").unwrap();

    // A FIFO cannot be packed, and the failure happens after the first input has
    // already been streamed into the archive.
    let fifo = dir.join("pipe");
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success(),
        "mkfifo failed"
    );

    let out = dir.join("out");
    fs::create_dir_all(&out).unwrap();
    let opts = crypt::EncryptOptions {
        workers: 1,
        level: 1,
    };
    let err = crypt::encrypt_file(&[src, fifo], "correcthorse", Some(&out), &opts)
        .expect_err("packing a FIFO must fail");
    assert!(err.to_string().contains("regular file"), "{err}");

    let coffins: Vec<PathBuf> = fs::read_dir(&out)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .map(|e| e.to_string_lossy() == "coffin")
                .unwrap_or(false)
        })
        .collect();
    assert_eq!(
        coffins.len(),
        1,
        "the partial archive should have been kept"
    );
    assert!(
        !out.join("x.crypt").exists(),
        "no .crypt should be published"
    );

    let recovered = dir.join("recovered");
    let (code, _, stderr) = decrypt(&dir, &coffins[0], &recovered, "correcthorse");
    assert_eq!(code, 0, "recovery failed: {stderr}");
    assert_eq!(fs::read(recovered.join("src/a.txt")).unwrap(), b"hello");

    fs::remove_dir_all(&dir).ok();
}

/// `crypt -e .` names the folder after itself, and the archive being written is
/// never packed into the archive it is becoming.
#[test]
fn encrypting_the_current_directory_never_packs_the_archive() {
    let dir = scratch("dot");
    fs::write(dir.join("a.txt"), b"hello").unwrap();
    fs::create_dir_all(dir.join("sub")).unwrap();
    fs::write(dir.join("sub/b.txt"), b"world").unwrap();

    // Input and output are both ".": the natural way to hit this.
    let (code, _, stderr) = run_in(
        &dir,
        &["-e", ".", "--output", ".", "--password-stdin"],
        Some("correcthorse"),
    );
    assert_eq!(code, 0, "encrypting '.' must work: {stderr}");
    assert!(
        stderr.contains("archive crypt is writing"),
        "the skipped staging file should be reported: {stderr}"
    );

    let archive = only_crypt_file(&dir);
    assert!(
        archive
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with(&*dir.file_name().unwrap().to_string_lossy()),
        "the archive is named after the directory: {archive:?}"
    );

    let restored = dir.join("restored");
    let (code, _, stderr) = decrypt(&dir, &archive, &restored, "correcthorse");
    assert_eq!(code, 0, "{stderr}");

    let tops = entries(&restored);
    assert_eq!(tops.len(), 1, "{tops:?}");
    let inner = entries(&restored.join(&tops[0]));
    assert_eq!(
        inner,
        vec!["a.txt".to_string(), "sub".to_string()],
        "no .coffin may be packed into the archive it belongs to"
    );
    assert_eq!(
        fs::read(restored.join(&tops[0]).join("sub/b.txt")).unwrap(),
        b"world"
    );

    fs::remove_dir_all(&dir).ok();
}

/// The library entry points are usable without the CLI, and failures arrive as
/// typed variants rather than as strings.
#[test]
fn library_round_trip_through_the_public_api() {
    let dir = scratch("libapi");
    let src = dir.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("a.txt"), b"hello").unwrap();

    let out = dir.join("out");
    let opts = crypt::EncryptOptions {
        workers: 1,
        ..Default::default()
    };
    let archive = crypt::encrypt_file(
        std::slice::from_ref(&src),
        "correcthorse",
        Some(&out),
        &opts,
    )
    .expect("encrypt_file");

    let dest = dir.join("dest");
    let created = crypt::decrypt_file(
        &archive,
        "correcthorse",
        Some(&dest),
        &crypt::DecryptOptions::default(),
    )
    .expect("decrypt_file");
    assert_eq!(created.len(), 1, "{created:?}");
    assert_eq!(fs::read(dest.join("src/a.txt")).unwrap(), b"hello");

    // A wrong password is an authentication failure, and writes nothing.
    let wrong = dir.join("wrong");
    fs::create_dir_all(&wrong).unwrap();
    let err = crypt::decrypt_file(
        &archive,
        "notthepassword",
        Some(&wrong),
        &crypt::DecryptOptions::default(),
    )
    .expect_err("a wrong password must fail");
    assert!(
        matches!(err, crypt::Error::Authentication(_)),
        "expected an authentication error, got {err:?}"
    );
    assert!(entries(&wrong).is_empty(), "{:?}", entries(&wrong));

    // A cut file is reported as truncated, which is the variant that tells a
    // caller "recover what you can" instead of "you got the password wrong".
    let bytes = fs::read(&archive).unwrap();
    let cut = dir.join("cut.crypt");
    fs::write(&cut, &bytes[..bytes.len() - 40]).unwrap();
    let partial_out = dir.join("partial");
    fs::create_dir_all(&partial_out).unwrap();
    let err = crypt::decrypt_file(
        &cut,
        "correcthorse",
        Some(&partial_out),
        &crypt::DecryptOptions::default(),
    )
    .expect_err("a truncated archive must fail");
    assert!(
        matches!(err, crypt::Error::Truncated(_)),
        "expected a truncated error, got {err:?}"
    );
    assert!(entries(&partial_out).is_empty());

    fs::remove_dir_all(&dir).ok();
}
