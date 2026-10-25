//! Compatibility tests against archives written by older crypt builds.
//!
//! The archives are inlined below as hex, so this file is the whole test: there is
//! nothing to regenerate, no fixture files on disk, no extra tooling, and no
//! dependency on this repository's history staying intact.
//!
//! They are still *real* old archives rather than bytes produced by today's
//! writer: each was written by the build from the commit that created that format
//! version — v1 is `83c0c1d`, v3 `7a7d812`, v4 `913cb87`. (v2 was never committed,
//! so it is not covered.) That distinction is the point of the test: bytes from
//! today's writer would only prove that the writer and the reader agree with each
//! other.
//!
//! Every archive was made over the same payload with a deliberately weak Argon2id
//! config (8 KiB, 1 pass, 1 lane) and the password `correcthorse`:
//!
//! ```text
//! payload.txt        "legacy fixture file\n"
//! payload/a.txt      "legacy fixture file\n"
//! payload/sub/b.txt  "legacy fixture nested\n"
//! ```
//!
//! The file/dir pair per version covers both extraction paths (a single regular
//! file named by the header, and the sanitizing tar walk) and the three versions
//! cover what the reader still has to handle: v1 with no KDF parameters anywhere,
//! v3 with them inside the authenticated header, v4 with the authenticated
//! end-of-stream trailer.
//!
//! Gated behind `test-kdf` for the same reason `tests/cli.rs` is: for v3 and v4
//! the *header* key comes from the build's built-in parameters, which are the weak
//! ones only in a `test-kdf` build. Run with `cargo test --features test-kdf`.

#![cfg(feature = "test-kdf")]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use crypt::{DecryptOptions, Error};

const PASSWORD: &str = "correcthorse";

/// v1 stored no KDF parameters at all, so the caller supplies them: that is what
/// lets the v1 archives use the weak parameters they were written with.
const V1_KDF: (u32, u32, u32) = (8, 1, 1);

/// Every embedded archive as `(label, hex)`. Labels only appear in assertion
/// messages; each is `<format version>-<payload shape>`.
const ARCHIVES: &[(&str, &str)] = &[
    (
        "v1-file",
        "435250540100349b97af4422f6f8d3df9500f9a868c8e0521f53e44392c193dbff0d9cfe37262a003dd7\
         62732db3667822ce0edd77175689182d9f4450304035c251c16376a4c5096bc999ff0363bdb4803b6600\
         000025f08ae7b08f594dc01ae1755ff22ad97cc65aacea05cf4bdfae61e74a8bc22c92083fe69dee8124\
         4cafa63d4cc75f822d60ba0af1f0838ddebe8a3fe29eed527a6287b4a6421f78b1527dc4e25057138002\
         c50c5719c311293a4adc800a7ff34c5a047c91df0b881b3617b406dfb0edc37ba0e331b2312ef1e162ae\
         a9da97ff279a00000000",
    ),
    (
        "v1-dir",
        "435250540100e96e93ea0c600df4bc8a802890fd4401207034d9e4e7ec9f2b87ea79f19be1a62600f2e5\
         f4230252a41b5bf2b0436fb60ee2e38655fd1e6421bdd3f6e5373e00b5c2598ea5167f17880000000160\
         3120d06e2cf606a79708f1de4dc1e11a2f78f8496d95ff92b5acb0bb286b8e693af5378a9cd93b3eeba7\
         d4675092c1ba5b70c71b76ca05e47818986a4b84d39dfdd9f437fd8d853e0805153b204a50f3f6338be8\
         049fbaf730641533234978e5451762524fcda1a65dc462f4087656a802da882578edb80c09d18cc10ac0\
         153368acbe0f3dc91ea0667de0829f74c17f629032e70baf4d3071ae680eb8c1f18329c400000000",
    ),
    (
        "v3-file",
        "435250540300794377b988d86a347fc9888fa33f8e0c17baca0901ea67b55bc725aff854b2fe3600b5ca\
         8c6e1eaed522a19fbc75c97615db49992798f31295adb793b16546fef032aba155d1d5b40c0ae6710417\
         2e226efe9b7693823a4666000000209ed2bba4c722ada1411d52d2217437275cebd5451fe497c3670818\
         870593eebe2f8d613dce3bbe7840f3c1da86c69f0478fe52f8c10838e6821d63556f880c01238e7dff3d\
         77ce172bfbe3f69b46ac3f3d10c635877081d3af9209c5f39692210b83a3ecd8fb80e3e124f73c9c54cc\
         b67ce7c55621139e8f455f2293125d8aaa9300000000",
    ),
    (
        "v3-dir",
        "435250540300f413ffe58a8da34565a1c0a6521d7ff119be6a0d37c21996d601ba555dd0ccae3200a0b0\
         bb48bdaf208d0b5b86112a305ecd07d126693d38ab6392a56917a2cc40a4b131a885bd88b14c1b79ec37\
         8f7d20ce90aba5000000bcda1042a1d50445b112f7a562556f9108f69b89abd3f16598adc7f769e42138\
         ef39c23f93b12a025ceb1a27a3edf76dea6a9403124780cf7728916f8a638b3d7e801565f6ab0c948e1d\
         e59c250207c53ff6597e7e98d76ef884790ae447c5f22c3169d4ecf93f569ab5313df9108292c00af745\
         b43996e326c9ace8da3e891b7efa4887bab77ad896bfc4f7fc515ff28f217f03c8a2c18064e244f3999c\
         b7f48bee3d30fe29593f76c98ac4cce7062fc604b9947c1147f0ec90e34e09b1ad274f00000000",
    ),
    (
        "v4-file",
        "43525054040054a5d2d0eaa1c15f8a5e68f8eeee642789c2c09c2981ab05b4365c48e483ac9136005a99\
         df1dc1f7a9b382ed0bc721c0de99f78080809db73b081cbf797d7c3e92e377bd2ee362da72c43a341a2a\
         9dbc48bf0602b201a52c66000000275a105da1a60456ad7ac3bd976ba4a4bf7dcb970a859b4f8084bf03\
         8301e432c8ed77efc3c1eb8da6ea1f8c4ccb4fbbc06366a20711fd1417fee778c1eedf22297e2ce6a7c8\
         c9f295e8306d5af34f7d8dee030dff084710861667a4d9db51f7382f77b3225a77354920a1c0fa006052\
         584832f97b276dea2fc623405d2d9c474a65ffffffffb0f8ebce6c7550d342b4885eb214b141f5f16152\
         aaec9568e739a915df8a86a7b8b93de8",
    ),
    (
        "v4-dir",
        "43525054040077df3fee89a72255c75b73451edcdc5b3314b3fadeef2b1dae8993f301b7952a32002e46\
         526098d0c824b0701db364b8689b28f7ed067b19cb000cac0d0114975504db1523359c127d4457b47c3e\
         751434a3705fa500000029bc3ce0be9935602912247d3f552fa08d709c5f87a4ba8d21f67d9b8c83f72d\
         c2793c1719c172804e2303e62f83066e8eccc609f1c84cd8dab9006a2dd63fb15c7d6aa83baa12dfacdb\
         24c75b0e33c079d0893114e1837067ec2cc8bd91af1159817fb855ddca71b2d0bd4d589d12deb637fd73\
         ab7e2a8a3364282557c7a8f5a3eb17205fd67a834b3944ebdaf7d8b693a9e9ca87fc373381db2946b822\
         0d8aee038397cd84cb05c39ac62bb60fbfeb3ae84204372ccff6e09e0d97edf0e0798bffffffffb09765\
         32141f553b611f1b9641f765c70540b18e5d3a1058c8520123b6cb642a3d633389",
    ),
];

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Decode one of the constants above. A dozen lines beats a dependency.
fn unhex(hex: &str) -> Vec<u8> {
    let digits: Vec<u8> = hex.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    assert!(digits.len() % 2 == 0, "odd number of hex digits");
    digits
        .chunks(2)
        .map(|pair| {
            let nibble = |b: u8| (b as char).to_digit(16).expect("hex digit") as u8;
            (nibble(pair[0]) << 4) | nibble(pair[1])
        })
        .collect()
}

/// A fresh directory for one case, so parallel tests cannot collide.
fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "crypt-legacy-{tag}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Options for one archive. Only v1 needs `legacy_kdf` filled in; v3 and v4 carry
/// their own parameters, so the value is ignored for them.
fn options(label: &str) -> DecryptOptions {
    let mut opts = DecryptOptions {
        workers: 1,
        ..Default::default()
    };
    if label.starts_with("v1") {
        opts.legacy_kdf = V1_KDF;
    }
    opts
}

/// Write an embedded archive out, so it can be decrypted the way a real file is.
fn write_archive(dir: &Path, label: &str, hex: &str) -> PathBuf {
    let path = dir.join(format!("{label}.crypt"));
    fs::write(&path, unhex(hex)).unwrap();
    path
}

/// Every legacy version still reads, in both shapes it can hold.
#[test]
fn every_legacy_version_still_decrypts() {
    for &(label, hex) in ARCHIVES {
        let dir = scratch(label);
        let archive = write_archive(&dir, label, hex);
        let out = dir.join("out");
        fs::create_dir_all(&out).unwrap();

        let created = crypt::decrypt_file(&archive, PASSWORD, Some(&out), &options(label))
            .unwrap_or_else(|e| panic!("{label}: {e}"));

        if label.ends_with("file") {
            assert_eq!(created, vec![out.join("payload.txt")], "{label}");
            assert_eq!(
                fs::read(out.join("payload.txt")).unwrap(),
                b"legacy fixture file\n",
                "{label}"
            );
        } else {
            assert_eq!(created, vec![out.join("payload")], "{label}");
            assert_eq!(
                fs::read(out.join("payload/a.txt")).unwrap(),
                b"legacy fixture file\n",
                "{label}"
            );
            assert_eq!(
                fs::read(out.join("payload/sub/b.txt")).unwrap(),
                b"legacy fixture nested\n",
                "{label}"
            );
        }

        fs::remove_dir_all(&dir).ok();
    }
}

/// An old archive is no easier to attack than a new one: the wrong password is
/// still an authentication failure, and it still writes nothing.
#[test]
fn old_archives_still_refuse_the_wrong_password() {
    let dirs = ARCHIVES.iter().filter(|(label, _)| label.ends_with("dir"));
    for &(label, hex) in dirs {
        let dir = scratch(&format!("{label}-wrong"));
        let archive = write_archive(&dir, label, hex);
        let out = dir.join("out");
        fs::create_dir_all(&out).unwrap();

        let err = crypt::decrypt_file(&archive, "notthepassword", Some(&out), &options(label))
            .expect_err("a wrong password must fail");

        assert!(
            matches!(err, Error::Authentication(_)),
            "{label}: expected an authentication error, got {err:?}"
        );
        assert!(
            fs::read_dir(&out).unwrap().next().is_none(),
            "{label}: nothing may be written on a failed decrypt"
        );

        fs::remove_dir_all(&dir).ok();
    }
}

/// v4 introduced the authenticated end-of-stream trailer, so it is the version
/// that can prove a file was cut short. v1 and v3 end with an unauthenticated
/// marker and cannot, which is the whole reason the catacomb exists.
#[test]
fn a_truncated_v4_archive_is_rejected() {
    let (label, hex) = ARCHIVES
        .iter()
        .copied()
        .find(|(label, _)| *label == "v4-dir")
        .expect("the v4-dir archive is embedded");

    let dir = scratch("v4-truncated");
    // A trailer is `marker u32 | nonce | count u64 | tag`, so 40 bytes drops it.
    let bytes = unhex(hex);
    let archive = dir.join("cut.crypt");
    fs::write(&archive, &bytes[..bytes.len() - 40]).unwrap();

    let out = dir.join("out");
    fs::create_dir_all(&out).unwrap();
    let err = crypt::decrypt_file(&archive, PASSWORD, Some(&out), &options(label))
        .expect_err("a truncated archive must fail");

    assert!(
        matches!(err, Error::Truncated(_)),
        "expected a truncated error, got {err:?}"
    );
    assert!(
        fs::read_dir(&out).unwrap().next().is_none(),
        "no partial output may remain"
    );

    fs::remove_dir_all(&dir).ok();
}
