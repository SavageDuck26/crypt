//! crypt — core library.
//!
//! Everything except argument-parsing-to-exit-code plumbing lives here, so the
//! format, framing and path logic can be unit tested without spawning a process
//! or needing a terminal.
//!
//! # Format (v5)
//!
//! ```text
//! magic "CRPT" | version u16le | salt[32] | header_len u16le | header_ct[header_len]
//! chunk* | CATACOMB_MARKER u32le | catacomb_ct[36]
//!
//! header_ct = AES-256-GCM(header_key, nonce[12] || ct || tag[16], aad = header_aad(version, salt))
//! chunk     = pt_len u32le | AES-256-GCM(data_key, aad = chunk_index u64le)
//! catacomb  = AES-256-GCM(data_key, plaintext = total_chunk_count u64le, aad = CATACOMB_AAD)
//! ```
//!
//! v5 binds the magic, version and salt into the header's AAD, so the version
//! byte can no longer be edited without failing authentication. v1–v4 used an
//! empty header AAD and are still readable (their version field is inherently
//! unauthenticated).
//!
//! # Key schedule
//!
//! `master = Argon2id(password, salt, built-in params)` (64 bytes), split into
//! two independent 32-byte keys: the header key and the data key. One KDF call
//! per file. The parameters are built into the binary and never read from the
//! file or the config, so there is no downgrade surface and nothing to validate.
//!
//! # Public API
//!
//! [`encrypt_file`] and [`decrypt_file`] are the library surface, their knobs
//! live in [`EncryptOptions`] and [`DecryptOptions`], and failures come back as
//! a typed [`Error`]. [`run_os`] is the CLI entry point — [`run`] is the same
//! thing for callers that only have `String`s, and the binary uses the `OsString`
//! one so a path that is not valid UTF-8 still arrives intact. The config file is
//! a CLI convenience that a library caller simply does not use.

use std::collections::HashMap;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, BufWriter, IsTerminal, Read, Seek, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;

use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use serde::Deserialize;
use termios::{Termios, ECHO, ICANON, ISIG, TCSANOW};
use zeroize::{Zeroize, Zeroizing};
use zstd::bulk::Decompressor;

// ---------------------------------------------------------------------------
// Format constants
// ---------------------------------------------------------------------------

/// Uncompressed chunk size. Nothing else in the format depends on this value.
const CHUNK_SIZE: usize = 16 * 1024 * 1024;
const SALT_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;
const GCM_TAG_SIZE: usize = 16;
const KEY_SIZE: usize = 32;

const CRYPT_MAGIC: &[u8; 4] = b"CRPT";
/// Version written by this build.
const CRYPT_VERSION: u16 = 5;
/// Oldest version this build can read.
///
/// The builds that wrote v1–v4 are still in this repository's history (`83c0c1d`,
/// `7a7d812`, `913cb87`), which is where the archives embedded in
/// `tests/legacy.rs` came from if one ever needs adding.
const MIN_READABLE_VERSION: u16 = 1;

/// The version that introduced the authenticated header AAD.
const VERSION_AUTHENTICATED_HEADER: u16 = 5;
/// The version that introduced the catacomb (authenticated end-of-stream trailer).
const VERSION_CATACOMB: u16 = 4;

/// Never a valid chunk length (chunks are <= `max_chunk_pt_len()`), so it can be
/// recognised as the start of the end-of-stream trailer.
const CATACOMB_MARKER: u32 = 0xFFFF_FFFF;
const CATACOMB_AAD: &[u8] = b"CRPT-catacomb";
/// Domain separation for the v5 header AAD.
const HEADER_AAD_DOMAIN: &[u8] = b"crypt/v5/header";
/// Legacy (v1–v4) unauthenticated end-of-stream marker.
const LEGACY_TRAILER: u32 = 0;

/// Largest plaintext length a single chunk may declare on disk.
///
/// This is exactly what `zstd::bulk::Compressor::compress` can emit for a
/// `CHUNK_SIZE` input (`compress_bound`), so it is tight rather than generous —
/// a tampered `pt_len` above this is rejected before any allocation happens.
fn max_chunk_pt_len() -> usize {
    zstd::zstd_safe::compress_bound(CHUNK_SIZE)
}

// ---------------------------------------------------------------------------
// KDF parameters
// ---------------------------------------------------------------------------

/// Built-in header/data KDF parameters. These are deliberately **not** stored in
/// the file and **not** configurable: the header key would otherwise be derived
/// from an attacker-supplied cost, which is a denial-of-service and downgrade
/// surface. Changing them changes the format's key schedule.
#[cfg(not(feature = "test-kdf"))]
mod kdf_strength {
    pub const MEM_COST: u32 = 512 * 1024; // 512 MiB, in KiB
    pub const TIME_COST: u32 = 12;
    pub const PARALLELISM: u32 = 2;
}

/// Deliberately weak parameters, for the test suite only. A single round trip
/// under the real settings costs seconds per file and hundreds of MB of RAM.
///
/// Files written with this feature cannot be read by a normal build, so it must
/// never be enabled for real archives.
#[cfg(feature = "test-kdf")]
mod kdf_strength {
    pub const MEM_COST: u32 = 8;
    pub const TIME_COST: u32 = 1;
    pub const PARALLELISM: u32 = 1;
}

// A weak-KDF build should be impossible in release, not merely discouraged.
// `debug_assertions` is on for the dev and test profiles and off for release, so
// this fires for `cargo build --release --features test-kdf` and stays quiet for
// `cargo test --features test-kdf`.
#[cfg(all(feature = "test-kdf", not(debug_assertions)))]
compile_error!(
    "the `test-kdf` feature is for testing only: it derives keys with deliberately weak \
     parameters, so it must not be enabled in a release build"
);

const HEADER_ARGON2_MEM_COST: u32 = kdf_strength::MEM_COST;
const HEADER_ARGON2_TIME_COST: u32 = kdf_strength::TIME_COST;
const HEADER_ARGON2_PARALLELISM: u32 = kdf_strength::PARALLELISM;

/// The built-in parameters as a tuple: the fallback for v1 archives, which store
/// no KDF parameters of their own.
const BUILT_IN_KDF: (u32, u32, u32) = (
    HEADER_ARGON2_MEM_COST,
    HEADER_ARGON2_TIME_COST,
    HEADER_ARGON2_PARALLELISM,
);

/// Bounds accepted for KDF params read back from a **legacy** (v1–v4) file.
const MIN_ARGON2_MEM_COST: u32 = 8;
const MAX_ARGON2_MEM_COST: u32 = 4 * 1024 * 1024; // 4 GiB, in KiB
const MAX_ARGON2_TIME_COST: u32 = 4096;
const MAX_ARGON2_PARALLELISM: u32 = 256;

// ---------------------------------------------------------------------------
// CLI/config defaults
// ---------------------------------------------------------------------------

const DEFAULT_NUM_WORKERS: usize = 4;

/// Most workers crypt will start, from any of the ways the count can arrive
/// (`--workers`, `num_workers` in the config, or `EncryptOptions::workers` and
/// `DecryptOptions::workers` for a library caller). Each worker holds a 16 MiB
/// chunk and its own Zstd context, and a chunk is memory rather than CPU bound
/// once the level is high, so a larger number buys nothing but a bigger footprint
/// and a thread that cannot be started.
const MAX_WORKERS: usize = 128;

/// Longest password accepted from a pipe, in bytes.
///
/// The prompt cannot exceed this because a person is typing, but a pipe can send
/// anything at all, and `read_line` would happily allocate it. A password that
/// does not fit here is not a password crypt encrypted anything with.
const MAX_PIPED_PASSWORD_BYTES: usize = 4096;
const DEFAULT_ZSTD_COMPRESSION_LEVEL: i32 = 22;
const MIN_ZSTD_LEVEL: i32 = 1;
const MAX_ZSTD_LEVEL: i32 = 22;

/// Minimum password length enforced **on encrypt only**. Decrypting legacy
/// archives may legitimately require shorter (or empty) passwords.
const MIN_PASSWORD_LEN: usize = 8;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a crypt operation failed.
///
/// The variants split the failures a caller can actually act on: a wrong
/// password, a damaged file, and a bad request are three different things.
/// The message is the operator-facing text (the same text the CLI prints) and is
/// deliberately preserved verbatim rather than reworded per variant.
///
/// Wrong password and tampering are *not* distinguished: telling them apart
/// would turn the tool into an oracle for attackers. Both are
/// [`Error::Authentication`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The request itself was unusable: no inputs, a path that cannot be
    /// archived, an output that would be overwritten, a password that breaks
    /// the documented rules, an unparsable argument.
    InvalidInput(String),
    /// The file is not a crypt archive, uses a version this build cannot read,
    /// or its framing is corrupt (bad lengths, a decompression bomb, absurd
    /// legacy KDF parameters).
    Malformed(String),
    /// The archive ends before its authenticated end-of-stream trailer, so part
    /// of the data is missing. The bytes that *are* there may still be sound,
    /// which is what "recover a `.coffin`" leans on.
    Truncated(String),
    /// Authentication failed: the password was wrong, or the archive was
    /// tampered with.
    Authentication(String),
    /// Anything else: I/O, a thread that died, an internal invariant.
    Other(String),
}

impl Error {
    /// The operator-facing message, without the variant's framing.
    pub fn message(&self) -> &str {
        match self {
            Error::InvalidInput(message)
            | Error::Malformed(message)
            | Error::Truncated(message)
            | Error::Authentication(message)
            | Error::Other(message) => message,
        }
    }

    fn invalid_input(message: impl Into<String>) -> Error {
        Error::InvalidInput(message.into())
    }

    fn malformed(message: impl Into<String>) -> Error {
        Error::Malformed(message.into())
    }

    fn truncated(message: impl Into<String>) -> Error {
        Error::Truncated(message.into())
    }

    fn authentication(message: impl Into<String>) -> Error {
        Error::Authentication(message.into())
    }

    fn other(message: impl Into<String>) -> Error {
        Error::Other(message.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for Error {}

/// `Result` with this crate's [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// TOML config. The `argon2_*` fields are accepted so existing config files keep
/// parsing, but they are ignored: KDF strength is fixed by the format (see
/// `HEADER_ARGON2_*`). They still affect decryption of legacy v1 archives.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(default)]
struct Config {
    pub num_workers: usize,
    pub zstd_compression_level: i32,
    pub argon2_mem_cost: u32,
    pub argon2_time_cost: u32,
    pub argon2_parallelism: u32,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            num_workers: DEFAULT_NUM_WORKERS,
            zstd_compression_level: DEFAULT_ZSTD_COMPRESSION_LEVEL,
            argon2_mem_cost: HEADER_ARGON2_MEM_COST,
            argon2_time_cost: HEADER_ARGON2_TIME_COST,
            argon2_parallelism: HEADER_ARGON2_PARALLELISM,
        }
    }
}

/// The template written on first run. It is the file at the repo root, so the
/// shipped default and the written default cannot drift apart.
const DEFAULT_CONFIG_TOML: &str = include_str!("../CryptConfig.toml");

/// Where crypt looks for a config file, in order.
fn config_search_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Some(explicit) = env::var_os("CRYPT_CONFIG") {
        if !explicit.is_empty() {
            paths.push(PathBuf::from(explicit));
        }
    }

    let base = env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")));
    if let Some(base) = base {
        paths.push(base.join("crypt").join("CryptConfig.toml"));
    }

    // Legacy location: next to the executable.
    if let Ok(exe) = env::current_exe() {
        if let Some(dir) = exe.parent() {
            paths.push(dir.join("CryptConfig.toml"));
        }
    }

    paths
}

/// Parse config text without touching the filesystem (unit-testable).
fn parse_config(text: &str) -> Result<Config> {
    let config: Config = toml::from_str(text).map_err(|e| Error::invalid_input(e.to_string()))?;
    if config.num_workers == 0 {
        return Err(Error::invalid_input("num_workers must be at least 1"));
    }
    Ok(config)
}

/// Load the config, falling back to defaults. Never panics and never exits: a
/// read-only config directory or a deleted binary must not stop the program.
fn load_config() -> Config {
    for path in config_search_paths() {
        if !path.is_file() {
            continue;
        }
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) => {
                eprintln!(
                    "[WARN] Cannot read config '{}': {}. Using built-in defaults.",
                    path.display(),
                    e
                );
                return Config::default();
            }
        };
        return match parse_config(&text) {
            Ok(config) => {
                warn_ignored_kdf_settings(&config, &path);
                config
            }
            Err(e) => {
                eprintln!(
                    "[WARN] Failed to parse config '{}': {}. Using built-in defaults.",
                    path.display(),
                    e
                );
                Config::default()
            }
        };
    }

    // Nothing on disk yet: try to write the template, but carry on if we can't
    // (read-only install directory, /nix/store, sealed .app bundle, ...).
    if let Some(path) = config_search_paths().first().cloned() {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        match fs::write(&path, DEFAULT_CONFIG_TOML) {
            Ok(()) => println!("Created default config: {}", path.display()),
            Err(e) => eprintln!(
                "[WARN] Could not write default config to '{}': {}. Using built-in defaults.",
                path.display(),
                e
            ),
        }
    }
    Config::default()
}

/// The KDF keys in the config no longer affect new archives; say so rather than
/// silently ignoring a user's security settings.
fn warn_ignored_kdf_settings(config: &Config, path: &Path) {
    let defaults = Config::default();
    let changed = config.argon2_mem_cost != defaults.argon2_mem_cost
        || config.argon2_time_cost != defaults.argon2_time_cost
        || config.argon2_parallelism != defaults.argon2_parallelism;
    if changed {
        eprintln!(
            "[WARN] '{}' sets argon2_* options ({}, {}, {}); they are fixed at ({}, {}, {}) by the \
             file format and will be ignored. They still apply when reading v1 archives.",
            path.display(),
            config.argon2_mem_cost,
            config.argon2_time_cost,
            config.argon2_parallelism,
            defaults.argon2_mem_cost,
            defaults.argon2_time_cost,
            defaults.argon2_parallelism,
        );
    }
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

/// The two independent keys a v5 file uses.
struct FileKeys {
    pub header: Zeroizing<[u8; KEY_SIZE]>,
    pub data: Zeroizing<[u8; KEY_SIZE]>,
}

/// Build Argon2id, returning an error instead of panicking on bad parameters
/// (which legacy files and config values can supply).
fn build_argon2(mem_cost: u32, time_cost: u32, parallelism: u32) -> Result<Argon2<'static>> {
    let params = Params::new(mem_cost, time_cost, parallelism, None).map_err(|e| {
        Error::other(format!(
            "invalid Argon2id parameters ({mem_cost}, {time_cost}, {parallelism}): {e}"
        ))
    })?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Derive a single key. Used for legacy (v1–v4) files only.
fn derive_single_key(
    password: &str,
    salt: &[u8; SALT_SIZE],
    mem_cost: u32,
    time_cost: u32,
    parallelism: u32,
) -> Result<Zeroizing<[u8; KEY_SIZE]>> {
    let mut key = Zeroizing::new([0u8; KEY_SIZE]);
    build_argon2(mem_cost, time_cost, parallelism)?
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|e| Error::other(format!("key derivation failed: {e}")))?;
    Ok(key)
}

/// Derive the v5 header and data keys with a single Argon2id call.
///
/// The 64-byte output is split into two independent 32-byte keys. This is domain
/// separation with no extra dependencies; HKDF-Expand over a 32-byte master
/// would be the textbook alternative (at the cost of two more crates).
fn derive_keys(password: &str, salt: &[u8; SALT_SIZE]) -> Result<FileKeys> {
    let mut master = Zeroizing::new([0u8; KEY_SIZE * 2]);
    build_argon2(
        HEADER_ARGON2_MEM_COST,
        HEADER_ARGON2_TIME_COST,
        HEADER_ARGON2_PARALLELISM,
    )?
    .hash_password_into(password.as_bytes(), salt, master.as_mut())
    .map_err(|e| Error::other(format!("key derivation failed: {e}")))?;

    let mut header = Zeroizing::new([0u8; KEY_SIZE]);
    let mut data = Zeroizing::new([0u8; KEY_SIZE]);
    header.copy_from_slice(&master[..KEY_SIZE]);
    data.copy_from_slice(&master[KEY_SIZE..]);
    Ok(FileKeys { header, data })
}

// ---------------------------------------------------------------------------
// AEAD helpers
// ---------------------------------------------------------------------------

/// Build the AES-256-GCM cipher, refusing a key of the wrong size.
///
/// `Aes256Gcm::new` panics on a wrong length. Every caller here passes
/// [`KEY_SIZE`] bytes, but reporting rather than aborting is what keeps the
/// library's side of the bargain: bad input is an error, never a panic.
fn cipher_for(key: &[u8]) -> Result<Aes256Gcm> {
    Aes256Gcm::new_from_slice(key).map_err(|_| {
        Error::other(format!(
            "internal error: the AES-GCM key must be {KEY_SIZE} bytes, got {}",
            key.len()
        ))
    })
}

fn aes_encrypt(data: &[u8], key: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = cipher_for(key)?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, Payload { msg: data, aad })
        .map_err(|e| Error::other(format!("AES-GCM encryption failed: {e}")))?;
    let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

fn aes_decrypt(encrypted: &[u8], key: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if encrypted.len() < NONCE_SIZE + GCM_TAG_SIZE {
        return Err(Error::malformed("ciphertext is too short"));
    }
    let nonce = &encrypted[..NONCE_SIZE];
    let ciphertext = &encrypted[NONCE_SIZE..];
    let cipher = cipher_for(key)?;
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| {
            Error::authentication("authentication failed (wrong password or corrupted file)")
        })
}

/// AAD for a data chunk: its index as u64 LE, binding ciphertext to position so
/// reordering or duplication is detected.
fn chunk_aad(index: u64) -> [u8; 8] {
    index.to_le_bytes()
}

/// AAD for the header. v5+ binds the magic, version and salt, so editing the
/// version to steer the parser makes the header fail to authenticate.
/// v1–v4 used an empty AAD (their version field is unauthenticated by design).
fn header_aad(version: u16, salt: &[u8]) -> Vec<u8> {
    if version < VERSION_AUTHENTICATED_HEADER {
        return Vec::new();
    }
    let mut aad = Vec::with_capacity(4 + 2 + salt.len() + HEADER_AAD_DOMAIN.len());
    aad.extend_from_slice(CRYPT_MAGIC);
    aad.extend_from_slice(&version.to_le_bytes());
    aad.extend_from_slice(salt);
    aad.extend_from_slice(HEADER_AAD_DOMAIN);
    aad
}

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

/// What a decrypted header tells us.
#[derive(Debug)]
struct HeaderInfo {
    pub is_directory: bool,
    /// Raw name bytes, exactly as stored (may not be valid UTF-8).
    pub name: Vec<u8>,
    /// Data KDF params for legacy v3/v4 files.
    pub kdf: Option<(u32, u32, u32)>,
}

/// Encode the v5 header plaintext: `'D'|'F' | name_len u16le | name`.
fn encode_header_plaintext(is_directory: bool, name: &[u8]) -> Result<Vec<u8>> {
    if name.len() > u16::MAX as usize {
        return Err(Error::invalid_input(format!(
            "archive name is too long ({} bytes, maximum {})",
            name.len(),
            u16::MAX
        )));
    }
    let mut out = Vec::with_capacity(3 + name.len());
    out.push(if is_directory { b'D' } else { b'F' });
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(name);
    Ok(out)
}

/// Decode a header plaintext. For v3/v4 the trailing 12 bytes are the data KDF
/// params; v5 has none (its key schedule is fixed), and v2 kept them in the
/// clear prefix, which `read_raw_header` handles.
fn parse_header_plaintext(plaintext: &[u8], version: u16) -> Result<HeaderInfo> {
    if plaintext.len() < 3 {
        return Err(Error::malformed("header is too short"));
    }
    let is_directory = match plaintext[0] {
        b'D' => true,
        b'F' => false,
        other => {
            return Err(Error::malformed(format!(
                "header has an unknown type byte 0x{other:02x}"
            )))
        }
    };
    let name_len = u16::from_le_bytes([plaintext[1], plaintext[2]]) as usize;
    let name_end = 3usize
        .checked_add(name_len)
        .ok_or_else(|| Error::malformed("header name length overflows"))?;
    if plaintext.len() < name_end {
        return Err(Error::malformed(
            "header is shorter than its declared name length",
        ));
    }
    let name = plaintext[3..name_end].to_vec();

    let kdf = if (3..VERSION_AUTHENTICATED_HEADER).contains(&version) {
        let start = name_end;
        let end = start + 12;
        if plaintext.len() < end {
            return Err(Error::malformed("header is missing its KDF parameters"));
        }
        let p = &plaintext[start..end];
        Some((
            u32::from_le_bytes([p[0], p[1], p[2], p[3]]),
            u32::from_le_bytes([p[4], p[5], p[6], p[7]]),
            u32::from_le_bytes([p[8], p[9], p[10], p[11]]),
        ))
    } else {
        None
    };

    Ok(HeaderInfo {
        is_directory,
        name,
        kdf,
    })
}

/// Reject absurd KDF parameters from a legacy file before deriving anything, so
/// a tampered header cannot exhaust memory or CPU.
fn validate_kdf_params(mem_cost: u32, time_cost: u32, parallelism: u32) -> Result<()> {
    if !(MIN_ARGON2_MEM_COST..=MAX_ARGON2_MEM_COST).contains(&mem_cost) {
        return Err(Error::malformed(format!(
            "mem_cost {mem_cost} is out of range ({}..={} KiB)",
            MIN_ARGON2_MEM_COST, MAX_ARGON2_MEM_COST
        )));
    }
    if !(1..=MAX_ARGON2_TIME_COST).contains(&time_cost) {
        return Err(Error::malformed(format!(
            "time_cost {time_cost} is out of range (1..={MAX_ARGON2_TIME_COST})"
        )));
    }
    if !(1..=MAX_ARGON2_PARALLELISM).contains(&parallelism) {
        return Err(Error::malformed(format!(
            "parallelism {parallelism} is out of range (1..={MAX_ARGON2_PARALLELISM})"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Framing: header prefix
// ---------------------------------------------------------------------------

/// Everything before (and including) the encrypted header.
#[derive(Debug)]
struct RawHeader {
    pub version: u16,
    pub salt: [u8; SALT_SIZE],
    pub encrypted: Vec<u8>,
    /// v2 stored the data KDF params in the clear, before the header length.
    pub clear_kdf: Option<(u32, u32, u32)>,
    /// Bytes consumed from the start of the file, including the encrypted header.
    pub header_skip: u64,
}

fn read_raw_header<R: Read>(reader: &mut R) -> Result<RawHeader> {
    let mut magic = [0u8; 4];
    reader
        .read_exact(&mut magic)
        .map_err(|_| Error::malformed("file is too short to be a crypt archive"))?;
    if &magic != CRYPT_MAGIC {
        return Err(Error::malformed("bad magic: not a crypt archive"));
    }

    let mut version_bytes = [0u8; 2];
    reader
        .read_exact(&mut version_bytes)
        .map_err(|_| Error::truncated("file is truncated (missing version)"))?;
    let version = u16::from_le_bytes(version_bytes);
    if !(MIN_READABLE_VERSION..=CRYPT_VERSION).contains(&version) {
        return Err(Error::malformed(format!(
            "unsupported format version {version} (this build reads \
             {MIN_READABLE_VERSION}..={CRYPT_VERSION})"
        )));
    }

    let mut salt = [0u8; SALT_SIZE];
    reader
        .read_exact(&mut salt)
        .map_err(|_| Error::truncated("file is truncated (missing salt)"))?;

    let clear_kdf = if version == 2 {
        let mut p = [0u8; 12];
        reader
            .read_exact(&mut p)
            .map_err(|_| Error::truncated("file is truncated (missing KDF parameters)"))?;
        Some((
            u32::from_le_bytes([p[0], p[1], p[2], p[3]]),
            u32::from_le_bytes([p[4], p[5], p[6], p[7]]),
            u32::from_le_bytes([p[8], p[9], p[10], p[11]]),
        ))
    } else {
        None
    };

    let mut len_bytes = [0u8; 2];
    reader
        .read_exact(&mut len_bytes)
        .map_err(|_| Error::truncated("file is truncated (missing header)"))?;
    let header_len = u16::from_le_bytes(len_bytes) as usize;

    let mut encrypted = vec![0u8; header_len];
    reader
        .read_exact(&mut encrypted)
        .map_err(|_| Error::truncated("file is truncated (header is incomplete)"))?;

    let header_skip =
        4 + 2 + SALT_SIZE as u64 + clear_kdf.map_or(0, |_| 12) + 2 + header_len as u64;

    Ok(RawHeader {
        version,
        salt,
        encrypted,
        clear_kdf,
        header_skip,
    })
}

/// Decrypt and parse a raw header. `header_key` must already be derived for the
/// claimed version. On failure the claimed version was wrong, the password was
/// wrong, or the header was edited — all three are reported the same way.
///
/// `legacy_kdf` only matters for v1 archives, which store no KDF parameters of
/// their own.
fn authenticate_header(
    raw: &RawHeader,
    header_key: &[u8],
    legacy_kdf: (u32, u32, u32),
) -> Result<HeaderInfo> {
    let aad = header_aad(raw.version, &raw.salt);
    let plaintext = aes_decrypt(&raw.encrypted, header_key, &aad).map_err(|_| {
        Error::authentication(
            "header authentication failed: wrong password, or the header was tampered with",
        )
    })?;

    let info = parse_header_plaintext(&plaintext, raw.version)?;

    // v1 archives carry no KDF params; fall back to the caller's settings.
    let effective_kdf = if raw.version == 1 {
        Some(legacy_kdf)
    } else if let Some(params) = raw.clear_kdf {
        Some(params)
    } else {
        info.kdf
    };

    if let Some((mem, time, par)) = effective_kdf {
        validate_kdf_params(mem, time, par)?;
    }

    Ok(info)
}

// ---------------------------------------------------------------------------
// Framing: chunk records
// ---------------------------------------------------------------------------

/// One record read from the chunk stream.
enum ChunkFrame {
    Data {
        plaintext: Zeroizing<Vec<u8>>,
    },
    End {
        /// Chunk count recorded in the authenticated catacomb, or `None` for the
        /// unauthenticated legacy (v1–v3) trailer.
        total_chunks: Option<u64>,
    },
}

/// Read one chunk record, or the end-of-stream trailer.
///
/// The declared length is validated **before** any allocation, so a tampered
/// `pt_len` can no longer request a multi-gigabyte buffer.
fn read_chunk_frame<R: Read>(
    reader: &mut R,
    key: &[u8],
    index: u64,
    allow_legacy_trailer: bool,
) -> Result<ChunkFrame> {
    let mut len_bytes = [0u8; 4];
    match reader.read_exact(&mut len_bytes) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
            return Err(Error::truncated(
                "file is truncated: the end-of-stream trailer is missing, so the data \
                        may be incomplete",
            ));
        }
        Err(e) => return Err(Error::other(format!("read failed: {e}"))),
    }
    let pt_len = u32::from_le_bytes(len_bytes);

    if pt_len == CATACOMB_MARKER {
        let mut buf = [0u8; NONCE_SIZE + 8 + GCM_TAG_SIZE];
        reader.read_exact(&mut buf).map_err(|_| {
            Error::truncated("file is truncated: the end-of-stream trailer is incomplete")
        })?;
        let plaintext = aes_decrypt(&buf, key, CATACOMB_AAD).map_err(|_| {
            Error::authentication("the end-of-stream trailer failed authentication: the file is truncated or tampered \
             with")
        })?;
        if plaintext.len() != 8 {
            return Err(Error::malformed(
                "the end-of-stream trailer has an unexpected size",
            ));
        }
        let mut count = [0u8; 8];
        count.copy_from_slice(&plaintext);
        return Ok(ChunkFrame::End {
            total_chunks: Some(u64::from_le_bytes(count)),
        });
    }

    if pt_len == LEGACY_TRAILER {
        if !allow_legacy_trailer {
            return Err(Error::truncated(
                "file is truncated: an authenticated end-of-stream trailer was expected",
            ));
        }
        return Ok(ChunkFrame::End { total_chunks: None });
    }

    let pt_len = pt_len as usize;
    let max = max_chunk_pt_len();
    if pt_len > max {
        return Err(Error::malformed(format!(
            "chunk {index} declares an impossible length ({pt_len} bytes; the maximum is {max})"
        )));
    }

    let mut buf = vec![0u8; NONCE_SIZE + pt_len + GCM_TAG_SIZE];
    reader
        .read_exact(&mut buf)
        .map_err(|_| Error::truncated(format!("file is truncated: chunk {index} is incomplete")))?;
    let plaintext = aes_decrypt(&buf, key, &chunk_aad(index)).map_err(|_| {
        Error::authentication(format!(
            "chunk {index} failed authentication (wrong password, reordering or corruption)"
        ))
    })?;
    Ok(ChunkFrame::Data { plaintext })
}

/// Write one chunk record.
fn write_chunk_frame<W: Write>(
    out: &mut W,
    key: &[u8],
    index: u64,
    compressed: &[u8],
) -> Result<()> {
    if compressed.is_empty() {
        return Err(Error::other(
            "internal error: refusing to write an empty chunk",
        ));
    }
    if compressed.len() > max_chunk_pt_len() {
        return Err(Error::other(format!(
            "compressor produced an oversized chunk ({} bytes)",
            compressed.len()
        )));
    }
    let ciphertext = aes_encrypt(compressed, key, &chunk_aad(index))?;
    out.write_all(&(compressed.len() as u32).to_le_bytes())
        .map_err(|e| Error::other(format!("write failed: {e}")))?;
    out.write_all(&ciphertext)
        .map_err(|e| Error::other(format!("write failed: {e}")))?;
    Ok(())
}

/// Write the authenticated end-of-stream trailer recording the chunk count.
fn write_trailer<W: Write>(out: &mut W, key: &[u8], total_chunks: u64) -> Result<()> {
    out.write_all(&CATACOMB_MARKER.to_le_bytes())
        .map_err(|e| Error::other(format!("write failed: {e}")))?;
    let ciphertext = aes_encrypt(&total_chunks.to_le_bytes(), key, CATACOMB_AAD)?;
    out.write_all(&ciphertext)
        .map_err(|e| Error::other(format!("write failed: {e}")))?;
    Ok(())
}

/// Compare the trailer's declared chunk count with what was actually read.
///
/// This is what catches a file cut at a chunk boundary: without it, the last
/// chunk is simply missing and nothing notices.
fn verify_chunk_count(declared: Option<u64>, read: u64) -> Result<()> {
    match declared {
        Some(declared) if declared != read => Err(Error::truncated(format!(
            "file is truncated: the end-of-stream trailer declares {declared} chunk(s) but {read} \
             were read"
        ))),
        _ => Ok(()),
    }
}

/// Write a complete header: prefix, then the AEAD-protected plaintext.
fn write_header<W: Write>(
    out: &mut W,
    is_directory: bool,
    name: &[u8],
    salt: &[u8],
    header_key: &[u8],
) -> Result<u64> {
    let plaintext = encode_header_plaintext(is_directory, name)?;
    let encrypted = aes_encrypt(&plaintext, header_key, &header_aad(CRYPT_VERSION, salt))?;
    if encrypted.len() > u16::MAX as usize {
        return Err(Error::invalid_input("header is too large to encode"));
    }

    out.write_all(CRYPT_MAGIC).map_err(write_err)?;
    out.write_all(&CRYPT_VERSION.to_le_bytes())
        .map_err(write_err)?;
    out.write_all(salt).map_err(write_err)?;
    out.write_all(&(encrypted.len() as u16).to_le_bytes())
        .map_err(write_err)?;
    out.write_all(&encrypted).map_err(write_err)?;

    Ok(4 + 2 + salt.len() as u64 + 2 + encrypted.len() as u64)
}

fn write_err(e: io::Error) -> Error {
    Error::other(format!("write failed: {e}"))
}

// ---------------------------------------------------------------------------
// Names and paths
// ---------------------------------------------------------------------------

/// Map characters that are illegal on exFAT/Win32 to '_'.
/// A literal backslash becomes '_' too: components cannot contain '/', and
/// inventing a separator inside one would change the tree's shape.
fn sanitize_component_bytes(bytes: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .map(|&b| match b {
            b'<' | b'>' | b':' | b'"' | b'|' | b'?' | b'*' | b'\\' | 0 => b'_',
            1..=0x1f if b != b'\t' => b'_',
            b => b,
        })
        .collect()
}

/// Sanitize a single path component, or reject it.
///
/// Operates on bytes so non-UTF-8 filenames survive a round trip instead of
/// being mangled into U+FFFD (which can also collapse two distinct names).
fn sanitize_name_bytes(name: &[u8]) -> Option<Vec<u8>> {
    if name.is_empty() || name == b"." || name == b".." {
        return None;
    }
    if name.contains(&b'/') || name.contains(&0) {
        return None;
    }
    Some(sanitize_component_bytes(name))
}

/// The on-disk name for a decrypted payload, with a fallback if the stored name
/// is unusable.
fn output_name_from_header(name: &[u8]) -> OsString {
    match sanitize_name_bytes(name) {
        Some(bytes) => OsString::from_vec(bytes),
        None => {
            eprintln!("[WARN] Stored filename is unusable; using a fallback name.");
            OsString::from("decrypted_output")
        }
    }
}

/// Pick `name`, or `name_1`, `name_2`, ... so an existing entry is never
/// clobbered.
fn unique_component(base: &Path, name: &OsStr) -> OsString {
    if !base.join(name).exists() {
        return name.to_os_string();
    }
    let mut n: u32 = 1;
    loop {
        let mut candidate = name.to_os_string();
        candidate.push(format!("_{n}"));
        if !base.join(&candidate).exists() {
            return candidate;
        }
        n += 1;
    }
}

// ---------------------------------------------------------------------------
// Compression
// ---------------------------------------------------------------------------

/// Decompress one chunk, refusing to expand past `max_len`.
///
/// A zstd frame may declare any content size, so the on-disk length cap alone is
/// not enough: the declared size is checked first, and the destination buffer is
/// capped at `max_len` as well, which catches a frame that declares nothing.
/// Between them that is what stops a decompression bomb.
///
/// `decompressor` is one per worker, reused for every chunk. A fresh zstd
/// context per chunk re-allocates its whole workspace (megabytes at the levels
/// crypt recommends) for every 16 MiB chunk, which is the same reason the
/// compressor on the encrypt side is reused.
fn decompress_chunk(
    decompressor: &mut Decompressor,
    data: &[u8],
    max_len: usize,
) -> Result<Vec<u8>> {
    if let Ok(Some(declared)) = zstd::zstd_safe::get_frame_content_size(data) {
        if declared > max_len as u64 {
            return Err(Error::malformed(format!(
                "chunk declares {declared} bytes of content, past the maximum chunk size \
                 ({max_len} bytes); refusing what looks like a decompression bomb"
            )));
        }
    }
    decompressor.decompress(data, max_len).map_err(|e| {
        Error::malformed(format!(
            "chunk decompressed past the maximum chunk size ({max_len} bytes) or is corrupt: {e}"
        ))
    })
}

// ---------------------------------------------------------------------------
// Building the archive
// ---------------------------------------------------------------------------

#[derive(Default, Debug)]
struct TarStats {
    pub symlinks_skipped: u64,
    pub others_skipped: u64,
    /// Times the archive being written was found inside the tree being packed.
    pub staging_skipped: u64,
    /// Entries that could not be opened or read while packing. Their data is
    /// missing from the archive.
    pub unreadable: u64,
    /// Directories left alone because they are a mount point onto another
    /// filesystem. Their data is missing from the archive too.
    pub other_filesystem: u64,
}

impl TarStats {
    /// True when the archive is missing data the caller asked for, as opposed to
    /// merely omitting what crypt never archives in the first place (symlinks,
    /// special files, its own staging file).
    fn lost_data(&self) -> bool {
        self.unreadable > 0 || self.other_filesystem > 0
    }
}

/// Say what the archive does not contain.
///
/// Everything crypt never archives is reported on stdout as informational, the
/// way it always has been. Data that was *meant* to be archived and could not be
/// is a warning on stderr, and it names the categories, because "the run
/// finished" must not read as "the backup is complete" when it is not.
fn report_skips(stats: &TarStats) {
    if stats.symlinks_skipped > 0 || stats.others_skipped > 0 || stats.staging_skipped > 0 {
        println!(
            "Skipped {} symlink(s), {} special file(s) and {} in-progress output file(s) while packing.",
            stats.symlinks_skipped, stats.others_skipped, stats.staging_skipped
        );
    }
    if !stats.lost_data() {
        return;
    }
    let mut missing = Vec::new();
    if stats.unreadable > 0 {
        missing.push(format!(
            "{} unreadable entr{}",
            stats.unreadable,
            if stats.unreadable == 1 { "y" } else { "ies" }
        ));
    }
    if stats.other_filesystem > 0 {
        missing.push(format!(
            "{} director{} on another filesystem",
            stats.other_filesystem,
            if stats.other_filesystem == 1 {
                "y (a mount point)"
            } else {
                "ies (mount points)"
            }
        ));
    }
    eprintln!(
        "[WARN] The archive is valid but NOT a full copy: {}. See the warnings above, fix the \
         inputs and run crypt again if you need everything.",
        missing.join(" and ")
    );
}

/// Copy real permission bits and mtime into a tar header, and zero the ownership
/// fields so the archive is reproducible and never attempts a chown.
///
/// Only the low 9 permission bits are stored: setuid/setgid/sticky are dropped on
/// the way in and can therefore never come back on the way out.
fn apply_metadata(header: &mut tar::Header, meta: &fs::Metadata) {
    header.set_mtime(meta.mtime().max(0) as u64);
    header.set_mode(meta.mode() & 0o777);
    header.set_uid(0);
    header.set_gid(0);
}

/// Add one regular file, counting it as missing data if it cannot be opened.
fn add_file_to_tar<W: Write>(
    builder: &mut tar::Builder<W>,
    archive_path: &Path,
    source: &Path,
    stats: &mut TarStats,
) -> Result<()> {
    let file = match File::open(source) {
        Ok(f) => f,
        Err(e) => {
            eprintln!(
                "[WARN] Skipping unreadable file '{}': {e}",
                source.display()
            );
            stats.unreadable += 1;
            return Ok(());
        }
    };
    let meta = file
        .metadata()
        .map_err(|e| Error::other(format!("cannot stat '{}': {e}", source.display())))?;

    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_size(meta.len());
    apply_metadata(&mut header, &meta);

    builder
        .append_data(&mut header, archive_path, file.take(meta.len()))
        .map_err(|e| {
            Error::other(format!(
                "failed to add '{}' to the archive: {e}. A file that changes size while it is \
                 being read will corrupt the archive",
                source.display()
            ))
        })?;
    Ok(())
}

/// Walk a directory and add every regular file and directory under `archive_root`.
///
/// Symlinks are skipped outright: following them would silently archive the
/// contents of files outside the tree (a symlink to ~/.ssh/id_rsa, for example).
///
/// The walk stays on one filesystem per input, so a mount point inside the tree
/// does not drag another disk (or a network mount, or a tmpfs) into the archive.
/// `same_file_system` does that pruning without a word, so this walk drives a
/// plain iterator and does the check itself — that is what lets the directory it
/// leaves out be counted and reported rather than silently missing.
fn add_tree_to_tar<W: Write>(
    builder: &mut tar::Builder<W>,
    archive_root: &Path,
    source_root: &Path,
    staging: Option<&Path>,
    stats: &mut TarStats,
) -> Result<()> {
    let root_device = fs::symlink_metadata(source_root)
        .map(|meta| meta.dev())
        .ok();

    let mut walker = walkdir::WalkDir::new(source_root)
        .follow_links(false)
        .into_iter();
    while let Some(walk_entry) = walker.next() {
        let walk_entry = match walk_entry {
            Ok(entry) => entry,
            Err(e) => {
                let path = e
                    .path()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default();
                eprintln!("[WARN] Skipping '{}': {e}", path);
                // A tree crypt cannot read is missing data, not an oddity it
                // never archives in the first place.
                stats.unreadable += 1;
                continue;
            }
        };

        let relative = walk_entry
            .path()
            .strip_prefix(source_root)
            .unwrap_or_else(|_| walk_entry.path());
        let archive_path = if relative.as_os_str().is_empty() {
            archive_root.to_path_buf()
        } else {
            archive_root.join(relative)
        };

        // The archive being written may live inside the tree being packed
        // (`crypt -e /data --output /data`). Packing it would embed a copy of the
        // archive in itself, with whatever content happened to be flushed.
        if staging.is_some_and(|staging| is_staging_file(walk_entry.path(), staging)) {
            eprintln!(
                "[WARN] Skipping '{}': it is the archive crypt is writing right now.",
                walk_entry.path().display()
            );
            stats.staging_skipped += 1;
            continue;
        }

        if walk_entry.file_type().is_symlink() {
            eprintln!(
                "[WARN] Skipping symlink '{}' (crypt archives regular files and directories only).",
                walk_entry.path().display()
            );
            stats.symlinks_skipped += 1;
            continue;
        }

        // Re-stat with symlink_metadata rather than metadata: if this path turned
        // into a symlink between the walk and here, it must not be followed.
        let meta = match fs::symlink_metadata(walk_entry.path()) {
            Ok(meta) => meta,
            Err(e) => {
                eprintln!("[WARN] Skipping '{}': {e}", walk_entry.path().display());
                stats.unreadable += 1;
                continue;
            }
        };
        let file_type = meta.file_type();

        // A directory on a different device is a mount point. It is left out
        // entirely (as `same_file_system` used to do silently) rather than
        // archived as an empty directory, and the walk does not descend.
        if file_type.is_dir() && root_device.is_some_and(|device| meta.dev() != device) {
            eprintln!(
                "[WARN] Skipping '{}': it is on another filesystem (a mount point), so crypt stays \
                 under '{}'.",
                walk_entry.path().display(),
                source_root.display()
            );
            stats.other_filesystem += 1;
            walker.skip_current_dir();
            continue;
        }

        if file_type.is_dir() {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            apply_metadata(&mut header, &meta);
            builder
                .append_data(&mut header, &archive_path, io::empty())
                .map_err(|e| {
                    Error::other(format!(
                        "failed to add directory '{}': {e}",
                        archive_path.display()
                    ))
                })?;
        } else if file_type.is_file() {
            add_file_to_tar(builder, &archive_path, walk_entry.path(), stats)?;
        } else if file_type.is_symlink() {
            // The walk called this a regular file or a directory and the re-stat
            // called it a symlink, so the path changed underneath us: report it
            // rather than dropping the entry without a word.
            eprintln!(
                "[WARN] Skipping '{}': it turned into a symlink while the tree was being packed.",
                walk_entry.path().display()
            );
            stats.symlinks_skipped += 1;
        } else {
            eprintln!(
                "[WARN] Skipping '{}': not a regular file or directory.",
                walk_entry.path().display()
            );
            stats.others_skipped += 1;
        }
    }
    Ok(())
}

/// Append `_1`, `_2`, ... to a top-level archive name already in use, so two
/// inputs with the same basename cannot merge into one archive entry.
fn dedupe_archive_name(used: &mut Vec<OsString>, name: &OsStr) -> OsString {
    if !used.iter().any(|existing| existing == name) {
        used.push(name.to_os_string());
        return name.to_os_string();
    }
    let mut n: u32 = 1;
    loop {
        let mut candidate = name.to_os_string();
        candidate.push(format!("_{n}"));
        if !used.iter().any(|existing| existing == &candidate) {
            used.push(candidate.clone());
            return candidate;
        }
        n += 1;
    }
}

/// The archive name for an input: its file name, or — for `.` and `..`, which
/// have none — the name of the directory they resolve to.
///
/// `crypt -e .` is the most obvious way to ask for "this folder", so it must not
/// be rejected for being nameless.
fn archive_name_for(path: &Path) -> Result<OsString> {
    if let Some(name) = path.file_name() {
        return Ok(name.to_os_string());
    }
    fs::canonicalize(path)
        .ok()
        .and_then(|canonical| canonical.file_name().map(OsStr::to_os_string))
        .ok_or_else(|| Error::invalid_input(format!("'{}' has no file name", path.display())))
}

/// True when `candidate` is the staging file crypt is writing at this moment.
///
/// `staging` is canonicalized by the caller. The staging name carries a random
/// suffix, so the cheap file-name comparison short-circuits every ordinary entry
/// and the canonicalize (a syscall) runs at most once per walk.
fn is_staging_file(candidate: &Path, staging: &Path) -> bool {
    if staging.file_name().is_none() || candidate.file_name() != staging.file_name() {
        return false;
    }
    candidate == staging
        || fs::canonicalize(candidate)
            .map(|path| path == staging)
            .unwrap_or(false)
}

/// Pack the inputs into a tar stream.
///
/// Top-level symlinks are refused (a clear error beats silently encrypting
/// nothing) and every symlink met while walking is skipped. `staging` is the
/// archive being written, which is skipped if the destination sits inside the
/// tree being packed.
fn build_tar<W: Write>(paths: &[PathBuf], writer: W, staging: Option<&Path>) -> Result<TarStats> {
    let mut builder = tar::Builder::new(writer);
    let mut stats = TarStats::default();
    let mut used: Vec<OsString> = Vec::new();

    for path in paths {
        let meta = fs::symlink_metadata(path)
            .map_err(|e| Error::other(format!("cannot stat '{}': {e}", path.display())))?;
        if meta.file_type().is_symlink() {
            return Err(Error::invalid_input(format!(
                "'{}' is a symlink; crypt does not archive symlinks. Pass the real path instead.",
                path.display()
            )));
        }
        let root = PathBuf::from(dedupe_archive_name(&mut used, &archive_name_for(path)?));

        if meta.is_dir() {
            add_tree_to_tar(&mut builder, &root, path, staging, &mut stats)?;
        } else if meta.is_file() {
            add_file_to_tar(&mut builder, &root, path, &mut stats)?;
        } else {
            return Err(Error::invalid_input(format!(
                "'{}' is neither a regular file nor a directory",
                path.display()
            )));
        }
    }

    builder
        .into_inner()
        .map_err(|e| Error::other(format!("failed to finish the tar stream: {e}")))?;
    Ok(stats)
}

// ---------------------------------------------------------------------------
// Extracting the archive
// ---------------------------------------------------------------------------

#[derive(Default, Debug)]
struct ExtractStats {
    pub skipped: u64,
}

struct ExtractResult {
    /// Top-level entries created, in the order they were first seen.
    pub tops: Vec<OsString>,
    pub stats: ExtractStats,
}

/// Split a stored tar path into sanitized components, or reject it.
///
/// Uses `Path::components` so `..` is caught structurally, and works on raw
/// bytes so non-UTF-8 names survive the round trip.
fn sanitized_components(path: &Path) -> Option<Vec<OsString>> {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(os) => {
                let bytes = sanitize_name_bytes(os.as_bytes())?;
                components.push(OsString::from_vec(bytes));
            }
            Component::CurDir => {}
            _ => return None,
        }
    }
    if components.is_empty() {
        None
    } else {
        Some(components)
    }
}

/// Extract a tar archive into `base_path`, sanitizing every path to be
/// exFAT-safe and giving any colliding top-level name a `_n` suffix.
///
/// Only regular files and directories are extracted: a symlink or hard-link
/// entry is skipped rather than created, which is what would otherwise let a
/// crafted archive write outside `base_path` through a link.
fn unpack_tar_sanitized<R: Read>(
    archive: &mut tar::Archive<R>,
    base_path: &Path,
) -> Result<ExtractResult> {
    let mut resolved: HashMap<OsString, OsString> = HashMap::new();
    let mut tops: Vec<OsString> = Vec::new();
    let mut stats = ExtractStats::default();
    // Directory modes are applied last: chmod-ing a directory to something
    // without u+w before its children are written would break the extraction.
    let mut deferred_dirs: Vec<(PathBuf, u32, u64)> = Vec::new();

    let entries = archive
        .entries()
        .map_err(|e| Error::other(format!("cannot read the tar stream: {e}")))?;
    for entry_result in entries {
        let mut entry = match entry_result {
            Ok(entry) => entry,
            Err(e) => {
                eprintln!("[WARN] Skipping unreadable tar entry: {e}");
                stats.skipped += 1;
                continue;
            }
        };

        let raw_path = match entry.path() {
            Ok(path) => path.into_owned(),
            Err(e) => {
                eprintln!("[WARN] Skipping tar entry with an unreadable path: {e}");
                stats.skipped += 1;
                continue;
            }
        };

        let mut components = match sanitized_components(&raw_path) {
            Some(components) => components,
            None => {
                eprintln!(
                    "[WARN] Skipping unsafe tar entry '{}' (path traversal or unusable name).",
                    raw_path.display()
                );
                stats.skipped += 1;
                continue;
            }
        };

        let top = components[0].clone();
        let mapped = match resolved.get(&top) {
            Some(name) => name.clone(),
            None => {
                let name = unique_component(base_path, &top);
                resolved.insert(top, name.clone());
                tops.push(name.clone());
                name
            }
        };
        components[0] = mapped;

        let mut full_path = base_path.to_path_buf();
        for component in &components {
            full_path.push(component);
        }
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| Error::other(format!("cannot create '{}': {e}", parent.display())))?;
        }

        let entry_type = entry.header().entry_type();
        if entry_type.is_dir() {
            fs::create_dir_all(&full_path).map_err(|e| {
                Error::other(format!("cannot create '{}': {e}", full_path.display()))
            })?;
            let mode = entry.header().mode().unwrap_or(0o755) & 0o777;
            let mtime = entry.header().mtime().unwrap_or(0);
            deferred_dirs.push((full_path, mode, mtime));
        } else if entry_type.is_file() {
            entry.unpack(&full_path).map_err(|e| {
                Error::other(format!("cannot extract '{}': {e}", full_path.display()))
            })?;
        } else {
            eprintln!(
                "[WARN] Skipping tar entry '{}': only regular files and directories are extracted.",
                raw_path.display()
            );
            stats.skipped += 1;
        }
    }

    // Deepest first, so a parent's restrictive mode never blocks its children.
    deferred_dirs.sort_by_key(|(path, _, _)| std::cmp::Reverse(path.components().count()));
    for (path, mode, mtime) in deferred_dirs {
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(mode));
        let _ =
            filetime::set_file_mtime(&path, filetime::FileTime::from_unix_time(mtime as i64, 0));
    }

    Ok(ExtractResult { tops, stats })
}

/// Extract the single regular file an archive holds into `dest`.
///
/// `create_new` closes the window between choosing a free name and writing it.
fn unpack_single_file<R: Read>(archive: &mut tar::Archive<R>, dest: &Path) -> Result<()> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| Error::other(format!("cannot create '{}': {e}", parent.display())))?;
    }
    let mut entries = archive
        .entries()
        .map_err(|e| Error::other(format!("cannot read the tar stream: {e}")))?;

    let mut entry = match entries.next() {
        Some(Ok(entry)) => entry,
        Some(Err(e)) => return Err(Error::other(format!("cannot read the tar stream: {e}"))),
        None => return Err(Error::malformed("the archive contains no entries")),
    };

    if !entry.header().entry_type().is_file() {
        return Err(Error::malformed(
            "the archive's first entry is not a regular file",
        ));
    }

    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dest)
        .map_err(|e| Error::other(format!("cannot create '{}': {e}", dest.display())))?;
    io::copy(&mut entry, &mut output)
        .map_err(|e| Error::other(format!("cannot write '{}': {e}", dest.display())))?;
    output
        .sync_all()
        .map_err(|e| Error::other(format!("cannot flush '{}': {e}", dest.display())))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Staging directory
// ---------------------------------------------------------------------------

/// A directory that is removed when dropped.
///
/// Decryption extracts here first so a truncated or tampered archive can never
/// leave half-written files under their final names.
struct StagingDir {
    path: PathBuf,
}

impl StagingDir {
    /// Create a fresh staging directory inside `parent` (same filesystem, so the
    /// final rename is atomic).
    pub fn new(parent: &Path) -> Result<StagingDir> {
        fs::create_dir_all(parent)
            .map_err(|e| Error::other(format!("cannot create '{}': {e}", parent.display())))?;
        for _ in 0..16 {
            let mut suffix = [0u8; 8];
            OsRng.fill_bytes(&mut suffix);
            let name = format!(".crypt-staging-{}", hex(&suffix));
            let path = parent.join(name);
            match fs::create_dir(&path) {
                Ok(()) => {
                    return Ok(StagingDir { path });
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => {
                    return Err(Error::other(format!(
                        "cannot create '{}': {e}",
                        path.display()
                    )));
                }
            }
        }
        Err(Error::other(format!(
            "cannot create a staging directory in '{}': too many name collisions",
            parent.display()
        )))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for StagingDir {
    fn drop(&mut self) {
        // Best effort: a failed decrypt should not litter the destination.
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Whatever ended up in the staging directory, used when a partial archive is
/// cut mid-entry and the tar stream cannot be finished.
fn staged_tops(dir: &Path) -> Result<Vec<OsString>> {
    let mut names = Vec::new();
    let entries = fs::read_dir(dir)
        .map_err(|e| Error::other(format!("cannot read '{}': {e}", dir.display())))?;
    for entry in entries {
        let entry =
            entry.map_err(|e| Error::other(format!("cannot read '{}': {e}", dir.display())))?;
        names.push(entry.file_name());
    }
    names.sort();
    Ok(names)
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

// ---------------------------------------------------------------------------
// Passwords
// ---------------------------------------------------------------------------

/// Rules enforced **before encrypting** only. Decrypting must accept whatever a
/// legacy archive was created with, including short or empty passwords.
fn validate_password_for_encrypt(password: &str) -> Result<()> {
    if password.is_empty() {
        return Err(Error::invalid_input("the password must not be empty"));
    }
    if let Some(c) = password.chars().find(|c| !c.is_ascii()) {
        return Err(Error::invalid_input(format!(
            "the password must be printable ASCII (found U+{:04X}); a password that normalizes \
             differently on another machine is a security problem",
            c as u32
        )));
    }
    if let Some(c) = password
        .chars()
        .find(|c| (*c as u32) < 0x20 || *c == '\x7f')
    {
        return Err(Error::invalid_input(format!(
            "the password must not contain control characters (found 0x{:02x})",
            c as u32
        )));
    }
    let length = password.chars().count();
    if length < MIN_PASSWORD_LEN {
        return Err(Error::invalid_input(format!(
            "the password must be at least {MIN_PASSWORD_LEN} characters for encryption \
             (got {length})"
        )));
    }
    Ok(())
}

/// Erase `len` masked characters from the screen and step back.
fn clear_masked_input(len: usize) {
    for _ in 0..len {
        print!("\x08 \x08");
    }
    let _ = io::stdout().flush();
}

/// Index and value of the first non-ASCII byte, if there is one.
fn first_non_ascii(bytes: &[u8]) -> Option<(usize, u8)> {
    bytes
        .iter()
        .position(|b| !b.is_ascii())
        .map(|i| (i, bytes[i]))
}

/// Restores terminal settings when dropped.
///
/// This is why `prompt_masked` clears `ISIG` along with echo: if the tty raised
/// SIGINT on Ctrl-C, the process would die without unwinding, this guard would
/// never run, and the shell would be left with echo off. Ctrl-C arrives as a
/// byte instead and unwinds normally.
struct TermiosGuard {
    fd: i32,
    original: Termios,
}

impl Drop for TermiosGuard {
    fn drop(&mut self) {
        let _ = termios::tcsetattr(self.fd, TCSANOW, &self.original);
    }
}

/// Read one line from a pipe, with the newline dropped.
///
/// A byte at a time rather than `read_line`, so the line can be capped: a pipe
/// can send as much as it likes and `read_line` would allocate all of it before
/// anything could look at it. 4 KiB is far more than a password anyone types.
fn read_piped_password() -> Result<Zeroizing<String>> {
    let mut stdin = io::stdin().lock();
    // Zeroizing: a line that is refused for being too long, or for not being
    // valid UTF-8, still leaves nothing behind in freed memory.
    let mut line: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(64));
    let mut byte = [0u8; 1];

    loop {
        let read = stdin
            .read(&mut byte)
            .map_err(|e| Error::other(format!("cannot read the password from stdin: {e}")))?;
        // End of input, or the end of the line. Either way the password is what
        // came before, not an error: an empty line is a legitimate (if unwise)
        // legacy password, and the caller decides whether to refuse it.
        if read == 0 || byte[0] == b'\n' {
            break;
        }
        if line.len() >= MAX_PIPED_PASSWORD_BYTES {
            return Err(Error::invalid_input(format!(
                "the password on stdin is longer than {MAX_PIPED_PASSWORD_BYTES} bytes"
            )));
        }
        line.push(byte[0]);
    }

    // A CRLF line ending leaves the `\r` behind.
    while line.last() == Some(&b'\r') {
        line.pop();
    }

    let text = std::str::from_utf8(&line)
        .map_err(|_| Error::invalid_input("the password on stdin is not valid UTF-8"))?;
    Ok(Zeroizing::new(text.to_owned()))
}

/// Read a password from the terminal with masked echo.
///
/// Keeps asking until the entry is printable ASCII: a non-ASCII character is
/// reported and the whole attempt is discarded, so nothing is silently dropped
/// and a multi-byte character produces one message rather than one per byte.
fn prompt_masked(prompt: &str) -> Result<Zeroizing<String>> {
    println!("{prompt}");

    let stdin_fd = io::stdin().as_raw_fd();
    let original = Termios::from_fd(stdin_fd)
        .map_err(|e| Error::other(format!("cannot read terminal attributes: {e}")))?;
    let mut raw = original;
    // ISIG is cleared too: leaving it on would make the tty raise SIGINT on
    // Ctrl-C, which kills the process without unwinding, so the guard below
    // would never run and the shell would be left with echo off. Clearing it
    // delivers Ctrl-C as a byte to the read loop, which aborts cleanly.
    raw.c_lflag &= !(ICANON | ECHO | ISIG);
    raw.c_cc[termios::VMIN] = 1;
    raw.c_cc[termios::VTIME] = 0;
    termios::tcsetattr(stdin_fd, TCSANOW, &raw)
        .map_err(|e| Error::other(format!("cannot switch the terminal to raw mode: {e}")))?;
    let _guard = TermiosGuard {
        fd: stdin_fd,
        original,
    };

    let mut stdin = io::stdin();
    'attempt: loop {
        // Zeroizing: an attempt that is thrown away for being non-ASCII, or that
        // never becomes a password, still leaves nothing in freed memory.
        let mut typed: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());

        loop {
            let mut byte = [0u8; 1];
            match stdin.read(&mut byte) {
                Ok(0) => {
                    println!();
                    break;
                }
                Ok(_) => {}
                Err(e) => {
                    return Err(Error::other(format!(
                        "cannot read the password from the terminal: {e}"
                    )));
                }
            }
            match byte[0] {
                b'\n' | b'\r' => {
                    println!();
                    break;
                }
                0x7f | 0x08 => {
                    if typed.pop().is_some() {
                        print!("\x08 \x08");
                        let _ = io::stdout().flush();
                    }
                }
                0x15 => {
                    clear_masked_input(typed.len());
                    typed.clear();
                }
                // Ctrl-C / Ctrl-D: abort. Returning drops the guard, which
                // restores the terminal (unlike `process::exit`).
                0x03 | 0x04 => {
                    println!();
                    return Err(Error::other("password entry aborted"));
                }
                // Printable ASCII and non-ASCII, so the check below can report
                // which byte was wrong. Other control bytes are ignored.
                byte if byte >= 0x20 => {
                    typed.push(byte);
                    print!("*");
                    let _ = io::stdout().flush();
                }
                _ => {}
            }
        }

        if let Some((index, byte)) = first_non_ascii(&typed) {
            eprintln!("[WARN] The password has a non-ASCII byte 0x{byte:02X} at position {index}.");
            eprintln!("[WARN] Passwords must be printable ASCII. Type a new password.");
            continue 'attempt;
        }

        // Borrowed rather than consumed, so the bytes above are zeroized either
        // way. The bytes accepted by the read loop are all ASCII, so this error
        // is unreachable today; it stays as the belt to that pair of braces.
        return match std::str::from_utf8(&typed) {
            Ok(password) => Ok(Zeroizing::new(password.to_owned())),
            Err(_) => Err(Error::other("password entry contained invalid bytes")),
        };
    }
}

/// Where an encryption password comes from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PasswordSource {
    /// Ask on the terminal (twice when encrypting).
    Terminal,
    /// Read one line from stdin. For scripting and tests; a password is never
    /// taken from an argument, because arguments are world-readable in `ps`.
    Stdin,
}

fn read_password(confirm: bool, source: PasswordSource) -> Result<Zeroizing<String>> {
    if source == PasswordSource::Stdin {
        return read_piped_password();
    }

    if !io::stdin().is_terminal() {
        return Err(Error::other(
            "no terminal is available to ask for a password. Use --password-stdin to read it from \
             a pipe instead",
        ));
    }

    if confirm {
        loop {
            let first = prompt_masked("Enter password:")?;
            let second = prompt_masked("Confirm password:")?;
            if *first == *second {
                return Ok(first);
            }
            eprintln!("Passwords did not match, try again.");
        }
    } else {
        prompt_masked("Enter password:")
    }
}

// ---------------------------------------------------------------------------
// Progress
// ---------------------------------------------------------------------------

/// Progress is only drawn when stdout is a terminal, so piped output stays clean.
fn print_progress_bar(current: u64, total: u64, finished: bool, enabled: bool) {
    if !enabled || total == 0 {
        return;
    }
    let percent = ((current as f64 / total as f64) * 100.0).clamp(0.0, 100.0);
    let bar_width = 50;
    let filled = (((percent / 100.0) * bar_width as f64).round() as usize).min(bar_width);

    print!("\r|");
    for i in 0..bar_width {
        if finished || i < filled {
            print!("=");
        } else if i == filled {
            print!(">");
        } else {
            print!(".");
        }
    }
    print!("| {percent:.0}%");
    if finished {
        println!();
    }
    let _ = io::stdout().flush();
}

fn progress_enabled() -> bool {
    io::stdout().is_terminal()
}

/// Spawn the thread that redraws the progress bar until `done` is set.
fn spawn_progress_thread(
    progress: Arc<AtomicU64>,
    done: Arc<AtomicBool>,
    total: u64,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let enabled = progress_enabled();
        while !done.load(Ordering::Relaxed) {
            thread::sleep(std::time::Duration::from_millis(400));
            if enabled && total > 0 {
                print_progress_bar(progress.load(Ordering::Relaxed), total, false, enabled);
            }
        }
        if enabled && total > 0 {
            print_progress_bar(total, total, true, enabled);
        }
    })
}

// ---------------------------------------------------------------------------
// Encryption
// ---------------------------------------------------------------------------

struct RawChunk {
    index: u64,
    data: Zeroizing<Vec<u8>>,
}

/// Compressed but not yet encrypted. Workers produce these; the writer encrypts
/// each with an AAD binding its index and appends it in order.
struct CompressedChunk {
    index: u64,
    compressed: Zeroizing<Vec<u8>>,
}

/// Knobs for [`encrypt_file`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptOptions {
    /// Worker threads used to compress chunks. Zero is treated as one, and
    /// anything over 128 is capped at 128, so a caller cannot ask for a thread
    /// count the machine cannot honour.
    ///
    /// Oversubscribing the machine costs memory rather than saving time: each
    /// worker holds a 16 MiB chunk plus a zstd context at the chosen level. Two
    /// to four fewer workers than cores is the sweet spot.
    pub workers: usize,
    /// Zstd compression level. Values outside `1..=22` are clamped, so a caller
    /// cannot ask for a level the build does not support.
    pub level: i32,
}

impl Default for EncryptOptions {
    fn default() -> Self {
        EncryptOptions {
            workers: DEFAULT_NUM_WORKERS,
            level: DEFAULT_ZSTD_COMPRESSION_LEVEL,
        }
    }
}

fn random_salt() -> Zeroizing<[u8; SALT_SIZE]> {
    let mut salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);
    Zeroizing::new(salt)
}

/// Total size of the regular files under `path`, using the same rules the
/// archiver uses (symlinks and special files are skipped, and so are
/// directories on another filesystem), so the progress bar denominator matches
/// what is actually read.
fn tree_size(path: &Path) -> Result<u64> {
    let mut total = 0u64;
    for entry in walkdir::WalkDir::new(path)
        .follow_links(false)
        .same_file_system(true)
    {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        if !entry.file_type().is_file() {
            continue;
        }
        if let Ok(meta) = fs::symlink_metadata(entry.path()) {
            if meta.file_type().is_file() {
                total = total.saturating_add(meta.len());
            }
        }
    }
    Ok(total)
}

/// Deletes a partially written archive unless it is explicitly kept.
struct PartialFileGuard {
    path: PathBuf,
    keep: bool,
}

impl Drop for PartialFileGuard {
    fn drop(&mut self) {
        if !self.keep {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Create the `.coffin` staging file with `create_new`, so an existing file is
/// never truncated, and a random suffix that cannot collide with a real archive.
fn create_coffin(base_dir: &Path, stem: &OsStr) -> Result<(PathBuf, BufWriter<File>)> {
    for _ in 0..16 {
        let mut suffix = [0u8; 4];
        OsRng.fill_bytes(&mut suffix);

        let mut name = stem.to_os_string();
        name.push(format!("-{}", hex(&suffix)));
        let mut coffin_path = base_dir.join(name);
        coffin_path.set_extension("coffin");
        let crypt_path = coffin_path.with_extension("crypt");
        if crypt_path.exists() {
            // Never overwrite an existing archive.
            continue;
        }

        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&coffin_path)
        {
            Ok(file) => {
                return Ok((coffin_path, BufWriter::with_capacity(8 * 1024 * 1024, file)));
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(Error::other(format!(
                    "cannot create '{}': {e}",
                    coffin_path.display()
                )));
            }
        }
    }
    Err(Error::other(format!(
        "cannot find a free output name in '{}'",
        base_dir.display()
    )))
}

/// Encrypt every chunk from `rx` in index order.
///
/// Returns how many chunks were written *contiguously*. A gap stops the loop
/// with an error instead of silently sealing a short stream: the trailer would
/// otherwise certify an incomplete archive as complete.
fn write_all_chunks<W: Write>(
    out: &mut W,
    key: &[u8],
    rx: crossbeam_channel::Receiver<CompressedChunk>,
    max_pending: usize,
) -> Result<u64> {
    let mut pending: HashMap<u64, CompressedChunk> = HashMap::new();
    let mut next_index: u64 = 0;

    while let Ok(chunk) = rx.recv() {
        pending.insert(chunk.index, chunk);
        while let Some(chunk) = pending.remove(&next_index) {
            write_chunk_frame(out, key, chunk.index, &chunk.compressed)?;
            next_index += 1;
        }
        if pending.len() > max_pending {
            return Err(Error::other(format!(
                "{} chunks arrived out of order and could not be written; the stream would contain \
                 a gap",
                pending.len()
            )));
        }
    }

    if let Some(lowest) = pending.keys().min().copied() {
        return Err(Error::other(format!(
            "chunk {lowest} (and {} after it) could not be written; the stream would contain a gap",
            pending.len()
        )));
    }

    Ok(next_index)
}

/// Flush what was written and keep it, so a failed run can still be decrypted
/// for the part that made it to disk.
fn abandon_partial(
    output_file: &mut BufWriter<File>,
    coffin_path: &Path,
    message: Error,
) -> Result<PathBuf> {
    let _ = output_file.flush();
    let _ = output_file.get_ref().sync_all();
    if coffin_path.exists() {
        eprintln!(
            "[WARN] A partial archive was left at '{}'. Decrypt it to recover what was written.",
            coffin_path.display()
        );
    }
    Err(message)
}

/// Flush a directory entry to disk so a rename survives a power loss.
fn sync_dir(dir: &Path) {
    if let Ok(handle) = File::open(dir) {
        let _ = handle.sync_all();
    }
}

/// Encrypt `inputs` into a single `.crypt` archive and return its path.
///
/// Writes to a `.coffin` staging file first and only publishes it once every
/// thread has finished, the trailer is sealed and the data is on disk. The
/// archive name comes from the first input (plus a random suffix), and the
/// archive is never written over an existing file.
///
/// # Errors
///
/// [`Error::InvalidInput`] for an empty `inputs`, a path that cannot be archived
/// (a symlink, a FIFO, a name with no file name), or an output that already
/// exists. I/O and thread failures are [`Error::Other`].
///
/// The password rules the CLI applies — printable ASCII, a minimum length — are
/// *not* enforced here: a caller that has decided its own policy is not
/// second-guessed.
pub fn encrypt_file(
    inputs: &[PathBuf],
    password: &str,
    output_dir: Option<&Path>,
    opts: &EncryptOptions,
) -> Result<PathBuf> {
    if inputs.is_empty() {
        return Err(Error::invalid_input("no input paths given"));
    }
    let first = &inputs[0];
    let archive_name = archive_name_for(first)?;
    let name_bytes = archive_name.as_bytes().to_vec();
    // The archive holds a tree if there is more than one top-level input.
    let is_directory = inputs.len() > 1 || first.is_dir();

    let base_dir = match output_dir {
        Some(dir) => dir.to_path_buf(),
        None => first
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
            .to_path_buf(),
    };
    fs::create_dir_all(&base_dir)
        .map_err(|e| Error::other(format!("cannot create '{}': {e}", base_dir.display())))?;

    let workers = opts.workers.clamp(1, MAX_WORKERS);
    let salt = random_salt();
    let keys = derive_keys(password, &salt)?;

    let mut total_input_size = 0u64;
    for path in inputs {
        total_input_size = total_input_size.saturating_add(tree_size(path)?);
    }

    let stem = Path::new(&archive_name)
        .file_stem()
        .map(|s| s.to_os_string())
        .unwrap_or_else(|| archive_name.clone());
    let (coffin_path, mut output_file) = create_coffin(&base_dir, &stem)?;
    let crypt_path = coffin_path.with_extension("crypt");
    let mut guard = PartialFileGuard {
        path: coffin_path.clone(),
        keep: false,
    };

    write_header(
        &mut output_file,
        is_directory,
        &name_bytes,
        &salt[..],
        &keys.header[..],
    )?;
    // Past this point a failure leaves a partial archive that can still be
    // decrypted for whatever was written, so stop treating it as disposable.
    guard.keep = true;

    // Pipeline: tar (I/O) -> pipe -> workers (compress) -> writer (encrypt+write).
    let (pipe_reader, pipe_writer) =
        os_pipe::pipe().map_err(|e| Error::other(format!("cannot create a pipe: {e}")))?;

    // Canonicalized so the walk recognises it through another spelling of the
    // same directory (`--output ./self` versus `self`).
    let staging_path = fs::canonicalize(&coffin_path).unwrap_or_else(|_| coffin_path.clone());
    let inputs_for_tar: Vec<PathBuf> = inputs.to_vec();
    let tar_handle =
        thread::spawn(move || build_tar(&inputs_for_tar, pipe_writer, Some(&staging_path)));

    let (raw_tx, raw_rx) = crossbeam_channel::bounded::<RawChunk>(workers);
    let (compressed_tx, compressed_rx) = crossbeam_channel::bounded::<CompressedChunk>(workers * 2);

    let progress = Arc::new(AtomicU64::new(0));
    let done = Arc::new(AtomicBool::new(false));
    let progress_handle =
        spawn_progress_thread(Arc::clone(&progress), Arc::clone(&done), total_input_size);

    let pipe_reader_handle = thread::spawn(move || -> Result<u64> {
        let mut pipe_buf = BufReader::new(pipe_reader);
        let mut chunk_index: u64 = 0;
        let mut chunk_data = Zeroizing::new(vec![0u8; CHUNK_SIZE]);

        loop {
            let mut offset = 0usize;
            loop {
                match pipe_buf.read(&mut chunk_data[offset..]) {
                    Ok(0) => break,
                    Ok(n) => offset += n,
                    Err(e) => {
                        return Err(Error::other(format!("reading the tar stream failed: {e}")))
                    }
                }
                if offset >= CHUNK_SIZE {
                    break;
                }
            }
            if offset == 0 {
                break;
            }

            let chunk = RawChunk {
                index: chunk_index,
                data: Zeroizing::new(chunk_data[..offset].to_vec()),
            };
            if raw_tx.send(chunk).is_err() {
                // The writer bailed out; its error is the interesting one.
                break;
            }
            chunk_data[..offset].zeroize();
            chunk_index += 1;
        }
        Ok(chunk_index)
    });

    // Clamped here rather than trusted: this is a public entry point, and
    // `zstd::bulk::Compressor::new` would otherwise fail late and vaguely.
    let level = opts.level.clamp(MIN_ZSTD_LEVEL, MAX_ZSTD_LEVEL);
    let mut worker_handles = Vec::with_capacity(workers);
    // Declared before the workers so a thread that cannot be started is reported
    // like any other failure instead of panicking: `thread::spawn` panics, and a
    // machine that has run out of threads is an error, not a bug in the caller.
    let mut first_error: Option<Error> = None;
    for _ in 0..workers {
        let raw_rx = raw_rx.clone();
        let compressed_tx = compressed_tx.clone();
        let progress_worker = Arc::clone(&progress);

        let spawned = thread::Builder::new().spawn(move || -> Result<()> {
            // One reusable compression context per worker: a fresh context per
            // chunk peaked at several GB per worker at level 22.
            let mut compressor = zstd::bulk::Compressor::new(level)
                .map_err(|e| Error::other(format!("cannot create a zstd compressor: {e}")))?;
            loop {
                let raw = match raw_rx.recv() {
                    Ok(chunk) => chunk,
                    Err(_) => break,
                };
                let raw_index = raw.index;
                let raw_len = raw.data.len() as u64;
                let compressed = compressor.compress(&raw.data).map_err(|e| {
                    Error::other(format!("compressing chunk {raw_index} failed: {e}"))
                })?;
                // Release the raw chunk before queueing the compressed one.
                drop(raw);
                progress_worker.fetch_add(raw_len, Ordering::Relaxed);

                let chunk = CompressedChunk {
                    index: raw_index,
                    compressed: Zeroizing::new(compressed),
                };
                if compressed_tx.send(chunk).is_err() {
                    break;
                }
            }
            Ok(())
        });
        match spawned {
            Ok(handle) => worker_handles.push(handle),
            Err(e) => {
                first_error.get_or_insert_with(|| {
                    Error::other(format!("cannot start a worker thread: {e}"))
                });
                break;
            }
        }
    }
    drop(compressed_tx);
    // Dropping the last receiver of `raw_rx` here (the workers hold clones) means
    // that if no worker could be started at all, the reader thread unblocks
    // instead of waiting on a channel nobody is reading.
    drop(raw_rx);

    let written = match write_all_chunks(
        &mut output_file,
        &keys.data[..],
        compressed_rx,
        (workers * 4).max(8),
    ) {
        Ok(count) => Some(count),
        Err(e) => {
            first_error.get_or_insert(e);
            None
        }
    };

    // The reader thread knows how many chunks the tar stream actually produced.
    let expected = match pipe_reader_handle.join() {
        Ok(Ok(count)) => Some(count),
        Ok(Err(e)) => {
            first_error.get_or_insert(e);
            None
        }
        Err(_) => {
            first_error.get_or_insert_with(|| Error::other("the chunk reader thread panicked"));
            None
        }
    };

    for handle in worker_handles {
        if let Ok(Err(e)) = handle.join() {
            first_error.get_or_insert(e);
        }
    }
    let mut tar_stats = TarStats::default();
    match tar_handle.join() {
        Ok(Ok(stats)) => tar_stats = stats,
        Ok(Err(e)) => {
            first_error.get_or_insert(e);
        }
        Err(_) => {
            first_error.get_or_insert_with(|| Error::other("the tar thread panicked"));
        }
    }

    done.store(true, Ordering::Relaxed);
    let _ = progress_handle.join();

    if let Some(message) = first_error {
        return abandon_partial(&mut output_file, &coffin_path, message);
    }

    let written = written.unwrap_or(0);
    let expected = expected.unwrap_or(0);
    if written != expected {
        return abandon_partial(
            &mut output_file,
            &coffin_path,
            Error::other(format!(
                "only {written} of {expected} chunks were written, so the archive would be incomplete"
            )),
        );
    }

    write_trailer(&mut output_file, &keys.data[..], written)?;
    output_file
        .flush()
        .map_err(|e| Error::other(format!("cannot flush '{}': {e}", coffin_path.display())))?;
    output_file.get_ref().sync_all().map_err(|e| {
        Error::other(format!(
            "cannot write '{}' to disk: {e}",
            coffin_path.display()
        ))
    })?;
    drop(output_file);

    // Publish the archive, never replacing an existing one.
    if crypt_path.exists() {
        return Err(Error::invalid_input(format!(
            "'{}' already exists; refusing to overwrite it",
            crypt_path.display()
        )));
    }
    match fs::hard_link(&coffin_path, &crypt_path) {
        Ok(()) => {
            let _ = fs::remove_file(&coffin_path);
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            return Err(Error::invalid_input(format!(
                "'{}' already exists; refusing to overwrite it",
                crypt_path.display()
            )));
        }
        Err(_) => {
            // Filesystems without hard links (exFAT, for instance); the name was
            // checked for collisions just above.
            fs::rename(&coffin_path, &crypt_path).map_err(|e| {
                Error::other(format!(
                    "cannot rename '{}' to '{}': {e}",
                    coffin_path.display(),
                    crypt_path.display()
                ))
            })?;
        }
    }
    guard.keep = true;
    sync_dir(&base_dir);
    report_skips(&tar_stats);

    Ok(crypt_path)
}

// ---------------------------------------------------------------------------
// Decryption
// ---------------------------------------------------------------------------

/// A chunk straight off disk, already decrypted (compressed, not yet expanded).
struct CompressedReadChunk {
    index: u64,
    compressed: Zeroizing<Vec<u8>>,
}

struct DecryptedChunk {
    index: u64,
    data: Zeroizing<Vec<u8>>,
}

/// Knobs for [`decrypt_file`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecryptOptions {
    /// Worker threads used to decompress chunks. Zero is treated as one, and
    /// anything over 128 is capped at 128.
    pub workers: usize,
    /// Recover whatever a partial (`.coffin`) archive contains instead of
    /// demanding that it be complete. Wrong-password and per-chunk
    /// authentication still fail: only the end-of-stream check is relaxed.
    pub partial: bool,
    /// Argon2id parameters `(mem_cost_kib, time_cost, parallelism)` used **only**
    /// for v1 archives, which store none of their own. Ignored for v2 and later,
    /// whose parameters come from the file. The CLI fills this in from
    /// `CryptConfig.toml`.
    pub legacy_kdf: (u32, u32, u32),
}

impl Default for DecryptOptions {
    fn default() -> Self {
        DecryptOptions {
            workers: DEFAULT_NUM_WORKERS,
            partial: false,
            legacy_kdf: BUILT_IN_KDF,
        }
    }
}

/// Decrypt one archive into `output_dir` (or next to the archive) and return the
/// paths that were created, in the order they were seen.
///
/// Everything is extracted into a hidden staging directory first and only moved
/// into place after the trailer has authenticated, so a truncated or tampered
/// file cannot leave partial output under the final names.
///
/// # Errors
///
/// [`Error::Authentication`] covers both a wrong password and tampering (they
/// are deliberately indistinguishable). [`Error::Truncated`] means the archive
/// ends early — pass `partial: true` in [`DecryptOptions`] to keep the readable
/// part of a `.coffin` instead.
pub fn decrypt_file(
    crypt_path: &Path,
    password: &str,
    output_dir: Option<&Path>,
    opts: &DecryptOptions,
) -> Result<Vec<PathBuf>> {
    let workers = opts.workers.clamp(1, MAX_WORKERS);
    let partial = opts.partial;

    let mut file = File::open(crypt_path)
        .map_err(|e| Error::other(format!("cannot open '{}': {e}", crypt_path.display())))?;
    let raw = read_raw_header(&mut file)?;

    // Derive the header key for the claimed version. v5 uses one KDF call for
    // both keys; v1–v4 used a single key (or two, with the data params in the
    // header).
    let mut data_key = None;
    let header_key = if raw.version >= VERSION_AUTHENTICATED_HEADER {
        let keys = derive_keys(password, &raw.salt)?;
        data_key = Some(keys.data);
        keys.header
    } else if raw.version >= 3 {
        derive_single_key(
            password,
            &raw.salt,
            HEADER_ARGON2_MEM_COST,
            HEADER_ARGON2_TIME_COST,
            HEADER_ARGON2_PARALLELISM,
        )?
    } else if raw.version == 2 {
        let (mem, time, par) = raw
            .clear_kdf
            .ok_or_else(|| Error::malformed("v2 archive is missing its KDF parameters"))?;
        validate_kdf_params(mem, time, par)?;
        let key = derive_single_key(password, &raw.salt, mem, time, par)?;
        data_key = Some(key.clone());
        key
    } else {
        // v1 stored no KDF parameters at all: the caller's settings decide.
        let (mem, time, par) = opts.legacy_kdf;
        validate_kdf_params(mem, time, par)?;
        let key = derive_single_key(password, &raw.salt, mem, time, par)?;
        data_key = Some(key.clone());
        key
    };

    let info = authenticate_header(&raw, &header_key[..], opts.legacy_kdf)?;

    let data_key = match data_key {
        Some(key) => key,
        None => match info.kdf {
            // v3/v4: if the data used the built-in params the header key is it.
            Some((mem, time, par))
                if (mem, time, par)
                    == (
                        HEADER_ARGON2_MEM_COST,
                        HEADER_ARGON2_TIME_COST,
                        HEADER_ARGON2_PARALLELISM,
                    ) =>
            {
                header_key.clone()
            }
            Some((mem, time, par)) => derive_single_key(password, &raw.salt, mem, time, par)?,
            None => header_key.clone(),
        },
    };
    drop(header_key);

    let dest_root = match output_dir {
        Some(dir) => dir.to_path_buf(),
        None => crypt_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
            .to_path_buf(),
    };

    // Staging lives inside the destination so the final move is a rename on the
    // same filesystem.
    let staging = StagingDir::new(&dest_root)?;

    let allow_legacy_trailer = raw.version < VERSION_CATACOMB;
    let header_skip = raw.header_skip;
    let total_data_size = fs::metadata(crypt_path)
        .map(|m| m.len().saturating_sub(header_skip))
        .unwrap_or(0);

    let (raw_pipe_reader, raw_pipe_writer) =
        os_pipe::pipe().map_err(|e| Error::other(format!("cannot create a pipe: {e}")))?;
    let (compressed_tx, compressed_rx) = crossbeam_channel::bounded::<CompressedReadChunk>(workers);
    let (decrypted_tx, decrypted_rx) = crossbeam_channel::bounded::<DecryptedChunk>(workers * 2);

    let progress = Arc::new(AtomicU64::new(0));
    let done = Arc::new(AtomicBool::new(false));
    let progress_handle =
        spawn_progress_thread(Arc::clone(&progress), Arc::clone(&done), total_data_size);

    let data_key = Arc::new(Zeroizing::new(data_key.to_vec()));
    let source_path = crypt_path.to_path_buf();

    let chunk_reader_handle = thread::spawn(move || -> Result<u64> {
        let mut file = File::open(&source_path)
            .map_err(|e| Error::other(format!("cannot open '{}': {e}", source_path.display())))?;
        file.seek(io::SeekFrom::Start(header_skip)).map_err(|e| {
            Error::other(format!("cannot seek in '{}': {e}", source_path.display()))
        })?;
        let mut reader = BufReader::with_capacity(8 * 1024 * 1024, file);

        let mut index: u64 = 0;
        loop {
            let frame =
                match read_chunk_frame(&mut reader, &data_key[..], index, allow_legacy_trailer) {
                    Ok(frame) => frame,
                    // A partial archive has no valid end of stream: take what is
                    // there and stop, rather than refusing the whole file.
                    Err(e) if partial => {
                        eprintln!("[WARN] Partial archive, stopping at the cut: {e}");
                        break;
                    }
                    Err(e) => return Err(e),
                };
            match frame {
                ChunkFrame::Data { plaintext } => {
                    let chunk = CompressedReadChunk {
                        index,
                        compressed: plaintext,
                    };
                    if compressed_tx.send(chunk).is_err() {
                        break;
                    }
                    index += 1;
                }
                ChunkFrame::End { total_chunks } => {
                    verify_chunk_count(total_chunks, index)?;
                    break;
                }
            }
        }
        Ok(index)
    });

    let mut worker_handles = Vec::with_capacity(workers);
    let mut worker_error: Option<Error> = None;
    for _ in 0..workers {
        let compressed_rx = compressed_rx.clone();
        let decrypted_tx = decrypted_tx.clone();
        let progress_worker = Arc::clone(&progress);

        let spawned = thread::Builder::new().spawn(move || -> Result<()> {
            // One decompression context per worker, reused for every chunk.
            let mut decompressor = Decompressor::new()
                .map_err(|e| Error::other(format!("cannot create a zstd decompressor: {e}")))?;
            loop {
                let chunk = match compressed_rx.recv() {
                    Ok(chunk) => chunk,
                    Err(_) => break,
                };
                let index = chunk.index;
                let raw = decompress_chunk(&mut decompressor, &chunk.compressed, CHUNK_SIZE)?;
                drop(chunk);
                let raw_len = raw.len() as u64;
                progress_worker.fetch_add(raw_len, Ordering::Relaxed);

                let decrypted = DecryptedChunk {
                    index,
                    data: Zeroizing::new(raw),
                };
                if decrypted_tx.send(decrypted).is_err() {
                    break;
                }
            }
            Ok(())
        });
        match spawned {
            Ok(handle) => worker_handles.push(handle),
            Err(e) => {
                worker_error.get_or_insert_with(|| {
                    Error::other(format!("cannot start a worker thread: {e}"))
                });
                break;
            }
        }
    }
    drop(decrypted_tx);
    // As on the encrypt side: if no worker could be started, this unblocks the
    // chunk reader instead of leaving it waiting on a channel with no readers.
    drop(compressed_rx);

    // Pipe writer reorders chunks by index and streams them to the tar reader.
    let pipe_writer_handle = thread::spawn(move || -> Result<()> {
        let mut pipe_buf = BufWriter::with_capacity(8 * 1024 * 1024, raw_pipe_writer);
        let mut next_index: u64 = 0;
        let mut pending: HashMap<u64, DecryptedChunk> = HashMap::new();
        let max_pending = (workers * 4).max(8);

        while let Ok(chunk) = decrypted_rx.recv() {
            pending.insert(chunk.index, chunk);
            while let Some(chunk) = pending.remove(&next_index) {
                pipe_buf
                    .write_all(&chunk.data)
                    .map_err(|e| Error::other(format!("cannot write the decrypted stream: {e}")))?;
                next_index += 1;
            }
            if pending.len() > max_pending {
                return Err(Error::other(format!(
                    "{} chunks arrived out of order and could not be written; the output would be \
                     incomplete",
                    pending.len()
                )));
            }
        }

        if let Some(lowest) = pending.keys().min().copied() {
            return Err(Error::other(format!(
                "chunk {lowest} (and {} after it) could not be written; the output would be \
                 incomplete",
                pending.len()
            )));
        }

        pipe_buf
            .flush()
            .map_err(|e| Error::other(format!("cannot flush the decrypted stream: {e}")))?;
        Ok(())
    });

    // Consume the decrypted tar on this thread. The archive is dropped at the end
    // of this block, which closes the pipe so the writer thread can finish — the
    // joins below must therefore happen after it.
    let extract_result = {
        let reader = BufReader::with_capacity(8 * 1024 * 1024, raw_pipe_reader);
        if info.is_directory {
            let mut archive = tar::Archive::new(reader);
            unpack_tar_sanitized(&mut archive, staging.path()).map(|result| {
                if result.stats.skipped > 0 {
                    eprintln!(
                        "[WARN] Skipped {} archive entr{} that could not be extracted safely.",
                        result.stats.skipped,
                        if result.stats.skipped == 1 {
                            "y"
                        } else {
                            "ies"
                        }
                    );
                }
                result.tops
            })
        } else {
            let name = output_name_from_header(&info.name);
            let dest = staging.path().join(&name);
            let mut archive = tar::Archive::new(reader);
            unpack_single_file(&mut archive, &dest).map(|()| vec![name])
        }
    };

    let reader_result = chunk_reader_handle
        .join()
        .unwrap_or_else(|_| Err(Error::other("the chunk reader thread panicked")));
    for handle in worker_handles {
        if let Ok(Err(e)) = handle.join() {
            worker_error.get_or_insert(e);
        }
    }
    let writer_result = pipe_writer_handle
        .join()
        .unwrap_or_else(|_| Err(Error::other("the pipe writer thread panicked")));

    done.store(true, Ordering::Relaxed);
    let _ = progress_handle.join();

    // A partial archive is recovered on purpose, so its failures are warnings.
    // Everything else keeps the strict behaviour: the crypto verdict wins,
    // because on a truncated or tampered file the tar stream can still look
    // complete.
    if let Err(e) = reader_result {
        if !partial {
            return Err(e);
        }
        eprintln!("[WARN] Partial archive: {e}");
    }
    let tops = match extract_result {
        Ok(tops) => tops,
        Err(e) if partial => {
            eprintln!("[WARN] Partial archive: {e}");
            eprintln!("[WARN] Keeping the entries that were readable before the cut.");
            staged_tops(staging.path())?
        }
        Err(e) => return Err(e),
    };
    if let Some(e) = worker_error {
        if !partial {
            return Err(e);
        }
        eprintln!("[WARN] Partial archive: {e}");
    }
    if let Err(e) = writer_result {
        if !partial {
            return Err(e);
        }
        eprintln!("[WARN] Partial archive: {e}");
    }

    // Everything authenticated; move the results into place. Collision suffixes
    // are assigned here, at commit time, so a failed file cannot shift them.
    let mut created = Vec::with_capacity(tops.len());
    for top in &tops {
        let from = staging.path().join(top);
        let final_name = unique_component(&dest_root, top);
        let to = dest_root.join(&final_name);
        fs::rename(&from, &to)
            .map_err(|e| Error::other(format!("cannot move '{}' into place: {e}", to.display())))?;
        created.push(to);
    }
    // The staging directory is empty now; dropping it removes the shell.
    drop(staging);
    sync_dir(&dest_root);

    Ok(created)
}

// ---------------------------------------------------------------------------
// Command line
// ---------------------------------------------------------------------------

const USAGE: &str = "Usage: crypt [-e|-E|-d|-D] <path>[,<path>...] [--workers <N>] [--level <n>] \
[--output <dir>] [--password-stdin]
       Run with no arguments for interactive mode.";

const HELP: &str = "crypt — store large amounts of data privately.

USAGE:
    crypt -e <path>[,<path>...] [--output <dir>] [--workers <N>] [--level <n>]
    crypt -d <file.crypt>[,<file.crypt>...] [--output <dir>] [--workers <N>]
    crypt                       (interactive; takes no arguments)

OPTIONS:
    -e, -E                  Encrypt. Prompts for the password twice.
    -d, -D                  Decrypt. Prompts for the password once.
    --output <dir>          Where the result goes; created if missing.
                            Defaults to the source's directory.
    --workers <N>           Worker threads (1-128; anything higher is clamped).
                            Defaults to num_workers from the config.
    --level <n>             Zstd level (1-22); values outside the range are clamped.
                            Ignored when decrypting.
    --password-stdin        Read the password from stdin instead of the terminal.
                            At most 4096 bytes, and at most one line. Arguments
                            are never used for passwords: they are world-readable
                            in the process list.
    --                      Treat every later argument as a path.
    -h, --help              Show this help.
    -v, -V, --version       Show the version.

PATHS:
    Several paths may be given. An argument is split on commas, unless the
    argument as a whole names a file that exists, so a real path containing a
    comma still works. `.` and `..` are accepted and the archive is named after
    the directory they resolve to.

INTERACTIVE MODE:
    `crypt` with no arguments at all asks for the operation, the paths, the
    output directory and the password, which always comes from the terminal, so
    it cannot be scripted. A flag with no operation and no paths is a usage
    error rather than a prompt; use the flags above with --password-stdin to
    drive crypt from a script.

SKIPS:
    Only regular files and directories are archived. Symlinks, special files and
    the archive crypt is writing are skipped and reported. So is a file that
    cannot be read, and a directory that is a mount point onto another
    filesystem: those two add a warning to stderr saying the archive is valid but
    is not a full copy.

EXIT STATUS:
    0  success
    1  one or more inputs failed (decrypt continues past a bad file)
    2  usage error

FILES:
    $CRYPT_CONFIG, then $XDG_CONFIG_HOME/crypt/CryptConfig.toml (~/.config/crypt/),
    then an executable-adjacent CryptConfig.toml are read in that order.";

#[derive(Debug, Default, PartialEq, Eq)]
struct CliArgs {
    pub paths: Vec<PathBuf>,
    pub operation: Option<char>,
    pub workers: Option<usize>,
    pub level: Option<i32>,
    pub output: Option<PathBuf>,
    pub password_stdin: bool,
    pub help: bool,
    pub version: bool,
}

/// A flag's value as text, for the flags whose value must be UTF-8 anyway
/// (they are numbers). `--output` is the one that carries a path, so it goes
/// through `OsStr` untouched instead.
fn flag_value_str(flag: &str, value: &OsStr) -> Result<String> {
    value.to_str().map(str::to_owned).ok_or_else(|| {
        Error::invalid_input(format!(
            "{flag} expects UTF-8 text, got '{}'",
            value.to_string_lossy()
        ))
    })
}

fn parse_worker_count(value: &OsStr) -> Result<usize> {
    let text = flag_value_str("--workers", value)?;
    match text.trim().parse::<usize>() {
        Ok(n) if n >= 1 => {
            if n > MAX_WORKERS {
                eprintln!(
                    "[WARN] --workers {n} exceeds the maximum of {MAX_WORKERS}; using {MAX_WORKERS}."
                );
                Ok(MAX_WORKERS)
            } else {
                Ok(n)
            }
        }
        _ => Err(Error::invalid_input(format!(
            "--workers expects a positive integer, got '{}'",
            text.trim()
        ))),
    }
}

fn parse_compression_level(value: &OsStr) -> Result<i32> {
    let text = flag_value_str("--level", value)?;
    let level = text.trim().parse::<i32>().map_err(|_| {
        Error::invalid_input(format!("--level expects an integer, got '{}'", text.trim()))
    })?;
    if level > MAX_ZSTD_LEVEL {
        eprintln!(
            "[WARN] --level {} exceeds the maximum of {}; using {}.",
            level, MAX_ZSTD_LEVEL, MAX_ZSTD_LEVEL
        );
        Ok(MAX_ZSTD_LEVEL)
    } else if level < MIN_ZSTD_LEVEL {
        eprintln!(
            "[WARN] --level {} is below the minimum of {}; using {}.",
            level, MIN_ZSTD_LEVEL, MIN_ZSTD_LEVEL
        );
        Ok(MIN_ZSTD_LEVEL)
    } else {
        Ok(level)
    }
}

/// Parse the command line. Generic over the argument type so the CLI can hand in
/// `OsString`s straight from `env::args_os` while tests (and [`run`]) can hand in
/// `String`s.
fn parse_cli<S: AsRef<OsStr>>(args: &[S]) -> Result<CliArgs> {
    let mut parsed = CliArgs::default();
    let mut only_paths = false;
    let mut i = 0;

    while i < args.len() {
        let arg = args[i].as_ref();
        let bytes = arg.as_bytes();

        if only_paths {
            push_paths(&mut parsed.paths, arg);
            i += 1;
            continue;
        }

        if arg == OsStr::new("--") {
            only_paths = true;
        } else if arg == OsStr::new("-h") || arg == OsStr::new("--help") {
            parsed.help = true;
        } else if arg == OsStr::new("-v")
            || arg == OsStr::new("-V")
            || arg == OsStr::new("--version")
        {
            parsed.version = true;
        } else if arg == OsStr::new("--password-stdin") {
            parsed.password_stdin = true;
        } else if arg == OsStr::new("-e") || arg == OsStr::new("-E") {
            set_operation(&mut parsed.operation, 'e')?;
        } else if arg == OsStr::new("-d") || arg == OsStr::new("-D") {
            set_operation(&mut parsed.operation, 'd')?;
        } else if let Some(value) = bytes.strip_prefix(b"--workers=") {
            parsed.workers = Some(parse_worker_count(OsStr::from_bytes(value))?);
        } else if arg == OsStr::new("--workers") {
            i += 1;
            let value = args
                .get(i)
                .ok_or_else(|| Error::invalid_input("--workers requires a value"))?;
            parsed.workers = Some(parse_worker_count(value.as_ref())?);
        } else if let Some(value) = bytes.strip_prefix(b"--level=") {
            parsed.level = Some(parse_compression_level(OsStr::from_bytes(value))?);
        } else if arg == OsStr::new("--level") {
            i += 1;
            let value = args
                .get(i)
                .ok_or_else(|| Error::invalid_input("--level requires a value"))?;
            parsed.level = Some(parse_compression_level(value.as_ref())?);
        } else if let Some(value) = bytes.strip_prefix(b"--output=") {
            parsed.output = Some(PathBuf::from(OsString::from_vec(value.to_vec())));
        } else if arg == OsStr::new("--output") {
            i += 1;
            let value = args
                .get(i)
                .ok_or_else(|| Error::invalid_input("--output requires a value"))?;
            parsed.output = Some(PathBuf::from(value.as_ref()));
        } else if bytes.first() == Some(&b'-') && arg != OsStr::new("-") {
            return Err(Error::invalid_input(format!(
                "unknown flag '{}'",
                arg.to_string_lossy()
            )));
        } else {
            push_paths(&mut parsed.paths, arg);
        }

        i += 1;
    }

    Ok(parsed)
}

/// Positional paths may be comma separated: `"a,b"`, `a b` and `"a", "b"` all work.
///
/// A comma-separated argument is only split when the whole argument is not
/// itself an existing path, so a real file called `we,ird.txt` (or a directory
/// called `/mnt/My, Files`) can still be named directly instead of being torn in
/// two. Splitting wins over a literal name that does not exist, which keeps the
/// documented comma-separated form working.
///
/// Works on bytes rather than `str`, so a path named with invalid UTF-8 is one
/// path instead of an argument the parser refuses to look at.
fn push_paths(paths: &mut Vec<PathBuf>, arg: &OsStr) {
    let trimmed = trim_ascii(arg.as_bytes());
    if trimmed.is_empty() {
        return;
    }
    let path = Path::new(OsStr::from_bytes(trimmed));
    if !trimmed.contains(&b',') || path.exists() {
        paths.push(path.to_path_buf());
        return;
    }
    for part in trimmed.split(|byte| *byte == b',') {
        let part = trim_ascii(part);
        if !part.is_empty() {
            paths.push(PathBuf::from(OsString::from_vec(part.to_vec())));
        }
    }
}

/// `slice::trim_ascii` is newer than this crate's MSRV, so trim by hand.
fn trim_ascii(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |index| index + 1);
    &bytes[start..end]
}

fn set_operation(operation: &mut Option<char>, op: char) -> Result<()> {
    match operation {
        Some(existing) if *existing != op => {
            Err(Error::invalid_input("conflicting operation flags"))
        }
        _ => {
            *operation = Some(op);
            Ok(())
        }
    }
}

/// Drop inputs that cannot be used, with a warning, instead of failing the batch.
fn validate_input_paths(paths: Vec<PathBuf>, operation: char) -> Vec<PathBuf> {
    let mut valid = Vec::with_capacity(paths.len());
    for path in paths {
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                eprintln!(
                    "[WARN] Skipping symlink '{}': pass the real path instead.",
                    path.display()
                );
            }
            Ok(meta) if operation == 'e' && (meta.is_file() || meta.is_dir()) => {
                println!("Added: {}", path.display());
                valid.push(path);
            }
            Ok(meta) if operation == 'd' && meta.is_file() => {
                println!("Added: {}", path.display());
                valid.push(path);
            }
            Ok(_) => {
                eprintln!(
                    "[WARN] Skipping '{}': not a {}.",
                    path.display(),
                    if operation == 'e' {
                        "file or directory"
                    } else {
                        "regular .crypt file"
                    }
                );
            }
            Err(e) => {
                if e.kind() == io::ErrorKind::NotFound {
                    eprintln!("[WARN] Path does not exist: {}. Skipping.", path.display());
                } else {
                    eprintln!("[WARN] Skipping '{}': {e}", path.display());
                }
            }
        }
    }
    valid
}

fn ensure_output_dir(dir: &Path) -> Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    if dir.exists() {
        return Err(Error::invalid_input(format!(
            "output path '{}' exists but is not a directory",
            dir.display()
        )));
    }
    fs::create_dir_all(dir)
        .map_err(|e| Error::other(format!("cannot create '{}': {e}", dir.display())))?;
    eprintln!(
        "[WARN] Output directory did not exist; created '{}'.",
        dir.display()
    );
    Ok(())
}

/// Read one line from stdin.
///
/// `None` means the input ended (Ctrl-D, or stdin closed). That is *not* the same
/// as an empty line: treating EOF as "the user pressed Enter" makes the caller
/// prompt again forever.
fn read_line(prompt: &str) -> Result<Option<String>> {
    println!("{prompt}");
    let mut line = String::new();
    let read = io::stdin()
        .read_line(&mut line)
        .map_err(|e| Error::other(format!("cannot read from stdin: {e}")))?;
    if read == 0 {
        println!();
        return Ok(None);
    }
    Ok(Some(line.trim().to_string()))
}

fn get_choice() -> Result<char> {
    loop {
        let input = match read_line("Enter 'e' to encrypt or 'd' to decrypt.")? {
            Some(input) => input,
            None => return Err(Error::invalid_input("no choice was entered (input ended)")),
        };
        match input.as_str() {
            "e" => return Ok('e'),
            "d" => return Ok('d'),
            "" => continue,
            _ => println!("Invalid choice, please enter 'e' or 'd'."),
        }
    }
}

fn get_input_paths() -> Vec<PathBuf> {
    println!("Enter paths (one per line, blank line to finish):");
    let mut paths = Vec::new();
    loop {
        let mut line = String::new();
        match io::stdin().read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => {
                eprintln!("[WARN] Cannot read a path from stdin: {e}");
                break;
            }
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            if paths.is_empty() {
                continue;
            }
            break;
        }
        push_paths(&mut paths, OsStr::new(trimmed));
    }
    paths
}

fn get_output_dir() -> Option<PathBuf> {
    let input =
        match read_line("Enter output directory (or press Enter to use the source's directory):") {
            Ok(Some(input)) => input,
            Ok(None) => {
                eprintln!("[WARN] Input ended; using the source's directory.");
                return None;
            }
            Err(e) => {
                eprintln!("[WARN] {e}. Using the source's directory.");
                return None;
            }
        };
    if input.is_empty() {
        return None;
    }
    let path = PathBuf::from(&input);
    if path.is_dir() {
        println!("Output directory: {}", path.display());
        Some(path)
    } else {
        eprintln!(
            "[WARN] '{}' is not a directory. Using the source's directory.",
            input
        );
        None
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Run the whole program with UTF-8 arguments and return the process exit code.
///
/// Everything cheap happens first: arguments, paths and the output directory are
/// all checked before the password prompt and the (deliberately expensive) key
/// derivation, so a typo does not cost 512 MiB of Argon2id.
pub fn run(args: &[String]) -> i32 {
    let args: Vec<OsString> = args.iter().map(OsString::from).collect();
    run_os(&args)
}

/// The same, taking arguments exactly as the operating system reported them.
///
/// This is what the binary calls. A path whose bytes are not valid UTF-8 is
/// still a usable path, and turning it into a `String` (as [`run`] has to) would
/// either panic or mangle it, so nothing here round-trips an argument through
/// `String`.
pub fn run_os(args: &[OsString]) -> i32 {
    let cli = match parse_cli(args) {
        Ok(cli) => cli,
        Err(e) => {
            eprintln!("Error: {e}");
            eprintln!("{USAGE}");
            return 2;
        }
    };

    if cli.help {
        println!("{HELP}");
        return 0;
    }
    if cli.version {
        println!("crypt {}", env!("CARGO_PKG_VERSION"));
        return 0;
    }

    let config = load_config();

    // Interactive mode means no arguments at all: it asks for the operation, the
    // paths and the output directory, and takes the password from the terminal.
    // It is one or the other, never a mix, so stray flags are a usage error here
    // rather than a prompt that quietly eats the pipeline a caller meant as
    // input.
    let interactive = args.is_empty();
    if !interactive {
        if cli.operation.is_none() {
            eprintln!("Error: specify -e/-E (encrypt) or -d/-D (decrypt).");
            eprintln!("{USAGE}");
            return 2;
        }
        if cli.paths.is_empty() {
            eprintln!("Error: no paths provided.");
            eprintln!("{USAGE}");
            return 2;
        }
    }

    let requested_workers = cli.workers.unwrap_or(config.num_workers);
    let workers = requested_workers.clamp(1, MAX_WORKERS);
    if workers != requested_workers {
        eprintln!(
            "[WARN] {requested_workers} worker(s) requested; using {workers} (the valid range is \
             1..={MAX_WORKERS})."
        );
    }

    let level = match cli.level {
        Some(level) => level,
        None => {
            let configured = config.zstd_compression_level;
            let clamped = configured.clamp(MIN_ZSTD_LEVEL, MAX_ZSTD_LEVEL);
            if clamped != configured {
                eprintln!(
                    "[WARN] zstd_compression_level {} is out of range ({}..={}); using {}.",
                    configured, MIN_ZSTD_LEVEL, MAX_ZSTD_LEVEL, clamped
                );
            }
            clamped
        }
    };

    let operation = match cli.operation {
        Some(op) => op,
        None => match get_choice() {
            Ok(op) => op,
            Err(e) => {
                eprintln!("Error: {e}");
                return 1;
            }
        },
    };
    if operation == 'd' && cli.level.is_some() {
        eprintln!("[WARN] --level has no effect when decrypting; ignoring it.");
    }

    let candidates = if interactive {
        get_input_paths()
    } else {
        cli.paths.clone()
    };
    let paths = validate_input_paths(candidates, operation);
    if paths.is_empty() {
        eprintln!("No usable input paths; nothing to do.");
        return 1;
    }

    let output_dir = match cli.output.clone() {
        Some(dir) => Some(dir),
        None if interactive => get_output_dir(),
        None => None,
    };
    if let Some(dir) = &output_dir {
        if let Err(e) = ensure_output_dir(dir) {
            eprintln!("Error: {e}");
            return 1;
        }
    }

    let source = if cli.password_stdin {
        PasswordSource::Stdin
    } else {
        PasswordSource::Terminal
    };
    let password = match read_password(operation == 'e', source) {
        Ok(password) => password,
        Err(e) => {
            eprintln!("Error: {e}");
            return 1;
        }
    };

    if operation == 'e' {
        if let Err(e) = validate_password_for_encrypt(&password) {
            eprintln!("Error: {e}");
            return 1;
        }
    }

    // `std::thread::available_parallelism` covers this, so `num_cpus` is not
    // needed as a dependency.
    let detected_cores = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    println!(
        "Detected {detected_cores} CPU cores. Using {workers} worker(s) ({}).",
        if cli.workers.is_some() {
            "--workers"
        } else {
            "config"
        }
    );

    if operation == 'e' {
        let opts = EncryptOptions { workers, level };
        match encrypt_file(&paths, &password, output_dir.as_deref(), &opts) {
            Ok(path) => {
                let size = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                println!(
                    "Encryption complete: {} ({} MB)",
                    path.display(),
                    size / (1024 * 1024)
                );
                0
            }
            Err(e) => {
                eprintln!("Error: {e}");
                1
            }
        }
    } else {
        let opts = DecryptOptions {
            workers,
            partial: false,
            // Only consulted for v1 archives; the config is where they have
            // always lived.
            legacy_kdf: (
                config.argon2_mem_cost,
                config.argon2_time_cost,
                config.argon2_parallelism,
            ),
        };
        let mut failed = 0usize;
        for path in &paths {
            // A `.coffin` is an interrupted run by definition: recover whatever
            // it holds instead of refusing it.
            let opts = DecryptOptions {
                partial: path
                    .extension()
                    .map(|e| e.to_string_lossy() == "coffin")
                    .unwrap_or(false),
                ..opts
            };
            if opts.partial {
                eprintln!(
                    "[WARN] '{}' is a partial archive; recovering whatever it contains.",
                    path.display()
                );
            }
            println!("Decrypting {}...", path.display());
            // One bad file does not stop the batch.
            match decrypt_file(path, &password, output_dir.as_deref(), &opts) {
                Ok(created) => {
                    let names: Vec<String> =
                        created.iter().map(|p| p.display().to_string()).collect();
                    println!("Decrypted into: {}", names.join(", "));
                }
                Err(e) => {
                    eprintln!("Error: '{}': {e}", path.display());
                    failed += 1;
                }
            }
        }
        if failed > 0 {
            eprintln!("{failed} of {} file(s) failed.", paths.len());
            1
        } else {
            0
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const HK: [u8; 32] = [0x11; 32];
    const DK: [u8; 32] = [0x22; 32];

    fn salt() -> [u8; SALT_SIZE] {
        [0x33; SALT_SIZE]
    }

    /// Build a small, complete v5 archive in memory with known keys.
    fn build_archive(name: &str, is_directory: bool, chunks: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        write_header(&mut out, is_directory, name.as_bytes(), &salt(), &HK).unwrap();
        for (index, chunk) in chunks.iter().enumerate() {
            write_chunk_frame(&mut out, &DK, index as u64, chunk).unwrap();
        }
        write_trailer(&mut out, &DK, chunks.len() as u64).unwrap();
        out
    }

    fn open(bytes: &[u8]) -> Result<(RawHeader, HeaderInfo)> {
        let mut reader = Cursor::new(bytes);
        let raw = read_raw_header(&mut reader)?;
        let info = authenticate_header(&raw, &HK, BUILT_IN_KDF)?;
        Ok((raw, info))
    }

    #[test]
    fn header_round_trip() {
        let bytes = build_archive("docs", true, &[b"one"]);
        let (raw, info) = open(&bytes).unwrap();
        assert_eq!(raw.version, CRYPT_VERSION);
        assert_eq!(info.name, b"docs");
        assert!(info.is_directory);
        assert!(info.kdf.is_none(), "v5 headers carry no KDF parameters");

        let bytes = build_archive("photo.jpg", false, &[b"one"]);
        let (_, info) = open(&bytes).unwrap();
        assert!(!info.is_directory);
        assert_eq!(info.name, b"photo.jpg");
    }

    #[test]
    fn header_name_may_be_non_utf8() {
        let name: [u8; 5] = [b'a', 0xff, b'b', 0xfe, b'c'];
        let mut out = Vec::new();
        write_header(&mut out, false, &name, &salt(), &HK).unwrap();
        let (_, info) = open(&out).unwrap();
        assert_eq!(info.name, name.to_vec());
        assert_eq!(output_name_from_header(&info.name).as_bytes(), name);
    }

    #[test]
    fn version_downgrade_breaks_authentication() {
        let mut bytes = build_archive("docs", false, &[b"one"]);
        // Claim v4: the AAD was empty for v1–v4, so the v5 header will not
        // authenticate against it.
        bytes[4] = 4;
        bytes[5] = 0;
        let err = open(&bytes).unwrap_err();
        assert!(
            err.to_string().contains("header authentication failed"),
            "{err}"
        );
    }

    #[test]
    fn version_upgrade_breaks_authentication() {
        let mut bytes = build_archive("docs", false, &[b"one"]);
        bytes[4] = 6;
        bytes[5] = 0;
        assert!(open(&bytes).is_err());
    }

    #[test]
    fn tampered_salt_breaks_header_authentication() {
        // The salt is part of the header AAD, so editing it is detected even
        // though the key used for the test is fixed.
        let mut bytes = build_archive("docs", false, &[b"one"]);
        bytes[6] ^= 0x01;
        let err = open(&bytes).unwrap_err();
        assert!(
            err.to_string().contains("header authentication failed"),
            "{err}"
        );
    }

    #[test]
    fn tampered_header_body_breaks_authentication() {
        let mut bytes = build_archive("docs", false, &[b"one"]);
        // First byte of the header's nonce: past magic, version, salt and the
        // two-byte header length.
        bytes[6 + SALT_SIZE + 2] ^= 0x80;
        let err = open(&bytes).unwrap_err();
        assert!(
            err.to_string().contains("header authentication failed"),
            "{err}"
        );
    }

    #[test]
    fn wrong_key_breaks_header_authentication() {
        let bytes = build_archive("docs", false, &[b"one"]);
        let mut reader = Cursor::new(&bytes);
        let raw = read_raw_header(&mut reader).unwrap();
        let err = authenticate_header(&raw, &[0x44; 32], BUILT_IN_KDF).unwrap_err();
        assert!(
            err.to_string().contains("header authentication failed"),
            "{err}"
        );
    }

    #[test]
    fn bad_magic_is_rejected() {
        let mut bytes = build_archive("docs", false, &[b"one"]);
        bytes[0] = b'X';
        let err = read_raw_header(&mut Cursor::new(&bytes)).unwrap_err();
        assert!(err.to_string().contains("bad magic"), "{err}");
    }

    #[test]
    fn header_aad_is_version_dependent() {
        assert!(header_aad(4, &salt()).is_empty());
        assert!(header_aad(3, &salt()).is_empty());
        let aad = header_aad(5, &salt());
        assert_eq!(&aad[..4], CRYPT_MAGIC);
        assert_eq!(&aad[4..6], &5u16.to_le_bytes());
    }

    /// Read the chunk stream of an archive built by `build_archive`.
    fn read_chunks(bytes: &[u8], allow_legacy: bool) -> Result<(Vec<Vec<u8>>, Option<u64>)> {
        let mut cursor = Cursor::new(bytes);
        let raw = read_raw_header(&mut cursor)?;
        cursor.set_position(raw.header_skip);

        let mut chunks = Vec::new();
        let mut index = 0u64;
        loop {
            match read_chunk_frame(&mut cursor, &DK, index, allow_legacy)? {
                ChunkFrame::Data { plaintext } => {
                    chunks.push(plaintext.to_vec());
                    index += 1;
                }
                ChunkFrame::End { total_chunks } => return Ok((chunks, total_chunks)),
            }
        }
    }

    fn header_skip_of(bytes: &[u8]) -> u64 {
        read_raw_header(&mut Cursor::new(bytes))
            .unwrap()
            .header_skip
    }

    #[test]
    fn chunk_stream_round_trip() {
        let bytes = build_archive("docs", true, &[b"first", b"second", b"third"]);
        let (chunks, total) = read_chunks(&bytes, false).unwrap();
        assert_eq!(
            chunks,
            vec![b"first".to_vec(), b"second".to_vec(), b"third".to_vec()]
        );
        assert_eq!(total, Some(3));
    }

    #[test]
    fn swapped_chunks_are_detected() {
        // The AAD binds each chunk to its index, so moving ciphertext between
        // positions must fail authentication. Both records are the same size so
        // the swap is a clean byte-for-byte exchange.
        let bytes = build_archive("docs", true, &[b"AAAABBBB", b"CCCCDDDD"]);
        let start = header_skip_of(&bytes) as usize;
        // A record is `pt_len u32 | nonce | ciphertext | tag`.
        let record_len = 4 + NONCE_SIZE + 8 + GCM_TAG_SIZE;

        let mut swapped = bytes.clone();
        let first = bytes[start..start + record_len].to_vec();
        let second = bytes[start + record_len..start + 2 * record_len].to_vec();
        swapped[start..start + record_len].copy_from_slice(&second);
        swapped[start + record_len..start + 2 * record_len].copy_from_slice(&first);

        let err = read_chunks(&swapped, false).unwrap_err();
        assert!(err.to_string().contains("failed authentication"), "{err}");
    }

    #[test]
    fn flipped_chunk_byte_is_detected() {
        let mut bytes = build_archive("docs", true, &[b"payload payload payload"]);
        let start = header_skip_of(&bytes) as usize;
        bytes[start + NONCE_SIZE + 2] ^= 0x01;
        let err = read_chunks(&bytes, false).unwrap_err();
        assert!(err.to_string().contains("failed authentication"), "{err}");
    }

    #[test]
    fn truncated_at_chunk_boundary_is_detected() {
        let bytes = build_archive("docs", true, &[b"first", b"second", b"third"]);
        let without_trailer = &bytes[..bytes.len() - (4 + NONCE_SIZE + 8 + GCM_TAG_SIZE)];
        let err = read_chunks(without_trailer, false).unwrap_err();
        assert!(
            err.to_string().contains("end-of-stream trailer is missing"),
            "{err}"
        );
    }

    #[test]
    fn truncated_mid_chunk_is_detected() {
        let bytes = build_archive("docs", true, &[b"first", b"second"]);
        let cut = &bytes[..bytes.len() - (4 + NONCE_SIZE + 8 + GCM_TAG_SIZE) - 5];
        let err = read_chunks(cut, false).unwrap_err();
        assert!(err.to_string().contains("incomplete"), "{err}");
    }

    #[test]
    fn catacomb_chunk_count_mismatch_is_detected() {
        // Exactly the case the trailer exists for: the file is cut on a chunk
        // boundary, so every remaining chunk decrypts and the count is the only
        // thing that can reveal the loss.
        assert!(verify_chunk_count(None, 7).is_ok());
        assert!(verify_chunk_count(Some(7), 7).is_ok());
        let err = verify_chunk_count(Some(9), 7).unwrap_err();
        assert!(
            err.to_string().contains("declares 9") && err.to_string().contains("7 were read"),
            "{err}"
        );
    }

    #[test]
    fn catacomb_is_authenticated() {
        let mut bytes = build_archive("docs", true, &[b"first"]);
        let trailer = bytes.len() - (4 + NONCE_SIZE + 8 + GCM_TAG_SIZE);
        bytes[trailer + 5] ^= 0x01;
        let err = read_chunks(&bytes, false).unwrap_err();
        assert!(
            err.to_string().contains("trailer failed authentication"),
            "{err}"
        );
    }

    #[test]
    fn legacy_trailer_needs_an_explicit_opt_in() {
        // v1–v3 ended with an unauthenticated 0u32 marker.
        let mut bytes = Vec::new();
        write_header(&mut bytes, false, b"docs", &salt(), &HK).unwrap();
        write_chunk_frame(&mut bytes, &DK, 0, b"first").unwrap();
        bytes.extend_from_slice(&0u32.to_le_bytes());

        let err = read_chunks(&bytes, false).unwrap_err();
        assert!(
            err.to_string()
                .contains("authenticated end-of-stream trailer"),
            "{err}"
        );

        let (chunks, total) = read_chunks(&bytes, true).unwrap();
        assert_eq!(chunks, vec![b"first".to_vec()]);
        assert_eq!(total, None);
    }

    #[test]
    fn oversized_chunk_length_is_rejected_before_allocating() {
        let mut bytes = build_archive("docs", true, &[b"first"]);
        let start = header_skip_of(&bytes) as usize;
        bytes[start..start + 4].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
        let err = read_chunks(&bytes, false).unwrap_err();
        assert!(err.to_string().contains("impossible length"), "{err}");
        // The bound must be the real compressor bound, not a guess.
        assert!(max_chunk_pt_len() > CHUNK_SIZE);
        assert!(max_chunk_pt_len() < CHUNK_SIZE + CHUNK_SIZE / 8);
    }

    #[test]
    fn decompression_bomb_is_capped() {
        let bomb = vec![0u8; CHUNK_SIZE + 1];
        let mut compressor = zstd::bulk::Compressor::new(1).unwrap();
        let compressed = compressor.compress(&bomb).unwrap();
        assert!(
            compressed.len() < 1024 * 64,
            "the bomb should be small on disk"
        );

        let mut decompressor = Decompressor::new().unwrap();
        let err = decompress_chunk(&mut decompressor, &compressed, CHUNK_SIZE).unwrap_err();
        assert!(err.to_string().contains("decompression bomb"), "{err}");
    }

    /// The declared size is the cheap check. A frame that declares nothing — a
    /// streaming encoder does not know its input size, so it cannot write one —
    /// has to be caught by the destination cap instead.
    #[test]
    fn a_bomb_that_declares_no_size_is_capped_too() {
        let bomb = vec![0u8; CHUNK_SIZE + 1];
        let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 1).unwrap();
        encoder.write_all(&bomb).unwrap();
        let compressed = encoder.finish().unwrap();
        assert_eq!(
            zstd::zstd_safe::get_frame_content_size(&compressed).unwrap(),
            None,
            "this frame is meant to declare no content size"
        );

        let mut decompressor = Decompressor::new().unwrap();
        let err = decompress_chunk(&mut decompressor, &compressed, CHUNK_SIZE).unwrap_err();
        assert!(
            err.to_string().contains("maximum chunk size"),
            "the cap has to reject it: {err}"
        );
    }

    #[test]
    fn legitimate_chunks_still_decompress() {
        let data = vec![7u8; CHUNK_SIZE];
        let mut compressor = zstd::bulk::Compressor::new(3).unwrap();
        let compressed = compressor.compress(&data).unwrap();
        assert!(compressed.len() <= max_chunk_pt_len());

        let mut decompressor = Decompressor::new().unwrap();
        let restored = decompress_chunk(&mut decompressor, &compressed, CHUNK_SIZE).unwrap();
        assert_eq!(restored.len(), CHUNK_SIZE);
    }

    #[test]
    fn empty_chunk_is_never_written() {
        let mut out = Vec::new();
        let err = write_chunk_frame(&mut out, &DK, 0, b"").unwrap_err();
        assert!(err.to_string().contains("empty chunk"), "{err}");
    }

    #[test]
    fn a_wrong_key_length_is_an_error_not_a_panic() {
        // One byte short: this used to reach `Key::from_slice`, which panics.
        let short = [0x11u8; KEY_SIZE - 1];

        let err = aes_encrypt(b"payload", &short, b"").unwrap_err();
        assert!(
            err.to_string().contains("must be 32 bytes, got 31"),
            "{err}"
        );

        // Long enough to get past the length check that runs first.
        let ciphertext = vec![0u8; NONCE_SIZE + GCM_TAG_SIZE];
        let err = aes_decrypt(&ciphertext, &short, b"").unwrap_err();
        assert!(
            err.to_string().contains("must be 32 bytes, got 31"),
            "{err}"
        );

        // And the right length still round trips, so the check is not simply
        // rejecting everything.
        let key = [0x22u8; KEY_SIZE];
        let encrypted = aes_encrypt(b"payload", &key, b"aad").unwrap();
        let decrypted = aes_decrypt(&encrypted, &key, b"aad").unwrap();
        assert_eq!(decrypted.to_vec(), b"payload");
    }

    fn scratch_dir(tag: &str) -> PathBuf {
        let mut suffix = [0u8; 4];
        OsRng.fill_bytes(&mut suffix);
        let dir = env::temp_dir().join(format!("crypt-test-{tag}-{}", hex(&suffix)));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn unusable_names_are_rejected() {
        for name in [&b""[..], b".", b"..", b"a/b", b"a\0b"] {
            assert!(sanitize_name_bytes(name).is_none(), "{name:?}");
        }
    }

    #[test]
    fn illegal_characters_are_replaced_not_dropped() {
        assert_eq!(sanitize_name_bytes(b"a:b*c?").unwrap(), b"a_b_c_");
        assert_eq!(sanitize_name_bytes(b"back\\slash").unwrap(), b"back_slash");
        assert_eq!(sanitize_name_bytes(b"tab\there").unwrap(), b"tab\there");
        // Non-UTF-8 bytes are preserved verbatim.
        assert_eq!(sanitize_name_bytes(b"bad\xffname").unwrap(), b"bad\xffname");
    }

    #[test]
    fn path_traversal_is_rejected_structurally() {
        let components = |p: &str| sanitized_components(Path::new(p));
        assert_eq!(components("a/b").unwrap().len(), 2);
        assert_eq!(components("./a").unwrap().len(), 1);
        assert!(components("a/../b").is_none(), "parent dir must be refused");
        assert!(components("../b").is_none());
        assert!(components("/etc/passwd").is_none(), "absolute paths too");
        assert!(components("").is_none());
    }

    #[test]
    fn output_name_from_header_falls_back() {
        assert_eq!(output_name_from_header(b"ok.txt").as_bytes(), b"ok.txt");
        assert_eq!(
            output_name_from_header(b"..").as_bytes(),
            b"decrypted_output"
        );
    }

    #[test]
    fn unique_component_never_clobbers() {
        let dir = scratch_dir("unique");
        assert_eq!(unique_component(&dir, OsStr::new("docs")), "docs");

        fs::write(dir.join("docs"), b"x").unwrap();
        assert_eq!(unique_component(&dir, OsStr::new("docs")), "docs_1");

        fs::write(dir.join("docs_1"), b"x").unwrap();
        assert_eq!(unique_component(&dir, OsStr::new("docs")), "docs_2");

        // Non-UTF-8 names keep their bytes.
        let odd = OsString::from_vec(b"odd\xffname".to_vec());
        assert_eq!(unique_component(&dir, &odd), odd);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn non_ascii_bytes_are_located() {
        assert_eq!(first_non_ascii(b"plain"), None);
        assert_eq!(first_non_ascii(b""), None);
        // "héllo": the first byte of the two-byte UTF-8 sequence.
        assert_eq!(first_non_ascii(b"h\xc3\xa9llo"), Some((1, 0xC3)));
        assert_eq!(first_non_ascii("pässword".as_bytes()), Some((1, 0xC3)));
        assert_eq!(first_non_ascii(b"\xff"), Some((0, 0xFF)));
    }

    #[test]
    fn password_rules_apply_to_encryption_only() {
        assert!(validate_password_for_encrypt("").is_err());
        assert!(validate_password_for_encrypt("short").is_err());
        let err = validate_password_for_encrypt("1234567").unwrap_err();
        assert!(err.to_string().contains("at least 8"), "{err}");
        assert!(validate_password_for_encrypt("12345678").is_ok());

        // Non-ASCII and control characters are refused with a reason.
        assert!(validate_password_for_encrypt("pässword").is_err());
        assert!(validate_password_for_encrypt("pass\tword").is_err());
        assert!(validate_password_for_encrypt("pass\nword").is_err());
    }

    #[test]
    fn config_template_matches_the_defaults() {
        let parsed = parse_config(DEFAULT_CONFIG_TOML).unwrap();
        // Only the settings that do something are compared. The template's
        // argon2_* lines document the format's fixed KDF parameters, which are
        // deliberately not the values a `test-kdf` build actually uses.
        assert_eq!(parsed.num_workers, DEFAULT_NUM_WORKERS);
        assert_eq!(
            parsed.zstd_compression_level,
            DEFAULT_ZSTD_COMPRESSION_LEVEL
        );
    }

    #[test]
    fn bad_configs_are_rejected_without_panicking() {
        assert!(parse_config("num_workers = \"lots\"").is_err());
        assert!(parse_config("num_workers = 0").is_err());
        // Unknown keys are ignored rather than fatal.
        assert_eq!(
            parse_config("nonsense = 1\nnum_workers = 3")
                .unwrap()
                .num_workers,
            3
        );
    }

    #[test]
    fn cli_parses_paths_flags_and_separators() {
        let args: Vec<String> = [
            "-e",
            "a,b",
            "/c",
            "--workers",
            "2",
            "--level=3",
            "--output",
            "out",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let cli = parse_cli(&args).unwrap();
        assert_eq!(cli.operation, Some('e'));
        assert_eq!(cli.paths.len(), 3);
        assert_eq!(cli.workers, Some(2));
        assert_eq!(cli.level, Some(3));
        assert_eq!(cli.output, Some(PathBuf::from("out")));

        // `--` makes a leading dash a path.
        let args: Vec<String> = ["-d", "--", "-weird-name"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            parse_cli(&args).unwrap().paths,
            vec![PathBuf::from("-weird-name")]
        );

        let args: Vec<String> = ["--help"].iter().map(|s| s.to_string()).collect();
        assert!(parse_cli(&args).unwrap().help);
        let args: Vec<String> = ["-V"].iter().map(|s| s.to_string()).collect();
        assert!(parse_cli(&args).unwrap().version);
    }

    #[test]
    fn cli_rejects_bad_usage() {
        let cli =
            |args: &[&str]| parse_cli(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert!(cli(&["--bogus"]).is_err(), "unknown flag");
        assert!(cli(&["-e", "a", "-d"]).is_err(), "conflicting operations");
        assert!(cli(&["--workers", "0", "-e", "a"]).is_err(), "zero workers");
        assert!(cli(&["--workers=abc"]).is_err(), "non-numeric workers");
        // An absurd worker count is clamped, not rejected: it is the same class
        // of request as an out-of-range level.
        assert_eq!(
            cli(&["--workers", "5000", "-e", "a"]).unwrap().workers,
            Some(MAX_WORKERS)
        );
        assert!(cli(&["--output"]).is_err(), "missing value");
        // Out-of-range levels are clamped, not rejected.
        assert_eq!(cli(&["--level", "99"]).unwrap().level, Some(MAX_ZSTD_LEVEL));
        assert_eq!(cli(&["--level", "-4"]).unwrap().level, Some(MIN_ZSTD_LEVEL));
    }

    #[test]
    fn cli_keeps_non_utf8_arguments_intact() {
        use std::os::unix::ffi::OsStringExt;

        let args = vec![
            OsString::from("-e"),
            OsString::from_vec(b"bad\xffname".to_vec()),
            OsString::from_vec(b"--output=/tmp/out\xff".to_vec()),
        ];
        let cli = parse_cli(&args).unwrap();
        assert_eq!(
            cli.paths,
            vec![PathBuf::from(OsString::from_vec(b"bad\xffname".to_vec()))]
        );
        assert_eq!(
            cli.output,
            Some(PathBuf::from(OsString::from_vec(b"/tmp/out\xff".to_vec())))
        );

        // A flag whose value is a number has to be UTF-8, and says so instead of
        // quietly parsing something else.
        let args = vec![
            OsString::from("--workers"),
            OsString::from_vec(b"4\xff".to_vec()),
            OsString::from("-e"),
            OsString::from("a"),
        ];
        assert!(parse_cli(&args).is_err());
    }

    #[test]
    fn kdf_param_bounds_are_enforced_without_panicking() {
        assert!(validate_kdf_params(HEADER_ARGON2_MEM_COST, 12, 2).is_ok());
        assert!(validate_kdf_params(0, 1, 1).is_err());
        assert!(validate_kdf_params(8, 0, 1).is_err());
        assert!(validate_kdf_params(8, 1, 0).is_err());
        assert!(validate_kdf_params(u32::MAX, 1, 1).is_err());
        // build_argon2 must report rather than panic on absurd values.
        assert!(build_argon2(1, 1, 1).is_err());
    }

    #[cfg(feature = "test-kdf")]
    #[test]
    fn header_and_data_keys_are_independent() {
        let salt = salt();
        let keys = derive_keys("correct horse battery", &salt).unwrap();
        assert_ne!(&keys.header[..], &keys.data[..]);

        // The derivation is deterministic, and a different salt changes it.
        let again = derive_keys("correct horse battery", &salt).unwrap();
        assert_eq!(&keys.header[..], &again.header[..]);
        assert_eq!(&keys.data[..], &again.data[..]);
        let other = derive_keys("correct horse battery", &[0x44; SALT_SIZE]).unwrap();
        assert_ne!(&keys.data[..], &other.data[..]);
        assert_ne!(
            &keys.data[..],
            &derive_keys("different", &salt).unwrap().data[..]
        );
    }

    #[test]
    fn errors_carry_a_typed_variant() {
        // A wrong key is an authentication failure.
        let bytes = build_archive("docs", false, &[b"one"]);
        let mut reader = Cursor::new(&bytes);
        let raw = read_raw_header(&mut reader).unwrap();
        let err = authenticate_header(&raw, &[0x44; 32], BUILT_IN_KDF).unwrap_err();
        assert!(matches!(err, Error::Authentication(_)), "{err:?}");

        // A stream cut at a chunk boundary is truncated, not malformed.
        let bytes = build_archive("docs", true, &[b"first", b"second"]);
        let cut = &bytes[..bytes.len() - (4 + NONCE_SIZE + 8 + GCM_TAG_SIZE)];
        let err = read_chunks(cut, false).unwrap_err();
        assert!(matches!(err, Error::Truncated(_)), "{err:?}");

        // Something that is not a crypt archive at all is malformed.
        let mut not_an_archive = build_archive("docs", false, &[b"one"]);
        not_an_archive[0] = b'X';
        let err = read_raw_header(&mut Cursor::new(&not_an_archive)).unwrap_err();
        assert!(matches!(err, Error::Malformed(_)), "{err:?}");

        // A request that cannot be honoured never reaches the KDF.
        let err = encrypt_file(&[], "correcthorse", None, &EncryptOptions::default()).unwrap_err();
        assert!(matches!(err, Error::InvalidInput(_)), "{err:?}");
    }

    #[test]
    fn error_display_is_the_bare_message() {
        let err = Error::truncated("file is truncated");
        assert_eq!(err.to_string(), "file is truncated");
        assert_eq!(err.message(), "file is truncated");
        assert!(std::error::Error::source(&err).is_none());

        // The options types are usable straight out of the box.
        assert_eq!(EncryptOptions::default().workers, DEFAULT_NUM_WORKERS);
        assert_eq!(
            EncryptOptions::default().level,
            DEFAULT_ZSTD_COMPRESSION_LEVEL
        );
        assert_eq!(
            DecryptOptions::default(),
            DecryptOptions {
                workers: DEFAULT_NUM_WORKERS,
                partial: false,
                legacy_kdf: BUILT_IN_KDF,
            }
        );
    }

    #[test]
    fn a_trailing_dot_still_names_the_directory() {
        let dir = scratch_dir("dotname");
        let expected = fs::canonicalize(&dir)
            .unwrap()
            .file_name()
            .unwrap()
            .to_os_string();

        // The spellings that have no file name of their own, which is why the
        // helper exists: `crypt -e .` used to be rejected.
        assert!(Path::new(".").file_name().is_none());
        assert!(Path::new("..").file_name().is_none());

        // A trailing `.` is normalized away, so it does have a name already.
        assert_eq!(dir.join(".").file_name().unwrap(), dir.file_name().unwrap());
        assert_eq!(archive_name_for(&dir.join(".")).unwrap(), expected);
        assert_eq!(archive_name_for(&dir).unwrap(), expected);

        // An ordinary file keeps its name untouched.
        let file = dir.join("a.txt");
        fs::write(&file, b"x").unwrap();
        assert_eq!(archive_name_for(&file).unwrap(), OsString::from("a.txt"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn comma_separated_paths_still_split_unless_the_path_exists() {
        let dir = scratch_dir("commapath");
        let odd = dir.join("we,ird.txt");
        fs::write(&odd, b"x").unwrap();

        // A real path containing a comma is taken literally.
        let mut paths = Vec::new();
        push_paths(&mut paths, odd.as_os_str());
        assert_eq!(paths, vec![odd.clone()]);

        // A comma-separated argument that names nothing is still split.
        let mut paths = Vec::new();
        push_paths(&mut paths, OsStr::new("a,b"));
        assert_eq!(paths, vec![PathBuf::from("a"), PathBuf::from("b")]);

        // Whitespace around the parts is still trimmed.
        let mut paths = Vec::new();
        push_paths(&mut paths, OsStr::new(" a , b "));
        assert_eq!(paths, vec![PathBuf::from("a"), PathBuf::from("b")]);

        // A single path is unaffected.
        let mut paths = Vec::new();
        push_paths(&mut paths, OsStr::new("  /tmp/nowhere  "));
        assert_eq!(paths, vec![PathBuf::from("/tmp/nowhere")]);

        // Bytes that are not UTF-8 stay in the path instead of being replaced.
        let mut paths = Vec::new();
        push_paths(&mut paths, OsStr::from_bytes(b"bad\xffname"));
        assert_eq!(
            paths,
            vec![PathBuf::from(OsStr::from_bytes(b"bad\xffname"))]
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_staging_file_is_recognised_by_identity() {
        let dir = scratch_dir("stagingid");
        let staging = dir.join("archive-1f3a9c2b.coffin");
        fs::write(&staging, b"partial").unwrap();
        let canonical = fs::canonicalize(&staging).unwrap();

        let sibling = dir.join("archive-1f3a9c2b.crypt");
        fs::write(&sibling, b"sealed").unwrap();

        assert!(is_staging_file(&staging, &canonical));
        // Another spelling of the same file is still the same file.
        assert!(is_staging_file(
            &dir.join("./archive-1f3a9c2b.coffin"),
            &canonical
        ));
        assert!(!is_staging_file(&sibling, &canonical));
        assert!(!is_staging_file(&dir, &canonical));

        fs::remove_dir_all(&dir).ok();
    }
}
