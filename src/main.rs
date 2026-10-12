use std::collections::HashMap;
use std::env;
use std::fs;
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io::{BufReader, BufWriter, Cursor, Read, Write};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::SystemTime;

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    Aes256Gcm, Nonce, Key,
};
use argon2::{Argon2, Algorithm, Version, Params};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use tar;
use termios::{Termios, ECHO, ICANON, TCSANOW};
use zeroize::{Zeroize, Zeroizing};
use zstd::stream::read::Decoder as ZstdDecoder;

const CHUNK_SIZE: usize = 16 * 1024 * 1024; // 16 MB
const SALT_SIZE: usize = 32; // 256-bit Argon2id salt
const NONCE_SIZE: usize = 12; // 96-bit AES-GCM nonce

// The "catacomb": an authenticated end-of-stream trailer (v4+) recording the total
// chunk count, so truncation at a chunk boundary is detectable. The marker is never
// a valid chunk length (chunks are <= CHUNK_SIZE), so it can't be a real chunk.
const CATACOMB_MARKER: u32 = 0xFFFF_FFFF;
const CATACOMB_AAD: &[u8] = b"CRPT-catacomb";

const CRYPT_MAGIC: &[u8; 4] = b"CRPT";
const CRYPT_VERSION: u16 = 4; // v4 adds the catacomb (authenticated end-of-stream trailer) to detect truncation

// Default worker threads 
const DEFAULT_NUM_WORKERS: usize = 4;

// Default Argon2id parameters 
const DEFAULT_ARGON2_MEM_COST: u32 = 524288;     // 512 MB
const DEFAULT_ARGON2_TIME_COST: u32 = 12;
const DEFAULT_ARGON2_PARALLELISM: u32 = 2;

const DEFAULT_ZSTD_COMPRESSION_LEVEL: i32 = 22;
const MIN_ZSTD_LEVEL: i32 = 1;
const MAX_ZSTD_LEVEL: i32 = 22;

// The header is ALWAYS encrypted with these built-in ("solid-state") Argon2id
// params, independent of the user's config, so its metadata stays protected by
// strong defaults. They are NOT stored in the file, so they must never change.
const HEADER_ARGON2_MEM_COST: u32 = 524288; // 512 MiB
const HEADER_ARGON2_TIME_COST: u32 = 12;
const HEADER_ARGON2_PARALLELISM: u32 = 2;

// Bounds accepted for KDF params read back from a file (DoS guard against tampered headers).
const MIN_ARGON2_MEM_COST: u32 = 8;
const MAX_ARGON2_MEM_COST: u32 = 4 * 1024 * 1024; // 4 GiB, in KiB
const MAX_ARGON2_TIME_COST: u32 = 4096;
const MAX_ARGON2_PARALLELISM: u32 = 256;

// TOML config, read from CryptConfig.toml next to the binary (TOML so it can hold comments).
#[derive(Serialize, Deserialize)]
#[serde(default)]
struct Config {
    num_workers: usize,
    argon2_mem_cost: u32,
    argon2_time_cost: u32,
    argon2_parallelism: u32,
    zstd_compression_level: i32,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            num_workers: DEFAULT_NUM_WORKERS,
            argon2_mem_cost: DEFAULT_ARGON2_MEM_COST,
            argon2_time_cost: DEFAULT_ARGON2_TIME_COST,
            argon2_parallelism: DEFAULT_ARGON2_PARALLELISM,
            zstd_compression_level: DEFAULT_ZSTD_COMPRESSION_LEVEL,
        }
    }
}

// Default config written on first run. Values mirror `Config::default()`.
const DEFAULT_CONFIG_TOML: &str = r#"# IMPORTANT NOTES:
# Crypt only takes ASCII passwords.
# Use a password over at least 8 characters.
# CryptConfig must be in the same directory as Crypt.

# Worker threads. Overridden by the --workers <n> CLI flag.
# Going over CPU cores will slow down progress.
num_workers = 4

# Argon2id parameters (mem cost in KiB; 524288 = 512 MiB).
# Already on strong settings, higher is better. No CLI flag.
argon2_mem_cost = 524288
argon2_time_cost = 12
argon2_parallelism = 2

# Zstd compression level (1-22), 19+ is recommended.
# --level <n> CLI flag. n>22 = 22.
zstd_compression_level = 22


# Encrypt Example:
# Crypt -e "/crazystuff", "/otherstuff/coolstuff" --output "/externaldrive" --workers 10 --level 20

# Crypt -e -> invokes binary in encryption mode.
# "/crazystuff", "/otherstuff/coolstuff" -> paths to encrypt, comma separated.
# --output "/externaldrive" -> where to save the .crypt file.
# --workers 10 -> how many threads to work with.
# --level 20 -> Zstd level.

# Decrypt Example:
# Crypt -d "/externaldrive/crazystuff.crypt", "/externaldrive/coolstuff.crypt" --output "/restored" --workers 10

# Crypt -d -> invokes binary in decryption mode.
# "/externaldrive/crazystuff.crypt", "/externaldrive/coolstuff.crypt" -> .crypt files to decrypt, comma separated.
# --output "/restored" -> where to save the decrypted files.
"#;

fn load_config() -> Config {
    let config_path = {
        let exe = env::current_exe().expect("Failed to get executable path");
        let dir = exe.parent().expect("Failed to get executable directory");
        dir.join("CryptConfig.toml")
    };

    if !config_path.exists() {
        fs::write(&config_path, DEFAULT_CONFIG_TOML)
            .expect("Failed to write default config");
        println!("Created default config: {}", config_path.display());
        // Parse what we just wrote so the file and defaults stay in sync.
        return toml::from_str(DEFAULT_CONFIG_TOML).unwrap_or_default();
    }

    let toml_str = fs::read_to_string(&config_path)
        .expect("Failed to read config file");
    toml::from_str(&toml_str)
        .unwrap_or_else(|e| {
            eprintln!("[WARN] Failed to parse config '{}', using defaults: {}", config_path.display(), e);
            Config::default()
        })
}

// Print a progress bar like `|==========>.....| 67%` using carriage return. 6-7 Lmao
fn print_progress_bar(current: u64, total: u64, finished: bool) {
    if total == 0 { return; }
    let percent = (current as f64 / total as f64) * 100.0;
    let percent = percent.clamp(0.0, 100.0);
    let bar_width: usize = 50;
    let filled = ((percent / 100.0) * (bar_width as f64)).round() as usize;
    let filled = filled.min(bar_width);

    if finished {
        print!("\r|");
        for _ in 0..bar_width { print!("="); }
        println!("| {:.0}%", percent);
    } else {
        print!("\r|");
        for i in 0..bar_width {
            if i < filled {
                print!("=");
            } else if i == filled && filled < bar_width {
                print!(">");
            } else {
                print!(".");
            }
        }
        print!("| {:.0}%", percent);
    }
    std::io::stdout().flush().ok();
}

// Replace characters illegal in exFAT/Win32 filenames with underscores.
fn sanitize_path_component(component: &str) -> String {
    component.chars()
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '|' | '?' | '*' | '\0' => '_',
            c if (c as u32) < 0x20 && c != '\t' => '_',
            '\\' => '/',
            c => c,
        })
        .collect()
}

// Return `name`, or `name_1` / `name_2` / … if `base/name` already exists.
fn unique_component(base: &Path, name: &str) -> String {
    if !base.join(name).exists() {
        return name.to_string();
    }
    let (stem, ext) = match name.rsplit_once('.') {
        Some((s, e)) if !s.is_empty() && !e.is_empty() => (s.to_string(), Some(e.to_string())),
        _ => (name.to_string(), None),
    };
    let mut n = 1u32;
    loop {
        let candidate = match &ext {
            Some(e) => format!("{}_{}.{}", stem, n, e),
            None => format!("{}_{}", stem, n),
        };
        if !base.join(&candidate).exists() {
            return candidate;
        }
        n += 1;
    }
}

// Extract a tar archive, sanitizing each path to be exFAT-safe and giving any
// colliding top-level name a `_n` suffix. Returns the resolved top-level names.
fn unpack_tar_sanitized<R: Read>(archive: &mut tar::Archive<R>, base_path: &Path) -> std::io::Result<Vec<String>> {
    let mut resolved: HashMap<String, String> = HashMap::new();
    let mut order: Vec<String> = Vec::new();

    for entry_result in archive.entries()? {
        let mut entry = entry_result?;
        let entry_path = entry.path()?.to_string_lossy().to_string();

        let mut sanitized: Vec<String> = entry_path.split('/')
            .map(sanitize_path_component)
            .collect();

        if sanitized.iter().any(|c| c == ".." || c == ".") {
            eprintln!("[WARN] Skipping entry with path traversal: '{}'", sanitized.join("/"));
            continue;
        }
        if sanitized.first().map_or(true, |c| c.is_empty()) {
            continue;
        }

        // Resolve the top-level component so an existing file/dir is never clobbered.
        let top = sanitized[0].clone();
        let mapped = match resolved.get(&top) {
            Some(name) => name.clone(),
            None => {
                let name = unique_component(base_path, &top);
                resolved.insert(top, name.clone());
                order.push(name.clone());
                name
            }
        };
        sanitized[0] = mapped;

        let full_path = base_path.join(sanitized.join("/"));
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent)?;
        }
        if entry.header().entry_type().is_dir() {
            fs::create_dir_all(&full_path)?;
        } else {
            entry.unpack(&full_path)?;
        }
    }

    Ok(order)
}

fn sanitize_filename(name: &str) -> String {
    if name.is_empty() { return "decrypted_output".to_string(); }
    if name.contains("..") || name.contains('/') || name.contains('\\') || name.contains('\0') {
        eprintln!("[WARN] Filename '{}' contains unsafe characters. Using fallback name.", name);
        return "decrypted_output".to_string();
    }
    if name == "." || name == ".." {
        eprintln!("[WARN] Filename '{}' is a special directory entry. Using fallback name.", name);
        return "decrypted_output".to_string();
    }
    name.to_string()
}

// Read a password with masked echo (`*` per keystroke).
// Clear the entered password and erase its '*'s from the screen.
fn clear_masked_input(password: &mut String) {
    let len = password.len();
    password.clear();
    for _ in 0..len {
        print!("\x08 \x08");
    }
    std::io::stdout().flush().ok();
}

fn get_password() -> Zeroizing<String> {
    println!("Enter password.");

    let stdin_fd = std::io::stdin().as_raw_fd();
    let orig_termios = Termios::from_fd(stdin_fd).expect("Failed to get terminal attributes");

    // Disable canonical mode (ICANON) for immediate keystroke reads and echo (ECHO) so
    // characters don't appear on screen.
    let mut raw = orig_termios.clone();
    raw.c_lflag &= !(ICANON | ECHO);
    raw.c_cc[termios::VMIN] = 1;
    raw.c_cc[termios::VTIME] = 0;
    termios::tcsetattr(stdin_fd, TCSANOW, &raw).expect("Failed to set raw terminal mode");

    // Restore terminal on exit (including panic unwind).
    struct RestoreTermios {
        fd: i32,
        orig: Termios,
    }
    impl Drop for RestoreTermios {
        fn drop(&mut self) {
            let _ = termios::tcsetattr(self.fd, TCSANOW, &self.orig);
        }
    }
    let _restore = RestoreTermios { fd: stdin_fd, orig: orig_termios };

    let mut password = String::new();
    let mut stdin = std::io::stdin();

    loop {
        let mut byte = [0u8; 1];
        match stdin.read_exact(&mut byte) {
            Ok(()) => {}
            Err(_) => break,
        }

        match byte[0] {
            b'\n' | b'\r' => {
                println!();
                break;
            }
            0x7f | 0x08 => {
                if password.pop().is_some() {
                    print!("\x08 \x08");
                    std::io::stdout().flush().ok();
                }
            }
            0x15 => clear_masked_input(&mut password),
            0x03 => {
                println!("^C");
                std::process::exit(130);
            }
            0x04 => {
                println!();
                break;
            }
            0x20..=0x7E => {
                password.push(byte[0] as char);
                print!("*");
                std::io::stdout().flush().ok();
            }
            0x80..=0xFF => {
                clear_masked_input(&mut password);
                eprintln!("[WARN] Non-ASCII password, disallowed.");
            }
            _ => {}
        }
    }

    Zeroizing::new(password)
}

// Used only on encrypt to prevent typos from locking you out.
fn get_password_with_confirm() -> Zeroizing<String> {
    loop {
        let first = get_password();
        let second = get_password();
        if *first == *second {
            return first;
        }
        eprintln!("Passwords did not match, try again.");
    }
}

fn get_input_paths() -> Vec<PathBuf> {
    println!("Enter paths (One per line, blank line to finish):");
    let mut all_input = String::new();
    loop {
        let mut line = String::new();
        let bytes_read = std::io::stdin().read_line(&mut line)
            .expect("Failed to read path input from stdin");
        if bytes_read == 0 { break; }
        let trimmed = line.trim().to_string();
        if trimmed.is_empty() {
            if all_input.is_empty() { continue; }
            break;
        }
        all_input.push_str(&trimmed);
        all_input.push('\n');
    }
    let mut paths = Vec::new();
    for line in all_input.lines() {
        let trimmed = line.trim().to_string();
        if trimmed.is_empty() { continue; }
        let path = PathBuf::from(&trimmed);
        if path.exists() { paths.push(path); println!("Added: {}", trimmed); }
        else { eprintln!("[WARN] Path does not exist: {}. Skipping.", trimmed); }
    }
    if paths.is_empty() { println!("No valid paths entered."); }
    paths
}

fn get_choice() -> char {
    loop {
        println!("Enter 'e' to encrypt or 'd' to decrypt.");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).expect("Failed to read choice from stdin");
        let trimmed = input.trim();
        if trimmed == "e" { return 'e'; }
        if trimmed == "d" { return 'd'; }
        if trimmed.is_empty() { continue; }
        println!("Invalid choice, please enter 'e' or 'd'.");
    }
}

fn get_output_dir() -> Option<PathBuf> {
    println!("Enter output directory (or press Enter to use the source file's directory):");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).expect("Failed to read output directory from stdin");
    let trimmed = input.trim().to_string();
    if trimmed.is_empty() { return None; }
    let path = PathBuf::from(&trimmed);
    if path.is_dir() {
        println!("Output directory: {}", path.display());
        Some(path)
    } else {
        eprintln!("[WARN] Path '{}' is not a valid directory. Using default (source file's directory).", trimmed);
        None
    }
}

// Make sure a `--output` directory exists, creating it if necessary.
fn ensure_output_dir(dir: &Path) {
    if dir.is_dir() {
        return;
    }
    if dir.exists() {
        eprintln!("Error: output path '{}' exists but is not a directory.", dir.display());
        std::process::exit(1);
    }
    if let Err(e) = fs::create_dir_all(dir) {
        eprintln!("Error: cannot create output directory '{}': {}", dir.display(), e);
        std::process::exit(1);
    }
    eprintln!("[WARN] Output not present, creating folder for output: {:?}", dir);
}

fn make_salt() -> Zeroizing<[u8; SALT_SIZE]> {
    let mut salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);
    Zeroizing::new(salt)
}

fn build_argon2(mem_cost: u32, time_cost: u32, parallelism: u32) -> Argon2<'static> {
    let params = Params::new(mem_cost, time_cost, parallelism, None)
        .expect("invalid argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

fn derive_key(password: &str, salt: &[u8; SALT_SIZE], mem_cost: u32, time_cost: u32, parallelism: u32) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    build_argon2(mem_cost, time_cost, parallelism)
        .hash_password_into(password.as_bytes(), salt, &mut *key)
        .expect("key derivation failed");
    key
}

// Reject absurd KDF params read from a file so a tampered header cannot exhaust
// memory/CPU before the wrong key is detected.
fn validate_kdf_params(mem_cost: u32, time_cost: u32, parallelism: u32) -> Result<(), String> {
    if mem_cost < MIN_ARGON2_MEM_COST || mem_cost > MAX_ARGON2_MEM_COST {
        return Err(format!("mem_cost {} out of range ({}..={} KiB)", mem_cost, MIN_ARGON2_MEM_COST, MAX_ARGON2_MEM_COST));
    }
    if time_cost < 1 || time_cost > MAX_ARGON2_TIME_COST {
        return Err(format!("time_cost {} out of range (1..={})", time_cost, MAX_ARGON2_TIME_COST));
    }
    if parallelism < 1 || parallelism > MAX_ARGON2_PARALLELISM {
        return Err(format!("parallelism {} out of range (1..={})", parallelism, MAX_ARGON2_PARALLELISM));
    }
    Ok(())
}

fn aes_encrypt(data: &[u8], key: &[u8], aad: &[u8]) -> std::io::Result<Vec<u8>> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, Payload { msg: data, aad }).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::Other, format!("AES-GCM encryption failed: {}", e))
    })?;
    let mut result = nonce.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

fn aes_decrypt(encrypted: &[u8], key: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, aes_gcm::aead::Error> {
    if encrypted.len() < NONCE_SIZE { return Err(aes_gcm::aead::Error); }
    let nonce = &encrypted[..NONCE_SIZE];
    let ciphertext = &encrypted[NONCE_SIZE..];
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    cipher.decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map(Zeroizing::new)
}

// Hash the current timestamp and return the first 8 hex characters.
// This produces a unique suffix so repeated backups don't collide.
fn date_hash() -> String {
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    nanos.hash(&mut hasher);
    format!("{:08x}", hasher.finish())
}

fn dir_total_size(path: &Path) -> std::io::Result<u64> {
    let mut total = 0u64;
    if path.is_dir() {
        for entry in walkdir::WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() { total += entry.metadata()?.len(); }
        }
    }
    Ok(total)
}

fn walkdir_and_add_to_tar<W: Write>(
    tar_builder: &mut tar::Builder<W>,
    archive_name: &Path,
    source_dir: &Path,
) -> std::io::Result<()> {
    let mut skipped = 0u64;
    for entry in walkdir::WalkDir::new(source_dir).into_iter().filter_map(|e| e.ok()) {
        let ft = match entry.path().metadata() {
            Ok(m) => m,
            Err(_) => { skipped += 1; continue; }
        };
        let relative = entry.path().strip_prefix(source_dir).unwrap_or(entry.path());
        let archive_entry = if relative.as_os_str().is_empty() {
            archive_name.to_path_buf()
        } else {
            archive_name.join(relative)
        };

        // Record directory entries too, so empty directories survive a round-trip.
        if ft.is_dir() {
            let mut header = tar::Header::new_gnu();
            header.set_size(0);
            header.set_entry_type(tar::EntryType::Directory);
            header.set_mtime(0);
            header.set_mode(0o755);
            tar_builder.append_data(&mut header, &archive_entry, std::io::empty())?;
            continue;
        }
        if !ft.is_file() { skipped += 1; continue; }

        // Stream the file via BufReader instead of loading it entirely into RAM
        // (a 500 MB file would otherwise allocate that much memory).
        let file = match File::open(entry.path()) {
            Ok(f) => f,
            Err(e) => { eprintln!("[WARN] Skipping unreadable file '{}': {}", entry.path().display(), e); skipped += 1; continue; }
        };
        let file_size = file.metadata()?.len();
        let mut header = tar::Header::new_gnu();
        header.set_size(file_size);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_mtime(0);
        header.set_mode(0o644);
        tar_builder.append_data(&mut header, &archive_entry, BufReader::new(file))?;
    }
    if skipped > 0 { eprintln!("[WARN] Skipped {} unreadable entries during tar creation", skipped); }
    Ok(())
}

fn stream_files_to_tar<W: Write + Send + 'static>(
    paths: Vec<PathBuf>,
    _archive_name: &str,
    writer: W,
) -> std::io::Result<()> {
    let mut tar_builder = tar::Builder::new(writer);
    for path in &paths {
        if path.is_dir() {
            let dir_name = path.file_name().unwrap_or_default();
            walkdir_and_add_to_tar(&mut tar_builder, Path::new(dir_name), path)?;
        } else if path.is_file() {
            let name = path.file_name().unwrap_or_default();
            let file = match File::open(path) {
                Ok(f) => f,
                Err(e) => { eprintln!("[WARN] Skipping unreadable file '{}': {}", path.display(), e); continue; }
            };
            let file_size = file.metadata()?.len();
            let mut header = tar::Header::new_gnu();
            header.set_size(file_size);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_mtime(0);
            header.set_mode(0o644);
            tar_builder.append_data(&mut header, name, BufReader::new(file))?;
        } else {
            eprintln!("[WARN] Skipping path '{}': not a file or directory.", path.display());
        }
    }
    tar_builder.into_inner()?;
    Ok(())
}

fn decompress_frame(data: &[u8]) -> std::io::Result<Vec<u8>> {
    let decoder = ZstdDecoder::new(Cursor::new(data))?;
    let mut decompressed = Vec::new();
    std::io::copy(&mut BufReader::new(decoder), &mut decompressed)?;
    Ok(decompressed)
}

fn write_crypt_header(
    output_file: &mut BufWriter<File>,
    header_key: &[u8],
    salt: &[u8],
    is_directory: bool,
    archive_name: &str,
    argon2_mem_cost: u32,
    argon2_time_cost: u32,
    argon2_parallelism: u32,
) -> std::io::Result<()> {
    output_file.write_all(CRYPT_MAGIC)?;
    output_file.write_all(&CRYPT_VERSION.to_le_bytes())?;
    output_file.write_all(salt)?;

    let type_byte: u8 = if is_directory { b'D' } else { b'F' };
    let name_bytes = archive_name.as_bytes();
    let name_len = name_bytes.len();
    if name_len > 65535 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Filename too long (max 65535 bytes)"));
    }

    // The data KDF params travel INSIDE the encrypted header so they stay hidden
    // yet recoverable even if the user changes the config later.
    let mut header_plaintext = Vec::with_capacity(1 + 2 + name_len + 12);
    header_plaintext.push(type_byte);
    header_plaintext.extend_from_slice(&(name_len as u16).to_le_bytes());
    header_plaintext.extend_from_slice(name_bytes);
    header_plaintext.extend_from_slice(&argon2_mem_cost.to_le_bytes());
    header_plaintext.extend_from_slice(&argon2_time_cost.to_le_bytes());
    header_plaintext.extend_from_slice(&argon2_parallelism.to_le_bytes());

    // Header gets no AAD — it's metadata, not a data-bearing chunk.
    let encrypted_header = aes_encrypt(&header_plaintext, header_key, &[])?;
    let header_total_len = encrypted_header.len() as u16;
    output_file.write_all(&header_total_len.to_le_bytes())?;
    output_file.write_all(&encrypted_header)?;
    Ok(())
}

struct RawChunk {
    index: u64,
    data: Zeroizing<Vec<u8>>,
}

// Compressed but not yet encrypted. Workers produce these; the main
// writer thread encrypts each one with an AAD binding its chunk index
// (prevents reordering/duplication) and writes to disk incrementally
// with a bounded pending map.
struct CompressedChunk {
    index: u64,
    compressed_len: u32,
    compressed: Zeroizing<Vec<u8>>,
}

// Encrypted chunk read from disk. AAD on decrypt uses only the chunk
// index (no is_last flag), so the decrypt reader is straightforward.
struct EncryptedChunk {
    index: u64,
    data: Vec<u8>,
}

struct DecryptedChunk {
    index: u64,
    data: Zeroizing<Vec<u8>>,
}

// Build an AAD tag for a data chunk: the chunk index encoded as u64 LE.
// This binds each ciphertext to its position in the chunk sequence,
// preventing undetected reordering or duplication.
fn chunk_aad(index: u64) -> Vec<u8> {
    index.to_le_bytes().to_vec()
}

// CLI: positional paths (comma-separated when more than one), an operation flag
// (-e/-E to encrypt, -d/-D to decrypt), `--workers <N>`, `--level <n>` and `--output <dir>`.
struct CliArgs {
    paths: Vec<PathBuf>,
    workers: Option<usize>,
    operation: Option<char>,
    output: Option<PathBuf>,
    level: Option<i32>,
}

const USAGE: &str = "Usage: Crypt [-e|-E|-d|-D] <path>[,<path>...] [--workers <N>] [--level <n>] [--output <dir>]\n       Run with no arguments for interactive mode.";

fn parse_cli_args() -> CliArgs {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut paths: Vec<PathBuf> = Vec::new();
    let mut workers: Option<usize> = None;
    let mut operation: Option<char> = None;
    let mut output: Option<PathBuf> = None;
    let mut level: Option<i32> = None;

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];

        if arg == "-e" || arg == "-E" {
            set_operation(&mut operation, 'e');
        } else if arg == "-d" || arg == "-D" {
            set_operation(&mut operation, 'd');
        } else if let Some(v) = arg.strip_prefix("--workers=") {
            workers = Some(parse_worker_count(v));
        } else if arg == "--workers" {
            i += 1;
            if i >= args.len() {
                eprintln!("Error: --workers requires a value.\n{}", USAGE);
                std::process::exit(2);
            }
            workers = Some(parse_worker_count(&args[i]));
        } else if let Some(v) = arg.strip_prefix("--level=") {
            level = Some(parse_compression_level(v));
        } else if arg == "--level" {
            i += 1;
            if i >= args.len() {
                eprintln!("Error: --level requires a value.\n{}", USAGE);
                std::process::exit(2);
            }
            level = Some(parse_compression_level(&args[i]));
        } else if let Some(v) = arg.strip_prefix("--output=") {
            output = Some(PathBuf::from(v));
        } else if arg == "--output" {
            i += 1;
            if i >= args.len() {
                eprintln!("Error: --output requires a value.\n{}", USAGE);
                std::process::exit(2);
            }
            output = Some(PathBuf::from(&args[i]));
        } else if arg.starts_with('-') && arg != "-" {
            eprintln!("Error: unknown flag '{}'.\n{}", arg, USAGE);
            std::process::exit(2);
        } else {
            // Positional path(s); commas split multiple paths: `"a,b"`, `a b` and `"a", "b"`.
            for part in arg.split(',') {
                let trimmed = part.trim();
                if !trimmed.is_empty() {
                    paths.push(PathBuf::from(trimmed));
                }
            }
        }

        i += 1;
    }

    CliArgs { paths, workers, operation, output, level }
}

fn set_operation(operation: &mut Option<char>, op: char) {
    match operation {
        Some(existing) if *existing != op => {
            eprintln!("Error: conflicting operation flags.\n{}", USAGE);
            std::process::exit(2);
        }
        _ => *operation = Some(op),
    }
}

fn parse_worker_count(value: &str) -> usize {
    match value.trim().parse::<usize>() {
        Ok(n) if n >= 1 => n,
        _ => {
            eprintln!("Error: --workers expects a positive integer, got '{}'.\n{}", value, USAGE);
            std::process::exit(2);
        }
    }
}

fn parse_compression_level(value: &str) -> i32 {
    let level = match value.trim().parse::<i32>() {
        Ok(n) => n,
        Err(_) => {
            eprintln!("Error: --level expects an integer, got '{}'.\n{}", value, USAGE);
            std::process::exit(2);
        }
    };
    if level > MAX_ZSTD_LEVEL {
        eprintln!("[WARN] --level {} exceeds the maximum of {}; using {}.", level, MAX_ZSTD_LEVEL, MAX_ZSTD_LEVEL);
        MAX_ZSTD_LEVEL
    } else if level < MIN_ZSTD_LEVEL {
        eprintln!("[WARN] --level {} is below the minimum of {}; using {}.", level, MIN_ZSTD_LEVEL, MIN_ZSTD_LEVEL);
        MIN_ZSTD_LEVEL
    } else {
        level
    }
}

fn main() -> std::io::Result<()> {
    let config = load_config();
    let cli = parse_cli_args();

    let requested_workers = cli.workers.unwrap_or(config.num_workers);
    let num_workers = requested_workers.max(1);
    if num_workers != requested_workers {
        eprintln!("[WARN] num_workers {} is invalid; using 1.", requested_workers);
    }

    // `--level` overrides the config; anything above 22 is capped at 22.
    let zstd_level = match cli.level {
        Some(level) => level, // already validated/clamped when parsing the flag
        None => {
            let configured = config.zstd_compression_level;
            let clamped = configured.clamp(MIN_ZSTD_LEVEL, MAX_ZSTD_LEVEL);
            if clamped != configured {
                eprintln!("[WARN] zstd_compression_level {} is out of range ({}..={}); using {}.", configured, MIN_ZSTD_LEVEL, MAX_ZSTD_LEVEL, clamped);
            }
            clamped
        }
    };

    let num_cores = num_cpus::get();
    let source = if cli.workers.is_some() { "--workers" } else { "config" };
    println!("Detected {} CPU cores. Using {} worker(s) ({}).", num_cores, num_workers, source);

    // Fully interactive only when invoked with no arguments at all.
    let interactive = cli.operation.is_none() && cli.paths.is_empty();

    // In CLI mode an operation flag and at least one path are required.
    if !interactive {
        if cli.operation.is_none() {
            eprintln!("Error: specify -e/-E (encrypt) or -d/-D (decrypt).\n{}", USAGE);
            std::process::exit(2);
        }
        if cli.paths.is_empty() {
            eprintln!("Error: no paths provided.\n{}", USAGE);
            std::process::exit(2);
        }
    }

    // Get the operation choice first so we know whether to prompt once or twice.
    let choice = match cli.operation {
        Some(op) => op,
        None => get_choice(),
    };

    if choice == 'd' && cli.level.is_some() {
        eprintln!("[WARN] --level has no effect when decrypting; ignoring it.");
    }

    let mut password = match choice {
        'e' => get_password_with_confirm(),
        'd' => get_password(),
        _ => unreachable!(),
    };
    let mut decrypt_password: Zeroizing<String> = Zeroizing::new(password.to_string());

    use std::sync::mpsc;
    let (key_tx, key_rx) = mpsc::channel();
    let pw_for_thread = password.clone();
    password.zeroize();
    let config_for_thread = Config {
        num_workers: config.num_workers,
        argon2_mem_cost: config.argon2_mem_cost,
        argon2_time_cost: config.argon2_time_cost,
        argon2_parallelism: config.argon2_parallelism,
        zstd_compression_level: config.zstd_compression_level,
    };
    let handle_derive = thread::spawn(move || {
        let salt = make_salt();
        let cfg = &config_for_thread;
        // Header key always uses the built-in defaults; the data key uses the user's config.
        let header_key = derive_key(&pw_for_thread, &salt, HEADER_ARGON2_MEM_COST, HEADER_ARGON2_TIME_COST, HEADER_ARGON2_PARALLELISM);
        // If the config already equals the built-in params, reuse the header key (no second heavy KDF).
        let same_as_header = cfg.argon2_mem_cost == HEADER_ARGON2_MEM_COST
            && cfg.argon2_time_cost == HEADER_ARGON2_TIME_COST
            && cfg.argon2_parallelism == HEADER_ARGON2_PARALLELISM;
        let data_key = if same_as_header {
            header_key.clone()
        } else {
            derive_key(&pw_for_thread, &salt, cfg.argon2_mem_cost, cfg.argon2_time_cost, cfg.argon2_parallelism)
        };
        let result: (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) = (salt, header_key, data_key);
        let _ = key_tx.send(result);
    });

    let input_paths = if interactive {
        get_input_paths()
    } else {
        let mut valid: Vec<PathBuf> = Vec::new();
        for path in cli.paths {
            if path.exists() {
                println!("Added: {}", path.display());
                valid.push(path);
            } else {
                eprintln!("[WARN] Path does not exist: {}. Skipping.", path.display());
            }
        }
        valid
    };

    if input_paths.is_empty() {
        handle_derive.join().unwrap();
        if !interactive { println!("No valid paths entered."); }
        return Ok(());
    }

    // `--output` wins; otherwise prompt (interactive) or use the source's directory.
    let output_dir = if let Some(dir) = cli.output {
        ensure_output_dir(&dir);
        Some(dir)
    } else if interactive {
        get_output_dir()
    } else {
        None
    };

    match choice {
        'e' => {
            let (salt, header_key, key) = key_rx.recv().unwrap();
            handle_derive.join().unwrap();

            let (archive_name, is_directory) = if input_paths.len() == 1 {
                let name = input_paths[0].file_name().unwrap_or_default().to_string_lossy().to_string();
                (name, input_paths[0].is_dir())
            } else {
                let name = input_paths[0].file_name().unwrap_or_default().to_string_lossy().to_string();
                (name, true)
            };

            let stem = input_paths[0].file_stem().unwrap_or_default().to_string_lossy();
            let base_dir = output_dir.as_deref().unwrap_or(
                input_paths[0].parent().unwrap_or(Path::new("."))
            );

            // Write to .coffin first; rename to .crypt only after everything succeeds.
            // If the process crashes mid-encryption, a .coffin file is clearly partial.
            let coffin_path = base_dir.join(format!("{}-{}.coffin", stem, date_hash()));
            let crypt_path = coffin_path.with_extension("crypt");

            let mut total_input_size = 0u64;
            for path in &input_paths {
                if path.is_dir() { total_input_size += dir_total_size(path)?; }
                else if path.is_file() { total_input_size += fs::metadata(path)?.len(); }
            }
            println!("  Total input size: ~{} MB", total_input_size / (1024 * 1024));

            // Pipeline: Tar thread (I/O) -> Pipe reader (I/O) -> crossbeam (CPU workers: compress only)
            // -> Writer (encrypt with AAD + write)

            let (pipe_reader, pipe_writer) = os_pipe::pipe()?;

            let paths_clone = input_paths.clone();
            let name_clone = archive_name.clone();
            let tar_handle = thread::spawn(move || {
                stream_files_to_tar(paths_clone, &name_clone, pipe_writer)
            });

            // Bounded to num_workers so the pipe reader blocks when workers are busy,
            // creating natural backpressure that prevents memory from piling up.
            let (raw_tx, raw_rx) = crossbeam_channel::bounded::<RawChunk>(num_workers);
            let (compressed_tx, compressed_rx) = crossbeam_channel::bounded::<CompressedChunk>(num_workers * 2);

            let progress = Arc::new(AtomicU64::new(0));
            let done = Arc::new(AtomicBool::new(false));

            let progress_clone = Arc::clone(&progress);
            let done_clone = Arc::clone(&done);
            let progress_handle = thread::spawn(move || {
                loop {
                    thread::sleep(std::time::Duration::from_millis(500));
                    if done_clone.load(Ordering::Relaxed) {
                        print_progress_bar(total_input_size, total_input_size, true);
                        break;
                    }
                    let current = progress_clone.load(Ordering::Relaxed);
                    if current > 0 {
                        print_progress_bar(current, total_input_size, false);
                    }
                }
            });

            let pipe_reader_handle = thread::spawn(move || -> std::io::Result<()> {
                let mut pipe_buf = BufReader::new(pipe_reader);
                let mut chunk_index: u64 = 0;
                let mut chunk_data = Zeroizing::new(vec![0u8; CHUNK_SIZE]);

                loop {
                    let mut buf_offset = 0usize;
                    loop {
                        match pipe_buf.read(&mut chunk_data[buf_offset..]) {
                            Ok(0) => break,
                            Ok(n) => buf_offset += n,
                            Err(e) => return Err(e),
                        }
                        if buf_offset >= CHUNK_SIZE { break; }
                    }

                    if buf_offset == 0 { break; }

                    let chunk = RawChunk {
                        index: chunk_index,
                        data: Zeroizing::new(chunk_data[..buf_offset].to_vec()),
                    };
                    if raw_tx.send(chunk).is_err() {
                        break;
                    }
                    chunk_data[..buf_offset].zeroize();
                    chunk_index += 1;
                }
                Ok(())
            });

            let mut worker_handles = Vec::new();
            for _ in 0..num_workers {
                let raw_rx = raw_rx.clone();
                let compressed_tx = compressed_tx.clone();
                let progress_w = Arc::clone(&progress);

                let handle = thread::spawn(move || -> std::io::Result<()> {
                    // Create one zstd compression context per worker and reuse it
                    // for every chunk instead of allocating a fresh CCtx per
                    // chunk (which peaked at ~4-5 GB per worker at level 22).
                    let mut compressor = zstd::bulk::Compressor::new(zstd_level)?;
                    loop {
                        let raw = match raw_rx.recv() {
                            Ok(chunk) => chunk,
                            Err(_) => break,
                        };

                        let raw_index = raw.index;
                        let raw_len = raw.data.len() as u64;

                        let compressed = compressor.compress(&raw.data)?;
                        let compressed_len = compressed.len() as u32;
                        // Drop 16 MB raw chunk before allocating encrypted output
                        drop(raw);

                        progress_w.fetch_add(raw_len, Ordering::SeqCst);

                        let chunk = CompressedChunk {
                            index: raw_index,
                            compressed_len,
                            compressed: Zeroizing::new(compressed),
                        };
                        if compressed_tx.send(chunk).is_err() {
                            break;
                        }
                    }
                    Ok(())
                });
                worker_handles.push(handle);
            }

            // Drop the original compressed_tx so the channel closes when all workers finish.
            // raw_tx is owned by the pipe reader thread and drops automatically.
            drop(compressed_tx);

            // Writer reorders chunks by index, encrypts each with AAD = chunk_index,
            // and writes to disk incrementally. The pending map is bounded to
            // num_workers * 3 to prevent memory from piling up if chunks arrive
            // severely out of order.
            let mut output_file = BufWriter::with_capacity(8 * 1024 * 1024, File::create(&coffin_path)?);
            write_crypt_header(
                &mut output_file, header_key.as_ref(), salt.as_ref(), is_directory, &archive_name,
                config.argon2_mem_cost, config.argon2_time_cost, config.argon2_parallelism,
            )?;

            let mut next_index: u64 = 0;
            let mut pending: HashMap<u64, CompressedChunk> = HashMap::new();
            let mut total_chunks: u64 = 0;

            while let Ok(chunk) = compressed_rx.recv() {
                if pending.len() >= num_workers * 3 {
                    while let Some(chunk) = pending.remove(&next_index) {
                        let aad = chunk_aad(chunk.index);
                        let encrypted = aes_encrypt(&chunk.compressed, key.as_ref(), &aad)?;
                        output_file.write_all(&chunk.compressed_len.to_le_bytes())?;
                        output_file.write_all(&encrypted)?;
                        next_index += 1;
                        total_chunks += 1;
                    }
                }

                pending.insert(chunk.index, chunk);

                while let Some(chunk) = pending.remove(&next_index) {
                    let aad = chunk_aad(chunk.index);
                    let encrypted = aes_encrypt(&chunk.compressed, key.as_ref(), &aad)?;
                    output_file.write_all(&chunk.compressed_len.to_le_bytes())?;
                    output_file.write_all(&encrypted)?;
                    next_index += 1;
                    total_chunks += 1;
                }
            }

            while let Some(chunk) = pending.remove(&next_index) {
                let aad = chunk_aad(chunk.index);
                let encrypted = aes_encrypt(&chunk.compressed, key.as_ref(), &aad)?;
                output_file.write_all(&chunk.compressed_len.to_le_bytes())?;
                output_file.write_all(&encrypted)?;
                next_index += 1;
                total_chunks += 1;
            }

            if !pending.is_empty() {
                eprintln!("[WARN] {} out-of-order chunks could not be written (gaps in sequence).", pending.len());
            }

            // Seal the stream with the catacomb: an authenticated trailer holding the
            // total chunk count, so truncation at a chunk boundary is detectable.
            output_file.write_all(&CATACOMB_MARKER.to_le_bytes())?;
            let catacomb = aes_encrypt(&total_chunks.to_le_bytes(), key.as_ref(), CATACOMB_AAD)?;
            output_file.write_all(&catacomb)?;
            output_file.flush()?;
            drop(output_file);

            // Rename .coffin -> .crypt only after everything is flushed and threads are joined.
            // If anything fails between create and rename, the .coffin stays as a partial marker.
            done.store(true, Ordering::SeqCst);

            pipe_reader_handle.join().unwrap().map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::Other, format!("Pipe reader thread failed: {:?}", e))
            })?;

            for wh in worker_handles {
                wh.join().unwrap().map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::Other, format!("Worker thread failed: {:?}", e))
                })?;
            }

            tar_handle.join().unwrap().map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::Other, format!("Tar thread failed: {:?}", e))
            })?;

            progress_handle.join().unwrap();

            // All threads succeeded — atomically rename to .crypt.
            fs::rename(&coffin_path, &crypt_path)?;

            drop(key);
            drop(header_key);
            drop(salt);

            let final_size = fs::metadata(&crypt_path).map(|m| m.len()).unwrap_or(0);
            println!("Encryption complete: {} ({} MB, {} chunks)", crypt_path.display(), final_size / (1024 * 1024), total_chunks);
        }

        'd' => {
            for input_path in &input_paths {
                println!("Decrypting {}...", input_path.display());
                if !input_path.is_file() {
                    eprintln!("Error: '{}' is not a valid .crypt file.", input_path.display());
                    continue;
                }

                let mut archive_file = File::open(input_path)?;
                let mut preader = BufReader::with_capacity(4096, &mut archive_file);

                let mut magic = [0u8; 4];
                if preader.read_exact(&mut magic).is_err() || &magic != CRYPT_MAGIC {
                    eprintln!("Error: '{}' is not a valid .crypt file (bad magic). Skipping.", input_path.display());
                    continue;
                }

                let mut version_bytes = [0u8; 2];
                if preader.read_exact(&mut version_bytes).is_err() { eprintln!("Error: '{}' is truncated. Skipping.", input_path.display()); continue; }
                let version = u16::from_le_bytes(version_bytes);
                if version < 1 || version > CRYPT_VERSION { eprintln!("Error: '{}' has unsupported version {}. Skipping.", input_path.display(), version); continue; }

                let mut salt = [0u8; SALT_SIZE];
                if preader.read_exact(&mut salt).is_err() { eprintln!("Error: '{}' is truncated (missing salt). Skipping.", input_path.display()); continue; }

                // v2 stored the data KDF params in the clear; v1 falls back to the config. v3 hides them in the header.
                let (kdf_mem, kdf_time, kdf_par) = if version == 2 {
                    let mut p = [0u8; 12];
                    if preader.read_exact(&mut p).is_err() { eprintln!("Error: '{}' is truncated (missing KDF parameters). Skipping.", input_path.display()); continue; }
                    (u32::from_le_bytes([p[0], p[1], p[2], p[3]]),
                     u32::from_le_bytes([p[4], p[5], p[6], p[7]]),
                     u32::from_le_bytes([p[8], p[9], p[10], p[11]]))
                } else {
                    (config.argon2_mem_cost, config.argon2_time_cost, config.argon2_parallelism)
                };

                let mut header_len_bytes = [0u8; 2];
                if preader.read_exact(&mut header_len_bytes).is_err() { eprintln!("Error: '{}' is truncated (missing header). Skipping.", input_path.display()); continue; }
                let header_total_len = u16::from_le_bytes(header_len_bytes) as usize;

                let mut header_encrypted = vec![0u8; header_total_len];
                if preader.read_exact(&mut header_encrypted).is_err() { eprintln!("Error: '{}' is truncated (missing header data). Skipping.", input_path.display()); continue; }

                let salt_zero = Zeroizing::new(salt);

                // v3 headers are always protected with the built-in params; v1/v2 used the single data key.
                let header_key = if version >= 3 {
                    derive_key(&*decrypt_password, &salt_zero, HEADER_ARGON2_MEM_COST, HEADER_ARGON2_TIME_COST, HEADER_ARGON2_PARALLELISM)
                } else {
                    if let Err(msg) = validate_kdf_params(kdf_mem, kdf_time, kdf_par) {
                        eprintln!("Error: '{}' has invalid KDF parameters ({}). Skipping.", input_path.display(), msg);
                        continue;
                    }
                    derive_key(&*decrypt_password, &salt_zero, kdf_mem, kdf_time, kdf_par)
                };

                // Header decrypt uses empty AAD (no chunk-level binding needed for metadata).
                let header_plaintext = match aes_decrypt(&header_encrypted, header_key.as_ref(), &[]) {
                    Ok(pt) => pt,
                    Err(e) => { eprintln!("Error decrypting '{}' header: {}. Wrong password or corrupted file. Skipping.", input_path.display(), e); continue; }
                };

                if header_plaintext.len() < 3 { eprintln!("Error: '{}' header too short. Skipping.", input_path.display()); continue; }

                let is_directory = header_plaintext[0] == b'D';
                let name_len = u16::from_le_bytes([header_plaintext[1], header_plaintext[2]]) as usize;
                if header_plaintext.len() < 3 + name_len { eprintln!("Error: '{}' header too short. Skipping.", input_path.display()); continue; }
                let name_bytes = &header_plaintext[3..3 + name_len];
                let original_name = String::from_utf8_lossy(name_bytes).to_string();
                let safe_name = sanitize_filename(&original_name);

                // v3 hides the data KDF params at the end of the header; derive the data key from them.
                let key = if version >= 3 {
                    let pstart = 3 + name_len;
                    if header_plaintext.len() < pstart + 12 {
                        eprintln!("Error: '{}' header is missing KDF parameters. Skipping.", input_path.display());
                        continue;
                    }
                    let p = &header_plaintext[pstart..pstart + 12];
                    let (data_mem, data_time, data_par) = (
                        u32::from_le_bytes([p[0], p[1], p[2], p[3]]),
                        u32::from_le_bytes([p[4], p[5], p[6], p[7]]),
                        u32::from_le_bytes([p[8], p[9], p[10], p[11]]),
                    );
                    if let Err(msg) = validate_kdf_params(data_mem, data_time, data_par) {
                        eprintln!("Error: '{}' has invalid KDF parameters ({}). Skipping.", input_path.display(), msg);
                        continue;
                    }
                    // If the data used the built-in params, the header key is already it.
                    if data_mem == HEADER_ARGON2_MEM_COST && data_time == HEADER_ARGON2_TIME_COST && data_par == HEADER_ARGON2_PARALLELISM {
                        header_key
                    } else {
                        derive_key(&*decrypt_password, &salt_zero, data_mem, data_time, data_par)
                    }
                } else {
                    header_key
                };

                let parent = output_dir.as_deref().unwrap_or(
                    input_path.parent().unwrap_or(Path::new("."))
                );

                // Pipeline: Chunk reader (I/O) -> crossbeam (CPU workers: decrypt + decompress) -> Pipe writer (I/O)

                let (raw_pipe_reader, raw_pipe_writer) = os_pipe::pipe()?;

                let crypt_path = input_path.to_owned();
                let key_thread = Arc::new(Zeroizing::new(key.as_ref().to_vec()));
                let argon_params_len = if version == 2 { 12u64 } else { 0 };
                let header_skip = 4u64 + 2 + SALT_SIZE as u64 + argon_params_len + 2 + header_total_len as u64;

                let total_file_size = fs::metadata(&crypt_path)?.len();
                let total_data_size = total_file_size.saturating_sub(header_skip);

                let (enc_tx, enc_rx) = crossbeam_channel::bounded::<EncryptedChunk>(num_workers);
                let (dec_tx, dec_rx) = crossbeam_channel::bounded::<DecryptedChunk>(num_workers * 2);

                let progress = Arc::new(AtomicU64::new(0));
                let done = Arc::new(AtomicBool::new(false));

                let progress_clone = Arc::clone(&progress);
                let done_clone = Arc::clone(&done);
                let progress_handle = thread::spawn(move || {
                    loop {
                        thread::sleep(std::time::Duration::from_millis(500));
                        if done_clone.load(Ordering::Relaxed) {
                            print_progress_bar(total_data_size, total_data_size, true);
                            break;
                        }
                        let current = progress_clone.load(Ordering::Relaxed);
                        if current > 0 {
                            print_progress_bar(current, total_data_size, false);
                        }
                    }
                });

                let key_r = Arc::clone(&key_thread);
                let legacy_trailer_ok = version < 4;
                let chunk_reader_handle = thread::spawn(move || -> std::io::Result<()> {
                    use std::io::Seek;
                    let mut crypt_file = File::open(&crypt_path)?;
                    crypt_file.seek(std::io::SeekFrom::Start(header_skip))?;
                    let mut chunk_reader = BufReader::with_capacity(8 * 1024 * 1024, crypt_file);
                    let mut chunk_index: u64 = 0;

                    loop {
                        let mut pt_len_bytes = [0u8; 4];
                        match chunk_reader.read_exact(&mut pt_len_bytes) {
                            Ok(()) => {}
                            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::UnexpectedEof,
                                    "File truncated: missing the catacomb (end-of-stream trailer). Data may be incomplete.",
                                ));
                            }
                            Err(e) => return Err(e),
                        }
                        let pt_len = u32::from_le_bytes(pt_len_bytes);

                        if pt_len == CATACOMB_MARKER {
                            // The catacomb: verify the recorded total chunk count so a
                            // file cut at a chunk boundary is detected as truncated.
                            let mut catacomb = [0u8; 12 + 8 + 16];
                            chunk_reader.read_exact(&mut catacomb)?;
                            let count_bytes = aes_decrypt(&catacomb, &**key_r, CATACOMB_AAD).map_err(|_| {
                                std::io::Error::new(std::io::ErrorKind::InvalidData,
                                    "Catacomb (end-of-stream trailer) failed authentication — truncated or tampered file.")
                            })?;
                            if count_bytes.len() != 8 {
                                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,
                                    "Catacomb (end-of-stream trailer) has an unexpected size."));
                            }
                            let mut count = [0u8; 8];
                            count.copy_from_slice(&count_bytes);
                            let expected = u64::from_le_bytes(count);
                            if expected != chunk_index {
                                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,
                                    format!("File truncated: catacomb declares {} chunk(s) but only {} were read.", expected, chunk_index)));
                            }
                            break;
                        }
                        if pt_len == 0 {
                            // Legacy (v1-v3) unauthenticated 0u32 trailer — no catacomb.
                            if !legacy_trailer_ok {
                                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,
                                    "File truncated: expected an authenticated catacomb (end-of-stream trailer)."));
                            }
                            break;
                        }

                        let chunk_len = 12 + pt_len as usize + 16;
                        let mut chunk_data = vec![0u8; chunk_len];
                        chunk_reader.read_exact(&mut chunk_data)?;

                        let chunk = EncryptedChunk {
                            index: chunk_index,
                            data: chunk_data,
                        };
                        if enc_tx.send(chunk).is_err() {
                            break;
                        }
                        chunk_index += 1;
                    }
                    Ok(())
                });

                let mut worker_handles = Vec::new();
                for _ in 0..num_workers {
                    let enc_rx = enc_rx.clone();
                    let dec_tx = dec_tx.clone();
                    let key_w = Arc::clone(&key_thread);
                    let progress_w = Arc::clone(&progress);

                    let handle = thread::spawn(move || -> std::io::Result<()> {
                        loop {
                            let chunk = match enc_rx.recv() {
                                Ok(c) => c,
                                Err(_) => break,
                            };

                            // AAD = chunk index only (no is_last flag).
                            let aad = chunk_aad(chunk.index);

                            let compressed = aes_decrypt(&chunk.data, &**key_w, &aad).map_err(|_| {
                                std::io::Error::new(std::io::ErrorKind::InvalidData,
                                    "Chunk decryption failed (AAD mismatch — chunk reordering or corruption detected).")
                            })?;

                            let raw = decompress_frame(&compressed)?;
                            let raw_len = raw.len() as u64;
                            drop(compressed);

                            progress_w.fetch_add(raw_len, Ordering::SeqCst);

                            let decrypted = DecryptedChunk {
                                index: chunk.index,
                                data: Zeroizing::new(raw),
                            };
                            if dec_tx.send(decrypted).is_err() {
                                break;
                            }
                        }
                        Ok(())
                    });
                    worker_handles.push(handle);
                }

                drop(dec_tx);

                // Pipe writer uses BufWriter to batch chunks before flushing to the pipe.
                // Without this, each write_all blocks on the 64 KB kernel pipe buffer,
                // causing backpressure that starves the worker threads.
                let pipe_writer_handle = thread::spawn(move || -> std::io::Result<()> {
                    let mut pipe_buf = BufWriter::with_capacity(8 * 1024 * 1024, raw_pipe_writer);
                    let mut next_index: u64 = 0;
                    let mut pending: HashMap<u64, DecryptedChunk> = HashMap::new();

                    while let Ok(decrypted) = dec_rx.recv() {
                        if pending.len() >= num_workers * 3 {
                            while let Some(chunk) = pending.remove(&next_index) {
                                pipe_buf.write_all(&chunk.data)?;
                                next_index += 1;
                            }
                        }

                        pending.insert(decrypted.index, decrypted);

                        while let Some(chunk) = pending.remove(&next_index) {
                            pipe_buf.write_all(&chunk.data)?;
                            next_index += 1;
                        }
                    }

                    while let Some(chunk) = pending.remove(&next_index) {
                        pipe_buf.write_all(&chunk.data)?;
                        next_index += 1;
                    }

                    if !pending.is_empty() {
                        eprintln!("[WARN] {} out-of-order decrypted chunks could not be written.", pending.len());
                    }

                    pipe_buf.flush()?;
                    drop(pipe_buf);
                    Ok(())
                });

                // Name collisions (e.g. two inputs that both contain "docs") get a
                // `_1`, `_2`, … suffix, numbered in the order they are produced.
                let decrypted_to: String;
                if is_directory {
                    // Entries (including directory entries) carry their own relative paths.
                    let mut archive = tar::Archive::new(BufReader::with_capacity(8 * 1024 * 1024, raw_pipe_reader));
                    let tops = unpack_tar_sanitized(&mut archive, parent)?;
                    decrypted_to = tops.iter()
                        .map(|t| parent.join(t).display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ");
                } else {
                    if !parent.as_os_str().is_empty() { fs::create_dir_all(parent)?; }
                    let dest = parent.join(unique_component(parent, &safe_name));
                    let mut archive = tar::Archive::new(BufReader::with_capacity(8 * 1024 * 1024, raw_pipe_reader));
                    // Read the first entry directly. Collecting all entries first would
                    // advance the reader past it, so the copy would read zero bytes.
                    let mut entries = archive.entries()?;
                    match entries.next() {
                        Some(entry) => {
                            let mut entry = entry?;
                            let mut output_file = File::create(&dest)?;
                            std::io::copy(&mut entry, &mut output_file)?;
                        }
                        None => eprintln!("[WARN] No entries found in decrypted tar for '{}'.", input_path.display()),
                    }
                    decrypted_to = dest.display().to_string();
                }

                done.store(true, Ordering::SeqCst);

                chunk_reader_handle.join().unwrap().map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::Other, format!("Chunk reader thread failed: {:?}", e))
                })?;

                for wh in worker_handles {
                    wh.join().unwrap().map_err(|e| {
                        std::io::Error::new(std::io::ErrorKind::Other, format!("Decrypt worker thread failed: {:?}", e))
                    })?;
                }

                pipe_writer_handle.join().unwrap().map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::Other, format!("Pipe writer thread failed: {:?}", e))
                })?;

                progress_handle.join().unwrap();

                println!("Decrypted into: {}", decrypted_to);
            }

            decrypt_password.zeroize();

        }

        _ => unreachable!(),
    }

    Ok(())
}