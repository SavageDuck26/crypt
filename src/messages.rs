//! Every line crypt prints and every message an [`Error`](crate::Error) carries.
//!
//! Keeping the text here means the wording can be read, reviewed and changed in
//! one place instead of being spread over the framing, extraction and CLI code.
//! The submodules follow the way the text reaches the user:
//!
//! - [`err`] is the payload of an [`Error`](crate::Error). Nothing here carries
//!   the `Error: ` prefix, because the caller adds it (and a library caller may
//!   not want it at all).
//! - [`warn`] is a complete line for stderr, `[WARN] ` prefix included: a warning
//!   has to be unmistakable next to normal progress output.
//! - [`info`] is a line for stdout, prompts included.
//!
//! Nothing in this module does any work beyond formatting: no I/O, no logging,
//! no decisions.
//!
//! Two conventions:
//!
//! - Text with nothing to fill in is a `const`, so the common case does not
//!   allocate; anything with a value in it is a function returning a `String`.
//! - Paths are passed as `&Path` and other details as `&dyn Display`, which is
//!   what lets an `io::Error`, a `tar::Error` and a `zstd` error all use the same
//!   helper.

use std::fmt::Display;
use std::path::Path;

/// What went wrong, as the payload of an [`Error`](crate::Error).
pub(crate) mod err {
    use super::*;
    use crate::{
        CRYPT_VERSION, KEY_SIZE, MAX_ARGON2_MEM_COST, MAX_ARGON2_PARALLELISM, MAX_ARGON2_TIME_COST,
        MAX_PIPED_PASSWORD_BYTES, MIN_ARGON2_MEM_COST, MIN_PASSWORD_LEN, MIN_READABLE_VERSION,
    };

    // -----------------------------------------------------------------------
    // Keys and the AEAD
    // -----------------------------------------------------------------------

    pub fn invalid_argon2_params(
        mem_cost: u32,
        time_cost: u32,
        parallelism: u32,
        e: &dyn Display,
    ) -> String {
        format!("invalid Argon2id parameters ({mem_cost}, {time_cost}, {parallelism}): {e}")
    }

    pub fn key_derivation_failed(e: &dyn Display) -> String {
        format!("key derivation failed: {e}")
    }

    pub fn wrong_key_length(got: usize) -> String {
        format!("internal error: the AES-GCM key must be {KEY_SIZE} bytes, got {got}")
    }

    pub fn aes_encrypt_failed(e: &dyn Display) -> String {
        format!("AES-GCM encryption failed: {e}")
    }

    pub const CIPHERTEXT_TOO_SHORT: &str = "ciphertext is too short";

    pub const AUTHENTICATION_FAILED: &str =
        "authentication failed (wrong password or corrupted file)";

    // -----------------------------------------------------------------------
    // Header
    // -----------------------------------------------------------------------

    pub fn archive_name_too_long(len: usize) -> String {
        format!(
            "archive name is too long ({len} bytes, maximum {})",
            u16::MAX
        )
    }

    pub const HEADER_TOO_SHORT: &str = "header is too short";

    pub fn unknown_header_type(byte: u8) -> String {
        format!("header has an unknown type byte 0x{byte:02x}")
    }

    pub const HEADER_NAME_LENGTH_OVERFLOWS: &str = "header name length overflows";
    pub const HEADER_NAME_TRUNCATED: &str = "header is shorter than its declared name length";
    pub const HEADER_MISSING_KDF: &str = "header is missing its KDF parameters";
    pub const HEADER_TOO_LARGE: &str = "header is too large to encode";

    pub fn mem_cost_out_of_range(mem_cost: u32) -> String {
        format!(
            "mem_cost {mem_cost} is out of range ({MIN_ARGON2_MEM_COST}..={MAX_ARGON2_MEM_COST} KiB)"
        )
    }

    pub fn time_cost_out_of_range(time_cost: u32) -> String {
        format!("time_cost {time_cost} is out of range (1..={MAX_ARGON2_TIME_COST})")
    }

    pub fn parallelism_out_of_range(parallelism: u32) -> String {
        format!("parallelism {parallelism} is out of range (1..={MAX_ARGON2_PARALLELISM})")
    }

    // -----------------------------------------------------------------------
    // Reading the file
    // -----------------------------------------------------------------------

    pub const FILE_TOO_SHORT: &str = "file is too short to be a crypt archive";
    pub const BAD_MAGIC: &str = "bad magic: not a crypt archive";
    pub const MISSING_VERSION: &str = "file is truncated (missing version)";
    pub const MISSING_SALT: &str = "file is truncated (missing salt)";
    pub const MISSING_KDF_PARAMS: &str = "file is truncated (missing KDF parameters)";
    pub const MISSING_HEADER: &str = "file is truncated (missing header)";
    pub const HEADER_INCOMPLETE: &str = "file is truncated (header is incomplete)";
    pub const HEADER_NOT_AUTHENTIC: &str =
        "header authentication failed: wrong password, or the header was tampered with";
    pub const V2_MISSING_KDF: &str = "v2 archive is missing its KDF parameters";

    pub fn unsupported_version(version: u16) -> String {
        format!(
            "unsupported format version {version} (this build reads \
             {MIN_READABLE_VERSION}..={CRYPT_VERSION})"
        )
    }

    pub fn cannot_open(path: &Path, e: &dyn Display) -> String {
        format!("cannot open '{}': {e}", path.display())
    }

    pub fn cannot_seek(path: &Path, e: &dyn Display) -> String {
        format!("cannot seek in '{}': {e}", path.display())
    }

    pub fn cannot_stat(path: &Path, e: &dyn Display) -> String {
        format!("cannot stat '{}': {e}", path.display())
    }

    pub fn read_failed(e: &dyn Display) -> String {
        format!("read failed: {e}")
    }

    // -----------------------------------------------------------------------
    // Chunk framing
    // -----------------------------------------------------------------------

    pub const TRAILER_MISSING: &str = "file is truncated: the end-of-stream trailer is missing, \
                                       so the data may be incomplete";
    pub const TRAILER_INCOMPLETE: &str =
        "file is truncated: the end-of-stream trailer is incomplete";
    pub const TRAILER_NOT_AUTHENTIC: &str = "the end-of-stream trailer failed authentication: the \
                                             file is truncated or tampered with";
    pub const TRAILER_ODD_SIZE: &str = "the end-of-stream trailer has an unexpected size";
    pub const EXPECTED_TRAILER: &str =
        "file is truncated: an authenticated end-of-stream trailer was expected";

    pub fn chunk_length_impossible(index: u64, declared: usize, max: usize) -> String {
        format!(
            "chunk {index} declares an impossible length ({declared} bytes; the maximum is {max})"
        )
    }

    pub fn chunk_incomplete(index: u64) -> String {
        format!("file is truncated: chunk {index} is incomplete")
    }

    pub fn chunk_auth_failed(index: u64) -> String {
        format!("chunk {index} failed authentication (wrong password, reordering or corruption)")
    }

    pub fn trailer_count_mismatch(declared: u64, read: u64) -> String {
        format!(
            "file is truncated: the end-of-stream trailer declares {declared} chunk(s) but {read} \
             were read"
        )
    }

    /// Chunks can only be written in order; a gap would be an archive that looks
    /// complete and is not.
    pub fn chunks_out_of_order(pending: usize) -> String {
        format!(
            "{pending} chunks arrived out of order and could not be written; the stream would \
             contain a gap"
        )
    }

    pub fn chunk_gap(lowest: u64, pending: usize) -> String {
        format!(
            "chunk {lowest} (and {pending} after it) could not be written; the stream would \
             contain a gap"
        )
    }

    pub fn chunks_out_of_order_output(pending: usize) -> String {
        format!(
            "{pending} chunks arrived out of order and could not be written; the output would be \
             incomplete"
        )
    }

    pub fn chunk_gap_output(lowest: u64, pending: usize) -> String {
        format!(
            "chunk {lowest} (and {pending} after it) could not be written; the output would be \
             incomplete"
        )
    }

    pub fn chunks_missing(written: u64, expected: u64) -> String {
        format!(
            "only {written} of {expected} chunks were written, so the archive would be incomplete"
        )
    }

    pub fn chunk_decompress_failed(max_len: usize, e: &dyn Display) -> String {
        format!(
            "chunk decompressed past the maximum chunk size ({max_len} bytes) or is corrupt: {e}"
        )
    }

    pub fn decompression_bomb(declared: u64, max_len: usize) -> String {
        format!(
            "chunk declares {declared} bytes of content, past the maximum chunk size ({max_len} \
             bytes); refusing what looks like a decompression bomb"
        )
    }

    pub const EMPTY_CHUNK: &str = "internal error: refusing to write an empty chunk";

    pub fn oversized_chunk(len: usize) -> String {
        format!("compressor produced an oversized chunk ({len} bytes)")
    }

    pub fn write_failed(e: &dyn Display) -> String {
        format!("write failed: {e}")
    }

    pub fn cannot_flush(path: &Path, e: &dyn Display) -> String {
        format!("cannot flush '{}': {e}", path.display())
    }

    pub fn cannot_write_to_disk(path: &Path, e: &dyn Display) -> String {
        format!("cannot write '{}' to disk: {e}", path.display())
    }

    // -----------------------------------------------------------------------
    // Threads and pipes
    // -----------------------------------------------------------------------

    pub fn cannot_create_pipe(e: &dyn Display) -> String {
        format!("cannot create a pipe: {e}")
    }

    pub fn cannot_start_worker(e: &dyn Display) -> String {
        format!("cannot start a worker thread: {e}")
    }

    pub const CHUNK_READER_PANICKED: &str = "the chunk reader thread panicked";
    pub const PIPE_WRITER_PANICKED: &str = "the pipe writer thread panicked";
    pub const TAR_THREAD_PANICKED: &str = "the tar thread panicked";

    pub fn cannot_create_compressor(e: &dyn Display) -> String {
        format!("cannot create a zstd compressor: {e}")
    }

    pub fn cannot_create_decompressor(e: &dyn Display) -> String {
        format!("cannot create a zstd decompressor: {e}")
    }

    pub fn compress_failed(index: u64, e: &dyn Display) -> String {
        format!("compressing chunk {index} failed: {e}")
    }

    pub fn cannot_read_tar_stream(e: &dyn Display) -> String {
        format!("reading the tar stream failed: {e}")
    }

    pub fn cannot_write_stream(e: &dyn Display) -> String {
        format!("cannot write the decrypted stream: {e}")
    }

    pub fn cannot_flush_stream(e: &dyn Display) -> String {
        format!("cannot flush the decrypted stream: {e}")
    }

    // -----------------------------------------------------------------------
    // Files and directories
    // -----------------------------------------------------------------------

    pub fn cannot_create(path: &Path, e: &dyn Display) -> String {
        format!("cannot create '{}': {e}", path.display())
    }

    pub fn cannot_read_dir(path: &Path, e: &dyn Display) -> String {
        format!("cannot read '{}': {e}", path.display())
    }

    pub fn cannot_write(path: &Path, e: &dyn Display) -> String {
        format!("cannot write '{}': {e}", path.display())
    }

    pub fn cannot_read_stdin(e: &dyn Display) -> String {
        format!("cannot read from stdin: {e}")
    }

    pub fn output_not_a_directory(path: &Path) -> String {
        format!(
            "output path '{}' exists but is not a directory",
            path.display()
        )
    }

    pub fn already_exists(path: &Path) -> String {
        format!(
            "'{}' already exists; refusing to overwrite it",
            path.display()
        )
    }

    pub fn cannot_rename(from: &Path, to: &Path, e: &dyn Display) -> String {
        format!(
            "cannot rename '{}' to '{}': {e}",
            from.display(),
            to.display()
        )
    }

    pub fn no_free_output_name(dir: &Path) -> String {
        format!("cannot find a free output name in '{}'", dir.display())
    }

    pub fn cannot_move_into_place(path: &Path, e: &dyn Display) -> String {
        format!("cannot move '{}' into place: {e}", path.display())
    }

    // -----------------------------------------------------------------------
    // Building the archive
    // -----------------------------------------------------------------------

    pub fn input_is_symlink(path: &Path) -> String {
        format!(
            "'{}' is a symlink; crypt does not archive symlinks. Pass the real path instead.",
            path.display()
        )
    }

    pub fn no_file_name(path: &Path) -> String {
        format!("'{}' has no file name", path.display())
    }

    pub fn not_a_file_or_directory(path: &Path) -> String {
        format!(
            "'{}' is neither a regular file nor a directory",
            path.display()
        )
    }

    pub fn cannot_add_file(path: &Path, e: &dyn Display) -> String {
        format!(
            "failed to add '{}' to the archive: {e}. A file that changes size while it is being \
             read will corrupt the archive",
            path.display()
        )
    }

    pub fn cannot_add_directory(path: &Path, e: &dyn Display) -> String {
        format!("failed to add directory '{}': {e}", path.display())
    }

    pub fn tar_finish_failed(e: &dyn Display) -> String {
        format!("failed to finish the tar stream: {e}")
    }

    // -----------------------------------------------------------------------
    // Extracting the archive
    // -----------------------------------------------------------------------

    pub fn cannot_read_tar(e: &dyn Display) -> String {
        format!("cannot read the tar stream: {e}")
    }

    pub fn cannot_extract(path: &Path, e: &dyn Display) -> String {
        format!("cannot extract '{}': {e}", path.display())
    }

    pub const NO_ENTRIES: &str = "the archive contains no entries";
    pub const FIRST_ENTRY_NOT_A_FILE: &str = "the archive's first entry is not a regular file";

    pub fn no_staging_name(parent: &Path) -> String {
        format!(
            "cannot create a staging directory in '{}': too many name collisions",
            parent.display()
        )
    }

    // -----------------------------------------------------------------------
    // Passwords
    // -----------------------------------------------------------------------

    pub const PASSWORD_EMPTY: &str = "the password must not be empty";

    pub fn password_control_char(c: char) -> String {
        format!(
            "the password must not contain control characters (found U+{:04X})",
            c as u32
        )
    }

    pub fn password_format_char(c: char) -> String {
        format!(
            "the password must not contain invisible formatting characters (found U+{:04X}); they \
             cannot be seen while typing, so the password could not be retyped",
            c as u32
        )
    }

    pub fn password_odd_space(c: char) -> String {
        format!(
            "the password may only use a plain space, not the whitespace character U+{:04X}",
            c as u32
        )
    }

    pub fn password_too_short(length: usize) -> String {
        format!(
            "the password must be at least {} characters for encryption (got {length})",
            MIN_PASSWORD_LEN
        )
    }

    pub fn cannot_read_password_stdin(e: &dyn Display) -> String {
        format!("cannot read the password from stdin: {e}")
    }

    pub fn cannot_read_password_terminal(e: &dyn Display) -> String {
        format!("cannot read the password from the terminal: {e}")
    }

    pub fn piped_password_too_long() -> String {
        format!("the password on stdin is longer than {MAX_PIPED_PASSWORD_BYTES} bytes")
    }

    pub const NUM_WORKERS_TOO_SMALL: &str = "num_workers must be at least 1";
    pub const NO_INPUT_PATHS: &str = "no input paths given";
    pub const CONFLICTING_OPERATIONS: &str = "conflicting operation flags";
    pub const PIPED_PASSWORD_NOT_UTF8: &str = "the password on stdin is not valid UTF-8";
    pub const PASSWORD_ABORTED: &str = "password entry aborted";
    pub const NO_TERMINAL: &str = "no terminal is available to ask for a password. Use \
                                   --password-stdin to read it from a pipe instead";

    pub fn cannot_read_terminal(e: &dyn Display) -> String {
        format!("cannot read terminal attributes: {e}")
    }

    pub fn cannot_set_raw_mode(e: &dyn Display) -> String {
        format!("cannot switch the terminal to raw mode: {e}")
    }

    // -----------------------------------------------------------------------
    // Command line
    // -----------------------------------------------------------------------

    pub fn flag_value_not_utf8(flag: &str, value: &str) -> String {
        format!("{flag} expects UTF-8 text, got '{value}'")
    }

    pub fn bad_worker_count(text: &str) -> String {
        format!("--workers expects a positive integer, got '{text}'")
    }

    pub fn bad_level(text: &str) -> String {
        format!("--level expects an integer, got '{text}'")
    }

    pub const WORKERS_REQUIRE_VALUE: &str = "--workers requires a value";
    pub const LEVEL_REQUIRES_VALUE: &str = "--level requires a value";
    pub const OUTPUT_REQUIRES_VALUE: &str = "--output requires a value";

    pub fn unknown_flag(flag: &str) -> String {
        format!("unknown flag '{flag}'")
    }

    /// A failure on the way out of the CLI, with the prefix the command line has
    /// always used. The library returns the bare [`Error`](crate::Error) instead.
    pub fn cli_error(e: &dyn Display) -> String {
        format!("Error: {e}")
    }

    pub const NO_OPERATION: &str = "Error: specify -e/-E (encrypt) or -d/-D (decrypt).";
    pub const NO_PATHS: &str = "Error: no paths provided.";
    pub const NO_CHOICE_ENTERED: &str = "no choice was entered (input ended)";

    pub fn file_failed(path: &Path, e: &dyn Display) -> String {
        format!("Error: '{}': {e}", path.display())
    }
}

/// A complete `[WARN]` line for stderr.
///
/// The prefix is part of every string here: a warning has to be unmistakable
/// next to the progress output, and one place that always adds it is easier to
/// audit than thirty call sites that mostly remember to.
pub(crate) mod warn {
    use super::*;
    use crate::{MAX_WORKERS, MAX_ZSTD_LEVEL, MIN_ZSTD_LEVEL};

    // -----------------------------------------------------------------------
    // Config
    // -----------------------------------------------------------------------

    pub fn cannot_read_config(path: &Path, e: &dyn Display) -> String {
        format!(
            "[WARN] Cannot read config '{}': {e}. Using built-in defaults.",
            path.display()
        )
    }

    pub fn cannot_parse_config(path: &Path, e: &dyn Display) -> String {
        format!(
            "[WARN] Failed to parse config '{}': {e}. Using built-in defaults.",
            path.display()
        )
    }

    pub fn cannot_write_default_config(path: &Path, e: &dyn Display) -> String {
        format!(
            "[WARN] Could not write default config to '{}': {e}. Using built-in defaults.",
            path.display()
        )
    }

    pub fn argon2_settings_ignored(
        path: &Path,
        changed: (u32, u32, u32),
        fixed: (u32, u32, u32),
    ) -> String {
        format!(
            "[WARN] '{}' sets argon2_* options ({}, {}, {}); they are fixed at ({}, {}, {}) by \
             the file format and will be ignored. They still apply when reading v1 archives.",
            path.display(),
            changed.0,
            changed.1,
            changed.2,
            fixed.0,
            fixed.1,
            fixed.2
        )
    }

    // -----------------------------------------------------------------------
    // Packing
    // -----------------------------------------------------------------------

    pub fn skipping_unreadable_file(path: &Path, e: &dyn Display) -> String {
        format!("[WARN] Skipping unreadable file '{}': {e}", path.display())
    }

    pub fn skipping(path: &Path, e: &dyn Display) -> String {
        format!("[WARN] Skipping '{}': {e}", path.display())
    }

    pub fn skipping_staging_file(path: &Path) -> String {
        format!(
            "[WARN] Skipping '{}': it is the archive crypt is writing right now.",
            path.display()
        )
    }

    pub fn skipping_symlink(path: &Path) -> String {
        format!(
            "[WARN] Skipping symlink '{}' (crypt archives regular files and directories only).",
            path.display()
        )
    }

    pub fn skipping_input_symlink(path: &Path) -> String {
        format!(
            "[WARN] Skipping symlink '{}': pass the real path instead.",
            path.display()
        )
    }

    pub fn skipping_new_symlink(path: &Path) -> String {
        format!(
            "[WARN] Skipping '{}': it turned into a symlink while the tree was being packed.",
            path.display()
        )
    }

    pub fn skipping_special_file(path: &Path) -> String {
        format!(
            "[WARN] Skipping '{}': not a regular file or directory.",
            path.display()
        )
    }

    pub fn skipping_other_filesystem(path: &Path, root: &Path) -> String {
        format!(
            "[WARN] Skipping '{}': it is on another filesystem (a mount point), so crypt stays \
             under '{}'.",
            path.display(),
            root.display()
        )
    }

    pub fn archive_not_a_full_copy(missing: &[String]) -> String {
        format!(
            "[WARN] The archive is valid but NOT a full copy: {}. See the warnings above, fix the \
             inputs and run crypt again if you need everything.",
            missing.join(" and ")
        )
    }

    pub fn missing_unreadable(count: u64) -> String {
        format!(
            "{count} unreadable entr{}",
            if count == 1 { "y" } else { "ies" }
        )
    }

    pub fn missing_other_filesystem(count: u64) -> String {
        format!(
            "{count} director{} on another filesystem",
            if count == 1 {
                "y (a mount point)"
            } else {
                "ies (mount points)"
            }
        )
    }

    pub fn partial_archive_left(path: &Path) -> String {
        format!(
            "[WARN] A partial archive was left at '{}'. Decrypt it to recover what was written.",
            path.display()
        )
    }

    // -----------------------------------------------------------------------
    // Extraction
    // -----------------------------------------------------------------------

    pub const STORED_NAME_UNUSABLE: &str =
        "[WARN] Stored filename is unusable; using a fallback name.";

    pub fn skipping_unsafe_entry(path: &Path) -> String {
        format!(
            "[WARN] Skipping unsafe tar entry '{}' (path traversal or unusable name).",
            path.display()
        )
    }

    pub fn skipping_special_entry(path: &Path) -> String {
        format!(
            "[WARN] Skipping tar entry '{}': only regular files and directories are extracted.",
            path.display()
        )
    }

    pub fn skipping_unreadable_entry(e: &dyn Display) -> String {
        format!("[WARN] Skipping unreadable tar entry: {e}")
    }

    pub fn skipping_unreadable_entry_path(e: &dyn Display) -> String {
        format!("[WARN] Skipping tar entry with an unreadable path: {e}")
    }

    pub fn skipped_entries(count: u64) -> String {
        format!(
            "[WARN] Skipped {count} archive entr{} that could not be extracted safely.",
            if count == 1 { "y" } else { "ies" }
        )
    }

    // -----------------------------------------------------------------------
    // Partial (`.coffin`) recovery
    // -----------------------------------------------------------------------

    pub fn recovering_partial(path: &Path) -> String {
        format!(
            "[WARN] '{}' is a partial archive; recovering whatever it contains.",
            path.display()
        )
    }

    pub fn partial_stopping_at_cut(e: &dyn Display) -> String {
        format!("[WARN] Partial archive, stopping at the cut: {e}")
    }

    pub fn partial_header_cut(e: &dyn Display) -> String {
        format!(
            "[WARN] Partial archive: the stream ends part-way through an entry header ({e}); \
             stopping here."
        )
    }

    pub fn partial_entry_cut(path: &Path, written: u64, declared: u64) -> String {
        format!(
            "[WARN] Partial archive: dropping '{}', cut off by the break ({written} of {declared} \
             bytes were written).",
            path.display()
        )
    }

    pub fn partial_error(e: &dyn Display) -> String {
        format!("[WARN] Partial archive: {e}")
    }

    pub const KEEPING_READABLE: &str =
        "[WARN] Keeping the entries that were readable before the cut.";

    // -----------------------------------------------------------------------
    // Names: --compat, and names it would have fixed
    // -----------------------------------------------------------------------

    pub fn compat_renamed(count: u64) -> String {
        format!("[WARN] --compat renamed {count} file(s) to names that exFAT/Win32 accept.")
    }

    pub fn compat_name_taken(stored: &Path, mapped: &str, replacement: &str) -> String {
        format!(
            "[WARN] --compat: '{}' maps to '{mapped}', which is already taken; using \
             '{replacement}' instead.",
            stored.display()
        )
    }

    pub fn names_not_exfat_safe(count: u64) -> String {
        format!(
            "[WARN] {count} restored name(s) contain characters that exFAT/Win32 refuses. They \
             were kept byte for byte; re-run with --compat to replace them with '_'."
        )
    }

    pub fn already_exists_suffixed(name: &str, dir: &Path, replacement: &str) -> String {
        format!(
            "[WARN] '{name}' already exists in '{}'; writing '{replacement}' instead.",
            dir.display()
        )
    }

    // -----------------------------------------------------------------------
    // Command line
    // -----------------------------------------------------------------------

    pub const LEVEL_NO_EFFECT_ON_DECRYPT: &str =
        "[WARN] --level has no effect when decrypting; ignoring it.";
    pub const COMPAT_NO_EFFECT_ON_ENCRYPT: &str =
        "[WARN] --compat has no effect when encrypting; ignoring it.";

    pub fn workers_clamped(requested: usize) -> String {
        format!(
            "[WARN] --workers {requested} exceeds the maximum of {MAX_WORKERS}; using {MAX_WORKERS}."
        )
    }

    pub fn workers_out_of_range(requested: usize, workers: usize) -> String {
        format!(
            "[WARN] {requested} worker(s) requested; using {workers} (the valid range is \
             1..={MAX_WORKERS})."
        )
    }

    pub fn level_clamped_high(level: i32) -> String {
        format!(
            "[WARN] --level {level} exceeds the maximum of {MAX_ZSTD_LEVEL}; using {MAX_ZSTD_LEVEL}."
        )
    }

    pub fn level_clamped_low(level: i32) -> String {
        format!(
            "[WARN] --level {level} is below the minimum of {MIN_ZSTD_LEVEL}; using {MIN_ZSTD_LEVEL}."
        )
    }

    pub fn config_level_out_of_range(configured: i32, clamped: i32) -> String {
        format!(
            "[WARN] zstd_compression_level {configured} is out of range \
             ({MIN_ZSTD_LEVEL}..={MAX_ZSTD_LEVEL}); using {clamped}."
        )
    }

    pub fn skipping_wrong_kind(path: &Path, kind: &str) -> String {
        format!("[WARN] Skipping '{}': not a {kind}.", path.display())
    }

    pub fn path_does_not_exist(path: &Path) -> String {
        format!("[WARN] Path does not exist: {}. Skipping.", path.display())
    }

    pub fn output_dir_created(dir: &Path) -> String {
        format!(
            "[WARN] Output directory did not exist; created '{}'.",
            dir.display()
        )
    }

    pub fn cannot_read_path_from_stdin(e: &dyn Display) -> String {
        format!("[WARN] Cannot read a path from stdin: {e}")
    }

    pub const INPUT_ENDED_USING_SOURCE_DIR: &str =
        "[WARN] Input ended; using the source's directory.";

    pub fn using_source_directory(e: &dyn Display) -> String {
        format!("[WARN] {e}. Using the source's directory.")
    }

    pub fn not_a_directory(input: &str) -> String {
        format!("[WARN] '{input}' is not a directory. Using the source's directory.")
    }

    pub const PASSWORD_NOT_UTF8: &str = "[WARN] The password is not valid UTF-8. Type it again.";

    pub fn some_files_failed(failed: usize, total: usize) -> String {
        format!("{failed} of {total} file(s) failed.")
    }
}

/// Everything crypt writes to stdout, plus the interactive prompts.
pub(crate) mod info {
    use super::*;

    // -----------------------------------------------------------------------
    // Prompts
    // -----------------------------------------------------------------------

    pub const ENTER_CHOICE: &str = "Enter 'e' to encrypt or 'd' to decrypt.";
    pub const ENTER_PASSWORD: &str = "Enter password:";
    pub const CONFIRM_PASSWORD: &str = "Confirm password:";
    pub const ENTER_PATHS: &str = "Enter paths (one per line, blank line to finish):";
    pub const ENTER_OUTPUT_DIR: &str =
        "Enter output directory (or press Enter to use the source's directory):";

    pub const INVALID_CHOICE: &str = "Invalid choice, please enter 'e' or 'd'.";
    pub const PASSWORDS_DID_NOT_MATCH: &str = "Passwords did not match, try again.";

    // -----------------------------------------------------------------------
    // Progress
    // -----------------------------------------------------------------------

    pub fn created_default_config(path: &Path) -> String {
        format!("Created default config: {}", path.display())
    }

    pub fn added(path: &Path) -> String {
        format!("Added: {}", path.display())
    }

    pub fn skipped_while_packing(symlinks: u64, others: u64, staging: u64) -> String {
        format!(
            "Skipped {symlinks} symlink(s), {others} special file(s) and {staging} in-progress \
             output file(s) while packing."
        )
    }

    pub fn output_directory(path: &Path) -> String {
        format!("Output directory: {}", path.display())
    }

    /// `source` is either `--workers` or `config`, so the line says where the
    /// number came from.
    pub fn detected_cores(cores: usize, workers: usize, source: &str) -> String {
        format!("Detected {cores} CPU cores. Using {workers} worker(s) ({source}).")
    }

    pub fn encryption_complete(path: &Path, megabytes: u64) -> String {
        format!("Encryption complete: {} ({megabytes} MB)", path.display())
    }

    pub fn decrypting(path: &Path) -> String {
        format!("Decrypting {}...", path.display())
    }

    pub fn decrypted_into(names: &[String]) -> String {
        format!("Decrypted into: {}", names.join(", "))
    }

    /// A `.coffin` cut too early to hold one whole entry has nothing to keep; say
    /// so instead of printing an empty `Decrypted into:` line.
    pub fn nothing_recovered(path: &Path) -> String {
        format!("Nothing recovered from '{}'.", path.display())
    }

    pub const NO_USABLE_INPUTS: &str = "No usable input paths; nothing to do.";
}
