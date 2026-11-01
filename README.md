# Crypt

Crypt is made for storing large amounts of data privately.

Files and folders you give it get packed into a tar, compressed with Zstd, and then encrypted with AES-256-GCM. Keys are derived with Argon2id on heavy settings (512 MiB, 12 passes), fixed by the file format rather than by the config.

## Getting it

crypt is distributed as source; there is no crates.io release. Build the binary:

```
git clone https://github.com/SavageDuck26/crypt
cd crypt
cargo build --release      # target/release/crypt
cargo doc --open           # the library reference
```

or use the library directly from git:

```toml
[dependencies]
crypt = { git = "https://github.com/SavageDuck26/crypt" }
```

It builds on Unix-like systems only; see Misc.

## Usage

Run `crypt` with no arguments and it walks you through it, or use it straight from the command line:

```
crypt -e "/crazystuff", "/otherstuff/coolstuff" --output "/externaldrive" --workers 10 --level 20
crypt -d "/externaldrive/crazystuff-1f3a9c2b.crypt" --output "/restored" --workers 10
```

- `-e` / `-E` encrypt, `-d` / `-D` decrypt.
- Paths are positional and comma separated when there's more than one. An argument that names a file which exists is always taken literally, so a path containing a comma still works: `crypt -e "/mnt/My, Files"` is one path, not two. Paths are passed through as raw bytes, so a name that isn't valid UTF-8 works too.
- `--output <dir>` where the result goes. It gets created if it isn't there already; leave it off and it goes next to the source.
- `--workers <n>` how many threads to work with, from 1 to 128; anything higher is clamped to 128.
- `--level <n>` the Zstd level, 19+ is recommended. Values outside 1-22 are clamped. It does nothing on decrypt.
- `--compat` restores names the exFAT/Win32 way: characters those filesystems refuse (`< > : " | ? *`, a backslash and control characters) become `_`, and a name whose target is already taken gets a `_1`, `_2` suffix — at every depth, so `dir/a:b` next to `dir/a_b` keeps both files instead of one replacing the other. Without it, names come back byte for byte and crypt warns if one of them would not survive such a filesystem. It does nothing on encrypt. The same switch exists as `compat` in the config, for a machine that always restores onto exFAT.
- `--password-stdin` reads the password from a pipe (one line, at most 4096 bytes) instead of prompting. Fine for decrypting; not recommended for encrypting. See Passwords below.
- `-h` / `--help` shows the usage, and `-v` / `-V` / `--version` shows the version.
- `--` treats every later argument as a path, so a file called `-weird-name` can be named.
- Exit status is 0 on success, 1 if any file failed, 2 for a usage error.
- With no arguments at all, crypt is interactive and asks you for everything. That's a separate mode: it takes no flags, and a flag with no operation and no paths is a usage error rather than a prompt.
- Encrypting `/crazystuff` writes `/externaldrive/crazystuff-1f3a9c2b.crypt`: the file is named after the first path you gave, plus a random 8-character suffix so repeated runs never collide.
- `.` and `..` work as inputs even though they have no name of their own: the archive is named after the directory they resolve to.
- If the output directory is inside what you are encrypting, the half-written `.coffin` is skipped rather than packed into itself.
- Giving more than one path puts all of them in a single archive, named after the first one present.
- That archive is built as `crazystuff-1f3a9c2b.coffin` and only given the `.crypt` name once it is sealed and on disk, so a leftover `.coffin` is an interrupted run. It still holds everything that had been encrypted when it stopped, and decrypting one recovers that part instead of failing. The entry the cut ran through is dropped and named in a warning — every file that finished writing is kept, and none of them is kept half-written. A `.coffin` cut too early to hold even one complete entry recovers nothing, and says so rather than printing an empty list.

## Config

Crypt looks for a `CryptConfig.toml` in `$CRYPT_CONFIG`, then `$XDG_CONFIG_HOME/crypt/` (usually `~/.config/crypt/`), then next to the binary, so an existing copy beside the binary still works. If none exists, it writes the shipped template to the first of those places on the first run; if it cannot write one, the built-in defaults are used. The file has comments explaining everything, but the short version:

- Workers default to 4 and are capped at 128. Going over your CPU core count slows things down. Memory follows the Zstd level far more than the worker count: one 40 MB test file peaked at 60 MB at level 1 with 1 or 4 workers, 300 MB at level 19 and 700 MB at level 22 with four workers, each extra worker at level 22 adding around 130 MB. A worker holds a 16 MiB chunk plus its own Zstd context. I recommend 2-4 fewer workers than you have cores.
- The Argon2id settings are fixed by the file format now, so they can no longer be tuned from here. They are only read when opening very old v1 archives.
- `compat` (default `false`) is the same as `--compat`: restore names the exFAT/Win32 way instead of byte for byte.
- If the config is missing, unreadable or unparsable, crypt says which and falls back to the defaults. A key it does not recognise is ignored without a warning.

## Passwords

Crypt takes passwords of at least 8 characters, in any script: accents, Cyrillic, CJK, emoji. The password is NFC-normalized (canonical composition only) before it is hashed, so the same visible password derives the same key whether the text arrives composed (`é`) or decomposed (`e` plus a combining accent) — which is what happens when a password is pasted out of a filename on a system that stores names decomposed. NFC leaves ASCII untouched, so every archive an older build wrote still opens. NFKC is deliberately *not* used: it would also merge characters Unicode defines as different (a fullwidth `ｅ` with `e`, `ﬁ` with `fi`), shrinking the password space for no gain. What is refused is what you cannot see or retype: control characters, invisible format characters (zero-width spaces and joiners, direction marks and overrides) and whitespace other than a plain space. The rules are applied when encrypting; decrypting accepts whatever password an existing archive was made with. Passwords are typed in the prompt (hidden, never echoed, never passed on the command line), or piped in with `--password-stdin` so a script can drive it:

```
echo 'mygreatpassword' | crypt -e "/crazystuff" --output "/externaldrive" --password-stdin
```

The pipe supplies exactly one line: everything up to the newline becomes the password, leading and trailing spaces included, and the bytes have to be valid UTF-8 and no more than 4096 of them. A piped password is not normalized by the pipe itself: encrypting applies the rules above, decrypting uses whatever it is given, normalized — with the spelling exactly as typed tried as well when the normalized form does not authenticate. Because nobody is there to retype it, there is no confirmation step, so a typo in a script gives you an archive you cannot open. It is also not a way to hide the password from yourself: pass `--password-stdin` while you are sitting at a terminal and the terminal echoes every character you type.

Encrypting from a pipe is not recommended. A wrong password when decrypting costs one failed run, but when encrypting it produces an archive nobody can open, and the password has usually been written down somewhere durable just to get it into the pipe — a script, a shell history, an environment variable, a process list. Type it at the prompt whenever there is a person there to type it; the example above, run as written, leaves `mygreatpassword` in your shell history.

## Security notes

- Losing the password loses the archive. There is no recovery key, hint or back door.
- A wrong password and a tampered file are reported the same way on purpose, so the tool is not an oracle for attackers.
- The magic, format version, salt and stream lengths are visible; the stored name, file data and end-of-stream count are inside the encrypted header, chunks and footer.
- Each file gets a fresh 32-byte salt and its own pair of keys (header and data), derived from the password with Argon2id at the built-in settings.
- Only regular files and directories are archived; symlinks are skipped rather than followed, so a link cannot pull in data from outside the tree.

## Library

The same code is usable as a crate. The short path uses the defaults and says nothing:

```rust
let written = crypt::encrypt(&["/data"], "correcthorse")?;
println!("{} files in {}", written.files, written.archive.display());

let restored = crypt::decrypt(&written.archive, "correcthorse")?;
for path in &restored.paths {
    println!("restored {}", path.display());
}
```

`crypt::encrypt_file` and `crypt::decrypt_file` are the same two operations with every knob exposed. The options are built with `with_*` methods, and both return an outcome rather than a bare path:

```rust
use crypt::EncryptOptions;

let outcome = crypt::encrypt_file(
    &["/data"],
    "correcthorse",
    Some(std::path::Path::new("/backup")),
    &EncryptOptions::default().with_workers(8).with_level(19),
)?;

// Ok does not always mean "everything got in": a file that could not be read
// is counted, and the archive is still published because it is valid.
if !outcome.is_complete() {
    eprintln!("{} unreadable file(s)", outcome.unreadable);
}
```

`EncryptOutcome` reports the number of files and bytes, and how many symlinks, special files, unreadable files and cross-filesystem mount points were left out. `DecryptOutcome` reports the paths that were created, which entries came back under a different name, and how many entries were skipped. `is_complete()` is the short answer for both.

An interrupted encryption leaves a `.coffin`, which the CLI recovers automatically. From the library, set the same switch yourself:

```rust
use crypt::DecryptOptions;

let partial = crypt::decrypt_file(
    "/backup/data-1f3a9c2b.coffin",
    "correcthorse",
    Some(std::path::Path::new("/restored")),
    &DecryptOptions::default().with_partial(true),
)?;

assert!(partial.partial);
```

The library never writes to stdout or stderr. The CLI's warnings, skip notices and progress bar are one implementation of `crypt::Reporter`; install your own with `.with_reporter(Arc::new(my_reporter))` if a human is watching, or leave it off and read the outcome. The same split covers errors: `crypt::Error` tells a wrong password (`Authentication`) from a damaged archive (`Truncated`, `Malformed`) from a bad request (`InvalidInput`), and operating-system failures are `Io { kind, message }` (see `err.kind()`) so a missing file, a permission problem and a full disk are distinguishable without matching on message strings.

The one thing the library does not do is apply the password rules the CLI enforces (control/format characters and odd whitespace refused, at least 8 characters); a caller that has its own policy is not second-guessed. The password is still NFC-normalized before it is hashed, so a caller's policy is applied to the password as typed while the key is derived from the same normalized form every time.

Plain `cargo test` runs the unit tests and the doc examples. The end-to-end tests in `tests/` drive the real binary, so they need `cargo test --features test-kdf`, which swaps in deliberately weak Argon2id parameters to keep a round trip at milliseconds instead of seconds. Archives written by such a build cannot be read by a normal one, and enabling the feature in a release build is a compile error. Nothing else is needed to run them: no terminal, no separate fixture files, no extra dependency — the legacy-format archives are embedded in `tests/legacy.rs`, and the one test that checks what a run does after a failure calls `mkfifo`, so it wants coreutils on `PATH`.

## Misc

- crypt builds on Unix-like systems only (Linux, macOS, the BSDs): the terminal handling and the raw-byte path handling both use `std::os::unix`.
- Only regular files and directories go in. Symlinks and special files are skipped, and the counts are printed in one line at the end of the run. A file it cannot read, or a directory that is a mount point onto another filesystem, gets a `[WARN]` on stderr saying the archive is valid but is not a full copy: the walk stays on one filesystem per input.
- Nothing decrypted is ever written over: if the name is already taken in the destination, the second gets a `_1`, then `_2`, and the rename is reported. That covers both a file already in the destination and two stored names `--compat` maps onto each other.
- The header is always locked with the built-in Argon2id settings, and every archive this version writes ends with an authenticated footer, so a file that's been cut short is caught instead of quietly half-decrypting. v1-v4 archives are still readable: v4 uses the same authenticated footer as v5, while v1-v3 end with an older, unauthenticated marker, so for those only the chunk framing catches a cut file.

## License

GPL-3.0-only; see [LICENSE](LICENSE).
