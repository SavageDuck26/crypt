# Crypt

Crypt is made for storing large amounts of data privately.

Files and folders you give it get packed into a tar, compressed with Zstd, and then encrypted with AES-GCM. Keys are derived with Argon2id on heavy settings (512 MiB, 12 passes), fixed by the file format rather than by the config.

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
- `--password-stdin` reads the password from a pipe (one line, at most 4096 bytes) instead of prompting. Fine for decrypting; not recommended for encrypting. See Passwords below.
- `-h` / `--help` shows the usage, and `-v` / `--version` shows the version.
- `--` treats every later argument as a path, so a file called `-weird-name` can be named.
- Exit status is 0 on success, 1 if any file failed, 2 for a usage error.
- With no arguments at all, crypt is interactive and asks you for everything. That's a separate mode: it takes no flags, and a flag with no operation and no paths is a usage error rather than a prompt.
- Encrypting `/crazystuff` writes `/externaldrive/crazystuff-1f3a9c2b.crypt`: the file is named after the first path you gave, plus a random 8-character suffix so repeated runs never collide.
- `.` and `..` work as inputs even though they have no name of their own: the archive is named after the directory they resolve to.
- If the output directory is inside what you are encrypting, the half-written `.coffin` is skipped rather than packed into itself.
- Giving more than one path puts all of them in a single archive, named after the first one present.
- That archive is built as `crazystuff-1f3a9c2b.coffin` and only given the `.crypt` name once it is sealed and on disk, so a leftover `.coffin` is an interrupted run. It still holds everything that had been encrypted when it stopped, and decrypting one recovers that part instead of failing.

## Config

Crypt writes a `CryptConfig.toml` to the first of those places the first time you run it, and looks for an existing one in `$CRYPT_CONFIG`, then `$XDG_CONFIG_HOME/crypt/` (usually `~/.config/crypt/`), then next to the binary, so an existing copy beside the binary still works. If it cannot write one, the built-in defaults are used. The file has comments explaining everything, but the short version:

- Workers default to 4 and are capped at 128. Going over your CPU core count slows things down. Memory follows the Zstd level far more than the worker count: one 40 MB test file peaked at 60 MB at level 1 with 1 or 4 workers, 300 MB at level 19 and 700 MB at level 22 with four workers, each extra worker at level 22 adding around 130 MB. A worker holds a 16 MiB chunk plus its own Zstd context. I recommend 2-4 fewer workers than you have cores.
- The Argon2id settings are fixed by the file format now, so they can no longer be tuned from here. They are only read when opening very old v1 archives.
- If the config is missing, unreadable or unparsable, crypt says which and falls back to the defaults. A key it does not recognise is ignored without a warning.

## Passwords

Crypt takes printable ASCII passwords of at least 8 characters. A non-ASCII character is refused rather than dropped, and the rules are applied when encrypting; decrypting accepts whatever password an existing archive was made with. Passwords are typed in the prompt (hidden, never echoed, never passed on the command line), or piped in with `--password-stdin` so a script can drive it:

```
echo 'mygreatpassword' | crypt -e "/crazystuff" --output "/externaldrive" --password-stdin
```

The pipe supplies exactly one line: everything up to the newline becomes the password, leading and trailing spaces included, and the bytes have to be valid UTF-8 and no more than 4096 of them. A piped password is not checked for printable ASCII on the way in: encrypting applies the rules above, decrypting uses whatever it is given. Because nobody is there to retype it, there is no confirmation step, so a typo in a script gives you an archive you cannot open. It is also not a way to hide the password from yourself: pass `--password-stdin` while you are sitting at a terminal and the terminal echoes every character you type.

Encrypting from a pipe is not recommended. A wrong password when decrypting costs one failed run, but when encrypting it produces an archive nobody can open, and the password has usually been written down somewhere durable just to get it into the pipe — a script, a shell history, an environment variable, a process list. Type it at the prompt whenever there is a person there to type it; the example above, run as written, leaves `mygreatpassword` in your shell history.

## Library

The same code is usable as a crate. `crypt::encrypt_file` and `crypt::decrypt_file` do the work, `crypt::EncryptOptions` and `crypt::DecryptOptions` are the knobs, and failures come back as a typed `crypt::Error` so a caller can tell a wrong password (`Authentication`) from a damaged archive (`Truncated`, `Malformed`) from a bad request (`InvalidInput`) without matching on message strings:

```rust
use crypt::{DecryptOptions, EncryptOptions};
use std::path::PathBuf;

let archive = crypt::encrypt_file(
    &[PathBuf::from("/data")],
    "correcthorse",
    None, // next to the source
    &EncryptOptions {
        workers: 4,
        ..Default::default()
    },
)?;

let created = crypt::decrypt_file(
    &archive,
    "correcthorse",
    None,
    &DecryptOptions::default(),
)?;
```

The one thing the library does not do is apply the password rules the CLI enforces (printable ASCII, at least 8 characters); a caller that has its own policy is not second-guessed.

Plain `cargo test` runs the unit tests. The end-to-end tests in `tests/` drive the real binary, so they need `cargo test --features test-kdf`, which swaps in deliberately weak Argon2id parameters to keep a round trip at milliseconds instead of seconds. Archives written by such a build cannot be read by a normal one, and enabling the feature in a release build is a compile error. Nothing else is needed to run them: no terminal, no separate fixture files, no extra dependency — the legacy-format archives are embedded in `tests/legacy.rs`, and the one test that checks what a run does after a failure calls `mkfifo`, so it wants coreutils on `PATH`.

## Misc

- Only regular files and directories go in. Symlinks and special files are skipped, and the counts are printed in one line at the end of the run. A file it cannot read, or a directory that is a mount point onto another filesystem, gets a `[WARN]` on stderr saying the archive is valid but is not a full copy: the walk stays on one filesystem per input.
- If two things decrypted share a name, the second gets a '_1', then '_2', etc.
- The header is always locked with the built-in Argon2id settings, and every archive this version writes ends with an authenticated footer, so a file that's been cut short is caught instead of quietly half-decrypting. v1-v3 archives are still readable; they end with an older, unauthenticated marker, so for those only the chunk framing catches a cut file.