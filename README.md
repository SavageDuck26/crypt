# Crypt

Crypt is made for storing large amounts of data privately.

Files and folders you give it get packed into a tar, compressed with Zstd, and then encrypted with AES-GCM. Keys are derived with Argon2id on heavy settings (512 MiB, 12 passes), which makes each guess expensive, but a bad idea in general.

## Usage

Run `crypt` with no arguments and it walks you through it, or use it straight from the command line:

```
crypt -e "/crazystuff", "/otherstuff/coolstuff" --output "/externaldrive" --workers 10 --level 20
crypt -d "/externaldrive/crazystuff-1f3a9c2b.crypt" --output "/restored" --workers 10
```

- `-e` / `-E` encrypt, `-d` / `-D` decrypt.
- Paths are positional and comma separated when there's more than one. An argument that names a file which exists is always taken literally, so a path containing a comma still works: `crypt -e "/mnt/My, Files"` is one path, not two.
- `--output <dir>` where the result goes. It gets created if it isn't there already; leave it off and it goes next to the source.
- `--workers <n>` how many threads to work with.
- `--level <n>` the Zstd level, 19+ is recommended. Anything over 22 gets clamped to 22. It does nothing on decrypt.
- `--password-stdin` reads the password from a pipe instead of prompting. See Passwords below.
- `-h` / `--help` shows the usage, and `-v` / `--version` shows the version.
- Exit status is 0 on success, 1 if any file failed, 2 for a usage error.
- Encrypting `/crazystuff` writes `/externaldrive/crazystuff-1f3a9c2b.crypt`: the file is named after the first path you gave, plus a random 8-character suffix so repeated runs never collide.
- `.` and `..` work as inputs even though they have no name of their own: the archive is named after the directory they resolve to.
- If the output directory is inside what you are encrypting, the half-written `.coffin` is skipped rather than packed into itself.
- Giving more than one path puts all of them in a single archive, named after the first one present.
- That archive is built as `crazystuff-1f3a9c2b.coffin` and only renamed with `.crypt` once it's done, so a leftover `.coffin` is an interrupted archive, however it still holds all of the data it has encrypted so far.

## Config

Crypt writes a `CryptConfig.toml` the first time you run it. It looks for one in `$CRYPT_CONFIG`, then `$XDG_CONFIG_HOME/crypt/` (usually `~/.config/crypt/`), then next to the binary, so an existing copy beside the binary still works. The file has comments explaining everything, but the short version:

- Workers default to 4. Going over your CPU core count slows things down. Each worker takes around 400mb of RAM, which I may work to lower in the future. I recommend 2-4 less workers than you have cores.
- The Argon2id settings are fixed by the file format now, so they can no longer be tuned from here. They are only read when opening very old v1 archives.
- If the config is missing or you typo it, Crypt tells you and falls back to the defaults.

## Passwords

Crypt only takes ASCII passwords. Type a non-ASCII character and it tells you it isn't allowed instead of dropping it. Passwords are typed in the prompt (hidden, never echoed, never passed on the command line), or piped in with `--password-stdin` so a script can drive it:

```
echo 'mygreatpassword' | crypt -e "/crazystuff" --output "/externaldrive" --password-stdin
```

The pipe supplies exactly one line: everything up to the newline becomes the password, leading and trailing spaces included, and the bytes have to be valid UTF-8. Because nobody is there to retype it, there is no confirmation step, so a typo in a script gives you an archive you cannot open. It is also not a way to hide the password from yourself: pass `--password-stdin` while you are sitting at a terminal and the terminal echoes every character you type.

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

Plain `cargo test` runs the unit tests. The end-to-end tests in `tests/` drive the real binary, so they need `cargo test --features test-kdf`, which swaps in deliberately weak Argon2id parameters to keep a round trip at milliseconds instead of seconds. Archives written by such a build cannot be read by a normal one, and enabling the feature in a release build is a compile error. Nothing else is needed to run them: no terminal, no separate fixture files, no extra dependency.

## Misc

- Symlinks and other oddities are skipped. Only normal files and folders go in.
- If two things decrypted share a name, the second gets a '_1', then '_2', etc.
- The header is always locked with the built-in Argon2id settings, and every stream ends with an authenticated footer, so a file that's been cut short is caught instead of quietly half-decrypting.