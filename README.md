# Crypt

Crypt is made for storing large amounts of data privately. Think of it like putting your data in a coffin that only you know where you buried.

Files and folders you give it get packed into a tar, compressed with Zstd, and then encrypted with AES-GCM. Keys are derived with Argon2id on heavy settings, so even a short password is expensive to crack.

## Running it

Run `Crypt` with no arguments and it walks you through it, or drive it straight from the command line:

```
Crypt -e "/crazystuff", "/otherstuff/coolstuff" --output "/externaldrive" --workers 10 --level 20
Crypt -d "/externaldrive/crazystuff.crypt", "/externaldrive/coolstuff.crypt" --output "/restored" --workers 10
```

- `-e` / `-E` encrypt, `-d` / `-D` decrypt.
- Paths are positional and comma separated when there's more than one.
- `--output <dir>` where the result goes. It gets created if it isn't there already; leave it off and it goes next to the source.
- `--workers <n>` how many threads to work with.
- `--level <n>` the Zstd level, 19+ is recommended. Anything over 22 gets clamped to 22. It does nothing on decrypt.

## The config

Crypt writes a `CryptConfig.toml` the first time you run it, and it has to sit in the same directory as the Crypt binary. The file has comments explaining everything, but the short version:

- Workers default to 4. Going over your CPU core count just slows things down. Each worker takes around 400mb of RAM, which I may work to lower in the future. I'd recommend 2-4 less workers than you have cores.
- The Argon2id settings are already strong. Higher is better if you don't mind the wait.
- If the config is missing or you typo it, Crypt tells you and falls back to the defaults.

Because everything a file needs to be read is tucked inside the file itself, you can change the config whenever you want and old files still decrypt fine.

## Passwords

Crypt only takes ASCII passwords, and it wants at least 8 characters. Type a non-ASCII character and it tells you it isn't allowed instead of quietly dropping it -- a password that normalises differently on another machine is a password you can't get back. It's always typed at the prompt (hidden, never echoed, never passed on the command line).

## Odds and ends

- Symlinks and other oddities are skipped. Only normal files and folders go in.
- If two things you decrypt share a name, the second gets a `_1`, then `_2`, and so on.
- The header is always locked with the built-in Argon2id settings, and every stream ends with a small authenticated footer (a catacomb, if you like), so a file that's been cut short is caught instead of quietly half-decrypting.
- This build writes format v4. Older Crypt builds can't read those files, but this one still reads everything older.
