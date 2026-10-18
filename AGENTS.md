# AGENTS.md

Personal encrypted file vault, CLI-only, Windows-first. `vault hide` moves a file out of its original location into `~/.vault`, encrypted. `vault release` decrypts it back to the same path.

## Commands

```
cargo build                    # first build downloads ~40 crates
cargo build --release          # single stripped exe at target/release/vault.exe (~0.76 MB)
cargo run -- <args>            # e.g. cargo run -- init

cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test                     # 19 crypto + password-decode unit tests

python scripts\e2e.py          # 60 end-to-end checks against the release binary
```

Run all four verification steps before calling work done. `clippy` with `-D warnings` is the gate that catches the classes of mistakes this codebase is prone to (`Zeroizing` deref coercions, needless borrows).

`cargo test` only covers the pure crypto layer. **It does not prove the CLI works.** `scripts\e2e.py` is what actually drives `target\release\vault.exe` through init → hide → list → show → release → forget and asserts real filesystem behaviour. It rebuilds nothing — it reads the release binary as-is, so `cargo build --release` first.

There is no `npm install` equivalent — cargo fetches dependencies into `~/.cargo/registry` automatically on first build, then works offline.

### Testing the CLI

`rpassword` **deliberately refuses piped stdin**, so a password cannot be supplied via a pipe or heredoc. There is no working pty API on Windows (`win32console.CreateConsole` does not exist; `pty` is Unix-only). Non-interactive runs must use:

```
vault --password-file pw.txt hide somefile
vault --recovery <64-hex> list
```

`init` accepts `--password-file` too. Interactive `init` confirms the password twice; `--password-file` does not, because there is no second party to confirm against.

### Password files must be decoded, not parsed as UTF-8

**Never change `read_password_file` to `fs::read_to_string`.** Windows PowerShell's default redirection (`pw.txt > file`, `Out-File`) writes **UTF-16LE with a BOM**, and cmd.exe writes the ANSI code page. Both are ordinary ways for a Windows user to create a password file, and `read_to_string` rejects both as invalid UTF-8. This shipped as a real bug: the e2e suite passed because Python writes UTF-8, and the first manual PowerShell attempt failed.

`read_password_file` reads raw bytes and decodes via `decode_text`, which handles UTF-8 (with/without BOM), UTF-16LE, UTF-16BE, and lossy fallback. It also detects BOM-less UTF-16LE by the NUL-byte interleaving pattern. Covered by 5 unit tests in `session.rs` and 2 e2e checks ([14] and [15] in `scripts\e2e.py`).

When editing `session.rs`, note that several comments there contain non-ASCII em-dashes and the test on line ~295 contains `pässwörd✓`. PowerShell's `Add-Content` and naive `[System.IO.File]::WriteAllText` calls will re-encode the file as UTF-16 and corrupt it. Prefer the edit tool; if you must script it, always pass an explicit `UTF8Encoding($false)` and verify by codepoint afterwards, not by eye.

## CLI surface

```
vault init [--raw] [--password-file F]
vault hide <path>... [--copy]
vault list [--paths] [--plain]
vault show <id>
vault release <id> [--to P] [--force] [--keep]
vault forget <id> [--yes]
vault scrub [--previews] [--recent] [--yes]
```

Global: `--vault <dir>` (env `VAULT_DIR`), `--recovery <hex>`, `--password-file <file>` (env `VAULT_PASSWORD_FILE`).

`hide` expands globs itself, because PowerShell and cmd do not expand them the way Unix shells do.

## Architecture

Four layers, dependencies point strictly downward:

```
commands/    init hide list show release forget scrub   <- no crypto logic
   |
session.rs   unlock (password / recovery / file), ID-prefix resolution
   |
object.rs    the .enc container
   |
crypto/      kdf, keys, stream, vault   <- pure, no I/O beyond Read/Write
```

`crypto/` is deliberately I/O-free. Keep it that way — it is the part worth reasoning about in isolation.

### Key hierarchy

```
master password ──Argon2id(salt)──> pwd_key ──┐
                                              ├──> root_key (32B random, generated at init)
recovery key ────HKDF─────────────> rec_key ──┘

root_key ──HKDF("vault.v1.blob")──> blob_key   encrypts file chunks
           HKDF("vault.v1.meta")──> meta_key   encrypts object metadata
```

`root_key` is **random**, never derived from the password. Both unlock paths only *unseal* it. Consequence: an attacker holding a stolen `vault.hdr` learns nothing about `root_key` without breaking one of the two Poly1305 tags.

The AAD strings (`vault.v1.root.pwd` / `vault.v1.root.rec`) are load-bearing. Changing them orphans every existing vault.

### `vault.hdr` (180 bytes, fixed)

```
8 magic · 16 argon2id salt · 4+4+4 KDF cost params
· 2 × (24 nonce + 48 sealed root key)
```

Fixed length is a **security property, not tidiness**: a variable-length header would leak the number of entries. It carries no counts, names, or timestamps. `VaultHeader::LEN` is a `const` and `write` has a `debug_assert_eq!` against it, so the format cannot silently drift.

### Object format (`.enc`)

```
magic       8   "VLTVOBJ1"
meta_len    4   LE u32
meta_ct    ??   XChaCha20-Poly1305(Meta) + 16B tag
nonce      24   per-file random, plaintext (safe — nonces are public)
chunk0_len 4   LE u32, plaintext bytes
chunk0_ct ??   ciphertext + tag
chunk1_len 4
...
```

Per-chunk nonces come from `derive_nonce(file_nonce, NONCE_TAG_CHUNK, index)`, so metadata and chunk nonces cannot collide under one file nonce. Chunks are 1 MiB, so a multi-GB video is never resident in memory.

## Conventions that differ from the obvious

- **Metadata is inside the AEAD, not beside it.** `strings objects/*.enc` reveals nothing, not even filenames. This forces `list` to require the password on every invocation. That is intended.
- **No index file.** Each `.enc` is self-describing. Listing opens every object and decrypts only its metadata record (skips chunk data). This removes the entire class of index/object desync bugs.
- **ID prefix matching.** `resolve_id` accepts any unambiguous prefix and *errors on ambiguity* rather than guessing. `vault release a3f9` works.
- **`release` writes to a temp sibling, then renames.** Decryption failure leaves no partial file at the destination. Never bypass this.
- **Source is deleted only after the object is fsynced.** `hide` encrypts, `sync_all`s, then secure-deletes the original. Failure order matters.
- **`decrypt_stream` rejects trailing data.** It does not trust the caller's chunk count. Without this a corrupted `size` in the metadata silently yields a short file that still passes every per-chunk tag — this was a real bug caught by the test suite, not a hypothetical.
- **`VaultKeys` holds plain `[u8; 32]`, not `Zeroizing`.** The `Drop` impl does the wiping. A `Zeroizing` field would force an explicit `&*` at every call site, and a missed deref in crypto code is not a chore worth imposing.
- **`&[u8]` params need `&*`, `&[u8; 32]` params do not.** `seal`/`open` take `&[u8]` so `Zeroizing<[u8;32]>` needs `&*pwd_key`. `VaultKeys::derive` and `seal_root` take `&[u8; 32]` and auto-deref. This asymmetry is the single most common compile error when adding call sites.

## Windows-specific

`win/secure_delete.rs` overwrites with random data, fsyncs, renames to an opaque scratch name, then unlinks. The read-only clear is `#[cfg(windows)]`-gated with an `#[allow(clippy::permissions_set_readonly_false)]`, because the same call on Unix would make the file world-writable.

**Secure delete is best-effort on SSDs and NVMe.** TRIM and wear-leveling mean the overwrite may never reach the physical cells holding the original data. The code comments and user-facing messages both say so. Do not "improve" this by removing the caveat — an overstated erasure guarantee in a vault is worse than no guarantee.

`win/traces.rs` purges `thumbcache_*.db`, `Recent\*.lnk`, `Prefetch\*.pf`. Explorer holds the thumbnail caches open, so `scrub` frequently reports skipped files. It never kills Explorer — do not add that.

Long paths are not yet handled. `\\?\` prefixing will be needed before releasing deeply nested files.

## Known gaps

- `hide` of a directory preserves relative structure via the stored absolute path only; there is no directory-level restore.
- No session key caching, so every command re-derives Argon2id (~0.5 s).
- ADS (alternate data streams) are not wiped on secure delete.
- `scrub` cannot guarantee forensic removal — the USN journal and $MFT are unreachable from userland, and the tool says so.
