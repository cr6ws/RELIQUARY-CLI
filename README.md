# Vault CLI

`vault` is a Windows-first command-line tool for keeping personal files in an encrypted vault.

It does more than rename or hide files: `vault hide` encrypts a file, moves the encrypted object into the vault, and removes the original from its previous location. `vault release` decrypts the object and restores it to its original path, including its original timestamp.

> **Status:** early-stage personal utility (`0.1.0`). Read the limitations before trusting it with important data.

## Highlights

- XChaCha20-Poly1305 authenticated encryption
- Argon2id password-based key derivation
- A randomly generated vault key, independently sealed by both:
  - your master password
  - a one-time recovery key
- Encrypted filenames, original paths, sizes, and timestamps
- Streaming encryption in 1 MiB chunks, so large files are not loaded into memory
- No plaintext index file to leak metadata or become out of sync
- Unambiguous ID-prefix matching, so commands can use short IDs safely
- Atomic restore: files are authenticated before they replace the destination
- Interactive terminal menu when `vault` is run without a subcommand
- Windows trace cleanup for thumbnail caches, Recent Documents, and Prefetch
- Non-interactive operation with password files or recovery keys

## How it works

Each vault contains a fixed-size `vault.hdr` and one encrypted object per hidden file:

```text
.vault\
  vault.hdr
  objects\
    <random-id>.enc
```

The vault's random root key is never derived directly from the password. Instead, the password and recovery key each independently unlock a sealed copy of that root key. File contents and metadata are then encrypted with keys derived from the root key.

Metadata is stored inside authenticated encryption. A person who finds the vault cannot read the original filenames, paths, sizes, or timestamps without unlocking it.

## Requirements

- Windows
- [Rust](https://rustup.rs/) and Cargo
- Python 3 if you want to run the end-to-end test suite

The release executable has no runtime dependencies beyond Windows:

```text
target\release\vault.exe
```

## Build and install

From the repository root:

```powershell
cargo build --release
```

You can run the binary directly:

```powershell
.\target\release\vault.exe --help
```

For convenient use, copy `target\release\vault.exe` to a directory on your `PATH`, or invoke it using its full path. Check the build with:

```powershell
vault --version
```

## Quick start

Create a vault:

```powershell
vault init
```

During initialization, choose a strong master password and save the displayed recovery key somewhere offline. The recovery key is the only alternative way to unlock the vault.

Hide a file:

```powershell
vault hide "C:\Users\you\Documents\secret.pdf"
```

List encrypted entries:

```powershell
vault list
```

Restore an entry:

```powershell
vault release <id>
```

After a successful release, the encrypted object is removed from the vault. To keep the encrypted copy, use `--keep`.

## Command reference

### `init`

Create a new vault and set its master password:

```powershell
vault init
vault init --raw
```

`--raw` prints the recovery key as one 64-character hexadecimal string instead of readable groups.

The default vault location is:

```text
C:\Users\<you>\.vault
```

### `hide`

Encrypt and move one or more files into the vault:

```powershell
vault hide "C:\path\file.txt"
vault hide "a.jpg" "b.mp4" "report.pdf"
vault hide "C:\path\folder"
vault hide "C:\path\*.pdf"
```

Directories are walked recursively. Globs are expanded by the application so they work consistently from PowerShell and `cmd.exe`.

Use `--copy` to encrypt a copy while leaving the original file in place:

```powershell
vault hide --copy "C:\path\draft.txt"
```

### `list`

List entries in the vault:

```powershell
vault list
vault list --paths
vault list --plain
```

- `--paths` includes original paths.
- `--plain` emits tab-separated, one-entry-per-line output for scripts.

Listing requires unlocking the vault because names and paths are encrypted.

### `show`

Display complete metadata for an entry:

```powershell
vault show <id>
```

Any unambiguous prefix of an ID is accepted:

```powershell
vault show 90f3
```

Ambiguous prefixes are rejected instead of guessed.

### `release`

Restore an entry to its original location:

```powershell
vault release <id>
```

Restore somewhere else:

```powershell
vault release <id> --to "C:\Users\you\Desktop\restored.txt"
```

Additional options:

- `--force` allows overwriting an existing destination.
- `--keep` retains the encrypted object after restoration.

The destination is written through a temporary sibling file and renamed only after all encrypted chunks have been authenticated.

### `forget`

Permanently destroy an encrypted entry without restoring it:

```powershell
vault forget <id>
vault forget <id> --yes
```

Without `--yes`, the command asks for confirmation. There is no undo.

### `scrub`

Best-effort cleanup of Windows traces:

```powershell
vault scrub --previews --recent
vault scrub --previews --recent --yes
```

- `--previews` targets Explorer thumbnail and icon caches.
- `--recent` targets Recent Documents and Prefetch entries.
- `--yes` skips confirmation.

Running `scrub` without either cleanup option performs no cleanup.

### Interactive menu

Run `vault` with no subcommand from an interactive terminal to open the arrow-key menu:

```powershell
vault
```

The regular subcommands remain the recommended interface for scripts and automation.

## Non-interactive use

Password prompts intentionally read directly from the console, so piping a password through stdin is not supported.

For scripts and scheduled tasks, use a password file:

```powershell
vault --password-file C:\secure\pw.txt list
vault --password-file C:\secure\pw.txt hide "C:\path\secret.txt"
```

The password file may contain a trailing newline. Windows UTF-8, UTF-16LE, UTF-16BE, and common legacy encodings are handled.

Password files are less safe than interactive prompts: any process or user that can read the file can read the password. Restrict the file's permissions and avoid keeping it longer than necessary.

The recovery key can also unlock any command:

```powershell
vault --recovery <64-hex-characters> list
```

`--recovery` and `--password-file` cannot be used together.

## Vault location and environment variables

Global options must appear before the subcommand:

```powershell
vault --vault "D:\private\my-vault" list
vault --password-file C:\secure\pw.txt --vault "D:\private\my-vault" list
```

Environment variables:

| Variable | Equivalent option | Purpose |
| --- | --- | --- |
| `VAULT_DIR` | `--vault` | Select the vault directory |
| `VAULT_PASSWORD_FILE` | `--password-file` | Select the password file |

## Security model

The cryptographic design uses:

1. Argon2id derives a key from the master password and a per-vault salt.
2. A random 256-bit root key is generated at initialization.
3. The root key is sealed independently with the password-derived key and recovery key.
4. Separate keys derived from the root key encrypt object metadata and file chunks.
5. Each chunk is authenticated, and trailing data is rejected during decryption.

The password and recovery key are not stored in the vault. Losing both means the vault cannot be recovered by design.

## Important limitations

This tool does not provide a guarantee of forensic erasure:

- Secure deletion is best-effort on SSDs and NVMe devices because TRIM and wear-leveling can prevent overwrites from reaching the original physical cells.
- Windows may retain traces in the USN journal, `$MFT`, thumbnail caches, Recent Documents, or other system locations.
- Explorer can keep thumbnail files open, so `scrub` may report skipped files. It never kills Explorer.
- Alternate data streams are not wiped.
- Very deeply nested Windows paths are not fully supported yet.
- Hiding a directory preserves its structure in metadata, but files are restored individually rather than as one directory-level operation.
- Passwords are re-derived on every command; there is no session key cache.

Do not treat `hide` or `scrub` as a substitute for full-disk encryption, secure media disposal, or an operating-system data-removal policy.

## Development and verification

Run the project's verification checks from the repository root:

```powershell
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
python scripts\e2e.py
```

The end-to-end suite exercises the release binary through initialization, hiding, listing, showing, releasing, and forgetting files. It also checks Windows password-file decoding behavior.

## License

No license file is currently included in this repository. Add a license before distributing or accepting external contributions.
