use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

use crate::crypto::kdf;
use crate::crypto::keys::{hkdf_expand, open, VaultKeys, KEY_LEN};
use crate::crypto::vault::{SealedKey, VaultDir, VaultHeader};

/// An unlocked vault, holding the derived keys for the lifetime of one command.
///
/// The keys are wiped when this drops, so no key material outlives the
/// command that needed it. Nothing else in the program should hold keys
/// outside this type.
pub struct Session {
    pub dir: VaultDir,
    keys: VaultKeys,
}

impl Session {
    /// Locate the vault at `explicit` or the default location and confirm it exists.
    pub fn locate(explicit: Option<PathBuf>) -> Result<VaultDir> {
        let dir = VaultDir::resolve(explicit)?;
        if !dir.exists() {
            bail!(
                "no vault found at {}\nrun `vault init` to create one",
                dir.root.display()
            );
        }
        Ok(dir)
    }

    /// Unlock using whichever credential the user supplied.
    ///
    /// This is the single entry point every command should use, so that
    /// `--recovery` and `--password-file` behave identically everywhere.
    /// Password prompts are centralized here for the same reason — no
    /// command should be able to accidentally prompt with echo enabled by
    /// calling rpassword directly.
    pub fn unlock(
        dir: VaultDir,
        recovery: Option<&str>,
        password_file: Option<&Path>,
    ) -> Result<Self> {
        match recovery {
            Some(hex) => Self::unlock_recovery(dir, hex),
            None => {
                let password = match password_file {
                    Some(path) => read_password_file(path)?,
                    None => crate::util::prompt_password()?,
                };
                Self::unlock_password(dir, &password)
            }
        }
    }

    /// Open and unlock a vault using the master password.
    pub fn unlock_password(dir: VaultDir, password: &str) -> Result<Self> {
        let header = VaultHeader::read(&dir.header_path())?;
        let pwd_key = kdf::derive(
            password.as_bytes(),
            &header.salt,
            header.m_cost,
            header.t_cost,
            header.p_cost,
        )?;
        let root = unseal_root(&header.pwd_blob, &pwd_key, b"vault.v1.root.pwd")?;
        Ok(Self {
            keys: VaultKeys::derive(&root),
            dir,
        })
    }

    /// Open and unlock a vault using the recovery key.
    pub fn unlock_recovery(dir: VaultDir, recovery_hex: &str) -> Result<Self> {
        let header = VaultHeader::read(&dir.header_path())?;
        let rec_key = recovery_key_from_hex(recovery_hex)?;
        let root = unseal_root(&header.rec_blob, &rec_key, b"vault.v1.root.rec")?;
        Ok(Self {
            keys: VaultKeys::derive(&root),
            dir,
        })
    }

    pub fn keys(&self) -> &VaultKeys {
        &self.keys
    }

    /// Every object file in the vault, sorted by name for stable ordering.
    pub fn objects(&self) -> Result<Vec<PathBuf>> {
        let mut out = Vec::new();
        let rd = std::fs::read_dir(self.dir.objects_dir())
            .with_context(|| format!("could not read {}", self.dir.objects_dir().display()))?;
        for entry in rd {
            let entry = entry?;
            let p = entry.path();
            if p.extension().and_then(|e| e.to_str()) == Some("enc") {
                out.push(p);
            }
        }
        out.sort();
        Ok(out)
    }

    /// Resolve a user-supplied ID or prefix to a concrete object path.
    ///
    /// Accepts any unambiguous prefix so `vault release a3f9` works without
    /// typing the full ID. Errors on ambiguity rather than guessing.
    pub fn resolve_id(&self, id: &str) -> Result<PathBuf> {
        let objects = self.objects()?;
        if objects.is_empty() {
            bail!("the vault is empty");
        }

        let mut matches = Vec::new();
        for obj in &objects {
            let stem = obj.file_stem().and_then(|s| s.to_str()).unwrap_or_default();
            if stem == id || stem.starts_with(id) {
                matches.push(obj.clone());
            }
        }

        match matches.len() {
            0 => bail!("no entry matches id `{id}`"),
            1 => Ok(matches.remove(0)),
            _ => bail!(
                "id `{id}` is ambiguous ({} matches) — use more characters",
                matches.len()
            ),
        }
    }
}

/// Read a master password from a file, for scripting.
///
/// Bytes are read first and decoded manually rather than via
/// `read_to_string`, because that would reject anything that is not valid
/// UTF-8. Windows PowerShell's default redirection (`>` / `Out-File`) writes
/// UTF-16LE with a BOM, and cmd.exe writes the ANSI code page — both are
/// perfectly ordinary ways to create a password file and both would fail
/// `read_to_string`. Decoding here means the flag works regardless of which
/// shell wrote the file.
///
/// Trailing CR/LF is stripped so a file written by `echo` works without the
/// user having to know to omit the final newline. Any other internal
/// whitespace is preserved, since it may be part of the password.
pub fn read_password_file(path: &Path) -> Result<Zeroizing<String>> {
    let raw = std::fs::read(path)
        .with_context(|| format!("could not read password file {}", path.display()))?;

    let mut password = decode_text(&raw);
    while password.ends_with('\r') || password.ends_with('\n') {
        password.pop();
    }
    // Also drop a trailing UTF-8 BOM left by some editors.
    if let Some(stripped) = password.strip_prefix('\u{feff}') {
        password = stripped.to_string();
    }

    if password.is_empty() {
        bail!("password file {} is empty", path.display());
    }
    Ok(Zeroizing::new(password))
}

/// Decode file bytes to a string, handling the encodings Windows shells
/// actually produce.
///
/// Order matters: UTF-16 must be detected before any UTF-8 interpretation,
/// since UTF-16 bytes frequently *look* like plausible UTF-8 until they don't.
fn decode_text(raw: &[u8]) -> String {
    if raw.starts_with(&[0xFF, 0xFE]) {
        return decode_utf16(&raw[2..], true);
    }
    if raw.starts_with(&[0xFE, 0xFF]) {
        return decode_utf16(&raw[2..], false);
    }
    // PowerShell without a BOM still writes UTF-16LE when the file is pure
    // ASCII plus NUL bytes interleaved. Detect that pattern rather than
    // handing back a string full of NULs.
    if looks_like_utf16le(raw) {
        return decode_utf16(raw, true);
    }
    match std::str::from_utf8(raw) {
        Ok(s) => s.to_string(),
        Err(_) => String::from_utf8_lossy(raw).into_owned(),
    }
}

fn decode_utf16(raw: &[u8], little_endian: bool) -> String {
    let units: Vec<u16> = raw
        .chunks_exact(2)
        .map(|c| {
            if little_endian {
                u16::from_le_bytes([c[0], c[1]])
            } else {
                u16::from_be_bytes([c[0], c[1]])
            }
        })
        .collect();
    String::from_utf16_lossy(&units)
}

/// True if the buffer looks like UTF-16LE that happens to be ASCII text.
///
/// Requires NUL bytes in the odd positions and none in the even ones, which
/// is a pattern ordinary UTF-8 text essentially never produces.
fn looks_like_utf16le(raw: &[u8]) -> bool {
    if raw.len() < 4 || !raw.len().is_multiple_of(2) {
        return false;
    }
    let even_nuls = raw.iter().step_by(2).filter(|b| **b == 0).count();
    let odd_nuls = raw.iter().skip(1).step_by(2).filter(|b| **b == 0).count();
    odd_nuls > 0 && even_nuls == 0
}

fn unseal_root(sealed: &SealedKey, key: &[u8; KEY_LEN], aad: &[u8]) -> Result<[u8; KEY_LEN]> {
    // Poly1305 tag is what actually proves the password is right. There is no
    // separate "wrong password" check because there is nothing to check
    // against — the tag either validates or it doesn't.
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(
        &open(key, &sealed.nonce, &sealed.ct, aad).map_err(|_| {
            anyhow::anyhow!("wrong password (or recovery key) — nothing was modified")
        })?,
    );
    Ok(out)
}

/// Derive the 32-byte key that seals the root key from the raw recovery secret.
///
/// The user holds 32 bytes of hex; we HKDF-expand them to the full key length
/// so the recovery secret never has to be exactly key-sized.
pub fn recovery_key_from_hex(s: &str) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = hex::decode(&clean).context("recovery key must be hexadecimal")?;
    if bytes.len() != 32 {
        bail!(
            "recovery key must be 32 bytes (64 hex characters), got {}",
            bytes.len()
        );
    }
    let mut ikm = Zeroizing::new([0u8; KEY_LEN]);
    ikm.copy_from_slice(&bytes);
    Ok(Zeroizing::new(hkdf_expand(&*ikm, b"vault.v1.recovery")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Windows PowerShell's default redirection writes UTF-16LE with a BOM.
    /// If this regresses, every password file created with `>` breaks.
    #[test]
    fn reads_utf16le_with_bom() {
        let pw = "hunter2";
        let mut bytes = vec![0xFF, 0xFE];
        for u in pw.encode_utf16() {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        assert_eq!(decode_text(&bytes), pw);
    }

    /// PowerShell can also emit UTF-16LE with no BOM.
    #[test]
    fn reads_utf16le_without_bom() {
        let pw = "s3cret pw";
        let mut bytes = Vec::new();
        for u in pw.encode_utf16() {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        assert_eq!(decode_text(&bytes), pw);
    }

    /// cmd.exe and plain editors write the ANSI code page, which is UTF-8
    /// compatible for the passwords people actually choose.
    #[test]
    fn reads_plain_utf8() {
        assert_eq!(
            decode_text(b"correct horse battery staple\n"),
            "correct horse battery staple\n"
        );
    }

    /// ASCII embedded in UTF-16LE must not be mistaken for UTF-8.
    #[test]
    fn ascii_in_utf16le_is_detected_by_interleaved_nuls() {
        let mut bytes = Vec::new();
        for u in "vault".encode_utf16() {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        assert!(looks_like_utf16le(&bytes));
        assert_eq!(decode_text(&bytes), "vault");
    }

    /// Real passwords can contain non-ASCII characters.
    #[test]
    fn reads_non_ascii_utf8() {
        assert_eq!(decode_text("pässwörd✓".as_bytes()), "pässwörd✓");
    }
}
