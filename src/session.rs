use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

use crate::crypto::kdf;
use crate::crypto::keys::{hkdf_expand, open, VaultKeys, KEY_LEN};
use crate::crypto::vault::{SealedKey, VaultDir, VaultHeader};
use crate::object::{Meta, Object};

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

    /// Unlock using whichever credential the caller supplied.
    ///
    /// This is the single entry point every command should use, so that
    /// `--recovery`, `--password-file` and an interactive prompt all behave
    /// identically everywhere. Password prompts are centralized here for the
    /// same reason — no command should be able to accidentally prompt with
    /// echo enabled by calling rpassword directly.
    pub fn unlock(dir: VaultDir, cred: &Credential) -> Result<Self> {
        match cred {
            Credential::Recovery(hex) => Self::unlock_recovery(dir, hex),
            Credential::File(path) => {
                let password = read_password_file(path)?;
                Self::unlock_password(dir, &password)
            }
            Credential::Password(password) => Self::unlock_password(dir, password),
            Credential::Prompt => {
                let password = crate::util::prompt_password()?;
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
    #[allow(dead_code)]
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

    /// Resolve a user-supplied ID, prefix, or folder name to a Target.
    /// Supports individual objects, native folder archives, and folder groups.
    pub fn resolve_target(&self, id: &str) -> Result<Target> {
        let objects = self.objects()?;
        if objects.is_empty() {
            bail!("the vault is empty");
        }

        let mut entries = Vec::with_capacity(objects.len());
        for obj in &objects {
            if let Ok(meta) = Object::read_meta(self.keys(), obj) {
                entries.push((obj.clone(), meta));
            }
        }

        let clean_id = id.trim().trim_end_matches('/');
        let folders = discover_folders(&entries);

        // 1. Exact match on object ID or exact file name
        for (obj, meta) in &entries {
            let stem = obj.file_stem().and_then(|s| s.to_str()).unwrap_or_default();
            if stem == clean_id {
                return Ok(Target::Object(obj.clone()));
            }
            if meta.orig_name.eq_ignore_ascii_case(clean_id) {
                return Ok(Target::Object(obj.clone()));
            }
        }

        // 2. Exact match on folder ID or exact folder name
        for folder in &folders {
            if folder.id == clean_id || folder.name.eq_ignore_ascii_case(clean_id) {
                return Ok(Target::Folder(folder.clone()));
            }
        }

        // 3. Prefix matching
        let mut obj_matches: Vec<PathBuf> = Vec::new();
        for (obj, _) in &entries {
            let stem = obj.file_stem().and_then(|s| s.to_str()).unwrap_or_default();
            if stem.starts_with(clean_id) {
                obj_matches.push(obj.clone());
            }
        }

        let mut folder_matches: Vec<FolderGroup> = Vec::new();
        for folder in &folders {
            if folder.id.starts_with(clean_id)
                || folder
                    .name
                    .to_lowercase()
                    .starts_with(&clean_id.to_lowercase())
            {
                folder_matches.push(folder.clone());
            }
        }

        let total_matches = obj_matches.len() + folder_matches.len();
        match total_matches {
            0 => bail!("no entry matches id `{id}`"),
            1 => {
                if let Some(obj) = obj_matches.into_iter().next() {
                    Ok(Target::Object(obj))
                } else {
                    Ok(Target::Folder(folder_matches.remove(0)))
                }
            }
            _ => bail!("id `{id}` is ambiguous ({total_matches} matches) — use more characters"),
        }
    }
}

/// A target resolved from a user-supplied ID: either an individual object or a folder.
#[derive(Clone, Debug)]
pub enum Target {
    /// A single vault object (.enc file, which could be a file or a native directory archive).
    Object(PathBuf),
    /// A folder grouping multiple vault objects.
    Folder(FolderGroup),
}

/// Information about a folder group spanning multiple vault objects.
#[derive(Clone, Debug)]
pub struct FolderGroup {
    pub id: String,
    pub name: String,
    pub path: PathBuf,
    pub total_size: u64,
    pub latest_hidden_at: i64,
    pub objects: Vec<(PathBuf, Meta)>,
}

/// Compute a deterministic 10-hex character ID for a folder path.
pub fn folder_id(path: &Path) -> String {
    use sha2::{Digest, Sha256};
    let norm = path.to_string_lossy().replace('/', "\\").to_lowercase();
    let hash = Sha256::digest(norm.as_bytes());
    hex::encode(&hash[..5])
}

/// Discover folder groupings from a set of vault entries.
///
/// Traces containing directories of vault files so that entire directories
/// can be inspected, released, or forgotten as a single unit.
pub fn discover_folders(entries: &[(PathBuf, Meta)]) -> Vec<FolderGroup> {
    use std::collections::HashMap;

    let mut dir_map: HashMap<PathBuf, Vec<(PathBuf, Meta)>> = HashMap::new();

    for (obj, meta) in entries {
        // Skip native folder objects — they already have their own object ID
        if meta.ext == "dir" {
            continue;
        }

        // Trace every parent so the directory containing the files is always
        // eligible, including Windows extended paths such as `\\?\C:\...`.
        let mut curr = meta.orig_path.parent();
        while let Some(parent) = curr {
            dir_map
                .entry(parent.to_path_buf())
                .or_default()
                .push((obj.clone(), meta.clone()));
            curr = parent.parent();
        }
    }

    let mut groups = Vec::new();
    for (dir_path, objs) in dir_map {
        if objs.is_empty() {
            continue;
        }
        let name = dir_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "folder".to_string());
        let id = folder_id(&dir_path);
        let total_size = objs.iter().map(|(_, m)| m.size).sum();
        let latest_hidden_at = objs.iter().map(|(_, m)| m.hidden_at).max().unwrap_or(0);

        groups.push(FolderGroup {
            id,
            name,
            path: dir_path,
            total_size,
            latest_hidden_at,
            objects: objs,
        });
    }

    // The same files naturally produce a group for every ancestor directory.
    // Keep the deepest directory for an identical object set; otherwise a
    // vault containing C:\work\docs would also advertise C:\Users and C:\.
    let filtered_groups: Vec<FolderGroup> = groups
        .iter()
        .filter(|group| {
            !groups.iter().any(|other| {
                other.path != group.path
                    && other.objects.len() == group.objects.len()
                    && other
                        .objects
                        .iter()
                        .map(|(obj, _)| obj)
                        .eq(group.objects.iter().map(|(obj, _)| obj))
                    && other.path.starts_with(&group.path)
            })
        })
        .cloned()
        .collect();

    let mut groups = filtered_groups;
    groups.sort_by_key(|g| std::cmp::Reverse(g.latest_hidden_at));
    groups
}

/// Prefix of the message produced when a sealed value fails to open.
///
/// The interactive menu watches for this to decide whether its cached password
/// has gone stale, so the wording `unseal_root` builds from it must stay in
/// sync. It is a prefix rather than the whole message because the tail names
/// the recovery key too, which the menu has no use for.
pub const AUTH_FAILED: &str = "wrong password";

/// How the caller wants to prove they own the vault.
///
/// The CLI fills this from `--recovery` / `--password-file`, falling back to
/// `Prompt`. The interactive menu holds a `Password` for as long as it is open
/// so the user is not re-prompted after every arrow-key selection; `Zeroizing`
/// wipes it when the menu exits.
///
/// No `Debug` impl on purpose — a stray `{:?}` must not be able to print a
/// live master password to a log.
#[derive(Clone)]
pub enum Credential {
    /// Ask on the terminal, with echo disabled.
    Prompt,
    /// Read the password from a file (scripting).
    File(PathBuf),
    /// The 64-hex recovery key printed by `vault init`.
    Recovery(String),
    /// Already in memory.
    Password(Zeroizing<String>),
}

impl Credential {
    /// Build the credential the command line asks for.
    ///
    /// `clap` marks `--recovery` and `--password-file` as conflicting, so
    /// recovery winning here can never silently override a password file.
    pub fn new(recovery: Option<String>, password_file: Option<PathBuf>) -> Self {
        match (recovery, password_file) {
            (Some(hex), _) => Credential::Recovery(hex),
            (None, Some(path)) => Credential::File(path),
            (None, None) => Credential::Prompt,
        }
    }

    /// True when a password still has to be obtained from the user.
    pub fn needs_prompt(&self) -> bool {
        matches!(self, Credential::Prompt)
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
            anyhow::anyhow!("{AUTH_FAILED} (or recovery key) — nothing was modified")
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
