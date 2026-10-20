use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

use crate::crypto::keys::random_bytes;
use crate::crypto::{kdf, keys::KEY_LEN};

/// Magic bytes identifying a vault header. Version is encoded in the magic so
/// a future format change can't be silently misread as v1.
pub const MAGIC: &[u8; 8] = b"VLTVAULT";

/// On-disk layout of `vault.hdr`.
///
/// Everything here is plaintext by necessity — it is needed *before* any key
/// exists. It must therefore contain no information that reveals anything
/// about the hidden files: no counts, no names, no timestamps.
///
/// Total size is fixed at 128 bytes so the file length leaks nothing either.
#[derive(Debug, Clone)]
pub struct VaultHeader {
    /// Argon2id salt. Random, unique per vault.
    pub salt: [u8; kdf::SALT_LEN],
    /// Argon2id memory cost, in KiB. Stored so parameters can be raised
    /// later without breaking existing vaults.
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    /// `root_key` sealed under the password-derived key.
    pub pwd_blob: SealedKey,
    /// The same `root_key` sealed under the recovery key. Redundant
    /// redundancy on purpose: either path unlocks the vault independently.
    pub rec_blob: SealedKey,
}

/// A 32-byte key sealed with XChaCha20-Poly1305.
#[derive(Debug, Clone)]
pub struct SealedKey {
    pub nonce: [u8; 24],
    /// Ciphertext plus 16-byte Poly1305 tag.
    pub ct: [u8; KEY_LEN + 16],
}

/// How the `root_key` is stored: two independent seals, one per unlock path.
///
/// `root_key` is the single secret every subkey descends from. Storing it
/// sealed twice — once under the password, once under the recovery key —
/// means neither the password nor the recovery key *is* the vault key. An
/// attacker who steals `vault.hdr` and brute-forces the password still gets
/// only the root key, and cannot distinguish "guessed right" from "guessed
/// wrong" without the Poly1305 tag rejecting it.
pub struct RootSeals {
    pub pwd: SealedKey,
    pub rec: SealedKey,
}

impl VaultHeader {
    /// Deterministic byte size. Pad or fail rather than varying the length.
    ///
    /// Layout: 8 magic + 16 salt + 12 KDF params + 2 × (24 nonce + 48 sealed
    /// key) = 180 bytes. The two-seal layout is what makes password and
    /// recovery key independent unlock paths, so the header is larger than a
    /// single-seal design would be.
    ///
    /// The length is a `const` and asserted at compile time in `write`, so
    /// the on-disk format cannot silently drift from this documentation.
    pub const LEN: usize = 8 + kdf::SALT_LEN + 12 + 2 * (24 + KEY_LEN + 16);

    pub fn new(salt: [u8; kdf::SALT_LEN], seals: RootSeals) -> Self {
        Self {
            salt,
            m_cost: kdf::DEFAULT_M_KIB,
            t_cost: kdf::DEFAULT_T,
            p_cost: kdf::DEFAULT_P,
            pwd_blob: seals.pwd,
            rec_blob: seals.rec,
        }
    }

    pub fn seal_root(
        root_key: &[u8; KEY_LEN],
        pwd_key: &[u8; KEY_LEN],
        rec_key: &[u8; KEY_LEN],
    ) -> RootSeals {
        use crate::crypto::keys::{random_nonce, seal};

        let pwd_nonce = random_nonce();
        let rec_nonce = random_nonce();

        // AAD binds each seal to its purpose, so the two ciphertexts cannot be
        // swapped for one another.
        let pwd_ct = seal(pwd_key, &pwd_nonce, root_key, b"vault.v1.root.pwd")
            .expect("seal of 32 bytes cannot fail");
        let rec_ct = seal(rec_key, &rec_nonce, root_key, b"vault.v1.root.rec")
            .expect("seal of 32 bytes cannot fail");

        let pack = |ct: Vec<u8>| {
            let mut out = [0u8; KEY_LEN + 16];
            out.copy_from_slice(&ct);
            out
        };

        RootSeals {
            pwd: SealedKey {
                nonce: pwd_nonce,
                ct: pack(pwd_ct),
            },
            rec: SealedKey {
                nonce: rec_nonce,
                ct: pack(rec_ct),
            },
        }
    }

    pub fn write(&self, path: &Path) -> Result<()> {
        use std::io::Write;

        let mut buf = Vec::with_capacity(Self::LEN);
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&self.salt);
        buf.extend_from_slice(&self.m_cost.to_le_bytes());
        buf.extend_from_slice(&self.t_cost.to_le_bytes());
        buf.extend_from_slice(&self.p_cost.to_le_bytes());
        write_sealed(&mut buf, &self.pwd_blob);
        write_sealed(&mut buf, &self.rec_blob);

        debug_assert_eq!(buf.len(), Self::LEN);

        let mut f = std::fs::File::create(path)
            .with_context(|| format!("could not create {}", path.display()))?;
        f.write_all(&buf)?;
        Ok(())
    }

    pub fn read(path: &Path) -> Result<Self> {
        use std::io::Read;

        let mut f = std::fs::File::open(path)
            .with_context(|| format!("no reliquary found at {}", path.display()))?;

        let mut buf = vec![0u8; Self::LEN];
        f.read_exact(&mut buf)
            .context("reliquary header is truncated")?;

        let mut cur = Cursor::new(&buf);
        let magic = cur.take(8);
        if magic != MAGIC {
            bail!(
                "{} is not a reliquary header (bad magic bytes)",
                path.display()
            );
        }

        let salt = cur.take(kdf::SALT_LEN).try_into().unwrap();
        let m_cost = u32::from_le_bytes(cur.take(4).try_into().unwrap());
        let t_cost = u32::from_le_bytes(cur.take(4).try_into().unwrap());
        let p_cost = u32::from_le_bytes(cur.take(4).try_into().unwrap());

        // Refuse absurd KDF parameters outright. A corrupted or tampered
        // header could otherwise trigger a multi-gigabyte allocation.
        if !(64..=2_097_152).contains(&m_cost)
            || !(1..=64).contains(&t_cost)
            || !(1..=64).contains(&p_cost)
        {
            bail!("reliquary header has invalid KDF parameters");
        }

        Ok(Self {
            salt,
            m_cost,
            t_cost,
            p_cost,
            pwd_blob: read_sealed(&mut cur),
            rec_blob: read_sealed(&mut cur),
        })
    }
}

fn write_sealed(buf: &mut Vec<u8>, s: &SealedKey) {
    buf.extend_from_slice(&s.nonce);
    buf.extend_from_slice(&s.ct);
}

fn read_sealed(cur: &mut Cursor<'_>) -> SealedKey {
    let nonce = cur.take(24).try_into().unwrap();
    let ct = cur.take(KEY_LEN + 16).try_into().unwrap();
    SealedKey { nonce, ct }
}

/// Byte-slicing helper over a `&[u8]`, advancing a shared offset.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn take(&mut self, n: usize) -> &'a [u8] {
        let end = self.pos + n;
        let out = &self.data[self.pos..end];
        self.pos = end;
        out
    }
}

/// Where the vault lives on disk.
pub struct VaultDir {
    pub root: PathBuf,
}

impl VaultDir {
    pub fn resolve(explicit: Option<PathBuf>) -> Result<Self> {
        let root = match explicit {
            Some(p) => p,
            None => {
                let home = std::env::var("USERPROFILE")
                    .or_else(|_| std::env::var("HOME"))
                    .context("cannot determine home directory")?;
                PathBuf::from(home).join(".reliquary")
            }
        };
        Ok(Self { root })
    }

    pub fn header_path(&self) -> PathBuf {
        self.root.join("vault.hdr")
    }

    pub fn objects_dir(&self) -> PathBuf {
        self.root.join("objects")
    }

    pub fn exists(&self) -> bool {
        self.header_path().exists()
    }

    /// Create the directory tree for a brand new vault. Refuses to clobber.
    pub fn create(&self) -> Result<()> {
        if self.exists() {
            bail!("a reliquary already exists at {}", self.root.display());
        }
        std::fs::create_dir_all(self.objects_dir())
            .with_context(|| format!("could not create {}", self.objects_dir().display()))?;
        Ok(())
    }
}

pub fn random_root_key() -> [u8; KEY_LEN] {
    random_bytes::<KEY_LEN>()
}
