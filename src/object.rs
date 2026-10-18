use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

use crate::crypto::keys::{
    derive_nonce, open, random_bytes, seal, VaultKeys, NONCE_LEN, NONCE_TAG_META,
};
use crate::crypto::stream::{decrypt_stream, encrypt_stream, CHUNK_SIZE};

const OBJ_MAGIC: &[u8; 8] = b"VLTVOBJ1";

/// Everything needed to restore a file, and nothing that isn't.
///
/// This struct is encrypted before it touches disk. It carries the original
/// path so `release` can return a file exactly where it came from without the
/// user having to remember or retype it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Meta {
    /// Original absolute path, as it existed before hiding.
    pub orig_path: PathBuf,
    /// Original file name, without the directory.
    pub orig_name: String,
    /// Size in bytes, as read from the source at hide time.
    pub size: u64,
    /// Modification time, preserved across hide/release.
    pub mtime: (i64, u32),
    /// Unix timestamp of when this file entered the vault.
    pub hidden_at: i64,
    /// Extension without the dot, used as a MIME-ish hint on release.
    pub ext: String,
}

/// Additional authenticated data for every record in an object.
///
/// Contains only values knowable *before* decryption — the object magic and
/// the per-file nonce — so the same bytes can be reconstructed on read. It
/// binds each ciphertext to its container, so a metadata record or chunk
/// lifted from one object and pasted into another fails authentication.
fn object_aad(file_nonce: &[u8; NONCE_LEN]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(OBJ_MAGIC.len() + NONCE_LEN);
    aad.extend_from_slice(OBJ_MAGIC);
    aad.extend_from_slice(file_nonce);
    aad
}

/// Read or write a single encrypted object.
///
/// # On-disk layout
///
/// ```text
/// magic       8   "VLTVOBJ1"
/// meta_len    4   little-endian u32
/// meta_ct    ??   XChaCha20-Poly1305(meta), 16-byte tag appended
/// nonce      24   per-file random nonce, plaintext
/// chunk0_len 4   little-endian u32, plaintext bytes in this chunk
/// chunk0_ct ??   ciphertext + tag
/// chunk1_len 4
/// chunk1_ct ??
/// ...
/// ```
///
/// The per-file nonce is stored in the clear. This is safe: nonces are
/// public by design, and each one here is 192 bits of fresh randomness, so a
/// nonce repeat across files is a 2^-192 event.
pub struct Object;

impl Object {
    /// Encrypt `src` into a new object file at `dst`.
    ///
    /// Streams in CHUNK_SIZE blocks, so a multi-gigabyte video never becomes
    /// resident in memory.
    pub fn write(keys: &VaultKeys, meta: &Meta, src: &Path, dst: &Path) -> Result<()> {
        let file_nonce = random_bytes::<NONCE_LEN>();
        let aad = object_aad(&file_nonce);

        let mut meta_bytes = bincode::serialize(meta).context("could not serialize metadata")?;
        let meta_nonce = derive_nonce(&file_nonce, NONCE_TAG_META, 0);
        let meta_ct = seal(&keys.meta, &meta_nonce, &meta_bytes, &aad)?;
        meta_bytes.zeroize();

        let mut out = BufWriter::new(
            File::create(dst).with_context(|| format!("could not create {}", dst.display()))?,
        );
        let mut src_file =
            File::open(src).with_context(|| format!("could not open {}", src.display()))?;

        // The caller obtained `meta.size` from a separate stat before we
        // opened the file. If the file changed in between, or the caller
        // passed a size it never measured, we would write an object whose
        // declared length disagrees with its own ciphertext -- and that
        // object would be unrecoverable, since `decrypt_stream` trusts
        // `meta.size` to know where the chunk stream ends. Take the length
        // from the handle we are actually reading so the record and the data
        // cannot diverge.
        let actual = src_file
            .metadata()
            .context("could not stat the file being hidden")?
            .len();
        if actual != meta.size {
            bail!(
                "size mismatch: metadata says {} bytes but {} is {} bytes now; \
                 refusing to write an object that could not be restored",
                meta.size,
                src.display(),
                actual
            );
        }

        out.write_all(OBJ_MAGIC)?;
        out.write_all(&(meta_ct.len() as u32).to_le_bytes())?;
        out.write_all(&meta_ct)?;
        out.write_all(&file_nonce)?;

        let chunks = encrypt_stream(
            &keys.blob,
            &file_nonce,
            &mut src_file,
            &mut out,
            meta.size,
            &aad,
        )?;

        out.flush()?;
        out.into_inner()
            .map_err(|e| anyhow!("could not flush object: {e}"))?
            .sync_all()
            .context("could not sync object to disk")?;

        let _ = chunks;
        Ok(())
    }

    /// Decrypt the metadata record without touching the chunk data.
    ///
    /// Used by `list` and `show` so browsing a vault doesn't have to read
    /// every encrypted byte of every file in it.
    pub fn read_meta(keys: &VaultKeys, path: &Path) -> Result<Meta> {
        let mut f = BufReader::new(File::open(path)?);
        let (meta, _nonce) = Self::read_header(keys, &mut f)?;
        Ok(meta)
    }

    /// Decrypt an entire object into `dest`.
    ///
    /// Verifies every chunk's Poly1305 tag as it goes. A failure partway
    /// through leaves a partial file at `dest` — the caller is responsible for
    /// cleaning that up, which is safer than silently deleting output that
    /// might be the only surviving copy.
    pub fn extract_to(keys: &VaultKeys, path: &Path, dest: &mut dyn Write) -> Result<Meta> {
        let mut f = BufReader::new(File::open(path)?);
        let (meta, file_nonce) = Self::read_header(keys, &mut f)?;
        let aad = object_aad(&file_nonce);

        let chunk_count = if meta.size == 0 {
            0
        } else {
            meta.size.div_ceil(CHUNK_SIZE as u64)
        };

        decrypt_stream(&keys.blob, &file_nonce, &mut f, dest, chunk_count, &aad)?;

        dest.flush()?;
        Ok(meta)
    }

    fn read_header(keys: &VaultKeys, f: &mut BufReader<File>) -> Result<(Meta, [u8; NONCE_LEN])> {
        let mut magic = [0u8; 8];
        f.read_exact(&mut magic).context("object is truncated")?;
        if &magic != OBJ_MAGIC {
            bail!("not a vault object (bad magic)");
        }

        let mut len_buf = [0u8; 4];
        f.read_exact(&mut len_buf).context("object is truncated")?;
        let meta_len = u32::from_le_bytes(len_buf) as usize;

        // Metadata is one struct's worth of data; anything wildly larger
        // means the header is corrupt or the file isn't a vault object.
        if meta_len == 0 || meta_len > 64 * 1024 {
            bail!("object metadata length is implausible ({meta_len} bytes)");
        }

        let mut meta_ct = vec![0u8; meta_len];
        f.read_exact(&mut meta_ct).context("object is truncated")?;

        let mut file_nonce = [0u8; NONCE_LEN];
        f.read_exact(&mut file_nonce)
            .context("object is truncated")?;

        let aad = object_aad(&file_nonce);
        let meta_nonce = derive_nonce(&file_nonce, NONCE_TAG_META, 0);

        let plain = open(&keys.meta, &meta_nonce, &meta_ct, &aad).map_err(|_| {
            anyhow!("could not decrypt object metadata — wrong password, or the vault is corrupted")
        })?;

        let meta: Meta = bincode::deserialize(&plain).context("metadata is malformed")?;
        // Wipe the ciphertext copy now that we hold the plaintext.
        meta_ct.zeroize();

        Ok((meta, file_nonce))
    }
}
