use anyhow::{anyhow, bail, Result};
use std::io::{Read, Write};
use zeroize::Zeroize;

use super::keys::{derive_nonce, open, seal, NONCE_LEN, NONCE_TAG_CHUNK, TAG_LEN};
/// Plaintext bytes per encrypted chunk.
///
/// Large enough that per-chunk overhead stays negligible (~0.002%), small
/// enough that a decryption buffer never grows unbounded. A 4 GB video is
/// processed 1 MiB at a time and never fully resident in memory.
pub const CHUNK_SIZE: usize = 1024 * 1024;

/// Derive the nonce for chunk `index`.
///
/// Delegates to the shared namespaced derivation so chunk nonces and metadata
/// nonces under the same file nonce cannot collide.
fn chunk_nonce(file_nonce: &[u8; NONCE_LEN], index: u64) -> [u8; NONCE_LEN] {
    derive_nonce(file_nonce, NONCE_TAG_CHUNK, index)
}

/// Encrypt a stream of exactly `total_len` plaintext bytes into `writer`.
///
/// Returns the number of chunks written. The final chunk is padded to
/// CHUNK_SIZE inside an AEAD record whose length is carried in the header, so
/// a partial final chunk is still self-delimiting on read.
pub fn encrypt_stream(
    key: &[u8],
    file_nonce: &[u8; NONCE_LEN],
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    total_len: u64,
    aad: &[u8],
) -> Result<u64> {
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut remaining = total_len;
    let mut index: u64 = 0;

    while remaining > 0 {
        let take = std::cmp::min(remaining, CHUNK_SIZE as u64) as usize;
        read_exact(reader, &mut buf[..take]).map_err(|e| anyhow!("failed reading source: {e}"))?;

        let ct = seal(key, &chunk_nonce(file_nonce, index), &buf[..take], aad)?;
        writer
            .write_all(&(take as u32).to_le_bytes())
            .map_err(|e| anyhow!("failed writing chunk header: {e}"))?;
        writer
            .write_all(&ct)
            .map_err(|e| anyhow!("failed writing chunk: {e}"))?;

        remaining -= take as u64;
        index += 1;
    }

    buf.zeroize();
    Ok(index)
}

/// Decrypt a stream previously produced by [`encrypt_stream`].
///
/// Reads chunk lengths from the framing rather than recomputing them, so this
/// is robust to any future change in how the final partial chunk is sized.
pub fn decrypt_stream(
    key: &[u8],
    file_nonce: &[u8; NONCE_LEN],
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    expected_chunks: u64,
    aad: &[u8],
) -> Result<()> {
    let mut buf = vec![0u8; CHUNK_SIZE + TAG_LEN];

    for index in 0..expected_chunks {
        let mut len_buf = [0u8; 4];
        read_exact(reader, &mut len_buf)
            .map_err(|_| anyhow!("vault is truncated — file is incomplete or corrupted"))?;
        let plain_len = u32::from_le_bytes(len_buf) as usize;

        if plain_len == 0 || plain_len > CHUNK_SIZE {
            bail!("corrupted chunk framing at index {index}");
        }

        let ct_len = plain_len + super::keys::TAG_LEN;
        read_exact(reader, &mut buf[..ct_len])
            .map_err(|_| anyhow!("vault is truncated — file is incomplete or corrupted"))?;

        let pt = open(key, &chunk_nonce(file_nonce, index), &buf[..ct_len], aad)
            .map_err(|_| anyhow!("authentication failed at chunk {index}"))?;

        writer
            .write_all(&pt)
            .map_err(|e| anyhow!("failed writing output: {e}"))?;
    }

    // Everything written must have been accounted for. If the caller asked
    // for fewer chunks than the file actually contains, or the metadata that
    // drove the chunk count was corrupted, this is what catches it. Without
    // this check a tampered `size` field silently yields a short file that
    // still passes every per-chunk tag.
    let mut trailing = [0u8; 1];
    match reader.read(&mut trailing) {
        Ok(0) => {}
        Ok(_) => bail!("trailing data after the last chunk — vault is truncated or corrupt"),
        Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
        Err(e) => return Err(anyhow!("error checking for trailing data: {e}")),
    }

    buf.zeroize();
    Ok(())
}

/// `read` that loops until the buffer is full or the stream ends.
///
/// `Read::read_exact` gives an opaque "failed to fill whole buffer" with no
/// hint at how far it got, which is useless for diagnosing a truncated vault.
fn read_exact(reader: &mut dyn Read, buf: &mut [u8]) -> std::io::Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    if filled == buf.len() {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "unexpected end of stream",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::{random_bytes, VaultKeys};

    fn round_trip(plaintext: &[u8]) -> Result<()> {
        let key = random_bytes::<32>();
        let file_nonce = random_bytes::<NONCE_LEN>();
        let aad = b"test-aad";

        let mut ciphertext = Vec::new();
        let chunks = encrypt_stream(
            &key,
            &file_nonce,
            &mut &plaintext[..],
            &mut ciphertext,
            plaintext.len() as u64,
            aad,
        )?;

        // Chunk count must match what the decryptor will be told to expect.
        let expected = if plaintext.is_empty() {
            0
        } else {
            (plaintext.len() as u64).div_ceil(CHUNK_SIZE as u64)
        };
        assert_eq!(chunks, expected, "chunk count mismatch");

        let mut out = Vec::new();
        decrypt_stream(
            &key,
            &file_nonce,
            &mut &ciphertext[..],
            &mut out,
            chunks,
            aad,
        )?;

        assert_eq!(out, plaintext, "round trip changed the data");
        Ok(())
    }

    #[test]
    fn round_trip_empty_file() {
        round_trip(b"").expect("empty file should round-trip");
    }

    #[test]
    fn round_trip_single_byte() {
        round_trip(b"x").expect("1-byte file should round-trip");
    }

    /// Exactly one chunk — the boundary where `remaining` hits zero on the
    /// nose rather than being truncated by a partial read.
    #[test]
    fn round_trip_exact_chunk_boundary() {
        let data = vec![0xABu8; CHUNK_SIZE];
        round_trip(&data).expect("exactly-one-chunk file should round-trip");
    }

    /// One byte past the boundary, forcing a second chunk that holds a
    /// single byte. This is the case most likely to expose an off-by-one
    /// in the final-chunk sizing.
    #[test]
    fn round_trip_chunk_boundary_plus_one() {
        let data = vec![0xCDu8; CHUNK_SIZE + 1];
        round_trip(&data).expect("boundary+1 file should round-trip");
    }

    #[test]
    fn round_trip_multi_chunk_randomish_data() {
        // Pseudo-random so it exercises varied byte values without needing
        // a rand dependency in the test module.
        let data: Vec<u8> = (0..CHUNK_SIZE * 3 + 777).map(|i| (i % 251) as u8).collect();
        round_trip(&data).expect("3-chunk file should round-trip");
    }

    /// Truncating the ciphertext must fail loudly rather than silently
    /// producing a shorter output. This is what protects a `release` from
    /// handing back a file that looks fine but is missing its tail.
    #[test]
    fn truncated_ciphertext_is_rejected() {
        let key = random_bytes::<32>();
        let file_nonce = random_bytes::<NONCE_LEN>();
        let plaintext = vec![7u8; CHUNK_SIZE * 2];
        let aad = b"aad";

        let mut ciphertext = Vec::new();
        encrypt_stream(
            &key,
            &file_nonce,
            &mut &plaintext[..],
            &mut ciphertext,
            plaintext.len() as u64,
            aad,
        )
        .expect("encrypt");

        let truncated = &ciphertext[..ciphertext.len() - 1];
        let mut out = Vec::new();
        let result = decrypt_stream(&key, &file_nonce, &mut &truncated[..], &mut out, 2, aad);
        assert!(result.is_err(), "truncated ciphertext must not decrypt");
    }

    /// A tampered chunk must fail authentication before any of it is
    /// written out as trusted plaintext.
    #[test]
    fn tampered_chunk_is_rejected() {
        let key = random_bytes::<32>();
        let file_nonce = random_bytes::<NONCE_LEN>();
        let plaintext = vec![9u8; CHUNK_SIZE + 500];
        let aad = b"aad";

        let mut ciphertext = Vec::new();
        encrypt_stream(
            &key,
            &file_nonce,
            &mut &plaintext[..],
            &mut ciphertext,
            plaintext.len() as u64,
            aad,
        )
        .expect("encrypt");

        let mut tampered = ciphertext.clone();
        let pos = tampered.len() - 10;
        tampered[pos] ^= 0x01;

        let mut out = Vec::new();
        let result = decrypt_stream(&key, &file_nonce, &mut &tampered[..], &mut out, 2, aad);
        assert!(result.is_err(), "tampered chunk must not decrypt");
    }

    /// Chunk framing must not depend on the caller guessing chunk sizes.
    #[test]
    fn wrong_chunk_count_is_rejected() {
        let key = random_bytes::<32>();
        let file_nonce = random_bytes::<NONCE_LEN>();
        let plaintext = vec![1u8; CHUNK_SIZE * 2];
        let aad = b"aad";

        let mut ciphertext = Vec::new();
        let chunks = encrypt_stream(
            &key,
            &file_nonce,
            &mut &plaintext[..],
            &mut ciphertext,
            plaintext.len() as u64,
            aad,
        )
        .expect("encrypt");

        // Ask for fewer chunks than were written. Must not silently succeed
        // with a truncated result.
        let mut out = Vec::new();
        let result = decrypt_stream(
            &key,
            &file_nonce,
            &mut &ciphertext[..],
            &mut out,
            chunks - 1,
            aad,
        );
        match result {
            Err(_) => {}
            Ok(()) => panic!("decrypting fewer chunks than exist must not succeed silently"),
        }
    }

    /// The AAD must be enforced by the stream layer, not just the AEAD.
    #[test]
    fn stream_aad_is_enforced() {
        let key = random_bytes::<32>();
        let file_nonce = random_bytes::<NONCE_LEN>();
        let plaintext = b"some content";

        let mut ciphertext = Vec::new();
        encrypt_stream(
            &key,
            &file_nonce,
            &mut &plaintext[..],
            &mut ciphertext,
            plaintext.len() as u64,
            b"aad-a",
        )
        .expect("encrypt");

        let mut out = Vec::new();
        let result = decrypt_stream(
            &key,
            &file_nonce,
            &mut &ciphertext[..],
            &mut out,
            1,
            b"aad-b",
        );
        assert!(result.is_err(), "wrong AAD must not decrypt");
    }

    /// Keep the VaultKeys import honest — it is what production callers hold.
    #[test]
    fn vault_keys_derives_distinct_subkeys() {
        let root = random_bytes::<32>();
        let keys = VaultKeys::derive(&root);
        assert_ne!(
            keys.blob.as_ref(),
            keys.meta.as_ref(),
            "blob and metadata keys must be independent"
        );
    }
}
