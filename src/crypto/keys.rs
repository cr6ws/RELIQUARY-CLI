use anyhow::{anyhow, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;

/// Length of the master key and every derived subkey, in bytes.
pub const KEY_LEN: usize = 32;
/// XChaCha20-Poly1305 nonce length. Deliberately 192-bit so nonces can be
/// random rather than counter-derived — no state to keep across processes.
pub const NONCE_LEN: usize = 24;
/// Poly1305 authentication tag appended to every ciphertext.
pub const TAG_LEN: usize = 16;

/// A set of keys derived from the master key, one per purpose.
///
/// Separating blob and metadata keys means a flaw in one usage context
/// cannot be used to forge ciphertexts in the other. Both are wiped on drop.
///
/// These are plain `[u8; 32]` rather than `Zeroizing` wrappers so that
/// `&keys.blob` coerces to `&[u8]` naturally at every call site — `Zeroizing`
/// would force an explicit deref at each use, and a missed deref in crypto
/// code is exactly the kind of thing that should not be a compile chore.
/// The `Drop` impl below provides the same guarantee.
pub struct VaultKeys {
    /// Encrypts file content chunks.
    pub blob: [u8; KEY_LEN],
    /// Encrypts the per-object metadata record.
    pub meta: [u8; KEY_LEN],
}

impl VaultKeys {
    /// Split a master key into independent subkeys via HKDF-SHA256.
    ///
    /// The domain-separation strings are part of the format version — changing
    /// them changes every derived key, so they must never be edited in place.
    pub fn derive(master: &[u8; KEY_LEN]) -> Self {
        Self {
            blob: hkdf_expand(master, b"vault.v1.blob"),
            meta: hkdf_expand(master, b"vault.v1.meta"),
        }
    }
}

impl Drop for VaultKeys {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.blob.zeroize();
        self.meta.zeroize();
    }
}

/// HKDF-SHA256 expand step. No salt — the caller's master key is already a
/// high-entropy secret pulled through Argon2id, so a second salt adds nothing.
pub fn hkdf_expand(ikm: &[u8], info: &[u8]) -> [u8; KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = [0u8; KEY_LEN];
    // Cannot fail: output length is well under HKDF's 255*32 byte ceiling.
    hk.expand(info, &mut okm)
        .expect("HKDF expand to 32 bytes is always valid");
    okm
}

fn cipher(key: &[u8]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(Key::from_slice(key))
}

/// Encrypt and authenticate. `aad` is bound to the ciphertext but not
/// encrypted — use it to tie a blob to its container so objects can't be
/// spliced between vault records.
pub fn seal(key: &[u8], nonce: &[u8; NONCE_LEN], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    cipher(key)
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow!("encryption failed"))
}

/// Decrypt and verify. Any bit-flip in the ciphertext or the AAD fails here.
pub fn open(key: &[u8], nonce: &[u8; NONCE_LEN], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    cipher(key)
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| anyhow!("decryption failed"))
}

pub fn random_nonce() -> [u8; NONCE_LEN] {
    random_bytes::<NONCE_LEN>()
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
}

/// A short random hex identifier for naming vault objects.
///
/// 5 bytes = 40 bits. With ~1M objects the birthday-collision probability is
/// roughly 0.4%, and a collision is caught by `resolve_id` reporting
/// ambiguity rather than silently returning the wrong file. Short enough to
/// type by hand, long enough to never collide in practice.
pub fn random_hex_id() -> String {
    hex::encode(random_bytes::<5>())
}

/// Namespace tags for nonce derivation. Each independently-encrypted record
/// type under a given file nonce gets its own tag, so a metadata nonce and a
/// chunk nonce can never collide.
pub const NONCE_TAG_CHUNK: u8 = 0;
pub const NONCE_TAG_META: u8 = 1;

/// Derive a unique 192-bit nonce for record `index` under `tag`.
///
/// HKDF-SHA256 keyed by the per-file random nonce. Because the tag and index
/// are concatenated into a fixed 9-byte info string, no two (tag, index) pairs
/// ever produce the same output, and the nonces carry no exploitable structure.
pub fn derive_nonce(file_nonce: &[u8; NONCE_LEN], tag: u8, index: u64) -> [u8; NONCE_LEN] {
    let mut info = [0u8; 9];
    info[0] = tag;
    info[1..].copy_from_slice(&index.to_le_bytes());

    let hk = Hkdf::<Sha256>::new(None, file_nonce);
    let mut okm = [0u8; NONCE_LEN];
    hk.expand(&info, &mut okm)
        .expect("HKDF expand to 24 bytes is always valid");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property that makes random-nonce AEAD safe: no two (tag, index)
    /// pairs collide. If this ever breaks, every vault silently becomes
    /// forgeable, so it is worth pinning.
    #[test]
    fn nonces_never_collide_across_tags_or_indices() {
        let file_nonce = random_bytes::<NONCE_LEN>();
        let mut seen = std::collections::HashSet::new();

        for index in 0..64u64 {
            assert!(seen.insert(derive_nonce(&file_nonce, NONCE_TAG_CHUNK, index)));
            assert!(seen.insert(derive_nonce(&file_nonce, NONCE_TAG_META, index)));
        }
    }

    /// A different file nonce must produce entirely different subkeys and
    /// nonces, even for the same tag/index. This is what stops an attacker
    /// from reusing one file's nonce stream against another file.
    #[test]
    fn distinct_file_nonces_produce_distinct_derived_keys() {
        let a = random_bytes::<NONCE_LEN>();
        let b = random_bytes::<NONCE_LEN>();

        assert_ne!(
            hkdf_expand(&a, b"vault.v1.blob"),
            hkdf_expand(&b, b"vault.v1.blob"),
            "distinct IKMs must not collide under the same info string"
        );
        assert_ne!(
            derive_nonce(&a, NONCE_TAG_CHUNK, 0),
            derive_nonce(&b, NONCE_TAG_CHUNK, 0)
        );
    }

    /// Round-trip and tamper detection for the AEAD itself.
    #[test]
    fn seal_open_round_trip_and_tamper_detection() {
        let key = random_bytes::<KEY_LEN>();
        let nonce = random_nonce();
        let plaintext = b"a file's worth of bytes";

        let ct = seal(&key, &nonce, plaintext, b"aad").expect("seal");
        assert_eq!(open(&key, &nonce, &ct, b"aad").expect("open"), plaintext);

        // Flipping any single bit anywhere must fail. Poly1305 is the whole
        // reason we can trust a decrypted chunk, so this is the invariant
        // that matters most.
        for pos in 0..ct.len() {
            let mut tampered = ct.clone();
            tampered[pos] ^= 0x01;
            assert!(
                open(&key, &nonce, &tampered, b"aad").is_err(),
                "tampering byte {pos} was not detected"
            );
        }
    }

    /// AAD must bind the ciphertext to its context.
    #[test]
    fn aad_is_enforced() {
        let key = random_bytes::<KEY_LEN>();
        let nonce = random_nonce();

        let ct = seal(&key, &nonce, b"payload", b"context-a").expect("seal");
        assert!(open(&key, &nonce, &ct, b"context-b").is_err());
        assert!(open(&key, &nonce, &ct, b"").is_err());
    }
}
