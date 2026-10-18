use anyhow::{anyhow, Result};
use argon2::{Algorithm, Argon2, Params, Version};

/// Argon2id tuning. 64 MiB / t=3 / p=4 is OWASP's 2024 guidance for
/// interactive logins — roughly 0.5s on a modern desktop, which is what we
/// want: fast enough to not be annoying, slow enough to make offline
/// brute-force of a stolen vault.hdr impractical.
pub const DEFAULT_M_KIB: u32 = 65536;
pub const DEFAULT_T: u32 = 3;
pub const DEFAULT_P: u32 = 4;

pub const SALT_LEN: usize = 16;

/// Derive a 256-bit key from the master password.
///
/// `salt` must be unique per vault and is stored in plaintext in `vault.hdr`.
/// The cost parameters are also stored there so we can raise them later
/// without breaking existing vaults.
pub fn derive(password: &[u8], salt: &[u8], m_kib: u32, t: u32, p: u32) -> Result<[u8; 32]> {
    // `argon2::Error` deliberately does not implement `std::error::Error`,
    // so it cannot be fed to anyhow's `Context`. Map it by hand instead.
    let params = Params::new(m_kib, t, p, Some(32))
        .map_err(|e| anyhow!("invalid argon2 parameters: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut out = [0u8; 32];
    argon
        .hash_password_into(password, salt, &mut out)
        .map_err(|e| anyhow!("argon2 derivation failed: {e}"))?;
    Ok(out)
}
