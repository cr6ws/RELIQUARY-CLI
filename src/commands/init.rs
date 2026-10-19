use anyhow::{bail, Context, Result};
use rand::RngCore;
use std::path::PathBuf;
use zeroize::Zeroizing;

use crate::cli::InitArgs;
use crate::crypto::kdf;
use crate::crypto::keys::{hkdf_expand, random_bytes, seal, VaultKeys};
use crate::crypto::vault::{random_root_key, VaultDir, VaultHeader};
use crate::session::Credential;

pub fn run(args: InitArgs, vault_dir: Option<PathBuf>, cred: &Credential) -> Result<()> {
    let dir = VaultDir::resolve(vault_dir)?;
    dir.create()?;

    // With a password file there is no second party to confirm against, so
    // the file is the single source of truth. Interactive init still
    // confirms twice — a typo here means a permanently inaccessible vault.
    //
    // A recovery key is ignored rather than rejected, which is what `vault
    // init --recovery` has always done: init sets a *new* password, and the
    // recovery key has no say in that.
    let password = match cred {
        Credential::File(path) => crate::session::read_password_file(path)?,
        _ => prompt_new_password()?,
    };

    let mut salt = [0u8; kdf::SALT_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);

    // The root key is pure random — it is never derived from the password.
    // The password and recovery key each seal it independently, so an
    // attacker who steals vault.hdr learns nothing about the root key
    // without breaking one of the two seals.
    let root_key = Zeroizing::new(random_root_key());

    let pwd_key = Zeroizing::new(kdf::derive(
        password.as_bytes(),
        &salt,
        kdf::DEFAULT_M_KIB,
        kdf::DEFAULT_T,
        kdf::DEFAULT_P,
    )?);

    // `&recovery_raw` is `&Zeroizing<[u8; 32]>`, which does not coerce to
    // `&[u8]` on its own. `&*` steps through Deref to reach `[u8; 32]`,
    // which then unsizes to `&[u8]`.
    let recovery_raw = Zeroizing::new(random_bytes::<32>());
    let recovery_key = Zeroizing::new(hkdf_expand(&*recovery_raw, b"vault.v1.recovery"));

    // `Zeroizing` derefs to its inner `[u8; 32]`, which coerces to the `&[u8]`
    // the callers expect — no explicit `&*` needed at these call sites.
    let seals = VaultHeader::seal_root(&root_key, &pwd_key, &recovery_key);
    let header = VaultHeader::new(salt, seals);
    header
        .write(&dir.header_path())
        .context("could not write vault header")?;

    // Read the header back before declaring success. Catching a malformed
    // write here is far cheaper than discovering it after the user has
    // deleted their originals.
    let reread = VaultHeader::read(&dir.header_path())
        .context("vault was written but could not be read back")?;
    if reread.salt != salt {
        bail!("vault self-test failed — header did not round-trip");
    }

    // Confirm the derived keys are usable before telling the user they are
    // done. A failure here means the vault would be unrecoverable.
    let _ = VaultKeys::derive(&root_key);
    seal(
        &*pwd_key,
        &random_bytes::<24>(),
        b"self-test",
        b"vault.v1.init-check",
    )
    .context("vault self-test failed")?;

    let recovery_hex = hex::encode(*recovery_raw);

    println!("Vault created at {}", dir.root.display());
    println!();
    println!("RECOVERY KEY — write this down and store it offline");
    println!("---------------------------------------------");
    print_recovery(&recovery_hex, args.raw);
    println!("---------------------------------------------");
    println!();
    println!("This is the ONLY way back in if you forget your master password.");
    println!("It is not stored on disk. If you lose both, the files are gone.");
    println!();
    println!("Try it now:  vault list");

    Ok(())
}

fn print_recovery(hex_str: &str, raw: bool) {
    if raw {
        println!("{hex_str}");
        return;
    }
    // Group into readable blocks so it can be transcribed without error.
    for chunk in hex_str.as_bytes().chunks(8) {
        println!("  {}", String::from_utf8_lossy(chunk));
    }
}

fn prompt_new_password() -> Result<Zeroizing<String>> {
    let p1 = Zeroizing::new(
        rpassword::prompt_password("New master password: ").context("could not read password")?,
    );
    if p1.is_empty() {
        bail!("password cannot be empty");
    }
    let p2 = Zeroizing::new(
        rpassword::prompt_password("Confirm password: ").context("could not read password")?,
    );
    if *p1 != *p2 {
        bail!("passwords do not match");
    }
    Ok(p1)
}
